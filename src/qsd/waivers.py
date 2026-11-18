"""The waiver file (`.qsdignore`): mark findings as ignored (a false positive or an accepted risk)
or tracked (a real finding that already has a ticket).

A waived finding is never removed. It stays in the report with a `waiver` on it; only the
headline counts differ (`ignore` rows are left out, `track` rows are still counted). The file is
always passed explicitly. It is never read from a scanned checkout, otherwise a pull request
could waive its own finding.
"""

import datetime as _dt
import fnmatch
import hashlib
import os
import re
import shlex

from .model import is_malware

MAX_BYTES = 256 * 1024
MAX_DAYS = 366            # "at most 12 months ahead"
VERBS = ("ignore", "track")
SOURCES = {"SonarQube", "Snyk", "Trivy", "Semgrep", "Dependabot", "ClamAV", "GuardDog", "Gitleaks",
           "OSV-Scanner", "zizmor"}   # kept equal to the schema's `src` enum by a test
KEYS = {"reason", "until", "ticket", "src", "ref", "loc", "project", "track", "expect"}
MATCHERS = ("src", "ref", "loc", "track")   # at least one; `project` alone would waive a whole project
# Rows that need an individual decision: only an exact `track=` may waive them, never a pattern.
STRICT_KINDS = {"Secret", "Malware", "Malicious Package"}
_TICKET = re.compile(r"^[^\s\x00-\x1f]{2,200}$")


class WaiverError(ValueError):
    """The waiver file is invalid, or would hide something it must not."""


class Waiver:
    def __init__(self, line, verb, fields):
        self.line = line
        self.verb = verb
        self.reason = fields["reason"]
        self.until = fields["until"]
        self.ticket = fields.get("ticket", "")
        self.expect = fields.get("expect")
        self.src = fields.get("src")
        self.ref = fields.get("ref")
        self.loc = fields.get("loc")
        self.project = fields.get("project")
        self.track = fields.get("track")
        self.matched = 0

    def describe(self):
        return {"line": self.line, "status": self.verb, "reason": self.reason,
                "ticket": self.ticket, "until": self.until.isoformat(), "expect": self.expect,
                "matched": self.matched}

    def tag(self):
        return {"status": self.verb, "reason": self.reason, "ticket": self.ticket,
                "until": self.until.isoformat(), "line": self.line}

    def selects(self, row):
        """Whether this line's matchers pick the row (expiry and policy are checked elsewhere)."""
        if self.src is not None:
            # Every scanner that saw the row must be the named one: a row merged from two
            # scanners is not waived by naming only one of them.
            if set(row.get("by") or [row["src"]]) != {self.src}:
                return False
        if self.ref is not None:
            if not any(fnmatch.fnmatchcase(v, self.ref)
                       for v in [row.get("ref", ""), *(row.get("ids") or [])] if v):
                return False
        if self.loc is not None and not fnmatch.fnmatchcase(row.get("loc", ""), self.loc):
            return False
        if self.project is not None and self.project not in (row.get("project_id"), row.get("proj")):
            return False
        if self.track is not None and self.track != row.get("track"):
            return False
        return True


def _fail(line, message):
    raise WaiverError(f"waiver file line {line}: {message}")


def parse(text, today):
    """Waiver text -> [Waiver]. Raises WaiverError with the line number on any bad line."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        try:
            tokens = shlex.split(raw, comments=True)
        except ValueError as exc:
            _fail(n, f"cannot read the line ({exc})")
        if not tokens:
            continue
        verb, pairs = tokens[0], tokens[1:]
        if verb not in VERBS:
            _fail(n, f"must start with {' or '.join(VERBS)}, not {verb!r}")
        fields = {}
        for pair in pairs:
            key, eq, value = pair.partition("=")
            if not eq or key not in KEYS:
                _fail(n, f"{pair!r} is not key=value with a key from {', '.join(sorted(KEYS))}")
            if key in fields:
                _fail(n, f"{key} is given twice")
            if not value:
                _fail(n, f"{key} is empty")
            fields[key] = value
        for need in ("reason", "until"):
            if need not in fields:
                _fail(n, f"{need} is required")
        if len(fields["reason"]) > 300:
            _fail(n, "reason is longer than 300 characters")
        if not any(k in fields for k in MATCHERS):
            _fail(n, f"needs at least one of {', '.join(MATCHERS)}; `project` alone would "
                     f"waive everything in it")
        if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", fields["until"]):
            _fail(n, "until must be a date like 2027-05-01")
        try:
            until = _dt.date.fromisoformat(fields["until"])
        except ValueError:
            _fail(n, f"until {fields['until']!r} is not a real date")
        if until > today + _dt.timedelta(days=MAX_DAYS):
            _fail(n, f"until is more than 12 months away (latest {today + _dt.timedelta(days=MAX_DAYS)}); "
                     f"a waiver must be renewed, not left forever")
        fields["until"] = until
        if "src" in fields and fields["src"] not in SOURCES:
            _fail(n, f"src {fields['src']!r} is not a scanner; use one of {', '.join(sorted(SOURCES))}")
        if "ticket" in fields and not _TICKET.match(fields["ticket"]):
            _fail(n, "ticket must be one word (an id or a link)")
        if verb == "track" and "ticket" not in fields:
            _fail(n, "track needs a ticket: it means a real finding that someone is working on")
        if "expect" in fields:
            if not fields["expect"].isdigit() or int(fields["expect"]) < 1:
                _fail(n, "expect must be a whole number, 1 or more")
            fields["expect"] = int(fields["expect"])
        out.append(Waiver(n, verb, fields))
    return out


def load(path, today):
    """Read the file at an explicit path -> (waivers, sha256 hex of its bytes)."""
    try:
        if os.path.getsize(path) > MAX_BYTES:
            raise WaiverError(f"{path}: larger than {MAX_BYTES // 1024} KB")
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        raise WaiverError(f"cannot read the waiver file {path!r} ({exc.__class__.__name__})") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WaiverError(f"{path}: not UTF-8") from exc
    return parse(text, today), hashlib.sha256(data).hexdigest()


def apply(rows, waivers, today):
    """Tag rows with `waiver` (None when none applies) and return the report block's pieces.

    Returns (errors, block). The first line that selects a row owns it; a later line that
    selects only already-owned rows is reported as stale. A line that is expired, or that
    selects more rows than its `expect`, waives nothing, so the findings come back, and it is
    listed in `errors` (a strict run exits 2 on them). A line that selects nothing is `stale`.
    Policy violations raise WaiverError: a pattern that reaches a secret or malware row, or an
    `ignore` of a HIGH-or-above finding without a ticket.
    """
    for r in rows:
        r["waiver"] = None
    errors = []
    for w in waivers:
        if w.until < today:
            errors.append(f"line {w.line}: expired on {w.until.isoformat()}; the findings "
                            f"it covered are counted again")
            continue
        picked = [r for r in rows if r["waiver"] is None and w.selects(r)]
        for r in picked:
            if r.get("kind") in STRICT_KINDS or is_malware(r):
                if w.track is None:
                    raise WaiverError(
                        f"waiver file line {w.line}: a pattern reaches the {r['kind']} finding "
                        f"{r.get('track')} ({r.get('loc')}); secrets and malware can only be waived "
                        f"one by one, with track=<its track key>")
            if r.get("rank", 5) <= 1 and not w.ticket:
                raise WaiverError(
                    f"waiver file line {w.line}: it covers the {r['sev']} finding {r.get('track')} "
                    f"({r.get('ref')} {r.get('loc')}); HIGH and above need ticket=")
        if w.expect is not None and len(picked) > w.expect:
            errors.append(f"line {w.line}: selects {len(picked)} findings but expect={w.expect}; "
                            f"it waives none until the file is reviewed")
            w.matched = len(picked)
            continue
        for r in picked:
            r["waiver"] = w.tag()
        w.matched = len(picked)
    stale = [w.line for w in waivers if w.matched == 0 and w.until >= today]
    return errors, {
        "lines": [w.describe() for w in waivers],
        "stale": stale,
        "expired": [w.line for w in waivers if w.until < today],
        "errors": errors,
    }
