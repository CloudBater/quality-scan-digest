"""The waiver file (`.qsdignore`): mark findings as ignored (a false positive or an accepted risk)
or tracked (a real finding that already has a ticket).

A waived finding is never removed. It stays in the report with a `waiver` on it; only the
headline counts differ (`ignore` rows are left out, `track` rows are still counted). The file is
always passed explicitly. It is never read from a scanned checkout, otherwise a pull request
could waive its own finding.
"""

import datetime as _dt
import hashlib
import os
import re
import shlex
import unicodedata

MAX_BYTES = 256 * 1024
VERBS = ("ignore", "track")
SOURCES = {"SonarQube", "Snyk", "Trivy", "Semgrep", "Dependabot", "ClamAV", "GuardDog", "Gitleaks",
           "OSV-Scanner", "zizmor"}   # kept equal to the schema's `src` enum by a test
KEYS = {"reason", "until", "ticket", "src", "ref", "loc", "project", "track", "expect"}
MATCHERS = ("src", "ref", "loc", "track")   # at least one; `project` alone would waive a whole project
# Rows that need an individual decision: only an exact `track=` may waive them, never a pattern.
STRICT_KINDS = {"Secret", "Malware", "Malicious Package"}
# A secret reported under another kind (Trivy DS-0031 is a Misconfiguration, a Semgrep or Sonar
# rule can be a Vulnerability): by name it is treated like a secret. A false match only means
# the waiver must name the finding with track=, which is the safe direction.
_SECRET_LIKE = re.compile(r"secret|passw(?:or)?d|credential|api[-_ ]?key|token|private[-_ ]?key|hard-?coded",
                          re.IGNORECASE)
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
        self._ref = _glob(self.ref) if self.ref is not None else None
        self._loc = _glob(self.loc) if self.loc is not None else None
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
            if not any(self._ref.fullmatch(v)
                       for v in [row.get("ref", ""), *(row.get("ids") or [])] if v):
                return False
        if self.loc is not None and not self._loc.fullmatch(row.get("loc", "")):
            return False
        if self.project is not None and self.project != row.get("project_id"):
            return False
        if self.track is not None and self.track != row.get("track"):
            return False
        return True


def _latest(today):
    """Twelve calendar months from today (29 February maps to 28 February)."""
    try:
        return today.replace(year=today.year + 1)
    except ValueError:
        return today.replace(year=today.year + 1, day=28)


def _glob(pattern):
    """`*` and `?` stay inside one path segment, `**` crosses `/`, `[` is a plain character.

    fnmatch would let `app/audit/*` reach `app/audit/new/deep.py` and read `pkg[extra]` as a
    character class; a waiver should cover what it says and nothing more.
    """
    out, i = [], 0
    while i < len(pattern):
        c = pattern[i]
        if pattern.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        out.append("[^/]*" if c == "*" else "[^/]" if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out), re.DOTALL)


def _strip_comment(raw):
    """Cut the line at a `#` that starts a word outside quotes.

    shlex's own comment handling also cuts at a `#` inside a word, so a ticket like `org/repo#12`
    would silently drop everything after it, `expect=` included.
    """
    quote, i = None, 0
    while i < len(raw):
        c = raw[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 1
            elif c == quote:
                quote = None
        elif c == "\\":
            i += 1
        elif c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or raw[i - 1].isspace()):
            return raw[:i]
        i += 1
    return raw


def _fail(line, message):
    raise WaiverError(f"waiver file line {line}: {message}")


def parse(text, today):
    """Waiver text -> [Waiver]. Raises WaiverError with the line number on any bad line."""
    out = []
    for n, raw in enumerate(text.splitlines(), 1):
        try:
            tokens = shlex.split(_strip_comment(raw), comments=False)
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
        if not any(unicodedata.category(ch)[0] in "LNPS" for ch in fields["reason"]):
            _fail(n, "reason must say why")
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
        if until > _latest(today):
            _fail(n, f"until is more than 12 months away (latest {_latest(today)}); "
                     f"a waiver must be renewed, not left forever")
        fields["until"] = until
        stars = lambda k: k in fields and re.fullmatch(r"[*?]+", fields[k])  # noqa: E731
        if not ("src" in fields or "track" in fields
                or ("ref" in fields and not stars("ref")) or ("loc" in fields and not stars("loc"))):
            if "expect" not in fields:
                _fail(n, "a line that matches everything (ref/loc made only of * or ?) needs expect=N")
        if "src" in fields and fields["src"] not in SOURCES:
            _fail(n, f"src {fields['src']!r} is not a scanner; use one of {', '.join(sorted(SOURCES))}")
        if "ticket" in fields and not _TICKET.match(fields["ticket"]):
            _fail(n, "ticket must be one word (an id or a link)")
        if verb == "track" and "ticket" not in fields:
            _fail(n, "track needs a ticket: it means a real finding that someone is working on")
        if "expect" in fields:
            if not re.fullmatch(r"[0-9]{1,6}", fields["expect"]) or int(fields["expect"]) < 1:
                _fail(n, "expect must be a whole number, 1 or more")
            fields["expect"] = int(fields["expect"])
        out.append(Waiver(n, verb, fields))
    return out


def load(path, today):
    """Read the file at an explicit path -> (waivers, sha256 hex of its bytes)."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_BYTES + 1)      # the reported size can be wrong (a pipe)
        if len(data) > MAX_BYTES:
            raise WaiverError(f"{path}: larger than {MAX_BYTES // 1024} KB")
    except OSError as exc:
        raise WaiverError(f"cannot read the waiver file {path!r} ({exc.__class__.__name__})") from exc
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise WaiverError(f"{path}: not UTF-8") from exc
    return parse(text, today), hashlib.sha256(data).hexdigest()


def _violation(w, picked):
    for r in picked:
        kinds = {r.get("kind"), *(a.get("kind") for a in r.get("also") or [])}
        looks_secret = any(_SECRET_LIKE.search(v or "") for v in
                           [r.get("ref"), r.get("msg"),
                            *(x for a in r.get("also") or [] for x in (a.get("ref"), a.get("msg")))])
        if (kinds & STRICT_KINDS or looks_secret) and w.track is None:
            return (f"a pattern reaches the {'/'.join(sorted(kinds & STRICT_KINDS)) or 'secret-like'} "
                    f"finding {r.get('track')} ({r.get('loc')}); secrets and malware can only be "
                    f"waived one by one, with track=<its track key>")
        if r.get("rank", 5) <= 1 and not w.ticket:
            return (f"it covers the {r['sev']} finding {r.get('track')} ({r.get('ref')} "
                    f"{r.get('loc')}); HIGH and above need ticket=")
    return None


def apply(rows, waivers, today):
    """Tag rows with `waiver` (None when none applies) and return the report block's pieces.

    Returns (errors, block). The first line that selects a row owns it; a later line that
    selects only already-owned rows is reported as stale. A line that is expired, or that
    selects more rows than its `expect`, waives nothing, so the findings come back, and it is
    listed in `errors` (a strict run exits 2 on them). A line that selects nothing is `stale`.
    A policy violation (a pattern that reaches a secret or malware row, or an `ignore` of a
    HIGH-or-above finding without a ticket) is an error on that line, which then waives nothing.
    """
    for r in rows:
        r["waiver"] = None
    errors = []
    for w in waivers:
        if w.until < today:
            errors.append(f"line {w.line}: expired on {w.until.isoformat()} and no longer applies; "
                          f"its findings are counted unless another line covers them")
            continue
        picked = [r for r in rows if r["waiver"] is None and w.selects(r)]
        # What a line covers depends on the scanned code, so a violation is an error on the line
        # (it waives nothing, a strict run exits 2), never a reason to write no report.
        violation = _violation(w, picked)
        if violation:
            errors.append(f"line {w.line}: {violation}; it waives none until the file is fixed")
            w.matched = len(picked)
            continue
        if w.expect is not None and len(picked) > w.expect:
            errors.append(f"line {w.line}: selects {len(picked)} findings but expect={w.expect}; "
                            f"it waives none itself until the file is reviewed")
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
