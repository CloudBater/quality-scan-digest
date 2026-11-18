"""Semgrep: Code (SAST) and Supply Chain results from `semgrep ... --json`."""

from ..model import finding
from . import failed, read_json, status, unreadable

# Semgrep severity is rule-level, not risk-level: a low-confidence audit rule
# can carry impact HIGH. Rank by `severity` so crit+high counts what Semgrep
# itself would block on.
SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
       "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def load(path, label, project_id=None, partial_is_gap=False):
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, dict) or "results" not in doc:
        return failed("not recognisable Semgrep JSON output")

    rows = []
    for r in doc.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        sca = extra.get("sca_info") or {}
        dep = (sca.get("dependency_match") or {}).get("found_dependency") or {}
        supply_chain = bool(sca) or str(r.get("check_id", "")).startswith("ssc-")
        security = supply_chain or meta.get("category") == "security"
        rows.append(finding(
            project_id=project_id, proj=label, src="Semgrep",
            kind=("Dependency" if supply_chain
                  else "Vulnerability" if security else "Code Smell"),
            sev=SEV.get(str(extra.get("severity", "")).upper(), "—"),
            msg=(extra.get("message") or "").strip(),
            loc=r.get("path", ""),
            line=(r.get("start") or {}).get("line"), col=(r.get("start") or {}).get("col"),
            ref=r.get("check_id", ""),
            fix=meta.get("shortlink") or "",
            ids=_as_list(meta.get("cve")) + _as_list(meta.get("ghsa")),
            cwe=meta.get("cwe"),
            package=dep.get("package", ""), ecosystem=dep.get("ecosystem", ""),
        ))

    # Errors and results are independent: findings from some files do not make
    # up for files that failed or only partly parsed. A partial parse is a coverage
    # gap by default — counting it complete paints a green zero under a hole.
    # Set semgrep_partial_is_gap=false for noisy repos that only want a note.
    errs = doc.get("errors") or []
    hard = [e for e in errs if str(e.get("level", "error")).lower() != "warn"]
    soft = [e for e in errs if e not in hard]
    # Several warnings can name one file (a syntax error and a partial parse), so count the
    # distinct files; a warning that names no file counts as one of its own.
    warns = len({e.get("path") for e in soft if e.get("path")}) + \
        sum(1 for e in soft if not e.get("path"))

    # PARTIAL SCAN vs INCOMPLETE SOURCE -- why these are two different things.
    #
    # `warn`-level errors mean Semgrep could only partly parse some files (language
    # features its parser lacks, e.g. newer Python syntax). On real repositories this is
    # the NORMAL state: 88 files (91 warnings) on a Django backend and 19 on a Next.js
    # frontend, on every single run. If that counted as an incomplete source, every strict run would
    # exit 2 and the only way to publish would be to switch strict off, which would then
    # hide real gaps as well. The published history also counted these runs as complete.
    #
    # But it is NOT a full scan either, and nobody reading a report may mistake it for
    # one: those files were scanned only in part, so "no finding there" means less than it
    # does elsewhere. So by default the source stays *complete* (strict passes) and
    # carries `partial` = number of partly parsed files, which every output shows loudly
    # (terminal, HTML banner and chip, `sources.*.partial` in the JSON).
    #
    # A project that wants it to block can set `semgrep_partial_is_gap: true`.
    # A hard Semgrep error (`level` other than `warn`) is a gap either way.
    notes = []
    if hard:
        notes.append(f"incomplete: {len(hard)} scan error(s)")
    if warns:
        if partial_is_gap:
            notes.append(f"incomplete: {warns} file(s) only partly parsed")
        else:
            notes.append(f"PARTIAL SCAN: {warns} file(s) only partly parsed, so Semgrep did "
                         f"not fully scan them (the rest of the repository was scanned)")
    return rows, status(note="; ".join(notes),
                        complete=not hard and not (warns and partial_is_gap),
                        partial=warns)


def _as_list(v):
    if not v:
        return []
    return [v] if isinstance(v, str) else list(v)
