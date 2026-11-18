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
    # up for files that failed or only partly parsed. A partial parse is still a
    # coverage gap — counting it complete would paint a green zero under a hole.
    errs = doc.get("errors") or []
    hard = [e for e in errs if str(e.get("level", "error")).lower() != "warn"]
    warns = len(errs) - len(hard)
    # A file Semgrep could only partly parse (`warn`) is the normal state of a real repo
    # (language features its parser lacks), so by default it is a note and the source stays
    # complete; `semgrep_partial_is_gap` makes it a gap. A hard error is always a gap.
    notes = ([f"incomplete: {len(hard)} scan error(s)"] if hard else []) + \
        ([f"{'incomplete: ' if partial_is_gap else ''}{warns} file(s) only partly parsed"]
         if warns else [])
    return rows, status(note="; ".join(notes), complete=not hard and not (warns and partial_is_gap))


def _as_list(v):
    if not v:
        return []
    return [v] if isinstance(v, str) else list(v)
