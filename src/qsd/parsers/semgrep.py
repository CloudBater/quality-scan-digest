"""Semgrep: Code (SAST) and Supply Chain results from `semgrep ... --json`."""

from ..model import finding
from . import failed, read_json, status, unreadable

# Semgrep severity is rule-level, not risk-level: a low-confidence audit rule
# can carry impact HIGH. Rank by `severity` so crit+high counts what Semgrep
# itself would block on.
SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
       "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def load(path, label, project_id=None):
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
            line=(r.get("start") or {}).get("line"),
            ref=r.get("check_id", ""),
            fix=meta.get("shortlink") or "",
            ids=_as_list(meta.get("cve")) + _as_list(meta.get("ghsa")),
            cwe=meta.get("cwe"),
            package=dep.get("package", ""), ecosystem=dep.get("ecosystem", ""),
        ))

    # Errors and results are independent: findings from some files do not make
    # up for files that failed to scan. `warn` (a file only partly parsed) is
    # recorded but does not make the source incomplete; anything else does.
    errs = doc.get("errors") or []
    hard = [e for e in errs if str(e.get("level", "error")).lower() != "warn"]
    warns = len(errs) - len(hard)
    notes = ([f"incomplete: {len(hard)} scan error(s)"] if hard else []) + \
        ([f"{warns} file(s) only partly parsed"] if warns else [])
    return rows, status(note="; ".join(notes), complete=not hard)


def _as_list(v):
    if not v:
        return []
    return [v] if isinstance(v, str) else list(v)
