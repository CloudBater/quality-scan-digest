"""Semgrep: Code (SAST) and Supply Chain results from `semgrep ... --json`."""

from ..model import finding
from . import read_json, unreadable

# Semgrep severity is rule-level, not risk-level: a low-confidence audit rule
# can carry impact HIGH. Rank by `severity` so crit+high counts what Semgrep
# itself would block on.
SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
       "CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}


def load(path, label):
    """Returns (rows, note)."""
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return [], unreadable(path, exc)

    rows = []
    for r in doc.get("results") or []:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        sca = extra.get("sca_info") or {}
        dep = (sca.get("dependency_match") or {}).get("found_dependency") or {}
        supply_chain = bool(sca) or str(r.get("check_id", "")).startswith("ssc-")
        security = supply_chain or meta.get("category") == "security"
        rows.append(finding(
            proj=label, src="Semgrep",
            kind=("Dependency" if supply_chain
                  else "Vulnerability" if security else "Code Smell"),
            sev=SEV.get(str(extra.get("severity", "")).upper(), "—"),
            msg=(extra.get("message") or "").strip(),
            loc=r.get("path", ""),
            line=(r.get("start") or {}).get("line"),
            ref=r.get("check_id", ""),
            fix=meta.get("shortlink") or "",
            ids=list(_as_list(meta.get("cve"))) + list(_as_list(meta.get("ghsa"))),
            cwe=meta.get("cwe"),
            package=dep.get("package", ""),
        ))

    # `errors` are scan failures, not findings: an empty list with errors is incomplete.
    errs = doc.get("errors") or []
    note = f"{len(errs)} scan error(s)" if errs and not rows else ""
    return rows, note


def _as_list(v):
    if not v:
        return []
    return [v] if isinstance(v, str) else list(v)
