"""Snyk: Open Source, Code (SARIF), IaC and Container JSON output."""

from ..model import finding
from . import read_json, unreadable

PRODUCTS = ("Open Source", "Code", "IaC", "Container")

_SARIF_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}


def load(path, product, label):
    """Parse one `snyk ... --json-file-output` file. Returns (rows, dep_count, note)."""
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return [], None, unreadable(path, exc)

    rows, deps = [], None
    # --all-projects emits a list; a single target emits an object.
    for proj in (doc if isinstance(doc, list) else [doc]):
        if not isinstance(proj, dict):
            continue
        if proj.get("dependencyCount"):
            deps = (deps or 0) + proj["dependencyCount"]

        # Snyk repeats a vulnerability once per dependency path; keep one per id.
        seen = {}
        for v in proj.get("vulnerabilities") or []:
            seen.setdefault(v.get("id"), v)
        for v in seen.values():
            fixed = v.get("fixedIn") or []
            ids = v.get("identifiers") or {}
            rows.append(finding(
                proj=label, src="Snyk",
                kind="Container" if product == "Container" else "Dependency",
                sev=v.get("severity"),
                msg=v.get("title", ""),
                loc=f"{v.get('packageName', '')}@{v.get('version', '')}",
                ref=v.get("id", ""),
                fix=("upgrade to " + ", ".join(fixed[:2])) if fixed else "no fix",
                ids=list(ids.get("CVE") or []) + list(ids.get("GHSA") or []),
                cwe=ids.get("CWE"),
                package=v.get("packageName", ""),
            ))

        for i in proj.get("infrastructureAsCodeIssues") or []:
            rows.append(finding(
                proj=label, src="Snyk", kind="IaC",
                sev=i.get("severity"),
                msg=i.get("title", ""),
                loc=proj.get("targetFile", ""),
                line=i.get("lineNumber"),
                ref=i.get("id", ""),
                fix=i.get("resolve") or "",
            ))

        # Snyk Code emits SARIF.
        for run in proj.get("runs") or []:
            rules = {r.get("id"): r for r in
                     run.get("tool", {}).get("driver", {}).get("rules", [])}
            for res in run.get("results") or []:
                loc, line = "", ""
                for loc_ in res.get("locations") or []:
                    pl = loc_.get("physicalLocation", {})
                    loc = pl.get("artifactLocation", {}).get("uri", "")
                    line = pl.get("region", {}).get("startLine", "")
                    break
                rule = rules.get(res.get("ruleId"), {})
                props = rule.get("properties", {})
                sev = str(props.get("problem", {}).get("severity")
                          or res.get("level") or "—").upper()
                rows.append(finding(
                    proj=label, src="Snyk", kind="Code",
                    sev=_SARIF_SEV.get(sev, sev),
                    msg=(res.get("message") or {}).get("text", ""),
                    loc=loc, line=line,
                    ref=res.get("ruleId", ""),
                    cwe=props.get("cwe"),
                ))
    return rows, deps, ""
