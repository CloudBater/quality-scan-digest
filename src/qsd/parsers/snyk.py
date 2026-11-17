"""Snyk: Open Source, Code (SARIF), IaC and Container JSON output."""

from ..model import finding
from . import failed, read_json, status, unreadable

PRODUCTS = ("Open Source", "Code", "IaC", "Container")

_SARIF_SEV = {"ERROR": "HIGH", "WARNING": "MEDIUM", "NOTE": "LOW"}
_KNOWN = ("vulnerabilities", "infrastructureAsCodeIssues", "runs", "applications")


def _is_error(doc):
    return (isinstance(doc, dict) and not any(k in doc for k in _KNOWN)
            and (doc.get("ok") is False or "error" in doc))


def load(path, product, label, project_id=None):
    """Parse one `snyk ... --json-file-output` file."""
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)

    docs = doc if isinstance(doc, list) else [doc]
    if not docs or any(_is_error(d) for d in docs):
        err = next((d.get("error") for d in docs if isinstance(d, dict) and d.get("error")), "")
        return failed(f"snyk reported an error: {str(err)[:200]}" if err
                      else "snyk reported an error")
    if not all(isinstance(d, dict) and any(k in d for k in _KNOWN) for d in docs):
        return failed("not recognisable Snyk output")

    rows, deps = [], None
    # Container results carry the image's OS packages at the top level and the
    # application dependencies found inside it under `applications`.
    targets = []
    for d in docs:
        targets.append(d)
        targets.extend(a for a in d.get("applications") or [] if isinstance(a, dict))

    for proj in targets:
        if proj.get("dependencyCount"):
            deps = (deps or 0) + proj["dependencyCount"]
        eco = proj.get("packageManager", "")
        target = proj.get("displayTargetFile") or proj.get("targetFile") or ""

        # Snyk repeats a vulnerability once per dependency path; keep one per
        # vulnerability, package and installed version, so a second affected
        # version is never lost.
        seen = {}
        for v in proj.get("vulnerabilities") or []:
            seen.setdefault((v.get("id"), v.get("packageName"), v.get("version")), v)
        for v in seen.values():
            fixed = v.get("fixedIn") or []
            ids = v.get("identifiers") or {}
            pkg_loc = f"{v.get('packageName', '')}@{v.get('version', '')}"
            rows.append(finding(
                project_id=project_id, proj=label, src="Snyk",
                kind="Container" if product == "Container" else "Dependency",
                sev=v.get("severity"),
                msg=v.get("title", ""),
                loc=f"{target}: {pkg_loc}" if target else pkg_loc,
                ref=v.get("id", ""),
                fix=("upgrade to " + ", ".join(fixed[:2])) if fixed else "no fix",
                ids=list(ids.get("CVE") or []) + list(ids.get("GHSA") or []),
                cwe=ids.get("CWE"),
                package=v.get("packageName", ""), ecosystem=eco,
            ))

        for i in proj.get("infrastructureAsCodeIssues") or []:
            rows.append(finding(
                project_id=project_id, proj=label, src="Snyk", kind="IaC",
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
                if res.get("suppressions"):
                    continue  # ignored in Snyk; not an open finding
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
                    project_id=project_id, proj=label, src="Snyk", kind="Vulnerability",
                    sev=_SARIF_SEV.get(sev, sev),
                    msg=(res.get("message") or {}).get("text", ""),
                    loc=loc, line=line,
                    ref=res.get("ruleId", ""),
                    cwe=props.get("cwe"),
                ))
    return rows, status(deps=deps)
