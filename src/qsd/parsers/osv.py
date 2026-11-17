"""OSV-Scanner: `osv-scanner scan source -r --format json`.

One row per package and per advisory group: OSV already groups aliases (a GHSA
and its CVE) into one group, so they are not counted twice. `MAL-` advisories,
from the OpenSSF malicious-packages feed, are reported as malicious packages.
"""

from ..model import finding
from . import failed, read_json, rel, status, unreadable

_DB_SEV = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MODERATE": "MEDIUM", "MEDIUM": "MEDIUM",
           "LOW": "LOW"}


def _band(score):
    """CVSS base score -> severity band (FIRST's qualitative scale)."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return ""
    return "CRITICAL" if s >= 9 else "HIGH" if s >= 7 else "MEDIUM" if s >= 4 else \
        "LOW" if s > 0 else ""


def _fixed(vulns, name):
    for v in vulns:
        for a in v.get("affected") or []:
            if (a.get("package") or {}).get("name", "").lower() != name.lower():
                continue
            for r in a.get("ranges") or []:
                for e in r.get("events") or []:
                    if e.get("fixed"):
                        return e["fixed"]
    return ""


def load(path, label, project_id=None, root=""):
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, dict) or not isinstance(doc.get("results"), list):
        return failed("not recognisable OSV-Scanner JSON output")

    rows = []
    for result in doc["results"]:
        source = rel((result.get("source") or {}).get("path", ""), root)
        for p in result.get("packages") or []:
            pkg = p.get("package") or {}
            name, version, eco = pkg.get("name", ""), pkg.get("version", ""), pkg.get("ecosystem", "")
            by_id = {v.get("id"): v for v in p.get("vulnerabilities") or []}
            groups = p.get("groups") or [{"ids": [i]} for i in by_id]
            for g in groups:
                ids = list(g.get("ids") or [])
                vulns = [by_id[i] for i in ids if i in by_id]
                aliases = set(ids) | set(g.get("aliases") or [])
                for v in vulns:
                    aliases |= set(v.get("aliases") or [])
                malicious = any(str(i).startswith("MAL-") for i in aliases)
                sev = "CRITICAL" if malicious else _band(g.get("max_severity")) or next(
                    (_DB_SEV.get(str((v.get("database_specific") or {}).get("severity", "")).upper())
                     for v in vulns if (v.get("database_specific") or {}).get("severity")), "—")
                fixed = _fixed(vulns, name)
                ref = next((i for i in ids if i.startswith("MAL-")), ids[0] if ids else "")
                summary = next((v.get("summary") for v in vulns if v.get("summary")), "") or ref
                rows.append(finding(
                    project_id=project_id, proj=label, src="OSV-Scanner",
                    kind="Malicious Package" if malicious else "Dependency",
                    sev=sev, msg=summary,
                    loc=f"{source}: {name}@{version}" if source else f"{name}@{version}",
                    ref=ref, fix=f"upgrade to {fixed}" if fixed else "no fix",
                    ids=[i for i in aliases if i.startswith(("CVE-", "GHSA-"))],
                    package=name, ecosystem=eco,
                ))
    return rows, status()
