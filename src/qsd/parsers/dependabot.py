"""Dependabot: open alerts from `gh api /repos/{owner}/{repo}/dependabot/alerts`."""

from ..model import finding
from . import read_json, unreadable


def load(path, label):
    """Returns (rows, counts, note). counts is None when the file is unusable."""
    try:
        alerts = read_json(path)
    except (OSError, ValueError) as exc:
        return [], None, unreadable(path, exc)
    if not isinstance(alerts, list):
        return [], None, "dependabot payload is not a list of alerts"
    # Paginated output is a list of pages; accept both shapes.
    if alerts and all(isinstance(a, list) for a in alerts):
        alerts = [a for page in alerts for a in page]

    by_sev, rows, seen = {}, [], set()
    for a in alerts:
        if a.get("state", "open") != "open":
            continue
        adv = a.get("security_advisory") or {}
        vuln = a.get("security_vulnerability") or {}
        sev = (adv.get("severity") or "unknown").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

        pkg = (vuln.get("package") or {}).get("name", "")
        ghsa = adv.get("ghsa_id", "")
        # One alert per advisory per manifest: a package listed in both a
        # manifest and its lockfile raises the same advisory twice.
        if (pkg, ghsa) in seen:
            continue
        seen.add((pkg, ghsa))
        cve = [i.get("value") for i in adv.get("identifiers") or [] if i.get("type") == "CVE"]
        fixed = (vuln.get("first_patched_version") or {}).get("identifier", "")
        rows.append(finding(
            proj=label, src="Dependabot", kind="Dependency",
            sev=sev, msg=adv.get("summary", ""),
            loc=f"{pkg}@{vuln.get('vulnerable_version_range', '')}".strip("@"),
            ref=ghsa, fix=f"upgrade to {fixed}" if fixed else "no fix",
            ids=cve + [ghsa],
            cwe=[c.get("cwe_id") for c in adv.get("cwes") or []],
            package=pkg,
        ))
    counts = {"total": sum(by_sev.values()), "unique": len(rows), "by_sev": by_sev}
    return rows, counts, ""
