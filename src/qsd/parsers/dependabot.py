"""Dependabot: open alerts from `gh api /repos/{owner}/{repo}/dependabot/alerts`."""

from ..model import finding
from . import failed, read_json, status, unreadable


def load(path, label, project_id=None):
    try:
        alerts = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    # Paginated output is a list of pages; accept both shapes.
    if isinstance(alerts, list) and alerts and all(isinstance(a, list) for a in alerts):
        alerts = [a for page in alerts for a in page]
    if not isinstance(alerts, list) or not all(isinstance(a, dict) for a in alerts):
        msg = alerts.get("message", "") if isinstance(alerts, dict) else ""
        return failed(f"not a list of alerts{': ' + msg if msg else ''}")

    by_sev, rows, seen = {}, [], set()
    for a in alerts:
        if a.get("state", "open") != "open":
            continue
        adv = a.get("security_advisory") or {}
        vuln = a.get("security_vulnerability") or {}
        sev = (adv.get("severity") or "unknown").upper()
        by_sev[sev] = by_sev.get(sev, 0) + 1

        pkg = (vuln.get("package") or {}).get("name", "")
        eco = (vuln.get("package") or {}).get("ecosystem", "")
        manifest = (a.get("dependency") or {}).get("manifest_path", "")
        ghsa = adv.get("ghsa_id", "")
        # One row per manifest: two services that both need the fix are two rows.
        if (manifest, pkg, ghsa) in seen:
            continue
        seen.add((manifest, pkg, ghsa))
        cve = [i.get("value") for i in adv.get("identifiers") or [] if i.get("type") == "CVE"]
        fixed = (vuln.get("first_patched_version") or {}).get("identifier", "")
        pkg_loc = f"{pkg}@{vuln.get('vulnerable_version_range', '')}".strip("@")
        rows.append(finding(
            project_id=project_id, proj=label, src="Dependabot", kind="Dependency",
            sev=sev, msg=adv.get("summary", ""),
            loc=f"{manifest}: {pkg_loc}" if manifest else pkg_loc,
            ref=ghsa, fix=f"upgrade to {fixed}" if fixed else "no fix",
            ids=cve + [ghsa],
            cwe=[c.get("cwe_id") for c in adv.get("cwes") or []],
            package=pkg, ecosystem=eco,
        ))
    counts = {"total": sum(by_sev.values()), "unique": len(rows), "by_sev": by_sev}
    return rows, status(counts=counts)
