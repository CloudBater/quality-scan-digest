"""Trivy: misconfigurations from `trivy config`, vulnerabilities from `trivy fs|image`."""

from ..model import finding
from . import failed, read_json, status, unreadable


def load(path, label, project_id=None):
    """`trivy config` reads Dockerfile build instructions, which no Snyk product
    does (e.g. DS-0031, a secret in ENV or ARG)."""
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, dict) or not ("SchemaVersion" in doc or "Results" in doc):
        return failed("not recognisable Trivy JSON output")

    rows = []
    for res in doc.get("Results") or []:
        target = res.get("Target", "")
        eco = res.get("Type", "")
        for m in res.get("Misconfigurations") or []:
            if m.get("Status") == "PASS":
                continue
            cause = m.get("CauseMetadata") or {}
            rows.append(finding(
                project_id=project_id, proj=label, src="Trivy", kind="Misconfiguration",
                sev=m.get("Severity"),
                # The message names the offending key; the title alone is generic.
                msg=m.get("Message") or m.get("Title", ""),
                loc=target, line=cause.get("StartLine"),
                ref=m.get("ID", ""), fix=m.get("Resolution", ""),
            ))
        for v in res.get("Vulnerabilities") or []:
            ref = v.get("VulnerabilityID", "")
            fixed = v.get("FixedVersion", "")
            rows.append(finding(
                project_id=project_id, proj=label, src="Trivy", kind="Dependency",
                sev=v.get("Severity"),
                msg=v.get("Title") or ref,
                loc=f"{target}: {v.get('PkgName', '')}@{v.get('InstalledVersion', '')}",
                ref=ref, fix=f"upgrade to {fixed}" if fixed else "no fix",
                ids=[ref] + list(v.get("VendorIDs") or []),
                cwe=v.get("CweIDs"),
                package=v.get("PkgName", ""), ecosystem=eco,
            ))
    return rows, status()
