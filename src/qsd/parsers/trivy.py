"""Trivy: misconfigurations from `trivy config`, vulnerabilities from `trivy fs|image`."""

from ..model import finding
from . import read_json, unreadable


def load(path, label):
    """Returns (rows, note).

    `trivy config` is the reason Trivy is in the set: it reads Dockerfile build
    instructions, which no Snyk product does (e.g. DS-0031, a secret in ENV/ARG).
    """
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return [], unreadable(path, exc)

    rows = []
    for res in doc.get("Results") or []:
        target = res.get("Target", "")
        for m in res.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            rows.append(finding(
                proj=label, src="Trivy", kind="Misconfiguration",
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
                proj=label, src="Trivy", kind="Dependency",
                sev=v.get("Severity"),
                msg=v.get("Title") or ref,
                loc=f"{v.get('PkgName', '')}@{v.get('InstalledVersion', '')}",
                ref=ref, fix=f"upgrade to {fixed}" if fixed else "no fix",
                ids=[ref] + list(v.get("VendorIDs") or []),
                cwe=v.get("CweIDs"),
                package=v.get("PkgName", ""),
            ))
    return rows, ""
