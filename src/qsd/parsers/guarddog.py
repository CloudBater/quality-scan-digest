"""GuardDog: `guarddog <ecosystem> verify <manifest> --output-format json`.

`threat-*` rules describe malicious behaviour (exfiltration, reverse shells,
download-and-execute). `capability-*` rules only say what a package can do --
`exec` alone trips one -- so they are kept at LOW. Metadata rules (typosquatting,
compromised maintainer domains) sit in between.
"""

from ..model import finding
from . import failed, read_json, status, unreadable


def _sev(rule):
    if rule.startswith("threat-"):
        return "HIGH"
    if rule.startswith("capability-"):
        return "LOW"
    return "MEDIUM"


def load(path, label, project_id=None, ecosystem="", manifest=""):
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, list) or not all(isinstance(d, dict) and "result" in d for d in doc):
        return failed("not recognisable GuardDog verify output")

    rows, errored = [], 0
    for dep in doc:
        name, version = dep.get("dependency", ""), dep.get("version", "")
        result = dep.get("result") or {}
        if result.get("errors"):
            errored += 1
        for rule, hit in (result.get("results") or {}).items():
            if not hit:
                continue
            matches = hit if isinstance(hit, list) else [hit]
            for m in matches:
                where = m.get("location", "") if isinstance(m, dict) else ""
                msg = m.get("message", "") if isinstance(m, dict) else str(m)
                rows.append(finding(
                    project_id=project_id, proj=label, src="GuardDog",
                    kind="Malicious Package" if rule.startswith("threat-") else "Package Risk",
                    sev=_sev(rule), msg=f"{name}@{version}: {msg or rule}".strip(),
                    loc=f"{manifest}: {name}@{version}" + (f" ({where})" if where else ""),
                    ref=rule, package=name, ecosystem=ecosystem,
                ))
    note = f"incomplete: {errored} dependenc(ies) failed analysis" if errored else ""
    return rows, status(note=note)
