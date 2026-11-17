"""zizmor: `zizmor --format json` over GitHub Actions workflows, actions and
Dependabot config. Findings marked `ignored` (inline or in zizmor.yml) are skipped.
"""

from ..model import finding
from . import failed, read_json, rel, status, unreadable

_SEV = {"HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "INFORMATIONAL": "INFO"}


def _primary(f):
    locs = f.get("locations") or []
    for loc in locs:
        if (loc.get("symbolic") or {}).get("kind") == "Primary":
            return loc
    return locs[0] if locs else {}


def load(path, label, project_id=None, root=""):
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, list) or not all(isinstance(f, dict) and "ident" in f for f in doc):
        return failed("not recognisable zizmor JSON output")

    rows = []
    for f in doc:
        if f.get("ignored"):
            continue
        det = f.get("determinations") or {}
        loc = _primary(f)
        sym = loc.get("symbolic") or {}
        key = sym.get("key") or {}
        file_ = next((v.get("verbatim_path") or v.get("path", "") for v in key.values()
                      if isinstance(v, dict)), "")
        start = ((loc.get("concrete") or {}).get("location") or {}).get("start_point") or {}
        row = start.get("row")
        note = sym.get("annotation") or ""
        rows.append(finding(
            project_id=project_id, proj=label, src="zizmor", kind="Workflow",
            sev=_SEV.get(str(det.get("severity", "")).upper(), "—"),
            msg=f"{f.get('desc', '')}{': ' + note if note else ''}"
                f" (confidence {str(det.get('confidence', '?')).lower()})",
            loc=rel(file_, root), line=row + 1 if isinstance(row, int) else "",
            ref=f["ident"], fix=f.get("url", ""),
        ))
    return rows, status()
