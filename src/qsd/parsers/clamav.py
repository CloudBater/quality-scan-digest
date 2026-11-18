"""ClamAV: `clamscan -r --infected --stdout` text output.

Lines look like `./path/to/file: Eicar-Test-Signature FOUND`. Lines starting
with `#` are metadata written by qsd. clamscan exits 1 when it finds something
and 2 on error; the runner handles the exit code, this reads the text.

The summary block at the end (`Scanned files: N`) is the only proof that the scan
finished and looked at something. Without it, an empty file, `{}` or any text would
read as a complete, clean scan, so its absence (or N = 0) makes the source incomplete.
"""

import re

from ..model import finding
from . import failed, status


def load(path, label, project_id=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return failed(f"clamav output unreadable ({exc.__class__.__name__})")

    rows, errors, freshclam_failed, scanned = [], 0, False, None
    for line in lines:
        if not line.strip():
            continue
        m = re.match(r"^Scanned files:\s*(\d+)\s*$", line.strip())
        if m:
            scanned = int(m.group(1))
            continue
        if line.startswith("#"):
            if "freshclam failed" in line.lower():
                freshclam_failed = True
            continue
        if line.endswith(" FOUND") and ": " in line:
            file_, sig = line[:-len(" FOUND")].rsplit(": ", 1)
            while file_.startswith("./"):
                file_ = file_[2:]
            rows.append(finding(
                project_id=project_id, proj=label, src="ClamAV", kind="Malware",
                sev="CRITICAL", msg=f"{sig} detected", loc=file_, ref=sig,
                fix="remove the file and investigate how it got here",
            ))
        elif "ERROR" in line or "Can't" in line:
            errors += 1
    notes = []
    if freshclam_failed:
        notes.append("incomplete: freshclam failed; signatures may be stale or missing")
    if errors:
        notes.append(f"incomplete: {errors} file(s) could not be scanned")
    if scanned is None:
        notes.append("incomplete: no scan summary, so the scan may not have finished")
    elif scanned == 0:
        notes.append("incomplete: ClamAV scanned 0 files")
    note = "; ".join(notes)
    return rows, status(note=note, complete=not note)
