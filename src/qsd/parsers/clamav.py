"""ClamAV: `clamscan -r --infected --no-summary --stdout` text output.

Lines look like `./path/to/file: Eicar-Test-Signature FOUND`. Lines starting
with `#` are metadata written by qsd. clamscan exits 1 when it finds something
and 2 on error; the runner handles the exit code, this reads the text.
"""

from ..model import finding
from . import failed, status


def load(path, label, project_id=None):
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError as exc:
        return failed(f"clamav output unreadable ({exc.__class__.__name__})")

    rows, errors = [], 0
    for line in lines:
        if not line.strip() or line.startswith("#"):
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
    return rows, status(note=f"incomplete: {errors} file(s) could not be scanned" if errors else "")
