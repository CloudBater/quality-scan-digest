"""The finding row shared by every parser, and the severity scale they map onto."""

import hashlib
import re

# Each tool names severities differently; collapse them onto one scale.
RANK = {"CRITICAL": 0, "BLOCKER": 0, "HIGH": 1, "MAJOR": 2, "MEDIUM": 2,
        "MINOR": 3, "LOW": 3, "INFO": 4, "—": 5}

# Classified by what a finding is, not by which scanner reported it, so a merge
# that changes the primary scanner cannot change whether a row counts as security.
SECURITY_KINDS = {"Vulnerability", "Security Hotspot", "Dependency", "Container", "IaC",
                  "Misconfiguration", "Malware", "Malicious Package", "Package Risk", "Secret", "Workflow"}

_CWE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)
_SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

# Python names are case- and separator-insensitive (PEP 503); most others are not.
_PEP503_ECOSYSTEMS = {"pip", "pypi", "poetry", "pipenv", "python"}


def rank(sev):
    return RANK.get(sev, 5)


def safe_name(name):
    """Project ids become file names, so they must be a single safe path component."""
    return bool(_SAFE_NAME.match(name or "")) and ".." not in name


def advisory_ids(*groups):
    """CVE/GHSA ids, upper-cased: the join key between dependency scanners."""
    out = set()
    for g in groups:
        if isinstance(g, str):
            g = [g]
        for i in (g or []):
            if i:
                out.add(str(i).strip().upper())
    return out


def cwe_ids(*groups):
    """Normalise "CWE-79", "CWE-79: Improper ..." or 79 to the string "CWE-79"."""
    out = set()
    for g in groups:
        if isinstance(g, (str, int)):
            g = [g]
        for v in (g or []):
            s = str(v)
            m = _CWE.search(s)
            if m:
                out.add(f"CWE-{int(m.group(1))}")
            elif s.isdigit():
                out.add(f"CWE-{int(s)}")
    return out


def norm_ecosystem(eco):
    e = (eco or "").strip().lower()
    return "pypi" if e in _PEP503_ECOSYSTEMS else e


def norm_package(name, ecosystem=""):
    n = (name or "").strip().lower()
    # Python's separator equivalence applied to npm would equate distinct packages.
    return re.sub(r"[-_.]+", "-", n) if norm_ecosystem(ecosystem) == "pypi" else n


def finding(*, proj, src, kind, sev, msg, loc="", line="", ref="", fix="",
            ids=(), cwe=(), package="", ecosystem="", project_id=None):
    """One row. Keys without a leading underscore are the export contract."""
    try:
        line = int(line) if line not in (None, "") else ""
    except (TypeError, ValueError):
        line = ""
    return {
        "project_id": project_id if project_id is not None else proj,
        "proj": proj,
        "src": src,
        "kind": kind,
        "sev": (sev or "—").upper(),
        "msg": msg or "",
        "loc": loc or "",
        # Tools use 0 or -1 for "no line"; both mean the same as absent.
        "line": line if isinstance(line, int) and line > 0 else "",
        "ref": ref or "",
        "fix": fix or "",
        "ids": sorted(advisory_ids(ids)),
        "cwe": sorted(cwe_ids(cwe)),
        "security": kind in SECURITY_KINDS,
        "_package": norm_package(package, ecosystem),
        "_eco": norm_ecosystem(ecosystem),
    }


def fingerprint(row):
    """Content hash of everything that distinguishes one occurrence from another."""
    key = "\x1f".join(str(row.get(k, "")) for k in
                      ("project_id", "src", "kind", "ref", "loc", "line", "msg"))
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def is_security(row):
    return bool(row.get("security"))
