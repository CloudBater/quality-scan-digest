"""The finding row shared by every parser, and the severity scale they map onto."""

import hashlib
import re

# Each tool names severities differently; collapse them onto one scale.
RANK = {"CRITICAL": 0, "BLOCKER": 0, "HIGH": 1, "MAJOR": 2, "MEDIUM": 2,
        "MINOR": 3, "LOW": 3, "INFO": 4, "—": 5}

SECURITY_KINDS = {"Vulnerability", "Security Hotspot"}
SECURITY_SOURCES = {"Snyk", "Trivy", "Dependabot"}

_CWE = re.compile(r"CWE-?(\d+)", re.IGNORECASE)


def rank(sev):
    return RANK.get(sev, 5)


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


def norm_package(name):
    """PEP 503-style package normalisation, applied to every ecosystem."""
    return re.sub(r"[-_.]+", "-", (name or "").strip().lower())


def finding(*, proj, src, kind, sev, msg, loc="", line="", ref="", fix="",
            ids=(), cwe=(), package=""):
    """One row. Keys without a leading underscore are the export contract."""
    return {
        "proj": proj,
        "src": src,
        "kind": kind,
        "sev": (sev or "—").upper(),
        "msg": msg or "",
        "loc": loc or "",
        "line": line if line not in (None, 0) else "",
        "ref": ref or "",
        "fix": fix or "",
        "ids": sorted(advisory_ids(ids)),
        "cwe": sorted(cwe_ids(cwe)),
        "_package": norm_package(package),
    }


def fingerprint(row):
    """Stable id for a finding while the code around it does not move."""
    key = "|".join(str(row.get(k, "")) for k in ("proj", "src", "ref", "loc", "line"))
    return hashlib.sha1(key.encode("utf-8")).hexdigest()[:16]


def is_security(row):
    """Dependency and misconfiguration scanners are all security; code tools by kind."""
    return row["src"] in SECURITY_SOURCES or row["kind"] in SECURITY_KINDS
