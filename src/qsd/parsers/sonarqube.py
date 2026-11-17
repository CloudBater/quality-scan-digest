"""SonarQube: issues, security hotspots and project measures, live or from files."""

import base64
import ipaddress
import json
import urllib.error
import urllib.parse
import urllib.request

from ..model import finding
from . import failed, read_json, status

PAGE_SIZE = 500
MAX_ISSUES = 10_000
MEASURE_KEYS = ("ncloc,coverage,duplicated_lines_density,bugs,vulnerabilities,"
                "code_smells,security_hotspots,sqale_index")


class Forbidden(Exception):
    """The token lacks the privilege for this endpoint."""


class SonarError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    # urllib keeps the Authorization header across a cross-host redirect; never follow one.
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SonarError(f"refusing to follow a redirect to {newurl}")


_OPENER = urllib.request.build_opener(_NoRedirect)


def check_host(host):
    """A token may only go to HTTPS, or to plain HTTP on this machine."""
    u = urllib.parse.urlsplit(host)
    if u.scheme == "https" and u.hostname:
        return
    if u.scheme == "http" and u.hostname:
        try:
            if u.hostname == "localhost" or ipaddress.ip_address(u.hostname).is_loopback:
                return
        except ValueError:
            pass
    raise SonarError(f"refusing to send a token to {host}: use https, or http on loopback")


def api(host, token, path, params):
    check_host(host)
    url = f"{host.rstrip('/')}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    # SonarQube takes the token as the basic-auth username with no password.
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    try:
        with _OPENER.open(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise Forbidden(path) from None
        raise SonarError(f"{path} returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise SonarError(f"cannot reach {host} ({exc.reason})") from None


def fetch_all(host, token, path, params, key):
    """Returns (items, total). total > len(items) means the result was truncated."""
    out, page = [], 1
    while True:
        data = api(host, token, path, {**params, "p": page, "ps": PAGE_SIZE})
        batch = data.get(key, [])
        out.extend(batch)
        total = data.get("paging", {}).get("total", data.get("total", len(out)))
        if len(batch) < PAGE_SIZE or len(out) >= min(total, MAX_ISSUES):
            return out, total
        page += 1


def fetch(host, token, project_key):
    """Read one project from a server into the same shape `export` writes."""
    issues, total = fetch_all(host, token, "/api/issues/search",
                              {"components": project_key, "resolved": "false"}, "issues")
    doc = {"issues": {"issues": issues, "total": total}}
    try:
        hs, htotal = fetch_all(host, token, "/api/hotspots/search",
                               {"project": project_key, "status": "TO_REVIEW"}, "hotspots")
        doc["hotspots"] = {"hotspots": hs, "total": htotal}
    except Forbidden:
        doc["hotspots"] = {"hotspots": [], "error": "forbidden: token is not a user token"}
    doc["measures"] = api(host, token, "/api/measures/component",
                          {"component": project_key, "metricKeys": MEASURE_KEYS})
    return doc


def load_files(cfg):
    """Read an exported issues/hotspots/measures set. Issues are required."""
    if not cfg.get("issues"):
        raise SonarError("no issues export")
    doc = {"issues": read_json(cfg["issues"])}
    if cfg.get("hotspots"):
        doc["hotspots"] = read_json(cfg["hotspots"])
    if cfg.get("measures"):
        doc["measures"] = read_json(cfg["measures"])
    return doc


def to_rows(doc, label, project_id=None):
    issues_doc = doc.get("issues") or {}
    if not isinstance(issues_doc, dict) or "issues" not in issues_doc:
        return failed("issues export is not recognisable") + ({},)
    notes = []
    issues = issues_doc.get("issues") or []
    total = issues_doc.get("total", issues_doc.get("paging", {}).get("total", len(issues)))
    if total > len(issues):
        notes.append(f"incomplete: {len(issues)} of {total} issues read")

    hs_doc = doc.get("hotspots")
    hotspots = []
    if hs_doc is None:
        notes.append("incomplete: no hotspots export")
    elif hs_doc.get("error"):
        notes.append(f"incomplete: hotspots {hs_doc['error']}")
    else:
        hotspots = hs_doc.get("hotspots") or []
        htotal = hs_doc.get("total", hs_doc.get("paging", {}).get("total", len(hotspots)))
        if htotal > len(hotspots):
            notes.append(f"incomplete: {len(hotspots)} of {htotal} hotspots read")

    measures = {m["metric"]: m.get("value") for m in
                (doc.get("measures") or {}).get("component", {}).get("measures", [])}
    if not measures:
        notes.append("incomplete: no measures")

    rows = []
    for i in issues:
        kind = (i.get("type") or "ISSUE").replace("_", " ").title()
        rows.append(finding(
            project_id=project_id, proj=label, src="SonarQube", kind=kind,
            sev=i.get("severity"), msg=i.get("message", ""),
            loc=(i.get("component") or "").split(":", 1)[-1],
            line=i.get("line"), ref=i.get("rule", ""),
        ))
    for h in hotspots:
        rows.append(finding(
            project_id=project_id, proj=label, src="SonarQube", kind="Security Hotspot",
            sev=h.get("vulnerabilityProbability"), msg=h.get("message", ""),
            loc=(h.get("component") or "").split(":", 1)[-1],
            line=h.get("line"), ref=h.get("ruleKey", ""),
        ))
    return rows, status(note="; ".join(notes)), measures
