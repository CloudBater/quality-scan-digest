"""SonarQube: issues, security hotspots and project measures, live or from files."""

import base64
import json
import sys
import urllib.error
import urllib.parse
import urllib.request

from ..model import finding
from . import read_json

PAGE_SIZE = 500
MAX_ISSUES = 10_000
MEASURE_KEYS = ("ncloc,coverage,duplicated_lines_density,bugs,vulnerabilities,"
                "code_smells,security_hotspots,sqale_index")


class Forbidden(Exception):
    """The token lacks the privilege for this endpoint."""


class SonarError(Exception):
    pass


def api(host, token, path, params):
    url = f"{host.rstrip('/')}{path}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url)
    # SonarQube takes the token as the basic-auth username with no password.
    req.add_header("Authorization",
                   "Basic " + base64.b64encode(f"{token}:".encode()).decode())
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        if exc.code == 403:
            raise Forbidden(path) from None
        raise SonarError(f"{path} returned HTTP {exc.code}") from None
    except urllib.error.URLError as exc:
        raise SonarError(f"cannot reach {host} ({exc.reason})") from None


def fetch_all(host, token, path, params, key):
    out, page = [], 1
    while True:
        data = api(host, token, path, {**params, "p": page, "ps": PAGE_SIZE})
        batch = data.get(key, [])
        out.extend(batch)
        total = data.get("paging", {}).get("total", data.get("total", len(out)))
        if len(batch) < PAGE_SIZE or len(out) >= min(total, MAX_ISSUES):
            if total > MAX_ISSUES:
                print(f"warning: {key} truncated at {MAX_ISSUES} of {total}", file=sys.stderr)
            return out
        page += 1


def fetch(host, token, project_key):
    """Read one project from a running server. Returns (issues, hotspots, measures, note)."""
    issues = fetch_all(host, token, "/api/issues/search",
                       {"components": project_key, "resolved": "false"}, "issues")
    note = ""
    try:
        hotspots = fetch_all(host, token, "/api/hotspots/search",
                             {"project": project_key, "status": "TO_REVIEW"}, "hotspots")
    except Forbidden:
        # An analysis token reads issues and measures but is refused on hotspots.
        hotspots, note = [], "hotspots unreadable: token is not a USER_TOKEN"
    measures = api(host, token, "/api/measures/component",
                   {"component": project_key, "metricKeys": MEASURE_KEYS})
    return issues, hotspots, measures, note


def load_files(cfg):
    """Read a previously exported issues/hotspots/measures set (API response bodies)."""
    def items(path, key):
        if not path:
            return []
        doc = read_json(path)
        pages = doc if isinstance(doc, list) else [doc]
        return [x for p in pages for x in (p.get(key) or [])]
    measures = read_json(cfg["measures"]) if cfg.get("measures") else {}
    return items(cfg.get("issues"), "issues"), items(cfg.get("hotspots"), "hotspots"), measures


def to_rows(issues, hotspots, measures, label):
    measures = {m["metric"]: m.get("value")
                for m in (measures or {}).get("component", {}).get("measures", [])}
    rows = []
    for i in issues:
        rows.append(finding(
            proj=label, src="SonarQube",
            kind=(i.get("type") or "ISSUE").replace("_", " ").title(),
            sev=i.get("severity"),
            msg=i.get("message", ""),
            loc=(i.get("component") or "").split(":", 1)[-1],
            line=i.get("line"),
            ref=i.get("rule", ""),
        ))
    for h in hotspots:
        rows.append(finding(
            proj=label, src="SonarQube", kind="Security Hotspot",
            sev=h.get("vulnerabilityProbability"),
            msg=h.get("message", ""),
            loc=(h.get("component") or "").split(":", 1)[-1],
            line=h.get("line"),
            ref=h.get("ruleKey", ""),
        ))
    return rows, measures
