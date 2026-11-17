"""Turn a manifest of raw scanner outputs into one deduplicated JSON payload.

The payload is the contract; the HTML report is one renderer of it. See
schema/report.schema.json for the shape.
"""

import datetime as _dt
import os

from . import __version__
from .dedup import dedup
from .model import fingerprint, is_security, rank
from .parsers import coverage as p_coverage
from .parsers import dependabot as p_dependabot
from .parsers import semgrep as p_semgrep
from .parsers import snyk as p_snyk
from .parsers import sonarqube as p_sonar
from .parsers import trivy as p_trivy

SCHEMA_VERSION = "1.0"


def _exists(path):
    return bool(path) and os.path.exists(path)


def collect_project(cfg, sonar_token=""):
    """Gather one project's sources. Returns (rows, summary, sources).

    A source listed in the manifest but missing on disk is reported as not
    collected, never silently dropped: its absence is not a clean result.
    """
    label = cfg.get("label") or cfg.get("name") or cfg.get("project") or "project"
    rows, sources, measures, deps = [], {}, {}, None

    sq = cfg.get("sonarqube")
    if sq is not None:
        name = f"{label}: SonarQube"
        try:
            if sq.get("host"):
                token = sq.get("token") or sonar_token
                if not token:
                    raise p_sonar.SonarError("no token (set SONAR_TOKEN)")
                issues, hotspots, raw, note = p_sonar.fetch(
                    sq["host"], token, sq.get("project_key") or cfg.get("name") or label)
            elif sq.get("issues") or sq.get("measures"):
                issues, hotspots, raw = p_sonar.load_files(sq)
                note = ""
            else:
                raise p_sonar.SonarError("not scanned")
            r, measures = p_sonar.to_rows(issues, hotspots, raw, label)
            rows += r
            sources[name] = (not note, note)
        except (p_sonar.SonarError, OSError, ValueError) as exc:
            sources[name] = (False, str(exc) or exc.__class__.__name__)

    snyk = cfg.get("snyk")
    if snyk is not None:
        for product in p_snyk.PRODUCTS:
            if product not in snyk:
                continue
            name, path = f"{label}: Snyk {product}", snyk[product]
            if not _exists(path):
                sources[name] = (False, "not scanned")
                continue
            r, d, note = p_snyk.load(path, product, label)
            rows += r
            if d is not None:
                deps = (deps or 0) + d
            sources[name] = (not note, note)

    # Named scans: a repo has both a Dockerfile and a chart, and a chart that
    # fails to render must not hide a Dockerfile that scanned fine.
    for scan, path in (cfg.get("trivy") or {}).items():
        name = f"{label}: Trivy {scan}"
        if not _exists(path):
            sources[name] = (False, "not scanned")
            continue
        r, note = p_trivy.load(path, label)
        rows += r
        sources[name] = (not note, note)

    if "semgrep" in cfg:
        name, path = f"{label}: Semgrep", cfg["semgrep"]
        if not _exists(path):
            sources[name] = (False, "not scanned")
        else:
            r, note = p_semgrep.load(path, label)
            rows += r
            sources[name] = (not note, note)

    dbot = None
    if "dependabot" in cfg:
        name, path = f"{label}: Dependabot", cfg["dependabot"]
        if not _exists(path):
            sources[name] = (False, "not collected")
        else:
            r, dbot, note = p_dependabot.load(path, label)
            rows += r
            sources[name] = (dbot is not None, note)

    cov = None
    if "coverage" in cfg:
        name = f"{label}: Coverage"
        if not _exists(cfg["coverage"]):
            sources[name] = (False, "not supplied")
        else:
            cov, note = p_coverage.load(cfg["coverage"])
            sources[name] = (cov is not None, note)

    summary = {"project": label, "repo": cfg.get("repo", ""), "commit": cfg.get("commit", ""),
               "sonar": measures, "coverage": cov, "dependabot": dbot, "deps": deps}
    return rows, summary, sources


def build_payload(manifest, sonar_token="", passes=("exact", "advisory", "sast")):
    """Manifest dict -> payload dict."""
    projects = manifest["projects"] if isinstance(manifest, dict) else manifest
    meta = manifest if isinstance(manifest, dict) else {}

    raw, summaries, sources = [], [], {}
    for cfg in projects:
        r, s, src = collect_project(cfg, sonar_token)
        raw += r
        summaries.append(s)
        sources.update(src)

    rows, stats = dedup(raw, passes or ())
    for r in rows:
        r.pop("_package", None)
        r["id"] = fingerprint(r)
        r["rank"] = rank(r["sev"])
    rows.sort(key=lambda r: (r["rank"], r["proj"], r["src"], r["loc"], str(r["line"])))

    for s in summaries:
        mine = [r for r in rows if r["proj"] == s["project"]]
        sec = [r for r in mine if is_security(r)]
        s.update({
            "findings": len(mine),
            "security": len(sec),
            "sec_crit_high": sum(1 for r in sec if r["rank"] <= 1),
            # Sightings per scanner: a merged row counts under each, so these do not sum.
            "by_source": _sightings(mine),
            # Kept for consumers of the original payload shape.
            "snyk": sum(1 for r in mine if "Snyk" in r["by"]),
            "semgrep": sum(1 for r in mine if "Semgrep" in r["by"]),
            "trivy": sum(1 for r in mine if "Trivy" in r["by"]),
        })

    title = meta.get("title") or (f"{summaries[0]['project']} — Quality & Security"
                                  if len(summaries) == 1 else "Quality & Security")
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "quality-scan-digest", "version": __version__},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "title": title,
        "version": meta.get("version", ""),
        "generated_from": summaries,
        "sources": {k: {"collected": ok, "note": why} for k, (ok, why) in sources.items()},
        "dedup": stats,
        "findings": rows,
    }


def _sightings(rows):
    out = {}
    for r in rows:
        for s in r["by"]:
            out[s] = out.get(s, 0) + 1
    return out
