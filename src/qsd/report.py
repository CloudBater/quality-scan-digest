"""Turn a manifest of raw scanner outputs into one deduplicated JSON payload.

The payload is the contract; the HTML report is one renderer of it. See
schema/report.schema.json for the shape.
"""

import datetime as _dt
import hashlib
import os

from . import __version__
from .dedup import DEFAULT_PASSES, dedup
from .model import fingerprint, is_malware, is_security, rank, safe_name, track_key
from .parsers import clamav as p_clamav
from .parsers import coverage as p_coverage
from .parsers import dependabot as p_dependabot
from .parsers import gitleaks as p_gitleaks
from .parsers import guarddog as p_guarddog
from .parsers import osv as p_osv
from .parsers import semgrep as p_semgrep
from .parsers import snyk as p_snyk
from .parsers import sonarqube as p_sonar
from .parsers import trivy as p_trivy
from .parsers import zizmor as p_zizmor

# Bump when the payload shape or enum set changes. Consumers pin on this, not the
# package version: v0.3.0 already grew under schema 1.0 without a signal.
SCHEMA_VERSION = "1.1"


class ManifestError(ValueError):
    pass


def _s(v):
    return "" if v is None else str(v)


def validate(manifest):
    """Normalise a manifest in place and return its project list."""
    if isinstance(manifest, list):
        manifest = {"projects": manifest}
    projects = manifest.get("projects")
    if not isinstance(projects, list) or not projects:
        raise ManifestError("manifest needs a non-empty `projects` list")
    names, labels = set(), set()
    for p in projects:
        if not isinstance(p, dict):
            raise ManifestError("each project must be an object")
        name = _s(p.get("name") or p.get("project"))
        if not safe_name(name):
            raise ManifestError(f"project name {name!r} must match [A-Za-z0-9][A-Za-z0-9._-]*")
        label = _s(p.get("label")) or name
        if name in names or label in labels:
            raise ManifestError(f"duplicate project name or label: {name!r} / {label!r}")
        names.add(name)
        labels.add(label)
        p["name"], p["label"] = name, label
        # Sources deliberately not run (--tools, or a tool with nothing configured).
        # Only this list makes a source optional; a note's wording never does.
        skipped = p.get("skipped")
        p["skipped"] = [str(x) for x in skipped] if isinstance(skipped, list) else []
        for k in ("repo", "commit"):
            p[k] = _s(p.get(k))
        # None = unknown (git status failed); do not coerce that into "clean".
        # Only real booleans (or 0/1 ints) count — the string "false" must not become True.
        dirty = p.get("commit_dirty")
        if dirty is None or isinstance(dirty, bool):
            p["commit_dirty"] = dirty
        elif dirty in (0, 1):
            p["commit_dirty"] = bool(dirty)
        elif isinstance(dirty, str) and dirty.strip().lower() in ("true", "false"):
            p["commit_dirty"] = dirty.strip().lower() == "true"
        else:
            p["commit_dirty"] = None
    manifest["title"] = _s(manifest.get("title"))
    manifest["version"] = _s(manifest.get("version"))
    return manifest


def _exists(path):
    return bool(path) and os.path.isfile(path)


def collect_project(cfg, sonar_token=""):
    """Gather one project's sources. Returns (rows, summary, sources).

    A source listed in the manifest is always reported: collected, collected but
    incomplete, or not collected with the reason. Its absence is never a clean result.
    """
    pid, label = cfg["name"], cfg["label"]
    run_notes = cfg.get("notes") or {}
    skipped = set(cfg.get("skipped") or [])
    rows, sources, measures, deps, dbot = [], {}, {}, None, None

    def record(source, st, optional=False):
        note = st["note"]
        opt = optional or bool(st.get("optional")) or source in skipped
        sources[f"{label}: {source}"] = {
            "collected": bool(st["ok"]),
            "complete": bool(st["ok"]) and st.get("complete", not st["note"]),
            "note": note,
            "suppressed": int(st.get("suppressed") or 0),
            "optional": opt,
        }

    def missing(source, default="not scanned"):
        record(source, {"ok": False, "note": run_notes.get(source, default)})

    def file_source(source, path, parse):
        nonlocal rows
        if not _exists(path):
            missing(source)
            return None
        r, st = parse(path)
        rows += r
        record(source, st)
        return st

    sq = cfg.get("sonarqube")
    if sq is not None:
        try:
            if sq.get("host"):
                if not sonar_token:
                    raise p_sonar.SonarError("no token (set SONAR_TOKEN)")
                doc = p_sonar.fetch(sq["host"], sonar_token, sq.get("project_key") or pid)
            elif sq.get("issues"):
                doc = p_sonar.load_files(sq)
            else:
                raise p_sonar.SonarError(run_notes.get("SonarQube", "not scanned"))
            r, st, measures = p_sonar.to_rows(doc, label, pid)
            rows += r
            record("SonarQube", st)
        except (p_sonar.SonarError, OSError, ValueError) as exc:
            record("SonarQube", {"ok": False, "note": str(exc) or exc.__class__.__name__})

    snyk = cfg.get("snyk")
    if snyk is not None:
        for product in p_snyk.PRODUCTS:
            if product in snyk:
                st = file_source(f"Snyk {product}", snyk[product],
                                 lambda p, pr=product: p_snyk.load(p, pr, label, pid))
                if st and st.get("deps") is not None:
                    deps = (deps or 0) + st["deps"]

    # Named scans: a repo has both a Dockerfile and a chart, and a chart that
    # fails to render must not hide a Dockerfile that scanned fine.
    for scan, path in (cfg.get("trivy") or {}).items():
        file_source(f"Trivy {scan}", path, lambda p: p_trivy.load(p, label, pid))

    if "semgrep" in cfg:
        # Default True: a partial parse is a coverage gap unless the project opts out.
        partial_gap = cfg.get("semgrep_partial_is_gap")
        if partial_gap is None:
            partial_gap = True
        file_source("Semgrep", cfg["semgrep"],
                    lambda p, g=bool(partial_gap): p_semgrep.load(p, label, pid, g))

    if "dependabot" in cfg:
        st = file_source("Dependabot", cfg["dependabot"],
                         lambda p: p_dependabot.load(p, label, pid))
        dbot = st.get("counts") if st else None

    if "clamav" in cfg:
        file_source("ClamAV", cfg["clamav"], lambda p: p_clamav.load(p, label, pid))

    if "gitleaks" in cfg:
        file_source("Gitleaks", cfg["gitleaks"], lambda p: p_gitleaks.load(p, label, pid))

    # Both may name a scan root so absolute paths in their output become relative.
    for key, name, parser in (("osv", "OSV-Scanner", p_osv), ("zizmor", "zizmor", p_zizmor)):
        if key in cfg:
            spec = cfg[key] if isinstance(cfg[key], dict) else {"path": cfg[key]}
            file_source(name, spec.get("path"), lambda p, s=spec, m=parser: m.load(
                p, label, pid, root=s.get("root", "")))

    for scan, g in (cfg.get("guarddog") or {}).items():
        g = g if isinstance(g, dict) else {"path": g}
        file_source(f"GuardDog {scan}", g.get("path"), lambda p, g=g: p_guarddog.load(
            p, label, pid, g.get("ecosystem", ""), g.get("manifest", scan)))

    cov = None
    if "coverage" in cfg:
        if not _exists(cfg["coverage"]):
            missing("Coverage", "not supplied")
        else:
            cov, note = p_coverage.load(cfg["coverage"])
            record("Coverage", {"ok": cov is not None, "note": note})

    summary = {"project_id": pid, "project": label, "repo": cfg["repo"], "commit": cfg["commit"],
               "commit_dirty": cfg.get("commit_dirty"),
               "sonar": measures, "coverage": cov, "dependabot": dbot, "deps": deps}
    return rows, summary, sources


def _assign_tracks(rows):
    """Give every row a `track` that is unique within the report.

    Two distinct findings must never share a key, because a consumer that keys on it
    would merge them. The key is location and identity without the free-text message,
    so it survives a scanner rewording its title; only rows whose key collides (same
    rule, file and line, different message, e.g. two Trivy secrets on one line) are
    told apart by a hash of the message. Rows still identical after that can only
    exist with dedup off, and get an ordinal suffix. Stability is therefore best
    effort for colliding rows: if a sibling drops out, the survivor's track reverts.
    """
    groups = {}
    for r in rows:
        r["track"] = track_key(r)
        groups.setdefault(r["track"], []).append(r)
    for group in groups.values():
        if len(group) == 1:
            continue
        for r in group:
            r["track"] = hashlib.sha256(
                f"{r['track']}\x1f{r.get('msg', '')}".encode("utf-8")).hexdigest()[:16]
    seen = {}
    for r in rows:
        n = seen.get(r["track"], 0)
        seen[r["track"]] = n + 1
        if n:
            r["track"] = f"{r['track']}-{n + 1}"
    for r in rows:
        r.pop("_track", None)


def build_payload(manifest, sonar_token="", passes=DEFAULT_PASSES):
    """Manifest dict -> payload dict."""
    manifest = validate(manifest)
    raw, summaries, sources = [], [], {}
    for cfg in manifest["projects"]:
        r, s, src = collect_project(cfg, sonar_token)
        raw += r
        summaries.append(s)
        sources.update(src)

    rows, stats = dedup(raw, passes or ())
    _assign_tracks(rows)
    seen_id = {}
    for r in rows:
        r.pop("_package", None)
        r.pop("_eco", None)
        r.pop("_track", None)
        r["rank"] = rank(r["sev"])

        fid = fingerprint(r)
        n = seen_id.get(fid, 0)
        seen_id[fid] = n + 1
        # Identical content twice (exact pass off) still gets two distinct ids.
        r["id"] = fid if n == 0 else f"{fid}-{n + 1}"
    rows.sort(key=lambda r: (r["rank"], r["proj"], r["src"], r["loc"], str(r["line"]),
                             str(r.get("col", ""))))

    for s in summaries:
        mine = [r for r in rows if r["project_id"] == s["project_id"]]
        sec = [r for r in mine if is_security(r)]
        by_source = {}
        for r in mine:
            for src in r["by"]:
                by_source[src] = by_source.get(src, 0) + 1
        s.update({
            "findings": len(mine),
            "security": len(sec),
            "sec_crit_high": sum(1 for r in sec if r["rank"] <= 1),
            # Unrated security (sev "—", rank 5) is invisible from the crit/high gate.
            "sec_unrated": sum(1 for r in sec if r["rank"] >= 5),
            "malware": sum(1 for r in mine if is_malware(r)),
            # Sightings per scanner: a merged row counts under each, so these do not sum.
            "by_source": by_source,
            # Kept for consumers of the original payload shape.
            "snyk": by_source.get("Snyk", 0),
            "semgrep": by_source.get("Semgrep", 0),
            "trivy": by_source.get("Trivy", 0),
        })

    title = manifest["title"] or (f"{summaries[0]['project']} — Quality & Security"
                                  if len(summaries) == 1 else "Quality & Security")
    return {
        "schema_version": SCHEMA_VERSION,
        "generator": {"name": "quality-scan-digest", "version": __version__},
        "generated_at": _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat(),
        "title": title,
        "version": manifest["version"],
        # Severity floors and rulesets the scanners ran with: zero findings under
        # a `high` floor is not the same claim as zero findings.
        "settings": manifest.get("settings") or {},
        "generated_from": summaries,
        "sources": sources,
        "dedup": stats,
        "findings": rows,
    }
