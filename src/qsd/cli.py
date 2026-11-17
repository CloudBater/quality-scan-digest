"""qsd scan | qsd digest"""

import argparse
import json
import os
import sys

from . import __version__
from .dedup import ALL_PASSES, DEFAULT_PASSES
from .html_report import render
from .report import ManifestError, build_payload
from .runner import TOOLS, ConfigError, scan


def _write(payload, json_out, html_out):
    if json_out:
        with open(json_out, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=1)
        print(f"{json_out}: {os.path.getsize(json_out) / 1024:.0f} KB", file=sys.stderr)
    if html_out:
        with open(html_out, "w", encoding="utf-8") as fh:
            fh.write(render(payload))
        print(f"{html_out}: {os.path.getsize(html_out) / 1024:.0f} KB", file=sys.stderr)

    src = payload["sources"]
    collected = sum(1 for v in src.values() if v["collected"])
    complete = sum(1 for v in src.values() if v["complete"])
    d = payload["dedup"]
    print(f"{d['output']} findings ({d['input']} sightings, {d['input'] - d['output']} merged) "
          f"from {collected}/{len(src)} sources ({complete} complete)", file=sys.stderr)
    for name, v in src.items():
        if not v["complete"]:
            state = "incomplete" if v["collected"] else "not collected"
            print(f"  {state}: {name} - {v['note']}", file=sys.stderr)
    return collected, complete, len(src)


def _passes(arg):
    if arg == "none":
        return ()
    out = tuple(p.strip() for p in arg.split(",") if p.strip())
    bad = [p for p in out if p not in ALL_PASSES]
    if bad:
        raise argparse.ArgumentTypeError(f"unknown dedup pass: {', '.join(bad)}")
    return out


def _common(p):
    p.add_argument("--dedup", type=_passes, default=DEFAULT_PASSES,
                   help="comma list of passes: exact,advisory (default), sast (opt-in), or 'none'")
    p.add_argument("--strict", action="store_true",
                   help="exit 2 unless every listed source was collected completely")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="qsd", description=__doc__)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the scanners, then digest")
    s.add_argument("config", help="qsd config JSON (see examples/qsd.example.json)")
    s.add_argument("--release", default="", help="label for this scan, e.g. v1.4.0")
    s.add_argument("--out-dir", default="qsd-out",
                   help="each run gets a fresh run-<timestamp>/ inside it")
    s.add_argument("--tools", default=",".join(TOOLS),
                   help=f"comma list, default all: {','.join(TOOLS)}")
    _common(s)

    d = sub.add_parser("digest", help="merge existing scanner outputs listed in a manifest")
    d.add_argument("manifest", help="manifest JSON (see examples/manifest.example.json)")
    d.add_argument("--json-out", default="report.json")
    d.add_argument("--html-out", default="", help="also write a self-contained HTML report")
    d.add_argument("--release", default=None, help="override the manifest's version label")
    _common(d)

    a = ap.parse_args(argv)
    token = os.environ.get("SONAR_TOKEN", "")

    try:
        if a.cmd == "scan":
            tools = tuple(t.strip() for t in a.tools.split(",") if t.strip())
            unknown = [t for t in tools if t not in TOOLS]
            if unknown:
                ap.error(f"unknown tool: {', '.join(unknown)}")
            with open(a.config, encoding="utf-8") as fh:
                config = json.load(fh)
            manifest, run_dir = scan(config, os.path.dirname(os.path.abspath(a.config)),
                                     os.path.abspath(a.out_dir), a.release, tools)
            manifest["settings"]["dedup"] = ",".join(a.dedup) or "none"
            with open(os.path.join(run_dir, "manifest.json"), "w", encoding="utf-8") as fh:
                json.dump(manifest, fh, indent=1)
            payload = build_payload(manifest, "", a.dedup)
            counts = _write(payload, os.path.join(run_dir, "report.json"),
                            os.path.join(run_dir, "report.html"))
        else:
            with open(a.manifest, encoding="utf-8") as fh:
                manifest = json.load(fh)
            if isinstance(manifest, list):
                manifest = {"projects": manifest}
            # Relative paths in a manifest resolve against the manifest itself.
            _resolve(manifest, os.path.dirname(os.path.abspath(a.manifest)))
            if a.release is not None:
                manifest["version"] = a.release
            manifest.setdefault("settings", {})["dedup"] = ",".join(a.dedup) or "none"
            payload = build_payload(manifest, token, a.dedup)
            counts = _write(payload, a.json_out, a.html_out)
    except (ManifestError, ConfigError) as exc:
        sys.exit(f"error: {exc}")

    collected, complete, total = counts
    if collected == 0:
        sys.exit("error: no sources collected - this report would be misleading")
    if a.strict and complete < total:
        print(f"error: --strict: {total - complete} source(s) not collected completely",
              file=sys.stderr)
        sys.exit(2)


def _resolve(manifest, base):
    def fix(p):
        return p if not p or not isinstance(p, str) or os.path.isabs(p) \
            else os.path.normpath(os.path.join(base, p))
    for p in manifest.get("projects", []):
        if not isinstance(p, dict):
            continue
        for k in ("semgrep", "dependabot", "coverage", "clamav", "gitleaks"):
            if isinstance(p.get(k), str):
                p[k] = fix(p[k])
        for k in ("snyk", "trivy"):
            if isinstance(p.get(k), dict):
                p[k] = {n: fix(v) for n, v in p[k].items()}
        for k in ("osv", "zizmor"):
            if isinstance(p.get(k), str):
                p[k] = fix(p[k])
            elif isinstance(p.get(k), dict):
                p[k]["path"] = fix(p[k].get("path"))
        if isinstance(p.get("guarddog"), dict):
            for n, g in p["guarddog"].items():
                if isinstance(g, dict):
                    g["path"] = fix(g.get("path"))
                else:
                    p["guarddog"][n] = fix(g)
        sq = p.get("sonarqube")
        if isinstance(sq, dict):
            for k in ("issues", "hotspots", "measures"):
                if sq.get(k):
                    sq[k] = fix(sq[k])


if __name__ == "__main__":
    main()
