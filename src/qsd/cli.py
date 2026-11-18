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
from .waivers import WaiverError


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
        elif v.get("note"):
            print(f"  note: {name} - {v['note']}", file=sys.stderr)
    w = payload.get("waivers")
    if w:
        ignored = sum(s.get("waived", 0) for s in payload["generated_from"])
        tracked = sum(s.get("tracked", 0) for s in payload["generated_from"])
        print(f"waivers ({w['file']}, sha256 {w['sha256'][:12]}): {ignored} ignored, {tracked} tracked",
              file=sys.stderr)
        for e in w["errors"]:
            print(f"  waiver error: {e}", file=sys.stderr)
        for line in w["stale"]:
            print(f"  waiver note: line {line} matched no finding; remove it or fix it", file=sys.stderr)
    partial = [(n, v) for n, v in src.items() if v.get("partial") and v["collected"]]
    if partial:
        # The source counts as complete (strict passes), but this is NOT a full scan of
        # those files, and a reader must not walk away thinking it was.
        print("", file=sys.stderr)
        print(f"!! PARTIAL SCAN: {len(partial)} source(s) could only partly scan some files, so a "
              f"missing finding there is weaker evidence than elsewhere:", file=sys.stderr)
        for n, v in partial:
            print(f"!!   {n}: {v['partial']} file(s) only partly scanned", file=sys.stderr)
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
    # Strict is the default: a release console that screenshots zero under a gap is worse
    # than a failing exit. --lenient is for local exploration of partial runs.
    p.add_argument("--strict", action=argparse.BooleanOptionalAction, default=None,
                   help="exit 2 unless every required source was collected completely (default)")
    p.add_argument("--ignore-file", default=None,
                   help="waiver file (.qsdignore); never read from a scanned checkout")
    p.add_argument("--lenient", action="store_true",
                   help="alias for --no-strict: allow incomplete sources")


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
    if a.lenient and a.strict:
        ap.error("--strict and --lenient contradict each other")
    if a.lenient:
        a.strict = False
    elif a.strict is None:
        a.strict = True
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
            if a.ignore_file:
                manifest["ignore_file"] = os.path.abspath(a.ignore_file)
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
            if a.ignore_file:
                manifest["ignore_file"] = os.path.abspath(a.ignore_file)
            manifest.setdefault("settings", {})["dedup"] = ",".join(a.dedup) or "none"
            payload = build_payload(manifest, token, a.dedup)
            counts = _write(payload, a.json_out, a.html_out)
    except (ManifestError, ConfigError, WaiverError) as exc:
        sys.exit(f"error: {exc}")

    collected, complete, total = counts
    if collected == 0:
        sys.exit("error: no sources collected - this report would be misleading")
    if a.strict:
        # Optional sources (skipped via --tools) do not fail the gate.
        required = [(n, v) for n, v in payload["sources"].items() if not v.get("optional")]
        gaps = [(n, v) for n, v in required if not v["complete"]]
        if gaps:
            print(f"error: --strict: {len(gaps)} required source(s) not collected completely",
                  file=sys.stderr)
            for n, v in gaps:
                print(f"  {n} - {v['note']}", file=sys.stderr)
            sys.exit(2)
        errors = (payload.get("waivers") or {}).get("errors") or []
        if errors:
            # An expired waiver or an over-broad one means the counts would understate.
            print(f"error: --strict: {len(errors)} waiver problem(s); the findings they would "
                  f"have hidden are counted", file=sys.stderr)
            sys.exit(2)


def _resolve(manifest, base):
    def fix(p):
        return p if not p or not isinstance(p, str) or os.path.isabs(p) \
            else os.path.normpath(os.path.join(base, p))
    if isinstance(manifest, dict) and manifest.get("ignore_file"):
        manifest["ignore_file"] = fix(manifest["ignore_file"])
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
