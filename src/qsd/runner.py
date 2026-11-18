"""Run the scanners against local checkouts and write a digest manifest.

Every tool is optional. One that is missing, unauthenticated or fails is
recorded as not collected, with the reason, and the run continues: a release
scan should say what it could not see rather than abort or report it as clean.

Each run writes into a fresh, private directory, so a file left by an earlier
run can never stand in for a scan that did not happen this time.
"""

import base64
import datetime as _dt
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse
import urllib.request
from importlib import resources

from .model import safe_name
from .parsers.sonarqube import MEASURE_KEYS, Forbidden, SonarError, api, fetch_all

TOOLS = ("sonarqube", "snyk", "trivy", "semgrep", "dependabot", "osv", "zizmor", "clamav",
         "guarddog", "gitleaks")

# Pinned by digest: a moving tag changes the code that runs with your token.
SCANNER_IMAGE = os.environ.get(
    "QSD_SCANNER_IMAGE",
    "sonarsource/sonar-scanner-cli@sha256:a3f4215076706c95a17a68c19322ee916e40a3acd081a8c1a1e839e0194afa57")
CLAMAV_IMAGE = os.environ.get(
    "QSD_CLAMAV_IMAGE",
    "clamav/clamav@sha256:bda39705e291105049c3936e2803ac90b955172af8030f94f05dce1252df6c6d")

GUARDDOG_ECOSYSTEMS = ("pypi", "npm", "go", "github_action")

GITLEAKS_IMAGE = os.environ.get(
    "QSD_GITLEAKS_IMAGE",  # v8.24.3
    "zricethezav/gitleaks@sha256:e1b35e12a8c6fa8901f060459cfb6b2fc4c484d3afbe3b029733a3bbfab07055")

OSV_IMAGE = os.environ.get(
    "QSD_OSV_IMAGE",  # v2.7.1
    "ghcr.io/google/osv-scanner@sha256:a70ffffc2bfd33482953e5d6b64c6fcdb30239717a07b0f0d3ab2859ce3e4cde")
ZIZMOR_IMAGE = os.environ.get(
    "QSD_ZIZMOR_IMAGE",  # 1.32.0
    "ghcr.io/zizmorcore/zizmor@sha256:3014cc8f68f663935f69b3c3e0e41f5ce102b268d97db13db0f62208747f860d")

# A `semgrep ci` inside a pull_request job would otherwise scan only the diff.
_DIFF_AWARE_ENV = ("GITHUB_EVENT_NAME", "GITHUB_EVENT_PATH", "GITHUB_BASE_REF",
                   "GITHUB_HEAD_REF", "SEMGREP_BASELINE_REF", "CI_MERGE_REQUEST_TARGET_BRANCH_NAME")


class ConfigError(ValueError):
    pass


# Allowlist only: a denylist still lets PR-edited config set javaExePath / scanner.*
# and run a checkout-supplied binary with SONAR_TOKEN in the environment.
_SONAR_ARG = re.compile(r"^-Dsonar\.[A-Za-z0-9_.]+=.+$")
_SONAR_ALLOWED = re.compile(
    r"^sonar\.("
    r"sources|tests|exclusions|inclusions|"
    r"test\.(exclusions|inclusions)|"
    r"coverage\.exclusions|cpd\.exclusions|"
    r"scm\.exclusions|"
    r"javascript\.[A-Za-z0-9_.]+|"
    r"typescript\.[A-Za-z0-9_.]+|"
    r"python\.[A-Za-z0-9_.]+|"
    r"java\.(binaries|libraries|test\.binaries)"
    r")$"
)
SEMGREP_MODES = ("auto", "ci", "public")


def log(msg):
    print(f"==> {msg}", file=sys.stderr)


def warn(msg):
    print(f"WARNING: {msg}", file=sys.stderr)


def run(cmd, logfile, cwd=None, env=None):
    with open(logfile, "w", encoding="utf-8") as fh:
        return subprocess.run(cmd, cwd=cwd, env=env, stdout=fh, stderr=subprocess.STDOUT).returncode


def have(tool):
    return shutil.which(tool) is not None


def git_sha(path):
    """Return (sha, dirty). dirty is True/False, or None when git status is unknown."""
    try:
        sha = subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"],
                                      text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return "", None
    try:
        porcelain = subprocess.check_output(
            ["git", "-C", path, "status", "--porcelain"],
            text=True, stderr=subprocess.DEVNULL)
    except (OSError, subprocess.CalledProcessError):
        return sha, None
    return sha, bool(porcelain.strip())


def _nonempty(path):
    return os.path.isfile(path) and os.path.getsize(path) > 0


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def _inside(base, *parts):
    """Join and refuse anything that resolves outside `base`."""
    root = os.path.realpath(base)
    p = os.path.realpath(os.path.join(base, *parts))
    if os.path.commonpath([p, root]) != root:
        raise ConfigError(f"{os.path.join(*parts)!r} resolves outside {base}")
    return p


def validate(config, base):
    projects = config.get("projects")
    if not isinstance(projects, list) or not projects:
        raise ConfigError("config needs a non-empty `projects` list")
    names, labels = set(), set()
    for p in projects:
        name = str(p.get("name", ""))
        if not safe_name(name):
            raise ConfigError(f"project name {name!r} must match [A-Za-z0-9][A-Za-z0-9._-]*")
        label = str(p.get("label") or name)
        if name in names or label in labels:
            raise ConfigError(f"duplicate project name or label: {name!r} / {label!r}")
        names.add(name)
        labels.add(label)
        if not p.get("path") or not os.path.isdir(os.path.join(base, p["path"])):
            raise ConfigError(f"{name}: `path` is not a directory")
        for arg in p.get("sonar_args") or []:
            if not _SONAR_ARG.match(str(arg)):
                raise ConfigError(f"{name}: sonar_args entry {arg!r} must be -Dsonar.<key>=<value>")
            key = str(arg).split("=", 1)[0][2:]
            if not _SONAR_ALLOWED.match(key):
                raise ConfigError(f"{name}: sonar_args entry {arg!r} is not an allowed analysis "
                                  f"property (no sonar.scanner.*, host, token, or executable overrides)")
    mode = config.get("semgrep_mode", "auto")
    if mode not in SEMGREP_MODES:
        raise ConfigError(f"semgrep_mode must be one of {', '.join(SEMGREP_MODES)}")


# --------------------------------------------------------------------------
# SonarQube: a throwaway container, started, scanned against, read, destroyed.
# --------------------------------------------------------------------------

def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Sonar:
    def __init__(self, logs):
        self.project = f"qsd-sonar-{secrets.token_hex(4)}"  # one deployment per run
        self.port = os.environ.get("QSD_SONAR_PORT") or str(_free_port())
        self.host = f"http://127.0.0.1:{self.port}"
        self.token = ""
        self.secret_dir = tempfile.mkdtemp(prefix="qsd-sonar-")  # 0700
        self.envfile = os.path.join(self.secret_dir, "env")
        self.compose = str(resources.files("qsd") / "data" / "sonarqube-compose.yml")
        self.logs = logs

    def _compose(self, *args):
        return ["docker", "compose", "--env-file", self.envfile, "-p", self.project,
                "-f", self.compose, *args]

    def _post(self, path, data, user, password):
        req = urllib.request.Request(f"{self.host}{path}",
                                     data=urllib.parse.urlencode(data).encode(), method="POST")
        cred = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {cred}")
        with urllib.request.urlopen(req, timeout=30) as r:
            body = r.read()
            return json.loads(body) if body else {}

    def up(self):
        fd = os.open(self.envfile, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"SONAR_DB_PASSWORD={secrets.token_hex(16)}\nQSD_SONAR_PORT={self.port}\n")
        log(f"starting SonarQube as {self.project} on {self.host} (a cold start is ~2 minutes)")
        if run(self._compose("up", "-d"), os.path.join(self.logs, "sonar-up.log")) != 0:
            raise SonarError("docker compose up failed, see logs/sonar-up.log")
        for _ in range(72):
            try:
                with urllib.request.urlopen(f"{self.host}/api/system/status", timeout=5) as r:
                    if json.load(r).get("status") == "UP":
                        break
            except (OSError, ValueError):
                pass
            time.sleep(5)
        else:
            raise SonarError("SonarQube never reached UP")
        # The image's documented first-boot login mints a user token (an analysis
        # token is refused on hotspots); then the password is rotated so no other
        # local user can log in with the default while source is loaded.
        self.token = self._post("/api/user_tokens/generate",
                                {"name": f"qsd-{os.getpid()}", "type": "USER_TOKEN"},
                                "admin", "admin")["token"]
        self._post("/api/users/change_password",
                   {"login": "admin", "previousPassword": "admin",
                    "password": secrets.token_urlsafe(24) + "aA1!"}, self.token, "")

    def scan(self, path, key, logfile, extra=()):
        log(f"SonarQube: {key}")
        # Joins the compose network (no host networking), mounts the source
        # read-only, and takes the token from the environment, not argv.
        cmd = ["docker", "run", "--rm", "--network", f"{self.project}_default",
               "-v", f"{path}:/usr/src:ro", "-e", "SONAR_HOST_URL=http://sonarqube:9000",
               "-e", "SONAR_TOKEN", SCANNER_IMAGE,
               f"-Dsonar.projectKey={key}", "-Dsonar.scm.disabled=true",
               # A sonar-project.properties in the checkout could otherwise set the host.
               "-Dsonar.host.url=http://sonarqube:9000",
               "-Dsonar.working.directory=/tmp/.scannerwork"]
        cmd.extend(extra)
        if not os.path.exists(os.path.join(path, "sonar-project.properties")) \
                and not any(str(a).startswith("-Dsonar.sources=") for a in extra):
            cmd.append("-Dsonar.sources=.")
        rc = run(cmd, logfile, env={**os.environ, "SONAR_TOKEN": self.token})
        with open(logfile, encoding="utf-8", errors="replace") as fh:
            ok = "ANALYSIS SUCCESSFUL" in fh.read()
        if rc != 0 or not ok:
            raise SonarError(f"analysis failed, see logs/{os.path.basename(logfile)}")

    def wait(self, key, timeout=900):
        """The compute engine processes asynchronously; the API is empty until it has."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            ce = api(self.host, self.token, "/api/ce/component", {"component": key})
            current = (ce.get("current") or {}).get("status")
            if not ce.get("queue") and current in ("SUCCESS", "FAILED", "CANCELED"):
                if current != "SUCCESS":
                    raise SonarError(f"compute engine finished {current}")
                return
            time.sleep(5)
        raise SonarError("compute engine did not finish in time")

    def export(self, key, raw):
        """Write issues/hotspots/measures, with totals, so the digest can run offline."""
        issues, total = fetch_all(self.host, self.token, "/api/issues/search",
                                  {"components": key, "resolved": "false"}, "issues")
        try:
            hs, htotal = fetch_all(self.host, self.token, "/api/hotspots/search",
                                   {"project": key, "status": "TO_REVIEW"}, "hotspots")
            hotspots = {"hotspots": hs, "total": htotal}
        except Forbidden:
            hotspots = {"hotspots": [], "error": "forbidden: token is not a user token"}
        measures = api(self.host, self.token, "/api/measures/component",
                       {"component": key, "metricKeys": MEASURE_KEYS})
        out = {}
        for name, doc in (("issues", {"issues": issues, "total": total}),
                          ("hotspots", hotspots), ("measures", measures)):
            path = os.path.join(raw, f"sonar-{key}-{name}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            out[name] = path
        return out

    def down(self):
        log(f"tearing down {self.project}")
        rc = run(self._compose("down", "-v"), os.path.join(self.logs, "sonar-down.log"))
        shutil.rmtree(self.secret_dir, ignore_errors=True)
        if rc != 0:
            warn(f"teardown failed; remove it by hand: docker compose -p {self.project} down -v")


# --------------------------------------------------------------------------
# Snyk. Exit codes carry meaning: 0 clean, 1 found, 3 nothing to scan, else failed.
# --------------------------------------------------------------------------

def snyk(args, cwd, out, logfile, severity):
    """Returns "" on success, else the reason the product was not scanned."""
    rc = run(["snyk", *args, f"--severity-threshold={severity}", f"--json-file-output={out}"],
             logfile, cwd=cwd)
    if rc == 0 and not _nonempty(out) and args[:2] == ["code", "test"]:
        # A clean `snyk code test` writes no file. Record it as an empty SARIF
        # run, which the parser recognises, rather than an arbitrary `{}`.
        with open(out, "w") as fh:
            json.dump({"runs": []}, fh)
        return ""
    if rc in (0, 1) and _nonempty(out):
        return ""
    _rm(out)  # never leave a truncated file that would read as a short result
    return {3: "nothing to scan"}.get(rc, f"snyk exited {rc}, see logs")


def render_helm(proj, root, logfile):
    """Return (state, dir_or_reason): nochart | rendered | failed.

    `snyk iac test` cannot parse Go templates: a raw chart tree either fails
    loudly or, worse, exits 0 having scanned the one plain manifest beside it.
    The render goes to a private temp dir that the caller removes, because a
    chart rendered with real values can contain Secret manifests.
    """
    helm = proj.get("helm")
    if not helm:
        return "nochart", root
    if not have("helm"):
        return "failed", "helm not on PATH"
    dest = tempfile.mkdtemp(prefix="qsd-render-")
    cmd = ["helm", "template", "release", _inside(root, helm["chart"])]
    for v in helm.get("values") or []:
        cmd += ["-f", _inside(root, v)]
    with open(os.path.join(dest, "chart.yaml"), "w") as out, open(logfile, "w") as err:
        if subprocess.run(cmd, stdout=out, stderr=err).returncode != 0:
            shutil.rmtree(dest, ignore_errors=True)
            return "failed", "helm template failed, see logs"
    extra = helm.get("extra_manifests")
    if extra:
        src = _inside(root, extra)
        for f in os.listdir(src) if os.path.isdir(src) else []:
            if f.endswith((".yaml", ".yml")):
                shutil.copy(os.path.join(src, f), dest)
    return "rendered", dest


# --------------------------------------------------------------------------

def _python_shim():
    """Snyk shells out to `python` for Poetry projects; some systems ship only python3."""
    if have("python") or not have("python3"):
        return None
    shim = tempfile.mkdtemp(prefix="qsd-py-")
    os.symlink(shutil.which("python3"), os.path.join(shim, "python"))
    os.environ["PATH"] = f"{shim}{os.pathsep}{os.environ.get('PATH', '')}"
    return shim


def scan(config, base, out_dir, version="", tools=TOOLS):
    """Run every enabled tool for every project. Returns (manifest, run_dir)."""
    validate(config, base)
    stamp = _dt.datetime.now(_dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    os.makedirs(out_dir, mode=0o700, exist_ok=True)
    run_dir = os.path.join(out_dir, f"run-{stamp}-{secrets.token_hex(3)}")
    os.mkdir(run_dir, 0o700)  # fresh: fails rather than reuse an old run
    raw, logs = os.path.join(run_dir, "raw"), os.path.join(run_dir, "logs")
    os.mkdir(raw, 0o700)
    os.mkdir(logs, 0o700)
    old_umask = os.umask(0o077)  # raw outputs and logs can hold code and secrets

    settings = {"snyk_severity": config.get("snyk_severity", "high"),
                "trivy_severity": config.get("trivy_severity", "CRITICAL,HIGH"),
                "semgrep": _semgrep_label(config.get("semgrep_mode", "auto")),
                "semgrep_mode": config.get("semgrep_mode", "auto"),
                "tools": ",".join(tools),
                # Digests actually referenced this run — pin ≠ what ran if PATH wins.
                "images": {
                    "sonar_scanner": SCANNER_IMAGE,
                    "clamav": CLAMAV_IMAGE,
                    "gitleaks": GITLEAKS_IMAGE,
                    "osv": OSV_IMAGE,
                    "zizmor": ZIZMOR_IMAGE,
                },
                "runners": {}}
    projects = []
    for p in config["projects"]:
        path = os.path.realpath(os.path.join(base, p["path"]))
        sha, dirty = git_sha(path)
        projects.append({"cfg": p, "path": path, "name": p["name"], "out": {
            "name": p["name"], "label": p.get("label") or p["name"],
            "repo": p.get("repo", ""), "commit": sha, "commit_dirty": dirty, "notes": {}}})

    shim = _python_shim() if "snyk" in tools else None
    sonar = None
    try:
        if "sonarqube" in tools:
            if not have("docker"):
                for pr in projects:
                    pr["out"]["sonarqube"] = {}
                    pr["out"]["notes"]["SonarQube"] = "docker not on PATH"
            else:
                sonar = Sonar(logs)
                try:
                    sonar.up()
                    for pr in projects:
                        key = pr["cfg"].get("sonar_project_key") or pr["name"]
                        sonar.scan(pr["path"], key, os.path.join(logs, f"{pr['name']}.sonar.log"),
                                   pr["cfg"].get("sonar_args") or ())
                    for pr in projects:
                        key = pr["cfg"].get("sonar_project_key") or pr["name"]
                        sonar.wait(key)
                        pr["out"]["sonarqube"] = sonar.export(key, raw)
                except (SonarError, OSError, ValueError, KeyError) as exc:
                    warn(f"SonarQube: {exc}")
                    for pr in projects:
                        pr["out"].setdefault("sonarqube", {})
                        pr["out"]["notes"]["SonarQube"] = str(exc)
        for pr in projects:
            _scan_project(pr, raw, logs, tools, settings)
    finally:
        if sonar:
            sonar.down()
        if shim:
            shutil.rmtree(shim, ignore_errors=True)
        os.umask(old_umask)

    manifest = {"title": config.get("title", ""), "version": version, "settings": settings,
                "projects": [pr["out"] for pr in projects]}
    return manifest, run_dir


def _scan_project(pr, raw, logs, tools, settings):
    cfg, path, name, out = pr["cfg"], pr["path"], pr["name"], pr["out"]
    notes = out["notes"]
    stem = os.path.join(raw, name)
    # Tools left out of --tools still appear in `sources` as optional skips, so a
    # screenshot cannot look like "only these scanners exist".
    _register_skipped(out, notes, tools, cfg, stem)

    def lg(tool):
        return os.path.join(logs, f"{name}.{tool}.log")

    if "snyk" in tools:
        products = {"Open Source": f"{stem}-snyk-oss.json", "Code": f"{stem}-snyk-code.json",
                    "IaC": f"{stem}-snyk-iac.json"}
        if cfg.get("image"):
            products["Container"] = f"{stem}-snyk-container.json"
        out["snyk"] = dict(products)
        if not have("snyk"):
            for p in products:
                notes[f"Snyk {p}"] = "snyk not on PATH"
        else:
            log(f"Snyk: {name}")
            sev = settings["snyk_severity"]
            # --fail-fast turns a partially scanned --all-projects run into a
            # failure instead of a complete-looking partial result.
            oss = cfg.get("snyk_open_source_args") or ["--all-projects", "--fail-fast"]
            for prod, args in (("Open Source", ["test", *oss]), ("Code", ["code", "test"])):
                why = snyk(args, path, products[prod], lg(f"snyk-{prod.split()[0].lower()}"), sev)
                if why:
                    notes[f"Snyk {prod}"] = why
            state, where = render_helm(cfg, path, lg("helm"))
            if state == "failed":
                notes["Snyk IaC"] = where
                _rm(products["IaC"])
            else:
                try:
                    # snyk iac refuses a target outside cwd, so run inside the render.
                    why = snyk(["iac", "test", "."], where, products["IaC"], lg("snyk-iac"), sev)
                    if why:
                        notes["Snyk IaC"] = why
                finally:
                    if state == "rendered":
                        shutil.rmtree(where, ignore_errors=True)
            if cfg.get("image"):
                why = snyk(["container", "test", cfg["image"]], path, products["Container"],
                           lg("snyk-container"), sev)
                if why:
                    notes["Snyk Container"] = why

    if "trivy" in tools:
        out["trivy"] = {"Config": f"{stem}-trivy-config.json"}
        helm = cfg.get("helm")
        if helm:
            out["trivy"]["Chart"] = f"{stem}-trivy-chart.json"
        if not have("trivy"):
            for t in out["trivy"]:
                notes[f"Trivy {t}"] = "trivy not on PATH"
        else:
            log(f"Trivy: {name}")
            base = ["config", "--quiet", "--severity", settings["trivy_severity"],
                    "--format", "json", "--output"]
            _trivy(base + [out["trivy"]["Config"], path], out["trivy"]["Config"],
                   lg("trivy-config"), notes, "Trivy Config")
            if helm:
                cmd = base + [out["trivy"]["Chart"]]
                for v in helm.get("values") or []:
                    cmd += ["--helm-values", _inside(path, v)]
                _trivy(cmd + [_inside(path, helm["chart"])], out["trivy"]["Chart"],
                       lg("trivy-chart"), notes, "Trivy Chart")

    if "semgrep" in tools:
        out["semgrep"] = f"{stem}-semgrep.json"
        if not have("semgrep"):
            notes["Semgrep"] = "semgrep not on PATH"
        else:
            _semgrep(cfg, path, out["semgrep"], lg("semgrep"), notes, settings["semgrep_mode"])

    if "dependabot" in tools:
        out["dependabot"] = f"{stem}-dependabot.json"
        if not cfg.get("repo"):
            notes["Dependabot"] = "no `repo` (owner/name) in config"
        elif not have("gh"):
            notes["Dependabot"] = "gh not on PATH"
        else:
            log(f"Dependabot: {cfg['repo']}")
            # Open findings plus waived ones (dismissed, auto-dismissed). `fixed` alerts are
            # left out on purpose: they are the whole history and are not waivers.
            with open(out["dependabot"], "w") as fh, open(lg("dependabot"), "w") as err:
                rc = subprocess.run(_dependabot_cmd(cfg["repo"]), stdout=fh, stderr=err).returncode
            if rc != 0:
                notes["Dependabot"] = f"gh api exited {rc}, see logs"
                _rm(out["dependabot"])

    if "osv" in tools:
        out["osv"] = {"path": f"{stem}-osv.json"}
        _osv(cfg, path, out["osv"], lg("osv"), notes, settings)

    if "zizmor" in tools:
        out["zizmor"] = {"path": f"{stem}-zizmor.json"}
        _zizmor(path, out["zizmor"], lg("zizmor"), notes, settings)

    if "clamav" in tools:
        out["clamav"] = f"{stem}-clamav.txt"
        _clamav(path, out["clamav"], lg("clamav"), notes, settings)

    if "gitleaks" in tools:
        out["gitleaks"] = f"{stem}-gitleaks.json"
        _gitleaks(cfg, path, out["gitleaks"], lg("gitleaks"), notes, settings)

    if "guarddog" in tools:
        if cfg.get("guarddog"):
            out["guarddog"] = {}
            for i, g in enumerate(cfg["guarddog"]):
                label = g["manifest"]
                dest = f"{stem}-guarddog-{i}.json"
                out["guarddog"][label] = {"path": dest, "ecosystem": g["ecosystem"],
                                          "manifest": g["manifest"]}
                _guarddog(g, path, dest, lg(f"guarddog-{i}"), notes, f"GuardDog {label}")
        else:
            # Still list the source so a missing GuardDog config is not invisible.
            out["guarddog"] = {"(not configured)": {
                "path": f"{stem}-guarddog.json", "ecosystem": "", "manifest": "(not configured)"}}
            notes["GuardDog (not configured)"] = "not configured: no `guarddog` list in this project"
            out.setdefault("skipped", []).append("GuardDog (not configured)")

    if cfg.get("coverage"):
        # Relative: a file inside the checkout. Absolute: a file produced elsewhere
        # (a CI artifact, a summary rebuilt from a PR comment); it is only parsed.
        out["coverage"] = (cfg["coverage"] if os.path.isabs(cfg["coverage"])
                           else _inside(path, cfg["coverage"]))


def _trivy(args, out, logfile, notes, source):
    # `trivy config` exits 0 even with findings, so any nonzero is a real failure.
    rc = run(["trivy", *args], logfile)
    if rc != 0 or not _nonempty(out):
        notes[source] = f"trivy exited {rc}, see logs"
        _rm(out)


def _semgrep_label(mode):
    has_token = bool(os.environ.get("SEMGREP_APP_TOKEN"))
    if mode == "public" or (mode == "auto" and not has_token):
        return "public ruleset"
    return "org policy (semgrep ci)" if has_token else "not scanned: SEMGREP_APP_TOKEN not set"


def _semgrep(cfg, path, out, logfile, notes, mode="auto"):
    env = {k: v for k, v in os.environ.items() if k not in _DIFF_AWARE_ENV}
    if mode == "public":
        env.pop("SEMGREP_APP_TOKEN", None)
    if mode == "ci" and not env.get("SEMGREP_APP_TOKEN"):
        # A trend must not silently switch rulesets under one "Semgrep" label.
        notes["Semgrep"] = "SEMGREP_APP_TOKEN not set (semgrep_mode is ci)"
        return
    if env.get("SEMGREP_APP_TOKEN"):
        # `semgrep ci` applies your organisation's policy (Code + Supply Chain).
        if cfg.get("repo"):
            sha, _ = git_sha(path)
            env.update(SEMGREP_REPO_NAME=cfg["repo"],
                       SEMGREP_REPO_URL=f"https://github.com/{cfg['repo']}",
                       SEMGREP_COMMIT=sha)
        if cfg.get("semgrep_branch"):
            env["SEMGREP_BRANCH"] = str(cfg["semgrep_branch"])
        cmd = ["semgrep", "ci", "--code", "--supply-chain", "--json",
               f"--json-output={out}", "--metrics=off"]
    else:
        cmd = ["semgrep", "scan", "--config", cfg.get("semgrep_config", "p/default"), "--json",
               f"--json-output={out}", "--metrics=off"]
    log(f"Semgrep: {cfg['name']}")
    rc = run(cmd, logfile, cwd=path, env=env)
    if rc not in (0, 1) or not _nonempty(out):
        notes["Semgrep"] = f"semgrep exited {rc}, see logs"
        _rm(out)


DEPENDABOT_STATES = "open,dismissed,auto_dismissed"


def _dependabot_cmd(repo):
    # GitHub silently ignores an unknown `state` and returns no alerts (not an error), so
    # the exact string is pinned by a test.
    return ["gh", "api", f"/repos/{repo}/dependabot/alerts?state={DEPENDABOT_STATES}&per_page=100",
            "--paginate"]


def _register_skipped(out, notes, tools, cfg, stem):
    """Stub every disabled tool so digest still lists it (optional, not collected)."""
    skip = "skipped: not in --tools"
    out.setdefault("skipped", [])

    def mark(source, note=skip):
        """Optional is recorded structurally: a note's wording never makes a gap optional."""
        notes.setdefault(source, note)
        if source not in out["skipped"]:
            out["skipped"].append(source)
    if "sonarqube" not in tools:
        out.setdefault("sonarqube", {})
        mark("SonarQube")
    if "snyk" not in tools:
        products = {"Open Source": f"{stem}-snyk-oss.json", "Code": f"{stem}-snyk-code.json",
                    "IaC": f"{stem}-snyk-iac.json"}
        if cfg.get("image"):
            products["Container"] = f"{stem}-snyk-container.json"
        out["snyk"] = products
        for p in products:
            mark(f"Snyk {p}")
    if "trivy" not in tools:
        out["trivy"] = {"Config": f"{stem}-trivy-config.json"}
        if cfg.get("helm"):
            out["trivy"]["Chart"] = f"{stem}-trivy-chart.json"
        for t in out["trivy"]:
            mark(f"Trivy {t}")
    if "semgrep" not in tools:
        out["semgrep"] = f"{stem}-semgrep.json"
        mark("Semgrep")
    if "dependabot" not in tools:
        out["dependabot"] = f"{stem}-dependabot.json"
        mark("Dependabot")
    if "osv" not in tools:
        out["osv"] = {"path": f"{stem}-osv.json"}
        mark("OSV-Scanner")
    if "zizmor" not in tools:
        out["zizmor"] = {"path": f"{stem}-zizmor.json"}
        mark("zizmor")
    if "clamav" not in tools:
        out["clamav"] = f"{stem}-clamav.txt"
        mark("ClamAV")
    if "gitleaks" not in tools:
        out["gitleaks"] = f"{stem}-gitleaks.json"
        mark("Gitleaks")
    if "guarddog" not in tools:
        if cfg.get("guarddog"):
            out["guarddog"] = {}
            for i, g in enumerate(cfg["guarddog"]):
                label = g["manifest"]
                out["guarddog"][label] = {"path": f"{stem}-guarddog-{i}.json",
                                          "ecosystem": g["ecosystem"], "manifest": label}
                mark(f"GuardDog {label}")
        else:
            out["guarddog"] = {"(not configured)": {
                "path": f"{stem}-guarddog.json", "ecosystem": "", "manifest": "(not configured)"}}
            mark("GuardDog (not configured)")


def _clamav(path, out, logfile, notes, settings=None):
    """Native clamscan when it has a database; otherwise the official image,
    which refreshes its signatures in the same container before scanning."""
    native = have("clamscan") and _clamav_db_ready()
    if native:
        cmd, cwd = ["clamscan", "-r", "--infected", "--no-summary", "--stdout", "."], path
        runner = "native"
    elif have("docker"):
        # freshclam failure must not silently look like a clean scan: the marker
        # line is what the parser turns into an incomplete source.
        cmd = ["docker", "run", "--rm", "--platform", "linux/amd64", "--entrypoint", "sh",
               "-v", f"{path}:/scan:ro", CLAMAV_IMAGE, "-c",
               "if ! freshclam --quiet >/dev/null 2>&1; then "
               "echo '# qsd: freshclam failed'; fi; "
               "cd /scan && clamscan -r --infected --no-summary --stdout ."]
        cwd = None
        runner = "container"
    else:
        notes["ClamAV"] = "neither clamscan (with a database) nor docker available"
        return
    if settings is not None:
        settings.setdefault("runners", {})["clamav"] = runner
    log("ClamAV: " + ("clamscan" if native else "clamav/clamav container"))
    with open(out, "w", encoding="utf-8") as fh, open(logfile, "w") as err:
        fh.write(f"# qsd clamav {'native' if native else CLAMAV_IMAGE}\n")
        fh.flush()
        rc = subprocess.run(cmd, cwd=cwd, stdout=fh, stderr=err).returncode
    # 0 clean, 1 found; 2 is an error and its partial output would read as clean.
    if rc not in (0, 1):
        notes["ClamAV"] = f"clamscan exited {rc}, see logs"
        _rm(out)


def _clamav_db_ready():
    try:
        r = subprocess.run(["clamscan", "--version"], capture_output=True, text=True, timeout=30)
        # "ClamAV 1.x/<db version>/<date>" carries a database version only when one is loaded.
        return r.returncode == 0 and r.stdout.count("/") >= 2
    except (OSError, subprocess.SubprocessError):
        return False


def _guarddog(g, path, out, logfile, notes, source):
    if g.get("ecosystem") not in GUARDDOG_ECOSYSTEMS:
        notes[source] = f"unsupported ecosystem {g.get('ecosystem')!r}"
        return
    if not have("guarddog"):
        notes[source] = "guarddog not on PATH"
        return
    manifest = _inside(path, g["manifest"])
    log(f"GuardDog: {g['ecosystem']} {g['manifest']}")
    with open(out, "w") as fh, open(logfile, "w") as err:
        rc = subprocess.run(["guarddog", g["ecosystem"], "verify", manifest,
                             "--output-format", "json"], stdout=fh, stderr=err).returncode
    if rc != 0 or not _nonempty(out):
        notes[source] = f"guarddog exited {rc}, see logs"
        _rm(out)


def _gitleaks(cfg, path, out, logfile, notes, settings=None):
    """Full git history when the checkout is a repository, the files otherwise.

    The free MIT CLI needs no licence key (only gitleaks-action does, for
    organisation repos). --redact keeps secrets out of the report, and
    --exit-code 0 makes any nonzero exit a real failure rather than "found".
    The repo's own .gitleaks.toml / .gitleaksignore apply as usual.
    """
    git = os.path.isdir(os.path.join(path, ".git")) or os.path.isfile(os.path.join(path, ".git"))
    mode = cfg.get("gitleaks_mode") or ("git" if git else "dir")
    if mode not in ("git", "dir"):
        notes["Gitleaks"] = f"unsupported gitleaks_mode {mode!r}"
        return
    args = ["--redact", "--exit-code", "0", "--report-format", "json",
            "--no-banner", "--log-level", "error"]
    if mode == "git" and cfg.get("gitleaks_log_opts"):
        args.append(f"--log-opts={cfg['gitleaks_log_opts']}")
    if have("gitleaks"):
        cmd, target, runner = ["gitleaks", mode, path, "--report-path", out, *args], None, "native"
        log(f"Gitleaks: {mode} (native)")
    elif have("docker"):
        # The report goes to stdout so the container never writes to the host.
        cmd = ["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
               "-e", "GIT_CONFIG_COUNT=1", "-e", "GIT_CONFIG_KEY_0=safe.directory",
               "-e", "GIT_CONFIG_VALUE_0=*", "-v", f"{path}:/repo:ro", GITLEAKS_IMAGE,
               mode, "/repo", "--report-path", "/dev/stdout", *args]
        target, runner = out, "container"
        log(f"Gitleaks: {mode} (container)")
    else:
        notes["Gitleaks"] = "neither gitleaks nor docker available"
        return
    if settings is not None:
        settings.setdefault("runners", {})["gitleaks"] = runner
    if target:
        with open(target, "w") as fh, open(logfile, "w") as err:
            rc = subprocess.run(cmd, stdout=fh, stderr=err).returncode
    else:
        rc = run(cmd, logfile)
    if rc != 0 or not _nonempty(out):
        notes["Gitleaks"] = f"gitleaks exited {rc}, see logs"
        _rm(out)


def _native_or_container(tool, image, path, args, target_args):
    """(cmd, root, runner): the native CLI on `path`, else the pinned image with the
    checkout mounted read-only. Output always goes to stdout."""
    if have(tool):
        return [tool, *args, *target_args(path)], path, "native"
    if have("docker"):
        return (["docker", "run", "--rm", "--user", f"{os.getuid()}:{os.getgid()}",
                 "-v", f"{path}:/src:ro", image, *args, *target_args("/src")], "/src",
                "container")
    return None, None, None


def _capture(cmd, out, logfile):
    with open(out, "w") as fh, open(logfile, "w") as err:
        return subprocess.run(cmd, stdout=fh, stderr=err).returncode


def _log_has(logfile, text):
    try:
        with open(logfile, encoding="utf-8", errors="replace") as fh:
            return text in fh.read()
    except OSError:
        return False


def _osv(cfg, path, spec, logfile, notes, settings=None):
    """Queries osv.dev with package names and versions (not code). Set
    `osv_offline` to use downloaded databases instead (native CLI only)."""
    args = ["scan", "source", "-r", "--format", "json"]
    if cfg.get("osv_offline"):
        if not have("osv-scanner"):
            notes["OSV-Scanner"] = "osv_offline needs the native osv-scanner"
            return
        args += ["--offline-vulnerabilities", "--download-offline-databases"]
    cmd, root, runner = _native_or_container("osv-scanner", OSV_IMAGE, path, args, lambda t: [t])
    if not cmd:
        notes["OSV-Scanner"] = "neither osv-scanner nor docker available"
        return
    if settings is not None:
        settings.setdefault("runners", {})["osv"] = runner
    log(f"OSV-Scanner: {cfg['name']}")
    spec["root"] = root
    rc = _capture(cmd, spec["path"], logfile)
    # 0 clean, 1 vulnerabilities found, 128 no package manifests; anything else failed.
    if rc in (0, 1) and _nonempty(spec["path"]):
        return
    notes["OSV-Scanner"] = ("no package manifests found" if rc == 128
                            else f"osv-scanner exited {rc}, see logs")
    _rm(spec["path"])


def _zizmor(path, spec, logfile, notes, settings=None):
    """Offline audits only: no GitHub token, nothing leaves the machine. With
    --no-exit-codes a run that finds problems exits 0, so nonzero is a failure."""
    args = ["--offline", "--no-exit-codes", "--format", "json"]
    cmd, root, runner = _native_or_container("zizmor", ZIZMOR_IMAGE, path, args, lambda t: [t])
    if not cmd:
        notes["zizmor"] = "neither zizmor nor docker available"
        return
    if settings is not None:
        settings.setdefault("runners", {})["zizmor"] = runner
    log("zizmor: GitHub Actions workflows")
    spec["root"] = root
    rc = _capture(cmd, spec["path"], logfile)
    if rc == 0 and _nonempty(spec["path"]):
        return
    notes["zizmor"] = ("no GitHub Actions workflows found" if _log_has(logfile, "no inputs collected")
                       else f"zizmor exited {rc}, see logs")
    _rm(spec["path"])
