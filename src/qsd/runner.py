"""Run the five scanners against local checkouts and write a digest manifest.

Every tool is optional. One that is missing, unauthenticated or fails is
recorded as not collected and the run continues: a release scan should say
what it could not see rather than abort or, worse, report it as clean.
"""

import base64
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from importlib import resources

from .parsers.sonarqube import SonarError, api

TOOLS = ("sonarqube", "snyk", "trivy", "semgrep", "dependabot")
SONAR_PROJECT = "qsd-sonar"
SCANNER_IMAGE = os.environ.get("QSD_SCANNER_IMAGE", "sonarsource/sonar-scanner-cli:latest")


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
    try:
        return subprocess.check_output(["git", "-C", path, "rev-parse", "HEAD"],
                                       text=True, stderr=subprocess.DEVNULL).strip()
    except (OSError, subprocess.CalledProcessError):
        return ""


# --------------------------------------------------------------------------
# SonarQube: a throwaway container, started, scanned against, read, destroyed.
# --------------------------------------------------------------------------

class Sonar:
    def __init__(self, workdir):
        self.port = os.environ.get("QSD_SONAR_PORT", "9000")
        self.host = f"http://127.0.0.1:{self.port}"
        self.token = ""
        self.envfile = os.path.join(workdir, ".env.sonar")
        self.compose = str(resources.files("qsd") / "data" / "sonarqube-compose.yml")
        self.logs = workdir

    def _compose(self, *args):
        return ["docker", "compose", "--env-file", self.envfile, "-p", SONAR_PROJECT,
                "-f", self.compose, *args]

    def up(self):
        with open(os.open(self.envfile, os.O_CREAT | os.O_WRONLY | os.O_TRUNC, 0o600), "w") as fh:
            fh.write(f"SONAR_DB_PASSWORD={secrets.token_hex(12)}\nQSD_SONAR_PORT={self.port}\n")
        log("starting SonarQube (a cold start is ~2 minutes)")
        if run(self._compose("up", "-d"), os.path.join(self.logs, "sonar-up.log")) != 0:
            raise SonarError("docker compose up failed, see sonar-up.log")
        for _ in range(72):
            try:
                with urllib.request.urlopen(f"{self.host}/api/system/status", timeout=5) as r:
                    if json.load(r).get("status") == "UP":
                        break
            except OSError:
                pass
            time.sleep(5)
        else:
            raise SonarError("SonarQube never reached UP")
        # Throwaway instance, throwaway credentials. A USER_TOKEN, because an
        # analysis token is refused on the hotspots endpoint.
        req = urllib.request.Request(
            f"{self.host}/api/user_tokens/generate",
            data=f"name=qsd-{os.getpid()}&type=USER_TOKEN".encode(), method="POST")
        # The image's documented first-boot login; the instance dies with this run.
        first_boot = base64.b64encode(b"admin:admin").decode()
        req.add_header("Authorization", f"Basic {first_boot}")
        with urllib.request.urlopen(req, timeout=30) as r:
            self.token = json.load(r)["token"]

    def scan(self, path, key, logfile):
        log(f"SonarQube: {key}")
        # Join the compose network instead of reaching the host: works the same
        # on Docker Desktop and on Linux, and needs no published port.
        cmd = ["docker", "run", "--rm", "--network", f"{SONAR_PROJECT}_default",
               "-v", f"{path}:/usr/src", "-e", "SONAR_HOST_URL=http://sonarqube:9000",
               "-e", f"SONAR_TOKEN={self.token}", SCANNER_IMAGE,
               f"-Dsonar.projectKey={key}", "-Dsonar.scm.disabled=true"]
        if not os.path.exists(os.path.join(path, "sonar-project.properties")):
            cmd.append("-Dsonar.sources=.")
        rc = run(cmd, logfile)
        with open(logfile, encoding="utf-8", errors="replace") as fh:
            ok = "ANALYSIS SUCCESSFUL" in fh.read()
        if rc != 0 or not ok:
            raise SonarError(f"analysis failed, see {os.path.basename(logfile)}")

    def wait(self, key, timeout=600):
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

    def export(self, key, outdir):
        """Write issues/hotspots/measures to files so the digest can run offline."""
        from .parsers.sonarqube import MEASURE_KEYS, Forbidden, fetch_all
        out = {}
        issues = fetch_all(self.host, self.token, "/api/issues/search",
                           {"components": key, "resolved": "false"}, "issues")
        try:
            hotspots = fetch_all(self.host, self.token, "/api/hotspots/search",
                                 {"project": key, "status": "TO_REVIEW"}, "hotspots")
        except Forbidden:
            hotspots = []
        measures = api(self.host, self.token, "/api/measures/component",
                       {"component": key, "metricKeys": MEASURE_KEYS})
        for name, doc in (("issues", {"issues": issues}), ("hotspots", {"hotspots": hotspots}),
                          ("measures", measures)):
            path = os.path.join(outdir, f"sonar-{key}-{name}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            out[name] = path
        return out

    def down(self):
        log("tearing down SonarQube")
        run(self._compose("down", "-v"), os.path.join(self.logs, "sonar-down.log"))
        try:
            os.remove(self.envfile)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Snyk. Exit codes carry meaning: 0 clean, 1 found, 3 nothing to scan, else failed.
# --------------------------------------------------------------------------

def snyk(args, cwd, out, logfile, severity):
    rc = run(["snyk", *args, f"--severity-threshold={severity}", f"--json-file-output={out}"],
             logfile, cwd=cwd)
    if rc == 0 and not _nonempty(out):
        # A clean `snyk code test` writes no file at all. Clean is a result.
        with open(out, "w") as fh:
            fh.write("{}")
        return True
    if rc in (0, 1) and _nonempty(out):
        return True
    warn(f"snyk {' '.join(args[:2])} in {cwd}: exit {rc} - reported as not scanned")
    _rm(out)  # never leave a truncated file that would read as a short result
    return False


def _nonempty(path):
    return os.path.exists(path) and os.path.getsize(path) > 0


def _rm(path):
    try:
        os.remove(path)
    except OSError:
        pass


def render_helm(proj, root, dest):
    """Return (state, dir): nochart | rendered | failed.

    `snyk iac test` cannot parse Go templates. A raw chart tree either fails
    loudly or, worse, exits 0 having scanned the one plain manifest beside it,
    so a chart that will not render is reported as not scanned, never as clean.
    """
    helm = proj.get("helm")
    if not helm:
        return "nochart", root
    if not have("helm"):
        warn("helm not on PATH - chart IaC reported as not scanned")
        return "failed", None
    chart = os.path.join(root, helm["chart"])
    cmd = ["helm", "template", "release", chart]
    for v in helm.get("values") or []:
        cmd += ["-f", os.path.join(root, v)]
    os.makedirs(dest, exist_ok=True)
    with open(os.path.join(dest, "chart.yaml"), "w") as fh:
        if subprocess.run(cmd, stdout=fh, stderr=subprocess.DEVNULL).returncode != 0:
            warn(f"helm template failed for {proj['name']} - IaC reported as not scanned")
            return "failed", None
    extra = helm.get("extra_manifests")
    if extra:
        src = os.path.join(root, extra)
        for f in os.listdir(src) if os.path.isdir(src) else []:
            if f.endswith((".yaml", ".yml")):
                shutil.copy(os.path.join(src, f), dest)
    return "rendered", dest


# --------------------------------------------------------------------------

def scan(config, base, out_dir, version="", tools=TOOLS):
    """Run every enabled tool for every project. Returns the manifest dict."""
    raw = os.path.join(out_dir, "raw")
    logs = os.path.join(out_dir, "logs")
    os.makedirs(raw, exist_ok=True)
    os.makedirs(logs, exist_ok=True)
    snyk_sev = config.get("snyk_severity", "high")
    trivy_sev = config.get("trivy_severity", "CRITICAL,HIGH")
    projects = []
    for p in config["projects"]:
        path = os.path.abspath(os.path.join(base, p["path"]))
        projects.append({"cfg": p, "path": path, "name": p["name"], "out": {
            "name": p["name"], "label": p.get("label") or p["name"],
            "repo": p.get("repo", ""), "commit": git_sha(path)}})

    shim = _python_shim() if "snyk" in tools else None
    sonar = None
    if "sonarqube" in tools:
        if not have("docker"):
            warn("docker not on PATH - SonarQube reported as not collected")
        else:
            sonar = Sonar(logs)
    try:
        if sonar:
            try:
                sonar.up()
                for pr in projects:
                    key = pr["cfg"].get("sonar_project_key") or pr["name"]
                    sonar.scan(pr["path"], key, os.path.join(logs, f"{pr['name']}.sonar.log"))
                for pr in projects:
                    key = pr["cfg"].get("sonar_project_key") or pr["name"]
                    sonar.wait(key)
                    pr["out"]["sonarqube"] = sonar.export(key, raw)
            except (SonarError, OSError) as exc:
                warn(f"SonarQube: {exc}")
        for pr in projects:
            if "sonarqube" in tools:
                pr["out"].setdefault("sonarqube", {})
            _scan_project(pr, raw, logs, tools, snyk_sev, trivy_sev)
    finally:
        if sonar:
            sonar.down()
        if shim:
            shutil.rmtree(shim, ignore_errors=True)

    return {"title": config.get("title", ""), "version": version,
            "projects": [pr["out"] for pr in projects]}


def _scan_project(pr, raw, logs, tools, snyk_sev, trivy_sev):
    cfg, path, name, out = pr["cfg"], pr["path"], pr["name"], pr["out"]
    stem = os.path.join(raw, name)
    lg = lambda tool: os.path.join(logs, f"{name}.{tool}.log")  # noqa: E731

    if "snyk" in tools:
        products = {"Open Source": f"{stem}-snyk-oss.json", "Code": f"{stem}-snyk-code.json",
                    "IaC": f"{stem}-snyk-iac.json"}
        if cfg.get("image"):
            products["Container"] = f"{stem}-snyk-container.json"
        out["snyk"] = dict(products)
        if not have("snyk"):
            warn("snyk not on PATH - Snyk reported as not collected")
        else:
            log(f"Snyk: {name}")
            # --fail-fast turns a partially scanned --all-projects run into a
            # failure instead of a complete-looking partial result.
            oss = cfg.get("snyk_open_source_args") or ["--all-projects", "--fail-fast"]
            snyk(["test", *oss], path, products["Open Source"], lg("snyk-oss"), snyk_sev)
            snyk(["code", "test"], path, products["Code"], lg("snyk-code"), snyk_sev)
            state, iac_dir = render_helm(cfg, path, os.path.join(raw, f".rendered-{name}"))
            if state != "failed":
                # snyk iac refuses a target outside cwd, so run inside the render.
                snyk(["iac", "test", "."], iac_dir, products["IaC"], lg("snyk-iac"), snyk_sev)
            if cfg.get("image"):
                snyk(["container", "test", cfg["image"]], path, products["Container"],
                     lg("snyk-container"), snyk_sev)

    if "trivy" in tools:
        out["trivy"] = {"Config": f"{stem}-trivy-config.json"}
        helm = cfg.get("helm")
        if helm:
            out["trivy"]["Chart"] = f"{stem}-trivy-chart.json"
        if not have("trivy"):
            warn("trivy not on PATH - Trivy reported as not collected")
        else:
            log(f"Trivy: {name}")
            _trivy(["config", "--quiet", "--severity", trivy_sev, "--format", "json",
                    "--output", out["trivy"]["Config"], path], out["trivy"]["Config"],
                   lg("trivy-config"))
            if helm:
                cmd = ["config", "--quiet", "--severity", trivy_sev, "--format", "json",
                       "--output", out["trivy"]["Chart"]]
                for v in helm.get("values") or []:
                    cmd += ["--helm-values", os.path.join(path, v)]
                _trivy(cmd + [os.path.join(path, helm["chart"])], out["trivy"]["Chart"],
                       lg("trivy-chart"))

    if "semgrep" in tools:
        out["semgrep"] = f"{stem}-semgrep.json"
        if not have("semgrep"):
            warn("semgrep not on PATH - Semgrep reported as not collected")
        else:
            _semgrep(cfg, path, out["semgrep"], lg("semgrep"))

    if "dependabot" in tools:
        out["dependabot"] = f"{stem}-dependabot.json"
        if not cfg.get("repo"):
            warn(f"{name}: no `repo` (owner/name) - Dependabot reported as not collected")
        elif not have("gh"):
            warn("gh not on PATH - Dependabot reported as not collected")
        else:
            log(f"Dependabot: {cfg['repo']}")
            with open(out["dependabot"], "w") as fh:
                rc = subprocess.run(
                    ["gh", "api", f"/repos/{cfg['repo']}/dependabot/alerts?state=open&per_page=100",
                     "--paginate"], stdout=fh, stderr=subprocess.DEVNULL).returncode
            if rc != 0:
                warn(f"Dependabot fetch failed for {cfg['repo']} - reported as not collected")
                _rm(out["dependabot"])

    if cfg.get("coverage"):
        out["coverage"] = os.path.join(path, cfg["coverage"])


def _trivy(args, out, logfile):
    # `trivy config` exits 0 even with findings, so any nonzero is a real failure.
    rc = run(["trivy", *args], logfile)
    if rc != 0 or not _nonempty(out):
        warn(f"trivy {args[0]} failed (exit {rc}) - reported as not scanned")
        _rm(out)


def _semgrep(cfg, path, out, logfile):
    token = os.environ.get("SEMGREP_APP_TOKEN")
    if token:
        # `semgrep ci` applies your organisation's policy (Code + Supply Chain).
        env = dict(os.environ)
        if cfg.get("repo"):
            env.update(SEMGREP_REPO_NAME=cfg["repo"],
                       SEMGREP_REPO_URL=f"https://github.com/{cfg['repo']}",
                       SEMGREP_COMMIT=git_sha(path))
        cmd = ["semgrep", "ci", "--code", "--supply-chain", "--json",
               f"--json-output={out}", "--metrics=off"]
    else:
        # Without a token, an explicit public ruleset. The label stays "Semgrep",
        # so say in the config which ruleset produced the numbers.
        env = None
        cmd = ["semgrep", "scan", "--config", cfg.get("semgrep_config", "p/default"), "--json",
               f"--json-output={out}", "--metrics=off"]
    log(f"Semgrep: {cfg['name']}")
    rc = run(cmd, logfile, cwd=path, env=env)
    if rc not in (0, 1) or not _nonempty(out):
        warn(f"semgrep {cfg['name']} failed (exit {rc}) - reported as not scanned")
        _rm(out)


def _python_shim():
    """Snyk shells out to `python` for Poetry projects; some systems ship only python3."""
    if have("python") or not have("python3"):
        return None
    shim = tempfile.mkdtemp(prefix="qsd-py-")
    os.symlink(shutil.which("python3"), os.path.join(shim, "python"))
    os.environ["PATH"] = f"{shim}{os.pathsep}{os.environ.get('PATH', '')}"
    return shim
