# quality-scan-digest

English | [繁體中文](README.zh-TW.md)

Merge overlapping scanner output into **one deduplicated JSON report** (plus optional HTML)
with an honest coverage contract: every source is *collected*, *incomplete*, or *not collected*.

This is **not** a DefectDojo / full AppSec platform substitute. It runs a fixed set of
parsers against tools you already have (or pin by digest), collapses duplicate advisories,
and refuses to look "clean" when a scan was partial. Trivy here is **`trivy config` only**
(Dockerfile / Helm); image CVE scanning is **Snyk Container** when you set `image`.

| What it covers | What it does **not** run |
|---|---|
| SonarQube quality + hotspots, Snyk OSS/Code/IaC/(optional) Container, Trivy config, Semgrep, Dependabot open alerts, OSV lockfiles (+ `MAL-`), zizmor workflows, Gitleaks history, ClamAV signatures, GuardDog manifests | Trivy `image`/`fs` CVE mode by default, SCA beyond the listed tools, runtime/DAST, ticket workflow |

| | Tool | What it reads | Official repository | Licence |
|---|---|---|---|---|
| <img src="https://github.com/SonarSource.png?size=144" width="72" height="72" alt="SonarQube"> | **SonarQube** | Source: bugs, vulnerabilities, code smells, security hotspots, size | [SonarSource/sonarqube](https://github.com/SonarSource/sonarqube) | LGPL-3.0 |
| <img src="https://github.com/snyk.png?size=144" width="72" height="72" alt="Snyk"> | **Snyk** | Open Source dependencies, Code (SAST), IaC and Container images | [snyk/cli](https://github.com/snyk/cli) | Apache-2.0 (CLI) |
| <img src="https://github.com/aquasecurity.png?size=144" width="72" height="72" alt="Trivy"> | **Trivy** | Dockerfile instructions and Helm charts (`trivy config`) | [aquasecurity/trivy](https://github.com/aquasecurity/trivy) | Apache-2.0 |
| <img src="https://github.com/semgrep.png?size=144" width="72" height="72" alt="Semgrep"> | **Semgrep** | Code (SAST) and, with a Semgrep token, Supply Chain advisories | [semgrep/semgrep](https://github.com/semgrep/semgrep) | LGPL-2.1 |
| <img src="https://github.com/dependabot.png?size=144" width="72" height="72" alt="Dependabot"> | **Dependabot** | Open dependency alerts, fetched from GitHub | [dependabot/dependabot-core](https://github.com/dependabot/dependabot-core) | MIT (core) |
| <img src="https://github.com/google.png?size=144" width="72" height="72" alt="OSV-Scanner"> | **OSV-Scanner** | Lockfiles across ecosystems against the OSV database, including OpenSSF malicious-package (`MAL-`) advisories | [google/osv-scanner](https://github.com/google/osv-scanner) | Apache-2.0 |
| <img src="https://github.com/zizmorcore.png?size=144" width="72" height="72" alt="zizmor"> | **zizmor** | GitHub Actions workflow security: template injection, excessive permissions, unpinned actions, credentials left by checkout | [zizmorcore/zizmor](https://github.com/zizmorcore/zizmor) | MIT |
| <img src="https://github.com/gitleaks.png?size=144" width="72" height="72" alt="Gitleaks"> | **Gitleaks** | Secrets committed anywhere in git history (or in the files, outside a repo) | [gitleaks/gitleaks](https://github.com/gitleaks/gitleaks) | MIT |
| <img src="https://github.com/Cisco-Talos.png?size=144" width="72" height="72" alt="ClamAV"> | **ClamAV** | Known malware in the checkout (signature scan) | [Cisco-Talos/clamav](https://github.com/Cisco-Talos/clamav) | GPL-2.0 |
| <img src="https://github.com/DataDog.png?size=144" width="72" height="72" alt="GuardDog"> | **GuardDog** | Malicious or risky PyPI / npm / Go packages in your dependency manifests | [DataDog/guarddog](https://github.com/DataDog/guarddog) | Apache-2.0 |

Logos are each maintainer's GitHub avatar; trademarks belong to their owners. Snyk and Dependabot ship open-source clients, but results need a Snyk account or a GitHub repository.

Test coverage (Cobertura XML or an Istanbul `coverage-summary.json`) can ride along.

Python 3.10+, standard library only. No server: SonarQube runs as a throwaway container
that is started, scanned against, exported and destroyed in one run.

## Why

**The tools overlap.** Snyk, Semgrep Supply Chain, OSV-Scanner, Trivy and Dependabot read the same
advisory databases, so one vulnerable package can show up four or five times and
every headline number is inflated. `qsd` lists each problem once, records every scanner
that saw it, and keeps the other sightings in full.

**A partial scan must look partial.** Every source is reported as *collected*,
*incomplete* (with what is missing), or *not collected* (with why). A tool that is
missing, unauthenticated, fails, or writes an error instead of results is never read
as an empty, clean result. **`--strict` is the default** (exit `2` on any required gap);
use `--lenient` only for local exploration. Tools left out of `--tools` still appear in
`sources` as `optional` skips so a screenshot cannot hide the rest of the contract.

## Install

```bash
pip install git+https://github.com/CloudBater/quality-scan-digest@v0.4.0
qsd --version
```

Install whichever scanners you want; each is optional and a missing one is reported:
`docker` (SonarQube, and ClamAV if `clamscan` is not installed),
[`snyk`](https://docs.snyk.io/snyk-cli), [`trivy`](https://trivy.dev),
[`semgrep`](https://semgrep.dev/docs/getting-started/), [`gh`](https://cli.github.com)
(Dependabot), [`gitleaks`](https://github.com/gitleaks/gitleaks), [`osv-scanner`](https://github.com/google/osv-scanner) and [`zizmor`](https://github.com/zizmorcore/zizmor) (or `docker` for these three), [`clamscan`](https://docs.clamav.net) with a current database
(`freshclam`), [`guarddog`](https://github.com/DataDog/guarddog), and `helm` if you scan charts.

## Usage

### 1. Scan and digest in one step

```bash
qsd scan examples/qsd.example.json --release v1.4.0 --out-dir qsd-out
```

Each run writes a fresh, private (`0700`) directory `qsd-out/run-<timestamp>-<id>/` with
`report.json`, `report.html`, `manifest.json`, the raw tool outputs under `raw/` and
per-tool logs under `logs/`. **Treat that directory as sensitive**: raw outputs and
logs contain code snippets and findings about your systems.

Limit the tools with `--tools snyk,trivy,clamav`. Paths in the config resolve against
the config file and may not point outside the project. See
[`examples/qsd.example.json`](examples/qsd.example.json):

| Key | Meaning |
|---|---|
| `name` | Project id: letters, digits, `.`, `_`, `-`; unique |
| `label` | Display name; unique |
| `path` | Local checkout to scan. Scan the release ref, not a working copy |
| `repo` | `owner/name` on GitHub, for Dependabot |
| `sonar_project_key` | Defaults to `name` |
| `snyk_open_source_args` | Defaults to `--all-projects --fail-fast` |
| `image` | Image for Snyk Container. Pin a **digest** of what you shipped, not a moving tag |
| `helm.chart`, `helm.values`, `helm.extra_manifests` | Rendered into a temp dir (removed afterwards) before IaC scanning; Snyk cannot parse raw templates |
| `semgrep_config` | Ruleset used when `SEMGREP_APP_TOKEN` is not set (default `p/default`) |
| `osv_offline` | `true`: OSV-Scanner downloads offline databases instead of querying osv.dev (native CLI only) |
| `gitleaks_mode` | `git` (full history; default inside a repository) or `dir` (files only) |
| `gitleaks_log_opts` | Limit the history, e.g. `origin/main..HEAD` |
| `guarddog` | List of `{"ecosystem": "pypi" \| "npm" \| "go" \| "github_action", "manifest": "requirements.txt"}` |
| `coverage` | Coverage file: relative path inside the checkout, or an absolute path to a CI artifact (parsed only) |
| `sonar_args` | Extra `-Dsonar.<allowed>=…` analysis properties (sources/exclusions/language settings only — no scanner/host/token/executable overrides) |
| `semgrep_mode` | `auto` (default), `ci` (require token, never fall back to public rules), or `public` |

Top level: `snyk_severity` (default `high`) and `trivy_severity` (default
`CRITICAL,HIGH`). These floors are recorded in the report's `settings`, because zero
findings above a floor is not the same claim as zero findings.

Environment: `SEMGREP_APP_TOKEN` switches Semgrep to `semgrep ci` with your
organisation's policy (always a full scan, never diff-aware). `QSD_SONAR_PORT`,
`QSD_SCANNER_IMAGE`, `QSD_CLAMAV_IMAGE`, `QSD_GITLEAKS_IMAGE`, `QSD_OSV_IMAGE` and `QSD_ZIZMOR_IMAGE` override
the defaults. Snyk and `gh` use
their own login.

### 2. Digest outputs you already have (CI)

If your pipeline already runs the tools, point a manifest at their outputs:

```bash
qsd digest manifest.json --json-out report.json --html-out report.html
# partial local digests only:
qsd digest manifest.json --json-out report.json --lenient
```

See [`examples/manifest.example.json`](examples/manifest.example.json). Trivy
vulnerability output (`trivy fs|image --format json`) is also accepted here when you
already produced it; `qsd scan` itself still runs **config** only.

SonarQube is read from exported API responses (`issues`, `hotspots`, `measures`) or
live from `{"host": "...", "project_key": "..."}` with `SONAR_TOKEN` set. The token is
only sent to `https://` hosts or plain HTTP on loopback, redirects are never followed,
and a token is never read from the manifest itself. Use a user token: an analysis
token cannot read hotspots, which is reported as incomplete.

Exit codes: `1` when **no** source was collected or the input is invalid; **`2` by
default** when any required source is incomplete (`--lenient` / `--no-strict` to allow).

## Deduplication

Each pass is conservative on purpose: a wrong merge hides a finding, a missed merge only
over-counts.

| Pass | Default | Merges rows that share |
|---|---|---|
| `exact` | on | project, source, kind, rule, location, line, **column** and message |
| `advisory` | on | project, package (ecosystem-aware name rules), and a CVE/GHSA id, from **different** scanners. A row with no package joins only when every id it carries points to one package group |
| `sast` | **off** | project, file, line and CWE, reported by **different** scanners; each row joins at most one group, so nothing chains |

The surviving row comes from the richest source, takes the **most severe** severity
of the group, and keeps every other sighting (message, severity, rule, location, fix)
under `also`. `by` lists every scanner that saw it. Nothing merges across projects;
Snyk IaC and Trivy use unrelated rule catalogues, so misconfigurations are not merged.
Choose passes with `--dedup exact,advisory,sast` or turn it off with `--dedup none`.
Parsers themselves keep every affected version and manifest.

## Output

[`schema/report.schema.json`](schema/report.schema.json) describes the payload:

```jsonc
{
  "schema_version": "1.1",
  "generator": { "name": "quality-scan-digest", "version": "0.4.0" },
  "title": "…", "version": "v1.4.0", "generated_at": "…",
  "settings": { "snyk_severity": "high", "trivy_severity": "CRITICAL,HIGH", "dedup": "exact,advisory",
                "tools": "…", "images": {…}, "runners": { "clamav": "container" } },
  "generated_from": [ { "project_id": "api", "project": "API", "repo": "…", "commit": "…",
                        "commit_dirty": false, "sonar": {…}, "coverage": {…}, "dependabot": {…},
                        "findings": 120, "security": 40, "sec_crit_high": 3, "sec_unrated": 1,
                        "malware": 2, "by_source": {…} } ],
  "sources": { "API: Semgrep": { "collected": true, "complete": false,
                                 "note": "incomplete: 2 scan error(s)", "suppressed": 0, "optional": false } },
  "dedup":   { "input": 180, "passes": ["exact", "advisory"], "exact": 4, "advisory": 56, "output": 120 },
  "findings": [ { "id": "…", "track": "…", "project_id": "api", "proj": "API", "src": "Snyk",
                  "by": ["Snyk", "Dependabot"], "kind": "Dependency", "security": true,
                  "sev": "HIGH", "rank": 1, "msg": "…", "loc": "poetry.lock: django@4.2.0",
                  "line": "", "col": "", "ref": "SNYK-…", "ids": ["CVE-…"], "cwe": ["CWE-89"],
                  "fix": "upgrade to …", "also": [ { "src": "Dependabot", "sev": "MEDIUM", "msg": "…" } ] } ]
}
```

Severities are normalised onto one scale (`rank` 0 = CRITICAL/BLOCKER … 4 = INFO, 5 = unrated `—`).
`security` is decided by what a finding is (dependency, container, IaC,
misconfiguration, vulnerability, hotspot, secret, workflow, malware, package risk), not by which scanner
reported it. Use **`track`** for trend / Backstage identity (stable without the message);
**`id`** is the display hash and changes when advisory text rewrites. Waived findings
are counted under `sources.*.suppressed`, not dropped silently.

## Security notes

- Raw outputs, logs and the rendered report can contain code and secrets from the
  scanned repositories. Do not publish them as public CI artifacts.
- The throwaway SonarQube binds to `127.0.0.1` on a random port, uses its documented
  first-boot `admin` login only to mint a token, then rotates that password. Each run
  uses its own compose project and removes it, with its volumes, at the end.
- The scanner, ClamAV, Gitleaks, OSV-Scanner and zizmor images are pinned by digest; Actions are pinned by commit SHA.
- Gitleaks uses the free MIT CLI, which needs no licence key (only `gitleaks-action` asks
  for one, for organisation repos). It always runs with `--redact`, and `qsd` keeps only
  the rule, file, line and commit: never the secret, the commit author, email or message.
  Your repo's `.gitleaks.toml` and `.gitleaksignore` apply. A secret found in history must
  be revoked; deleting it from the code does not undo the leak.
- OSV-Scanner sends package names and versions (never code) to osv.dev by default; set
  `osv_offline` to use downloaded databases instead. zizmor always runs `--offline`: no
  GitHub token, nothing leaves the machine.
- On Linux, SonarQube needs `vm.max_map_count >= 524288` on the host.
- GuardDog downloads each listed dependency from its registry to analyse it (it does
  not install or execute it). Capability rules (`capability-*`) only say what a package
  *can* do and are reported as LOW; `threat-*` rules are HIGH.
- Report vulnerabilities in this tool privately: see [SECURITY.md](SECURITY.md).

## Development

```bash
python3 -m unittest discover -s tests -v
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and the [CHANGELOG](CHANGELOG.md).

## License

[MIT](LICENSE)
