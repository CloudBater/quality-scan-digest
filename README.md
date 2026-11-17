# quality-scan-digest

Run five code and supply-chain scanners against your repositories, merge what they
report into **one deduplicated list**, and export it as **JSON** (plus an optional
self-contained HTML report).

| Tool | What it reads |
|---|---|
| **SonarQube** | Source: bugs, vulnerabilities, code smells, security hotspots, size and duplication |
| **Snyk** | Open Source dependencies, Code (SAST), IaC and Container images |
| **Trivy** | Dockerfile instructions and Helm charts (`trivy config`) |
| **Semgrep** | Code (SAST) and Supply Chain advisories |
| **Dependabot** | Open dependency alerts, fetched from GitHub |

Test coverage (Cobertura XML or an Istanbul `coverage-summary.json`) can ride along.

Python 3.10+, standard library only. No server: SonarQube runs as a throwaway
container that is started, scanned against, exported and destroyed in one run.

## Why

The five tools overlap. Snyk, Semgrep Supply Chain, Trivy and Dependabot all read the
same advisory databases; SonarQube, Snyk Code and Semgrep all do SAST. Added up naively,
one vulnerable package shows up three times and every headline number is inflated.
`qsd` lists each problem once and records every scanner that saw it.

It is also built to make a **partial scan visible**. A tool that is missing, not
authenticated, or fails is reported as *not collected*, never as an empty, reassuring
result.

## Install

```bash
pip install git+https://github.com/CloudBater/quality-scan-digest
qsd --version
```

Install whichever scanners you want to use; each one is optional:
`docker` (SonarQube), [`snyk`](https://docs.snyk.io/snyk-cli), [`trivy`](https://trivy.dev),
[`semgrep`](https://semgrep.dev/docs/getting-started/), [`gh`](https://cli.github.com)
(Dependabot), and `helm` if you scan charts.

## Usage

### 1. Scan and digest in one step

```bash
qsd scan examples/qsd.example.json --release v1.4.0 --out-dir qsd-out
```

Writes `qsd-out/report.json`, `qsd-out/report.html`, the raw tool outputs under
`qsd-out/raw/`, per-tool logs under `qsd-out/logs/`, and `qsd-out/manifest.json`.

Limit the tools with `--tools snyk,trivy,semgrep`. Paths in the config resolve
against the config file. See [`examples/qsd.example.json`](examples/qsd.example.json):

| Key | Meaning |
|---|---|
| `name`, `label` | Project id and display name |
| `path` | Local checkout to scan. Scan the release ref, not a working copy |
| `repo` | `owner/name` on GitHub, for Dependabot |
| `sonar_project_key` | Defaults to `name` |
| `snyk_open_source_args` | Defaults to `--all-projects --fail-fast` |
| `image` | Image for Snyk Container. Pin a **digest** of what you shipped, not a moving tag |
| `helm.chart`, `helm.values`, `helm.extra_manifests` | Rendered before IaC scanning; Snyk cannot parse raw templates |
| `semgrep_config` | Ruleset used when `SEMGREP_APP_TOKEN` is not set (default `p/default`) |
| `coverage` | Coverage file inside the checkout |

Environment: `SEMGREP_APP_TOKEN` switches Semgrep to `semgrep ci` with your
organisation's policy; `QSD_SONAR_PORT` (default `9000`) and `QSD_SCANNER_IMAGE`
tune the SonarQube container. Snyk and `gh` use their own login.

### 2. Digest outputs you already have (CI)

If your pipeline already runs the tools, point a manifest at their JSON outputs:

```bash
qsd digest manifest.json --json-out report.json --html-out report.html
```

See [`examples/manifest.example.json`](examples/manifest.example.json). SonarQube can
be read from exported API responses (`issues`, `hotspots`, `measures`) or live from
`{"host": "...", "project_key": "..."}` with `SONAR_TOKEN` set (a user token: an
analysis token cannot read hotspots).

The command exits non-zero when **no** source was collected.

## Deduplication

Three passes, in order. Each is conservative on purpose: a wrong merge hides a
finding, a missed merge only over-counts.

| Pass | Merges rows that share |
|---|---|
| `exact` | project, source, rule, location, line and message |
| `advisory` | project, a CVE/GHSA id, and the same package (names normalised; a sighting with no package joins only when the id names one package) |
| `sast` | project, file, line and a CWE — across tools, and across two rules of one tool flagging the same line |

The surviving row comes from the richest source (Snyk, Semgrep, SonarQube, Trivy,
Dependabot, in that order), takes the **most severe** severity of the group, and keeps
the others under `also`. `by` lists every scanner that saw it. Nothing merges across
projects. Snyk IaC and Trivy use unrelated rule catalogues, so misconfigurations are
not merged. Choose passes with `--dedup exact,advisory` or turn it off with `--dedup none`.

## Output

[`schema/report.schema.json`](schema/report.schema.json) describes the payload:

```jsonc
{
  "schema_version": "1.0",
  "title": "…", "version": "v1.4.0", "generated_at": "…",
  "generated_from": [ { "project": "API", "repo": "…", "commit": "…",
                        "sonar": {…}, "coverage": {…}, "dependabot": {…},
                        "findings": 120, "security": 40, "sec_crit_high": 3, "by_source": {…} } ],
  "sources": { "API: Snyk Code": { "collected": true, "note": "" } },
  "dedup":   { "input": 180, "exact": 4, "advisory": 50, "sast": 6, "output": 120 },
  "findings": [ { "id": "…", "proj": "API", "src": "Snyk", "by": ["Snyk", "Dependabot"],
                  "kind": "Dependency", "sev": "HIGH", "rank": 1, "msg": "…",
                  "loc": "django@4.2.0", "line": "", "ref": "SNYK-…",
                  "ids": ["CVE-…"], "cwe": ["CWE-89"], "fix": "upgrade to …", "also": [ … ] } ]
}
```

Severities are normalised onto one scale (`rank` 0 = CRITICAL/BLOCKER … 4 = INFO).
`id` is stable while the code around a finding does not move, so it can key triage
state across runs.

## Caveats

- Scan what you shipped. A mutable image tag or a dirty working copy describes
  something else.
- `trivy config` exits 0 with findings and `snyk` exits 1 with findings; both are
  handled. Any other exit is reported as not scanned and its partial output removed.
- On Linux, SonarQube needs `vm.max_map_count >= 524288` on the host.
- The throwaway SonarQube uses its first-boot `admin` login to mint a token. It binds
  to `127.0.0.1` only and is destroyed at the end of the run.

## Development

```bash
python3 -m unittest discover -s tests -v
```

## License

[MIT](LICENSE)
