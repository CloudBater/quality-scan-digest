# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.3.0] - 2026-11-17

### Added
- OSV-Scanner: lockfiles against the OSV database, one row per advisory group;
  OpenSSF `MAL-` advisories reported as CRITICAL malicious packages. Joins the
  advisory dedup with Snyk, Semgrep, Trivy and Dependabot. `osv_offline` option.
- zizmor: offline security audit of GitHub Actions workflows and Dependabot config;
  findings marked `ignored` are skipped.
- Both run natively or from a container pinned by digest (osv-scanner v2.7.1,
  zizmor 1.32.0). Absolute paths in their output are made relative to the project.

## [0.2.0] - 2026-11-17

### Added
- Gitleaks as the eighth source: full git history (or files outside a repository),
  native CLI or a pinned v8.24.3 container, always `--redact`. Reports keep only rule,
  file, line and commit; never the secret or commit author, email and message.
- Traditional Chinese README (`README.zh-TW.md`).

## [0.1.0] - 2026-11-17

First release.

- `qsd scan` runs SonarQube (throwaway container), Snyk (Open Source, Code, IaC,
  Container), Trivy (`config`), Semgrep, Dependabot, ClamAV and GuardDog.
- `qsd digest` merges existing scanner outputs listed in a manifest.
- Deduplication: `exact` and `advisory` passes by default; `sast` is opt-in.
- JSON payload with a published schema (`schema/report.schema.json`) and a
  self-contained HTML report.
- Every source is reported as collected, incomplete, or not collected with the
  reason; `--strict` fails the run unless every source is complete.
