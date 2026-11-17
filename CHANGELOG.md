# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

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
