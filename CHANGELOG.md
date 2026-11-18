# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/).

## [0.4.0] - 2026-11-17

### Fixed
- Exact dedup now keys on column as well as line: two Sonar smells of one rule on
  the same line stay two findings. `col` is on the finding, the sighting, and the schema.
  Gitleaks now keeps `StartColumn` so same-line secrets stay distinct too.
- HTML "Security crit + high" turns green only when every *required* source is complete;
  a zero under a gap is no longer painted as clean. Incomplete runs get a banner.
- Semgrep "file only partly parsed" (`warn`) marks the source incomplete.
- `sonar_args` is an allowlist of analysis properties — `sonar.scanner.javaExePath` and
  other executable / host / token overrides are rejected.
- `track` no longer gets encounter-order suffixes; Gitleaks commit feeds `_track` so
  same-line secrets in different commits stay distinct without flipping identity.
- Dependabot scan fetches open **and** dismissed alerts; only dismissed counts as
  `suppressed`, fixed alerts are counted separately (not "waived").
- `commit_dirty` is `null` when git status is unknown (no longer claims clean).
- GuardDog always appears in `sources` (skipped / not configured), even with no manifests.
- Malware tile counts ClamAV `Malware` **and** OSV/GuardDog `Malicious Package`.
- ClamAV container runs mark the source incomplete when `freshclam` fails, instead of
  looking clean on a stale or missing signature DB.

### Added
- `track`: stable finding key (no message) for Backstage / trend diffs; `id` still
  includes the message and remains the display hash.
- `sources.*.suppressed`: waived Snyk suppressions, zizmor `ignored`, and non-open
  Dependabot alerts are counted instead of vanishing.
- `sources.*.optional`: tools left out of `--tools` still appear in `sources` so a
  screenshot cannot hide the rest of the coverage contract; they do not fail `--strict`.
- Project `sec_unrated`, `malware`, `commit_dirty`; settings `tools`, `images`, `runners`.
- Schema `1.1`, shipped inside the wheel (`qsd/data/report.schema.json`).

### Changed
- **`--strict` is the default.** Use `--lenient` / `--no-strict` for partial local runs.
  Exit `2` when any required source is incomplete.
- Package version `0.4.0`. Install pin: `@v0.4.0`.

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
