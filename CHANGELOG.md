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
- `track` is unique within a report. It is location and identity without the message, so it
  survives a scanner rewording a title; rows whose key collides (same rule, file and line,
  different message) are told apart by a hash of the message, and identical rows with dedup
  off get an ordinal suffix. Stability is therefore best effort for colliding rows. Gitleaks'
  commit feeds `_track` so same-line secrets in different commits stay distinct.
- Dependabot scan fetches `open,dismissed,auto_dismissed` in one call (GitHub silently
  ignores an unknown `state`, so the exact string is pinned by a test); stderr goes to
  the log and paginated output is read by the parser. `dismissed` and `auto_dismissed`
  count as `suppressed`. `fixed` alerts are **not** fetched (they are the whole history),
  so `dependabot.fixed` is 0 from `qsd scan`.
- **A source is optional only when the project's `skipped` list says so.** The runner
  writes that list for tools left out of `--tools` and for GuardDog with no `guarddog`
  list; a manifest note that merely starts with `skipped:` no longer makes a failed
  source optional (it let a hand-written digest manifest exit 0 with a green tile).
- A project with no `guarddog` list lists "GuardDog (not configured)" as optional, so a
  default `qsd scan` no longer exits 2 over a tool that was never configured.
- `id` appends the column only when the tool reported one: rows without a column keep
  the `id` they had in 0.3.0. Rows that gained a column (Sonar, Semgrep, Snyk Code,
  zizmor, Gitleaks) change **once** at this upgrade.
- SonarQube: the scanner is pinned to the local server on the command line (a checkout's
  own `sonar-project.properties` cannot set the host), `sonar.scm.disabled` and
  `sonar.scm.provider` are no longer accepted in `sonar_args`, and an analysis of zero
  lines of code (a bogus `sonar.sources`, an exclusion like `**`) is *incomplete*, not clean.
- `--strict` together with `--lenient` is an error instead of silently lenient.
- `commit_dirty` is `null` when git status is unknown, and when a manifest omits it
  (it used to default to `false`, "clean").
- GuardDog always appears in `sources` (skipped / not configured), even with no manifests;
  an unconfigured GuardDog is optional (see above).
- Malware tile counts ClamAV `Malware` **and** OSV/GuardDog `Malicious Package`.
- ClamAV container runs mark the source incomplete when `freshclam` fails, instead of
  looking clean on a stale or missing signature DB.

### Added
- `track`: stable finding key (no message) for trend diffs; `id` still
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
- Advisory dedup never merges two rows reported by the same scanner (a tool's own separate
  findings, such as Snyk filing one CVE under several ids, stay separate). This changes
  counts against 0.3.0: the test fixture goes from 20 to 21 rows. Which same-scanner row
  joins a cross-scanner group follows input order.
- `coverage` may be an absolute path (parsed only); a relative one stays confined to the
  checkout. New config keys `semgrep_mode` (`auto`, `ci`, `public`) and `semgrep_branch`;
  new settings `images` and `runners`.
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
