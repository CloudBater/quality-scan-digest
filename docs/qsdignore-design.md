# `.qsdignore`: design

Status: **built in v0.5.0** (report schema 1.2). The three decisions taken while designing are
at the end. This page is the rationale; the README is the reference.

## Why

A real scan of two production repositories returned hundreds of high-severity findings, and most were
not actionable: a scanner matching the word "Update" in an audit-log sentence as SQL, Kubernetes
hardening notes, DDL built from constants. Re-reading them every release hides the few that matter.
Two other things people mean by "ignore" also need a home: a real finding that **already has a
ticket**, and a risk someone has **accepted**.

qsd's first promise still holds: **a finding never silently disappears.** A waived finding stays in
the report, marked with why, and is left out of the headline counts. It is never deleted.

## Two statuses

| Status | Meaning | Counted in the headline? |
|---|---|---|
| `ignore` | A false positive or an accepted risk. Has a reason and an expiry. | No (listed under "Waived") |
| `track` | A real finding that already has a ticket. | **Yes**, labelled with the ticket |

With both, the report can show one tile that answers the question that matters: **HIGH or above with
neither a waiver nor a ticket** ("untracked").

## Where the file lives (security)

The file is passed **explicitly** in the qsd config (`ignore_file`) and is **never read automatically
from the scanned checkout.** Otherwise a pull request could add a waiver for its own finding. This is
the same reason qsd refuses security-relevant keys in a checkout's own `sonar-project.properties`.

For a release scan, keep the file in the repository that owns the scan configuration and is reviewed
by whoever owns security, not in the code under test.

## Format

One waiver per line, `key=value` pairs, `#` starts a comment. Parsed with the standard library's
`shlex`, so quoting works and there is no new dependency. (TOML is not in Python 3.10's standard
library, and JSON has no comments.)

```
# Semgrep matches the word "Update" in audit-log sentences; none of it is SQL.
ignore src=Semgrep ref="python.django.security.injection.tainted-sql-string.*" loc="app/audit/descriptions.py" expect=16 until=2027-05-01 reason="audit-log text, not SQL"

# A real finding with a ticket: still counted, labelled.
track src=OSV-Scanner ref=GHSA-xxxx-xxxx-xxxx loc="lock-file: pkg@1.2.3" ticket=PROJ-123 until=2027-02-01 reason="upgrade scheduled"
```

| Key | Required | Meaning |
|---|---|---|
| verb (`ignore` / `track`) | yes | The status |
| `reason` | yes | Why |
| `until` | yes | Expiry date, at most 12 months ahead. After it the finding counts again. |
| `ticket` | for HIGH and above, and always for `track` | The tracking reference |
| `src` | one of the matchers | The scanner, e.g. `Semgrep` |
| `ref` | one of the matchers | The rule or advisory id; `*` wildcards allowed inside the value |
| `loc` | optional | A path or `package@version`; glob |
| `project` | optional | Restrict to one project |
| `track` | alternative | The exact `track` key of one finding (v0.4.0), the precise handle |
| `expect` | recommended | The number of findings the line is expected to match |

No line numbers: they drift. A line that matches nothing at all (no `src`, `ref`, `loc` or `track`) is
an error.

## Guardrails

- **`expect=N`**: if a line starts matching more than N findings, qsd fails. This stops "ignore this
  rule" from quietly hiding new, real findings later.
- **Expiry is mandatory.** An expired waiver stops applying and the finding returns.
- **Stale lines are reported**, not silently kept: a line that matched nothing this run is listed.
- **Malware cannot be waived by pattern.** Secrets only by exact fingerprint. The highest-risk
  categories need a deliberate, individual decision.
- **HIGH and above need a `ticket`.**
- The waiver file's **SHA-256** is recorded in the report, so the numbers are traceable to the exact
  waiver set that produced them.

## Output (schema 1.2)

- Each finding gets `waiver`: `null`, or `{status, reason, ticket, until, line}`.
- `sec_crit_high` and the other headline counts **exclude** `ignore` findings and **include**
  `track` ones. New per-project counts: `waived`, `tracked`, `untracked_crit_high`.
- A `waivers` block: per line, how many findings it matched; plus `stale` and `expired` lists and the
  file's SHA-256.
- HTML: a collapsed "Waived (N)" section with reasons, a "Tracked" tag with the ticket, and the
  untracked tile.
- It does not replace the tools' own suppressions (Snyk, Dependabot dismissals, zizmor `ignored`,
  SonarQube accepted). Those are already counted under `sources.*.suppressed`, and remain the right
  place when a tool supports it. `.qsdignore` is the one layer across all tools.

## Strict mode

A waiver never makes a source *incomplete*. An **expired** waiver, or an `expect` that is exceeded, is
an error in strict mode (exit 2), because the report would otherwise understate the findings.

## Decisions

1. **Both `ignore` and `track` in v1.** They share one data model, and the untracked tile is the
   most valuable part.
2. **A waived finding stays in the findings array** with `waiver` set. Nothing is moved or deleted.
3. **A consumer with a fixed payload shape** drops `ignore` rows (so its numbers match the headline)
   and keeps `track` rows (they are real and still counted). Each adapter does this itself; the
   report keeps everything.

## Test plan

Each rule gets a test that fails if the rule is removed: required fields, expiry cap and expiry
behaviour, `expect` over and under, stale lines, no-pattern lines, malware and secret restrictions,
the file never read from the checkout, quoting, comments, matching by `track`, headline counts with
each status, the report block, and the SHA.

## Rollout

1. qsd v0.4.1 (done), then update consumers' pins.
2. Build this as v0.5.0 on a branch; independent reviews as for 0.4.0.
3. Start with an empty file in the consuming repository; add lines only with a reason and an expiry.
