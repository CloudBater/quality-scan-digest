# Contributing

Issues and pull requests are welcome.

## Ground rules

- **Standard library only.** The runtime has no third-party dependencies; keep it that way.
- **Never report a missing scan as clean.** A source that did not run, failed, or was
  only partly read must show up as not collected or incomplete. This is the tool's main
  promise; changes that weaken it will not be merged.
- **Dedup must not hide findings.** A missed merge only over-counts; a wrong merge hides
  a vulnerability. New merge rules need tests for the cases they must *not* merge.
- **Every bug fix comes with a test.** Fixtures are synthetic; never commit real scanner
  output from a real project.

## Development

```bash
python3 -m unittest discover -s tests -v
pip install -e .   # optional: puts `qsd` on PATH
```

Python 3.10+. Keep inline comments to one line that says *why*.

## Adding a scanner

1. Add `src/qsd/parsers/<tool>.py` that returns `(rows, status)` and rejects anything
   that is not recognisably that tool's output.
2. Wire it into `report.collect_project` and, if `qsd scan` should run it, `runner.py`
   (handle the tool's exit codes explicitly).
3. Add fixtures and tests, update the schema `src` enum, the README and the CHANGELOG.

## Commits and releases

Small, focused commits with a clear subject line.

**Releasing is merging a version bump.** The version lives in `src/qsd/__init__.py`. To
release: change `__version__` to the new `X.Y.Z`, add a `## [X.Y.Z]` section to
`CHANGELOG.md`, and merge to `main`. Once the tests pass on `main`, CI
(`.github/workflows/ci.yml`, `.github/scripts/auto_tag.py`) creates the annotated tag
`vX.Y.Z` on that commit, with the changelog section as its message, and publishes the
GitHub Release `vX.Y.Z` with the same text. Most merges do not change the version, and then
nothing is tagged.

- A pull request shows what its merge will do (`tag-check`): tag, nothing to do, or refuse.
- It refuses, and tags nothing, when the version is not plain `X.Y.Z`, is lower than the
  newest tag, or has no non-empty changelog section.
- It never moves or overwrites a tag, and never edits a Release that exists. A tagged version
  whose Release is missing gets just the Release on the next merge. To fix a bad release, bump
  to the next version.
- Tags created this way are annotated but not signed (CI has no signing key).
