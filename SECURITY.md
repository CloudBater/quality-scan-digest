# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub:
**Security → Report a vulnerability** on this repository
([private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)).
Do not open a public issue for a security problem.

Include the `qsd --version`, the command you ran, and a minimal reproduction.

**Never attach real scanner output, reports, logs or manifests.** They contain your
source paths, code snippets and findings about your own systems. Reduce the problem to
synthetic input like the files in `tests/fixtures/`.

We aim to acknowledge reports within 7 days. There is no bug bounty.

## Supported versions

Only the latest release receives fixes.

## Scope

In scope: this tool's own code — for example command or path injection from a config
or manifest, script injection into the HTML report, leaking a token, or reporting a
scan as clean when it did not run.

Out of scope: vulnerabilities in SonarQube, Snyk, Trivy, Semgrep, GitHub, ClamAV or
GuardDog themselves; report those to their maintainers.
