"""Gitleaks: `gitleaks git|dir --redact --report-format json`.

Only the rule, file, line, column and commit are kept. The secret and match are
never copied (even from an unredacted report), and neither are the commit author,
email or message: a findings report should not become a new place secrets or
personal data live.
"""

from ..model import finding
from . import failed, read_json, status, unreadable


def load(path, label, project_id=None):
    try:
        doc = read_json(path)
    except (OSError, ValueError) as exc:
        return unreadable(path, exc)
    if not isinstance(doc, list) or not all(isinstance(d, dict) and "RuleID" in d for d in doc):
        return failed("not recognisable Gitleaks JSON report")

    rows = []
    for leak in doc:
        commit = (leak.get("Commit") or "")[:12]
        rows.append(finding(
            project_id=project_id, proj=label, src="Gitleaks", kind="Secret",
            sev="HIGH",
            msg=(leak.get("Description") or leak["RuleID"])
                + (f" (commit {commit})" if commit else " (working tree)"),
            loc=leak.get("File", ""), line=leak.get("StartLine"),
            col=leak.get("StartColumn"),
            # Commit (not free-text message) keeps track keys distinct across history.
            track=commit,
            ref=leak["RuleID"],
            fix="revoke and rotate the secret; removing it from history alone is not enough",
        ))
    return rows, status()
