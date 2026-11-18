#!/usr/bin/env python3
"""Tag the version in src/qsd/__init__.py as vX.Y.Z when that tag does not exist yet.

    auto_tag.py            create and push the annotated tag (CI: after a push to main passes)
    auto_tag.py --check    validate only, and say what would happen (CI: on pull requests)

It never moves or overwrites a tag, and it refuses (exit 1) instead of guessing:
a version that is not X.Y.Z, a version lower than the newest existing tag, or a new
version with no `## [X.Y.Z]` section in CHANGELOG.md. A version that is already tagged
is a normal no-op, since most merges do not change the version.

It also makes sure the GitHub Release for that version exists (notes = the same CHANGELOG
section), so a tag never sits without one. A Release that already exists is left as it is;
a tagged version whose Release is missing gets just the Release. Needs GITHUB_TOKEN and `gh`.

The tag message is the CHANGELOG section, so `git show vX.Y.Z` is the release note.
Standard library only; nothing from the environment is interpreted as a command.
"""

import base64
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SEMVER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
TAG_REF = re.compile(r"^refs/tags/v(\d+\.\d+\.\d+)(\^\{\})?$")
BOT = ["-c", "user.name=github-actions[bot]",
       "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com"]


class Refuse(Exception):
    """The release is not in a state that can be tagged; the message says why."""


def read_version(init_text):
    m = re.search(r'^__version__\s*=\s*"([^"]*)"\s*$', init_text, re.MULTILINE)
    if not m:
        raise Refuse("no `__version__ = \"X.Y.Z\"` line in src/qsd/__init__.py")
    if not SEMVER.match(m.group(1)):
        raise Refuse(f"version {m.group(1)!r} is not X.Y.Z (digits only, no suffix)")
    return m.group(1)


def changelog_section(text, version):
    """The body of `## [version]` up to the next `## [`; empty or absent is a refusal."""
    m = re.search(rf"^## \[{re.escape(version)}\][^\n]*\n(.*?)(?=^## \[|\Z)", text,
                  re.MULTILINE | re.DOTALL)
    body = m.group(1).strip() if m else ""
    if not body:
        raise Refuse(f"CHANGELOG.md has no non-empty `## [{version}]` section; "
                     f"write the release notes before releasing")
    return body


def parse_tags(ls_remote):
    """{ '0.3.0': commit } from `git ls-remote --tags`; annotated tags use the peeled commit."""
    tags, peeled = {}, {}
    for line in ls_remote.splitlines():
        sha, _, ref = line.partition("\t")
        m = TAG_REF.match(ref.strip())
        if m:
            (peeled if m.group(2) else tags)[m.group(1)] = sha
    return {v: peeled.get(v, sha) for v, sha in tags.items()}


def key(version):
    return tuple(int(p) for p in version.split("."))


def decide(version, tags):
    """('skip', why) when already tagged, ('tag', '') when it should be; Refuse on a downgrade."""
    if version in tags:
        return "skip", f"v{version} already exists at {tags[version][:7]}; nothing to do"
    newest = max(tags, key=key, default=None)
    if newest is not None and key(version) < key(newest):
        raise Refuse(f"version {version} is lower than the newest tag v{newest}; "
                     f"bump `__version__` instead of tagging an older number")
    return "tag", ""


def auth_env(token):
    """Environment that lets one `git push` authenticate to github.com, or None without a token.

    Passed through git's env-based config, as actions/checkout does, so the token never
    appears in a command line, a file or the repository's .git/config.
    """
    if not token:
        return None
    basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
    return {**os.environ, "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}"}


def git(*args, check=True, env=None):
    return subprocess.run(["git", *args], cwd=ROOT, text=True, capture_output=True,
                          check=check, env=env)


def remote_tags():
    return parse_tags(git("ls-remote", "--tags", "origin", "refs/tags/v*").stdout)


def gh(*args, token, stdin=None):
    """Run the GitHub CLI with the token in its environment (never on the command line)."""
    env = {**os.environ, "GH_TOKEN": token}
    repo = os.environ.get("GITHUB_REPOSITORY")
    extra = ["--repo", repo] if repo else []
    try:
        return subprocess.run(["gh", *args, *extra], cwd=ROOT, text=True, capture_output=True,
                              input=stdin, env=env)
    except FileNotFoundError:
        raise Refuse("the GitHub CLI `gh` is not installed")


def release_exists(tag, token):
    found = gh("release", "view", tag, token=token)
    if found.returncode == 0:
        return True
    if "release not found" in found.stderr.lower():
        return False
    raise Refuse(f"could not look up the {tag} Release: {found.stderr.strip()[:300]}")


def ensure_release(tag, notes, token):
    """Create the Release for an existing tag if there is none; never edit one that exists."""
    if release_exists(tag, token):
        say(f"the {tag} Release already exists; left as it is")
        return
    made = gh("release", "create", tag, "--verify-tag", "--latest", "--title", tag,
              "--notes-file", "-", token=token, stdin=notes + "\n")
    if made.returncode != 0:
        if release_exists(tag, token):
            say(f"the {tag} Release was created by another run; nothing to do")
            return
        raise Refuse(f"could not create the {tag} Release: {made.stderr.strip()[:300]}")
    say(f"created the {tag} Release")


def say(message):
    print(message)
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(message + "\n")


def run(check_only):
    version = read_version((ROOT / "src" / "qsd" / "__init__.py").read_text(encoding="utf-8"))
    tag = f"v{version}"
    action, why = decide(version, remote_tags())
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    token = os.environ.get("GITHUB_TOKEN")

    if action == "skip":
        say(why)
        try:
            section = changelog_section(changelog, version)
        except Refuse:
            return  # an old tag without notes: nothing to publish, and no reason to fail a merge
        if not check_only:
            release_step(tag, section, token)
        return

    section = changelog_section(changelog, version)
    if check_only:
        say(f"would tag {tag} and publish its GitHub Release (the merge will create both); "
            f"its notes are {len(section)} characters")
        return

    commit = os.environ.get("GITHUB_SHA") or git("rev-parse", "HEAD").stdout.strip()
    git(*BOT, "tag", "-a", tag, "-m", f"qsd {tag}\n\n{section}\n", commit)
    pushed = git("push", "origin", f"refs/tags/{tag}", check=False,
                 env=auth_env(token))
    if pushed.returncode != 0:
        # Lost a race with another run: fine if the tag is there now, an error if not.
        if version in remote_tags():
            say(f"{tag} was created by another run; nothing to do")
        else:
            raise Refuse(f"could not push {tag}: {pushed.stderr.strip()[:300]}")
    else:
        say(f"tagged {tag} at {commit[:7]}")
    release_step(tag, section, token)


def release_step(tag, section, token):
    if not token:
        say(f"no GITHUB_TOKEN; the {tag} GitHub Release was not checked")
        return
    ensure_release(tag, section, token)


def main(argv):
    if argv not in ([], ["--check"]):
        sys.exit(__doc__.split("\n\n")[0])
    try:
        run("--check" in argv)
    except Refuse as exc:
        say(f"refusing to tag: {exc}")
        sys.exit(1)


if __name__ == "__main__":
    main(sys.argv[1:])
