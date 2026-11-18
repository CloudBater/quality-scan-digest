"""The release-tagging script (.github/scripts/auto_tag.py): rules, and the real git behaviour."""

import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "..", ".github", "scripts", "auto_tag.py")

spec = importlib.util.spec_from_file_location("auto_tag", SCRIPT)
auto_tag = importlib.util.module_from_spec(spec)
spec.loader.exec_module(auto_tag)

ID = ["-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
      "-c", "tag.gpgsign=false"]


class Rules(unittest.TestCase):
    def test_version_must_be_plain_x_y_z(self):
        self.assertEqual(auto_tag.read_version('x = 1\n__version__ = "0.4.0"\n'), "0.4.0")
        for bad in ('__version__ = "0.4.0rc1"', '__version__ = "1.2"', '__version__ = ""',
                    "no version here", '__version__ = "v0.4.0"'):
            with self.assertRaises(auto_tag.Refuse, msg=bad):
                auto_tag.read_version(bad)

    def test_changelog_section_is_exactly_that_versions_body(self):
        text = ("# Changelog\n\n## [Unreleased]\n- later\n\n## [0.4.0] - 2026-11-17\n### Fixed\n"
                "- one\n- two\n\n## [0.3.0]\n- old\n")
        self.assertEqual(auto_tag.changelog_section(text, "0.4.0"), "### Fixed\n- one\n- two")
        self.assertEqual(auto_tag.changelog_section(text, "0.3.0"), "- old")

    def test_a_missing_empty_or_lookalike_section_is_refused(self):
        for text in ("## [0.3.0]\n- old\n", "## [0.4.0]\n\n## [0.3.0]\n- old\n",
                     "## [0.4.0-rc1]\n- notes\n", "## [10.4.0]\n- notes\n"):
            with self.assertRaises(auto_tag.Refuse, msg=text):
                auto_tag.changelog_section(text, "0.4.0")

    def test_only_x_y_z_tags_count_and_annotated_tags_use_the_commit(self):
        out = ("aaa\trefs/tags/v0.1.0\nbbb\trefs/tags/v0.2.0\nccc\trefs/tags/v0.2.0^{}\n"
               "ddd\trefs/tags/v1.0\neee\trefs/tags/v1.0.0-rc1\nfff\trefs/tags/nightly\n")
        self.assertEqual(auto_tag.parse_tags(out), {"0.1.0": "aaa", "0.2.0": "ccc"})

    def test_the_token_reaches_git_only_through_the_environment(self):
        self.assertIsNone(auto_tag.auth_env(""))
        self.assertIsNone(auto_tag.auth_env(None))
        env = auto_tag.auth_env("s3cret")
        self.assertEqual(env["GIT_CONFIG_COUNT"], "1")
        self.assertEqual(env["GIT_CONFIG_KEY_0"], "http.https://github.com/.extraheader")
        import base64
        self.assertEqual(env["GIT_CONFIG_VALUE_0"], "AUTHORIZATION: basic "
                         + base64.b64encode(b"x-access-token:s3cret").decode())

    def test_decide(self):
        tags = {"0.3.0": "abcdef1234", "0.10.0": "9999999"}
        self.assertEqual(auto_tag.decide("0.3.0", tags)[0], "skip")
        self.assertEqual(auto_tag.decide("0.11.0", tags), ("tag", ""))   # numeric, not text, order
        self.assertEqual(auto_tag.decide("0.1.0", {}), ("tag", ""))
        with self.assertRaises(auto_tag.Refuse):
            auto_tag.decide("0.9.0", tags)  # 0.9.0 < 0.10.0


class Repo:
    """A bare origin and a working clone with the files the script reads."""

    def __init__(self, version="0.4.0", changelog=None, tags=()):
        self.tmp = tempfile.mkdtemp()
        self.origin = os.path.join(self.tmp, "origin.git")
        self.work = os.path.join(self.tmp, "work")
        self.git("init", "-q", "--bare", "-b", "main", self.origin, cwd=self.tmp)
        self.git("clone", "-q", self.origin, self.work, cwd=self.tmp)
        os.makedirs(os.path.join(self.work, "src", "qsd"))
        os.makedirs(os.path.join(self.work, ".github", "scripts"))
        shutil.copy(SCRIPT, os.path.join(self.work, ".github", "scripts", "auto_tag.py"))
        self.write_version(version)
        with open(os.path.join(self.work, "CHANGELOG.md"), "w") as fh:
            fh.write(changelog if changelog is not None
                     else f"# Changelog\n\n## [{version}]\n- the notes\n- more notes\n")
        self.commit("first")
        for t in tags:
            self.git("tag", "-a", t, "-m", t)
            self.git("push", "-q", "origin", f"refs/tags/{t}")

    def git(self, *args, cwd=None):
        return subprocess.run(["git", *ID, *args], cwd=cwd or self.work, text=True,
                              capture_output=True, check=True).stdout.strip()

    def write_version(self, version):
        with open(os.path.join(self.work, "src", "qsd", "__init__.py"), "w") as fh:
            fh.write(f'__version__ = "{version}"\n')

    def commit(self, msg):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", msg)
        self.git("push", "-q", "origin", "HEAD:main")
        return self.git("rev-parse", "HEAD")

    def run(self, *args, **env):
        e = dict(os.environ, GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null", **env)
        e.pop("GITHUB_SHA", None) if "GITHUB_SHA" not in env else None
        return subprocess.run([sys.executable, os.path.join(self.work, ".github", "scripts",
                                                            "auto_tag.py"), *args],
                              cwd=self.work, env=e, text=True, capture_output=True)

    def remote_tags(self):
        return self.git("tag", "-l", cwd=self.origin).split()

    def cleanup(self):
        shutil.rmtree(self.tmp, ignore_errors=True)


class WithGit(unittest.TestCase):
    def repo(self, **kw):
        r = Repo(**kw)
        self.addCleanup(r.cleanup)
        return r

    def test_it_creates_an_annotated_tag_whose_message_is_the_changelog_section(self):
        r = self.repo(tags=("v0.3.0",))
        res = r.run()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("v0.4.0", r.remote_tags())
        self.assertEqual(r.git("cat-file", "-t", "v0.4.0", cwd=r.origin), "tag")
        body = r.git("tag", "-l", "-n99", "v0.4.0", cwd=r.origin)
        self.assertIn("the notes", body)
        self.assertIn("more notes", body)
        self.assertEqual(r.git("rev-parse", "v0.4.0^{commit}", cwd=r.origin),
                         r.git("rev-parse", "HEAD"))
        self.assertIn("github-actions[bot]", r.git("for-each-ref", "--format=%(taggername)",
                                                   "refs/tags/v0.4.0", cwd=r.origin))

    def test_a_second_run_is_a_no_op_and_never_moves_the_tag(self):
        r = self.repo()
        r.run()
        first = r.git("rev-parse", "v0.4.0", cwd=r.origin)
        with open(os.path.join(r.work, "unrelated.txt"), "w") as fh:
            fh.write("x")
        r.commit("unrelated change")  # main moves on; the version does not
        res = r.run()
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("already exists", res.stdout)
        self.assertEqual(r.git("rev-parse", "v0.4.0", cwd=r.origin), first)

    def test_it_tags_the_commit_that_was_tested_not_whatever_main_became(self):
        r = self.repo()
        tested = r.git("rev-parse", "HEAD")
        r.write_version("0.4.0")
        with open(os.path.join(r.work, "x.txt"), "w") as fh:
            fh.write("later")
        r.commit("a later commit")
        res = r.run(GITHUB_SHA=tested)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertEqual(r.git("rev-parse", "v0.4.0^{commit}", cwd=r.origin), tested)

    def test_check_mode_creates_nothing(self):
        r = self.repo()
        res = r.run("--check")
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)
        self.assertIn("would tag v0.4.0", res.stdout)
        self.assertEqual(r.remote_tags(), [])

    def test_refusals_exit_1_and_create_nothing(self):
        cases = {
            "downgrade": dict(version="0.4.0", tags=("v0.10.0",)),
            "no changelog section": dict(changelog="# Changelog\n\n## [0.3.0]\n- old\n"),
            "bad version": dict(version="0.4.0rc1"),
        }
        for name, kw in cases.items():
            r = self.repo(**kw)
            before = r.remote_tags()
            for args in ((), ("--check",)):
                res = r.run(*args)
                self.assertEqual(res.returncode, 1, f"{name} {args}: {res.stdout}{res.stderr}")
                self.assertIn("refusing to tag", res.stdout)
            self.assertEqual(r.remote_tags(), before, name)

    def test_an_already_tagged_version_needs_no_changelog_section(self):
        # Most merges do not change the version; they must not fail for lack of a section.
        r = self.repo(changelog="# Changelog\n", tags=("v0.4.0",))
        for args in ((), ("--check",)):
            self.assertEqual(r.run(*args).returncode, 0)

    def test_unknown_arguments_are_rejected(self):
        r = self.repo()
        self.assertNotEqual(r.run("--force").returncode, 0)
        self.assertEqual(r.remote_tags(), [])


if __name__ == "__main__":
    unittest.main()
