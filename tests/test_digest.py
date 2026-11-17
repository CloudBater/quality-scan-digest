import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
FIX = os.path.join(HERE, "fixtures")
sys.path.insert(0, os.path.join(HERE, "..", "src"))

from qsd.cli import _resolve  # noqa: E402
from qsd.dedup import dedup  # noqa: E402
from qsd.html_report import render  # noqa: E402
from qsd.model import finding  # noqa: E402
from qsd.parsers import dependabot, semgrep, snyk, trivy  # noqa: E402
from qsd.report import build_payload  # noqa: E402


def fx(name):
    return os.path.join(FIX, name)


def load_manifest():
    with open(fx("manifest.json")) as fh:
        m = json.load(fh)
    _resolve(m, FIX)
    return m


class Parsers(unittest.TestCase):
    def test_snyk_collapses_repeated_paths(self):
        rows, deps, note = snyk.load(fx("snyk-oss.json"), "Open Source", "API")
        self.assertEqual((len(rows), deps, note), (2, 42, ""))
        self.assertEqual(rows[0]["ids"], ["CVE-2099-0001"])

    def test_snyk_code_sarif_severity_and_cwe(self):
        rows, _, _ = snyk.load(fx("snyk-code.json"), "Code", "API")
        self.assertEqual((rows[0]["sev"], rows[0]["cwe"]), ("HIGH", ["CWE-89"]))

    def test_semgrep_kinds(self):
        rows, _ = semgrep.load(fx("semgrep.json"), "API")
        self.assertEqual([r["kind"] for r in rows],
                         ["Vulnerability", "Dependency", "Code Smell", "Code Smell"])
        self.assertEqual(rows[0]["cwe"], ["CWE-89"])

    def test_dependabot_concatenated_pages_and_manifest_dupes(self):
        rows, counts, note = dependabot.load(fx("dependabot.json"), "API")
        self.assertEqual(note, "")
        self.assertEqual((counts["total"], counts["unique"]), (3, 2))

    def test_trivy_dockerfile_rule(self):
        rows, _ = trivy.load(fx("trivy-config.json"), "API")
        self.assertEqual((rows[0]["ref"], rows[0]["line"]), ("DS-0031", 7))

    def test_unreadable_file_is_a_note_not_a_crash(self):
        rows, _, note = snyk.load(fx("does-not-exist.json"), "Code", "API")
        self.assertEqual(rows, [])
        self.assertIn("unreadable", note)


class Dedup(unittest.TestCase):
    def row(self, **kw):
        base = dict(proj="A", src="Snyk", kind="Dependency", sev="HIGH", msg="m")
        base.update(kw)
        return finding(**base)

    def test_same_cve_different_package_is_not_merged(self):
        rows, stats = dedup([self.row(ids=["CVE-1"], package="a"),
                             self.row(src="Dependabot", ids=["CVE-1"], package="b")])
        self.assertEqual(stats["advisory"], 0)

    def test_unknown_package_does_not_bridge_two_packages(self):
        rows, stats = dedup([self.row(ids=["CVE-1"], package="a"),
                             self.row(src="Trivy", ids=["CVE-1"], package="b"),
                             self.row(src="Semgrep", ids=["CVE-1"])])
        self.assertEqual(stats["output"], 3)

    def test_projects_never_merge(self):
        rows, stats = dedup([self.row(ids=["CVE-1"], package="a"),
                             self.row(proj="B", src="Dependabot", ids=["CVE-1"], package="a")])
        self.assertEqual(stats["output"], 2)

    def test_package_names_normalise(self):
        rows, _ = dedup([self.row(ids=["CVE-1"], package="Foo_Bar"),
                         self.row(src="Dependabot", ids=["cve-1"], package="foo-bar")])
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["by"], ["Snyk", "Dependabot"])

    def test_sast_needs_shared_cwe(self):
        a = self.row(kind="Code", loc="x.py", line=3, cwe=["CWE-79"])
        b = self.row(src="Semgrep", kind="Vulnerability", loc="./x.py", line=3, cwe=["CWE-89"])
        self.assertEqual(len(dedup([a, b])[0]), 2)


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.p = build_payload(load_manifest())

    def test_counts(self):
        self.assertEqual(self.p["dedup"], {"input": 14, "exact": 1, "advisory": 2,
                                           "sast": 1, "output": 10})

    def test_three_scanners_one_row_most_severe_wins(self):
        dj = [r for r in self.p["findings"] if "CVE-2099-0001" in r["ids"]]
        self.assertEqual(len(dj), 1)
        self.assertEqual(dj[0]["by"], ["Snyk", "Semgrep", "Dependabot"])
        self.assertEqual(dj[0]["sev"], "CRITICAL")
        self.assertEqual(len(dj[0]["also"]), 2)

    def test_missing_source_is_reported_not_dropped(self):
        s = self.p["sources"]
        self.assertFalse(s["API: Snyk Container"]["collected"])
        self.assertEqual(sum(v["collected"] for v in s.values()), 8)

    def test_backward_compatible_shape(self):
        for k in ("title", "version", "generated_from", "sources", "findings"):
            self.assertIn(k, self.p)
        for k in ("proj", "src", "kind", "sev", "msg", "loc", "line", "ref", "fix", "rank", "by"):
            self.assertIn(k, self.p["findings"][0])
        self.assertNotIn("_package", self.p["findings"][0])
        s = self.p["generated_from"][0]
        self.assertEqual((s["project"], s["coverage"]["pct"], s["sonar"]["ncloc"]),
                         ("API", 80.0, "1000"))

    def test_ids_are_unique_and_rows_sorted(self):
        ids = [r["id"] for r in self.p["findings"]]
        self.assertEqual(len(ids), len(set(ids)))
        ranks = [r["rank"] for r in self.p["findings"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_html_escapes_script_close(self):
        self.p["findings"][0]["msg"] = "</script><img src=x>"
        out = render(self.p)
        self.assertNotIn("</script><img", out)

    def test_no_dedup(self):
        p = build_payload(load_manifest(), passes=())
        self.assertEqual(len(p["findings"]), 14)


class Cli(unittest.TestCase):
    def test_digest_cli(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
            subprocess.run([sys.executable, "-m", "qsd", "digest", fx("manifest.json"),
                            "--json-out", out, "--html-out", os.path.join(d, "r.html"),
                            "--release", "v9"], check=True, env=env, capture_output=True)
            with open(out) as fh:
                p = json.load(fh)
            self.assertEqual((p["version"], len(p["findings"])), ("v9", 10))


if __name__ == "__main__":
    unittest.main()
