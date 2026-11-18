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
from qsd.parsers import (clamav, dependabot, gitleaks, guarddog, osv, semgrep, snyk,  # noqa: E402
                         sonarqube, trivy, zizmor)
from qsd.report import ManifestError, build_payload  # noqa: E402


def fx(name):
    return os.path.join(FIX, name)


def load_manifest():
    with open(fx("manifest.json")) as fh:
        m = json.load(fh)
    _resolve(m, FIX)
    return m


def tmpjson(doc):
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as fh:
        fh.write(doc if isinstance(doc, str) else json.dumps(doc))
    return path


def row(**kw):
    base = dict(proj="A", src="Snyk", kind="Dependency", sev="HIGH", msg="m")
    base.update(kw)
    return finding(**base)


class Parsers(unittest.TestCase):
    def test_snyk_collapses_paths_but_keeps_versions(self):
        rows, st = snyk.load(fx("snyk-oss.json"), "Open Source", "API")
        self.assertEqual((len(rows), st["deps"], st["note"]), (2, 42, ""))
        v = {"id": "S-1", "packageName": "lodash", "severity": "high", "identifiers": {}}
        rows, _ = snyk.load(tmpjson({"vulnerabilities": [dict(v, version="1"), dict(v, version="2"),
                                                         dict(v, version="1")]}), "Open Source", "A")
        self.assertEqual(sorted(r["loc"] for r in rows), ["lodash@1", "lodash@2"])

    def test_snyk_error_file_is_not_a_clean_scan(self):
        for doc in ({"ok": False, "error": "auth failed"}, {}, {"something": 1}):
            rows, st = snyk.load(tmpjson(doc), "Code", "A")
            self.assertFalse(st["ok"], doc)

    def test_snyk_container_applications_and_suppressions(self):
        v = {"id": "S-2", "packageName": "flask", "version": "1", "severity": "high",
             "identifiers": {}}
        rows, _ = snyk.load(tmpjson({"vulnerabilities": [], "applications": [
            {"vulnerabilities": [v], "targetFile": "/app/poetry.lock"}]}), "Container", "A")
        self.assertEqual(len(rows), 1)
        sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
            {"ruleId": "r", "message": {"text": "x"}, "suppressions": [{"kind": "external"}]}]}]}
        self.assertEqual(snyk.load(tmpjson(sarif), "Code", "A")[0], [])

    def test_snyk_code_is_security_with_cwe(self):
        rows, _ = snyk.load(fx("snyk-code.json"), "Code", "API")
        self.assertEqual((rows[0]["sev"], rows[0]["cwe"], rows[0]["security"]),
                         ("HIGH", ["CWE-89"], True))

    def test_negative_line_is_absent(self):
        self.assertEqual(row(line=-1)["line"], "")

    def test_semgrep_errors_mark_incomplete_even_with_results(self):
        rows, st = semgrep.load(tmpjson({"results": [{"check_id": "x", "path": "a.py",
                                                       "extra": {"severity": "INFO"}}],
                                         "errors": [{"message": "parse"}]}), "A")
        self.assertTrue(st["ok"])
        self.assertIn("incomplete", st["note"])
        self.assertFalse(semgrep.load(tmpjson({"error": "x"}), "A")[1]["ok"])
        # Partly parsed files: by default the source stays complete (a normal repo has dozens,
        # and strict would fail every run) but it is marked as a PARTIAL SCAN, never silent.
        warn = tmpjson({"results": [], "errors": [{"level": "warn"}]})
        _, st = semgrep.load(warn, "A")
        self.assertTrue(st["complete"])
        self.assertEqual(st["partial"], 1)
        self.assertIn("PARTIAL SCAN: 1 file(s) only partly parsed", st["note"])
        self.assertIn("did not fully scan", st["note"])
        # Opting in turns it into a gap.
        _, st = semgrep.load(warn, "A", partial_is_gap=True)
        self.assertEqual((st["complete"], st["note"], st["partial"]),
                         (False, "incomplete: 1 file(s) only partly parsed", 1))
        # A hard error is a gap either way.
        hard = tmpjson({"results": [], "errors": [{"level": "error"}, {"level": "warn"}]})
        for gap in (False, True):
            self.assertFalse(semgrep.load(hard, "A", partial_is_gap=gap)[1]["complete"])

    def test_semgrep_partial_parse_setting_reaches_the_report_and_the_manifest(self):
        from qsd import runner
        f = tmpjson({"results": [], "errors": [{"level": "warn"}]})
        # Omitted -> note-only: complete, but marked partial. Opting in makes it a gap.
        src = build_payload({"projects": [{"name": "a", "semgrep": f}]})["sources"]["a: Semgrep"]
        self.assertTrue(src["complete"])
        self.assertEqual(src["partial"], 1)
        for flag in (False, True):
            src = build_payload({"projects": [{"name": "a", "semgrep": f,
                                               "semgrep_partial_is_gap": flag}]})["sources"]["a: Semgrep"]
            self.assertEqual(src["complete"], not flag)
        with tempfile.TemporaryDirectory() as d:
            m, _ = runner.scan({"projects": [{"name": "a", "path": "."}]}, d, os.path.join(d, "o"),
                               tools=())
            self.assertIs(m["projects"][0]["semgrep_partial_is_gap"], False)
            self.assertIs(m["settings"]["semgrep_partial_is_gap"], False)
            m2, _ = runner.scan({"projects": [{"name": "a", "path": "."}],
                                 "semgrep_partial_is_gap": True}, d, os.path.join(d, "o2"), tools=())
            self.assertIs(m2["settings"]["semgrep_partial_is_gap"], True)
            with self.assertRaises(runner.ConfigError):
                runner.validate({"projects": [{"name": "a", "path": "."}],
                                 "semgrep_partial_is_gap": "yes"}, d)

    def test_semgrep_supply_chain_counts_as_security(self):
        rows, _ = semgrep.load(fx("semgrep.json"), "API")
        self.assertEqual([r["kind"] for r in rows],
                         ["Vulnerability", "Dependency", "Code Smell", "Code Smell"])
        self.assertTrue(rows[1]["security"])

    def test_dependabot_keeps_each_manifest(self):
        rows, st = dependabot.load(fx("dependabot.json"), "API")
        self.assertEqual(st["note"], "")
        self.assertEqual((st["counts"]["total"], st["counts"]["unique"]), (3, 3))
        self.assertFalse(dependabot.load(tmpjson({"message": "Bad credentials"}), "A")[1]["ok"])

    def test_trivy_rule_and_envelope(self):
        rows, _ = trivy.load(fx("trivy-config.json"), "API")
        self.assertEqual((rows[0]["ref"], rows[0]["line"]), ("DS-0031", 7))
        self.assertFalse(trivy.load(tmpjson({"error": "x"}), "A")[1]["ok"])

    def test_sonar_truncation_and_missing_hotspots_are_incomplete(self):
        rows, st, _ = sonarqube.to_rows({"issues": {"issues": [{"type": "BUG"}], "total": 5}}, "A")
        self.assertIn("1 of 5 issues", st["note"])
        self.assertIn("no hotspots", st["note"])

    def test_sonar_token_only_to_https_or_loopback(self):
        for bad in ("http://sonar.example.com", "ftp://x", "sonar.example.com"):
            with self.assertRaises(sonarqube.SonarError):
                sonarqube.check_host(bad)
        for ok in ("https://sonar.example.com", "http://127.0.0.1:9000", "http://localhost:9000"):
            sonarqube.check_host(ok)

    def test_clamav(self):
        rows, st = clamav.load(fx("clamav.txt"), "API")
        self.assertEqual((rows[0]["loc"], rows[0]["ref"], rows[0]["sev"], rows[0]["kind"]),
                         ("sub/eicar.com", "Eicar-Test-Signature", "CRITICAL", "Malware"))

    def test_guarddog(self):
        rows, st = guarddog.load(fx("guarddog.json"), "API", ecosystem="pypi",
                                 manifest="requirements.txt")
        by = {(r["package"] if "package" in r else r["ref"]): r for r in rows}
        sev = sorted((r["ref"], r["sev"]) for r in rows)
        self.assertEqual(sev, [("capability-process-spawn", "LOW"),
                               ("threat-network-exfiltration", "HIGH"),
                               ("typosquatting", "MEDIUM")])
        self.assertFalse(guarddog.load(tmpjson({"x": 1}), "A")[1]["ok"])
        del by

    def test_gitleaks_drops_secret_and_personal_data(self):
        with open(fx("gitleaks.json")) as fh:
            doc = json.load(fh)
        # Built at runtime so no token-shaped string is committed to this repo.
        fake = "ghp_" + "FAKE" * 9
        doc[0].update(Secret=fake, Match=f"token = '{fake}'")
        rows, st = gitleaks.load(tmpjson(doc), "API")
        r = rows[0]
        self.assertEqual((r["ref"], r["loc"], r["line"], r["col"], r["kind"], r["sev"], r["security"]),
                         ("github-pat", "app/settings.py", 3, "", "Secret", "HIGH", True))
        self.assertEqual(r["_track"], "0123456789ab")
        blob = json.dumps(rows)
        for leaked in ("ghp_FAKE", "jane@example.com", "Jane Doe", "oops"):
            self.assertNotIn(leaked, blob)
        self.assertEqual(gitleaks.load(tmpjson([]), "A")[1], {"ok": True, "note": ""})
        self.assertFalse(gitleaks.load(tmpjson({"error": "x"}), "A")[1]["ok"])
        two = [dict(doc[0], StartColumn=4, Commit="aaa"),
               dict(doc[0], StartColumn=40, Commit="aaa")]
        cols, _ = gitleaks.load(tmpjson(two), "API")
        self.assertEqual(sorted(r["col"] for r in cols), [4, 40])

    def test_osv(self):
        rows, st = osv.load(fx("osv.json"), "API", root="/src")
        by = {r["ref"]: r for r in rows}
        dj = by["GHSA-xxxx-yyyy-zzzz"]
        self.assertEqual((dj["sev"], dj["loc"], dj["fix"], dj["ids"]),
                         ("CRITICAL", "poetry.lock: Django@4.2.0", "upgrade to 4.2.99",
                          ["CVE-2099-0001", "GHSA-XXXX-YYYY-ZZZZ"]))
        mal = by["MAL-2099-1"]
        self.assertEqual((mal["kind"], mal["sev"], mal["security"]),
                         ("Malicious Package", "CRITICAL", True))
        self.assertEqual(by["GHSA-npm1-npm1-npm1"]["sev"], "MEDIUM")
        self.assertFalse(osv.load(tmpjson({"error": "x"}), "A")[1]["ok"])

    def test_osv_cvss_bands(self):
        self.assertEqual([osv._band(s) for s in ("9.0", "7.5", "4", "0.1", "", None)],
                         ["CRITICAL", "HIGH", "MEDIUM", "LOW", "", ""])

    def test_zizmor(self):
        rows, st = zizmor.load(fx("zizmor.json"), "API", root="/src")
        self.assertEqual([(r["ref"], r["sev"], r["loc"], r["line"]) for r in rows],
                         [("template-injection", "HIGH", ".github/workflows/ci.yml", 12),
                          ("dependabot-cooldown", "MEDIUM", ".github/dependabot.yml", 8)])
        self.assertTrue(rows[0]["security"])
        self.assertIn("confidence high", rows[0]["msg"])
        self.assertFalse(zizmor.load(tmpjson({"error": "x"}), "A")[1]["ok"])

    def test_unreadable_file_is_a_note_not_a_crash(self):
        rows, st = snyk.load(fx("does-not-exist.json"), "Code", "API")
        self.assertEqual((rows, st["ok"]), ([], False))


class Dedup(unittest.TestCase):
    def test_same_cve_different_package_is_not_merged(self):
        _, stats = dedup([row(ids=["CVE-1"], package="a"),
                          row(src="Dependabot", ids=["CVE-1"], package="b")])
        self.assertEqual(stats["advisory"], 0)

    def test_unknown_package_never_bridges_packages(self):
        rows = [row(ids=["CVE-1"], package="aaa"), row(src="Trivy", ids=["CVE-2"], package="bbb"),
                row(src="Semgrep", ids=["CVE-1", "CVE-2"])]
        self.assertEqual(len(dedup(rows)[0]), 3)
        rows = [row(ids=["CVE-1"], package="aaa"), row(src="Semgrep", ids=["CVE-1", "GHSA-Y"]),
                row(src="Trivy", ids=["GHSA-Y"], package="bbb")]
        self.assertEqual(len(dedup(rows)[0]), 3)

    def test_a_malicious_package_report_is_never_merged_into_an_ordinary_advisory(self):
        # OSV files a malicious package under MAL-… and copies CVE/GHSA aliases into `ids`. Merged
        # under a Snyk dependency row it would be counted as one more vulnerable package.
        dep = row(ids=["CVE-1"], package="evil", ecosystem="pypi")
        mal = row(src="OSV-Scanner", kind="Malicious Package", ids=["CVE-1"], package="evil",
                  ecosystem="pypi", ref="MAL-1")
        rows, stats = dedup([dep, mal])
        self.assertEqual((len(rows), stats["advisory"]), (2, 0))
        self.assertEqual(sorted(r["kind"] for r in rows), ["Dependency", "Malicious Package"])
        # Order must not matter, and a package-less row joining by id must obey it too.
        rows, _ = dedup([mal, dep, row(src="Trivy", ids=["CVE-1"])])
        self.assertEqual(sorted(r["kind"] for r in rows if "Malicious Package" in
                                [r["kind"], *(a["kind"] for a in r["also"])]), ["Malicious Package"])
        self.assertEqual(sum(1 for r in rows if r["kind"] == "Malicious Package"), 1)
        self.assertTrue(all(a["kind"] != "Malicious Package" for r in rows for a in r["also"]))

    def test_two_scanners_that_both_say_malicious_still_merge(self):
        a = row(src="OSV-Scanner", kind="Malicious Package", ids=["GHSA-M"], package="evil", ref="MAL-1")
        b = row(src="GuardDog", kind="Malicious Package", ids=["GHSA-M"], package="evil", ref="g")
        rows, stats = dedup([a, b])
        self.assertEqual((len(rows), stats["advisory"]), (1, 1))
        self.assertEqual(rows[0]["kind"], "Malicious Package")

    def test_a_merged_malware_group_does_not_later_absorb_an_ordinary_row(self):
        a = row(src="OSV-Scanner", kind="Malicious Package", ids=["GHSA-M"], package="evil", ref="MAL-1")
        b = row(src="GuardDog", kind="Malicious Package", ids=["GHSA-M"], package="evil", ref="g")
        dep = row(src="Snyk", ids=["GHSA-M"], package="evil")
        rows, _ = dedup([a, b, dep])
        self.assertEqual(sorted(r["kind"] for r in rows), ["Dependency", "Malicious Package"])
        mal = next(r for r in rows if r["kind"] == "Malicious Package")
        self.assertEqual(sorted(mal["by"]), ["GuardDog", "OSV-Scanner"])

    def test_malware_and_a_plain_dependency_never_chain_through_a_third_row(self):
        mal = row(src="OSV-Scanner", kind="Malicious Package", ids=["CVE-1"], package="evil", ref="MAL-1")
        dep = row(ids=["CVE-1"], package="evil")
        bridge = row(src="Dependabot", ids=["CVE-1"], package="evil")
        rows, _ = dedup([mal, dep, bridge])
        kinds = sorted(r["kind"] for r in rows)
        self.assertEqual(kinds.count("Malicious Package"), 1)
        for r in rows:
            if r["kind"] == "Malicious Package":
                self.assertEqual(r["by"], ["OSV-Scanner"])

    def test_projects_never_merge(self):
        _, stats = dedup([row(ids=["CVE-1"], package="a"),
                          row(proj="B", src="Dependabot", ids=["CVE-1"], package="a")])
        self.assertEqual(stats["output"], 2)

    def test_package_names_normalise_per_ecosystem(self):
        rows, _ = dedup([row(ids=["CVE-1"], package="Foo_Bar", ecosystem="pip"),
                         row(src="Dependabot", ids=["cve-1"], package="foo-bar", ecosystem="pypi")])
        self.assertEqual(rows[0]["by"], ["Snyk", "Dependabot"])
        rows, _ = dedup([row(ids=["CVE-1"], package="foo.bar", ecosystem="npm"),
                         row(src="Dependabot", ids=["CVE-1"], package="foo-bar", ecosystem="npm")])
        self.assertEqual(len(rows), 2)

    def test_sast_is_off_by_default(self):
        a = row(kind="Vulnerability", loc="x.py", line=3, cwe=["CWE-79"])
        b = row(src="Semgrep", kind="Vulnerability", loc="./x.py", line=3, cwe=["CWE-79"])
        self.assertEqual(len(dedup([a, b])[0]), 2)
        self.assertEqual(len(dedup([a, b], ("exact", "advisory", "sast"))[0]), 1)

    def test_sast_same_tool_and_chains_do_not_merge(self):
        p = ("sast",)
        same = [row(src="Semgrep", kind="Vulnerability", loc="x.py", line=3, cwe=["CWE-79"],
                    ref=r) for r in ("r1", "r2")]
        self.assertEqual(len(dedup(same, p)[0]), 2)
        chain = [row(src="Snyk", kind="Vulnerability", loc="x.py", line=3, cwe=["CWE-79"]),
                 row(src="Semgrep", kind="Vulnerability", loc="x.py", line=3,
                     cwe=["CWE-79", "CWE-89"]),
                 row(src="SonarQube", kind="Vulnerability", loc="x.py", line=3, cwe=["CWE-89"])]
        self.assertEqual(len(dedup(chain, p)[0]), 2)

    def test_one_scanners_separate_findings_never_merge(self):
        # Snyk files one CVE under several ids; those are Snyk's own separate findings.
        a = row(ref="SNYK-1", ids=["CVE-1"], package="next")
        b = row(ref="SNYK-2", ids=["CVE-1"], package="next")
        c = row(src="Dependabot", ref="GHSA-1", ids=["CVE-1"], package="next")
        rows, stats = dedup([a, b, c])
        self.assertEqual((len(rows), stats["advisory"]), (2, 1))
        self.assertEqual(sorted(len(r["by"]) for r in rows), [1, 2])
        for passes in (("advisory",), ("exact", "advisory", "sast")):
            self.assertEqual(len(dedup([a, b], passes)[0]), 2)

    def test_two_issues_on_one_line_are_distinct_unless_the_column_matches(self):
        mk = lambda col: row(src="SonarQube", kind="Code Smell", ref="ts:S6353", loc="a.ts", line=18,
                             msg="Use concise character class", col=col)
        self.assertEqual(len(dedup([mk(10), mk(24)])[0]), 2)
        self.assertEqual(len(dedup([mk(10), mk(10)])[0]), 1)

    def test_sonar_text_range_becomes_the_column(self):
        issue = {"type": "CODE_SMELL", "severity": "MINOR", "message": "m", "line": 18,
                 "component": "p:a.ts", "rule": "ts:S6353", "textRange": {"startOffset": 24}}
        rows, st, _ = sonarqube.to_rows({"issues": {"issues": [issue, dict(issue, textRange={"startOffset": 40})],
                                                    "total": 2}}, "A")
        self.assertEqual(sorted(r["col"] for r in rows), [24, 40])

    def test_merged_rows_keep_full_sightings(self):
        rows, _ = dedup([row(ids=["CVE-1"], package="a", msg="first", fix="f1"),
                         row(src="Dependabot", ids=["CVE-1"], package="a", msg="second",
                             sev="LOW", fix="f2")])
        also = rows[0]["also"][0]
        self.assertEqual((also["msg"], also["sev"], also["fix"]), ("second", "LOW", "f2"))


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.p = build_payload(load_manifest())

    def test_counts(self):
        # 15 raw + ClamAV 1 + GuardDog 3 + Gitleaks 1 + OSV 3 + zizmor 2 = 25; 1 exact duplicate;
        # 3 advisory merges: Django is seen by Snyk, Semgrep, OSV and Dependabot, which join into
        # one row. Dependabot's second alert (another manifest) stays its own row.
        self.assertEqual(self.p["dedup"], {"input": 25, "passes": ["exact", "advisory"],
                                           "exact": 1, "advisory": 3, "output": 21})

    def test_four_sightings_one_row_most_severe_wins(self):
        dj = [r for r in self.p["findings"] if "CVE-2099-0001" in r["ids"]]
        merged = [r for r in dj if len(r["by"]) > 1]
        self.assertEqual(len(merged), 1)
        self.assertEqual(merged[0]["by"], ["Snyk", "Semgrep", "OSV-Scanner", "Dependabot"])
        self.assertEqual((merged[0]["sev"], len(merged[0]["also"])), ("CRITICAL", 3))
        self.assertEqual([r["by"] for r in dj if len(r["by"]) == 1], [["Dependabot"]])

    def test_security_counts_include_dependencies_and_malware(self):
        s = self.p["generated_from"][0]
        crit = [r for r in self.p["findings"] if r["security"] and r["rank"] <= 1]
        self.assertEqual(s["sec_crit_high"], len(crit))
        self.assertTrue(any(r["kind"] == "Malware" for r in crit))

    def test_missing_and_incomplete_sources_are_reported(self):
        s = self.p["sources"]
        self.assertFalse(s["API: Snyk Container"]["collected"])
        self.assertTrue(s["API: SonarQube"]["collected"])
        self.assertTrue(s["API: ClamAV"]["complete"])
        self.assertEqual(sum(v["collected"] for v in s.values()), 13)
        self.assertNotIn("ghp_FAKE", json.dumps(self.p))

    def test_backward_compatible_shape(self):
        for k in ("title", "version", "generated_from", "sources", "findings", "schema_version"):
            self.assertIn(k, self.p)
        self.assertEqual(self.p["schema_version"], "1.2")
        for k in ("proj", "src", "kind", "sev", "msg", "loc", "line", "col", "ref", "fix",
                  "rank", "by", "id", "track"):
            self.assertIn(k, self.p["findings"][0])
        self.assertNotIn("_package", self.p["findings"][0])
        s = self.p["generated_from"][0]
        self.assertEqual((s["project"], s["coverage"]["pct"], s["sonar"]["ncloc"]),
                         ("API", 80.0, "1000"))
        self.assertIn("sec_unrated", s)
        self.assertIn("malware", s)
        src = next(iter(self.p["sources"].values()))
        self.assertEqual(set(src), {"collected", "complete", "note", "suppressed", "partial", "optional"})

    def test_track_stable_when_message_rewrites(self):
        from qsd.model import finding, fingerprint, track_key
        a = finding(proj="A", src="Snyk", kind="Dependency", sev="HIGH", msg="old title",
                    ref="SNYK-1", ids=["CVE-1"], package="django")
        b = finding(proj="A", src="Snyk", kind="Dependency", sev="HIGH", msg="new title",
                    ref="SNYK-1", ids=["CVE-1"], package="django")
        self.assertEqual(track_key(a), track_key(b))
        self.assertNotEqual(fingerprint(a), fingerprint(b))

    def test_track_keeps_gitleaks_commits_and_columns_apart(self):
        from qsd.model import finding, track_key
        from qsd.dedup import exact
        a = finding(proj="A", src="Gitleaks", kind="Secret", sev="HIGH", msg="pat (commit aaa)",
                    loc="a.env", line=1, col=4, ref="generic-api-key", track="aaa")
        b = finding(proj="A", src="Gitleaks", kind="Secret", sev="HIGH", msg="pat (commit bbb)",
                    loc="a.env", line=1, col=4, ref="generic-api-key", track="bbb")
        c = finding(proj="A", src="Gitleaks", kind="Secret", sev="HIGH", msg="pat (commit aaa)",
                    loc="a.env", line=1, col=40, ref="generic-api-key", track="aaa")
        self.assertEqual(len({track_key(a), track_key(b), track_key(c)}), 3)
        self.assertEqual(len(exact([a, b, c])), 3)
        # Empty cols still collapse when truly identical; distinct cols do not.
        same = dict(proj="A", src="Gitleaks", kind="Secret", sev="HIGH", msg="m",
                    loc="a.env", line=1, ref="r")
        self.assertEqual(len(exact([finding(**same, col=""), finding(**same, col="")])), 1)
        self.assertEqual(len(exact([finding(**same, col=4), finding(**same, col=40)])), 2)
        # Exported track ignores encounter order: reverse input, same key set.
        fwd = build_payload({"projects": [{"name": "a", "gitleaks": tmpjson([
            {"RuleID": "r", "Description": "m", "StartLine": 1, "StartColumn": 4,
             "File": "a.env", "Commit": "aaa111"},
            {"RuleID": "r", "Description": "m", "StartLine": 1, "StartColumn": 4,
             "File": "a.env", "Commit": "bbb222"},
        ])}]}, passes=())
        rev = build_payload({"projects": [{"name": "a", "gitleaks": tmpjson([
            {"RuleID": "r", "Description": "m", "StartLine": 1, "StartColumn": 4,
             "File": "a.env", "Commit": "bbb222"},
            {"RuleID": "r", "Description": "m", "StartLine": 1, "StartColumn": 4,
             "File": "a.env", "Commit": "aaa111"},
        ])}]}, passes=())
        self.assertEqual({r["track"] for r in fwd["findings"]}, {r["track"] for r in rev["findings"]})
        self.assertEqual(len(fwd["findings"]), 2)

    def test_dependabot_suppressed_is_dismissed_not_fixed(self):
        doc = [
            {"state": "open", "security_advisory": {"severity": "high", "summary": "a",
                                                    "ghsa_id": "GHSA-1", "identifiers": [], "cwes": []},
             "security_vulnerability": {"package": {"name": "x", "ecosystem": "npm"},
                                        "vulnerable_version_range": "<1",
                                        "first_patched_version": {"identifier": "1"}},
             "dependency": {"manifest_path": "a/package.json"}},
            {"state": "dismissed", "security_advisory": {"severity": "low", "summary": "b",
                                                         "ghsa_id": "GHSA-2", "identifiers": [], "cwes": []},
             "security_vulnerability": {"package": {"name": "y", "ecosystem": "npm"}},
             "dependency": {"manifest_path": "a/package.json"}},
            {"state": "fixed", "security_advisory": {"severity": "low", "summary": "c",
                                                     "ghsa_id": "GHSA-3", "identifiers": [], "cwes": []},
             "security_vulnerability": {"package": {"name": "z", "ecosystem": "npm"}},
             "dependency": {"manifest_path": "a/package.json"}},
            {"state": "mystery", "security_advisory": {"severity": "low", "summary": "d",
                                                       "ghsa_id": "GHSA-4", "identifiers": [], "cwes": []},
             "security_vulnerability": {"package": {"name": "w", "ecosystem": "npm"}},
             "dependency": {"manifest_path": "a/package.json"}},
        ]
        rows, st = dependabot.load(tmpjson(doc), "A")
        self.assertEqual((len(rows), st["suppressed"], st["counts"]["fixed"]), (1, 1, 1))
        self.assertFalse(st["complete"])
        self.assertIn("unrecognised state", st["note"])

    def test_malware_count_includes_malicious_packages(self):
        s = self.p["generated_from"][0]
        kinds = {r["kind"] for r in self.p["findings"] if r["kind"] in ("Malware", "Malicious Package")}
        self.assertEqual(s["malware"], sum(1 for r in self.p["findings"]
                                           if r["kind"] in ("Malware", "Malicious Package")))
        self.assertTrue(kinds)

    def test_ids_unique_even_without_dedup(self):
        p = build_payload(load_manifest(), passes=())
        ids = [r["id"] for r in p["findings"]]
        self.assertEqual((len(ids), len(set(ids))), (25, 25))

    def test_rows_sorted_by_severity(self):
        ranks = [r["rank"] for r in self.p["findings"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_same_label_or_unsafe_name_rejected(self):
        m = load_manifest()
        m["projects"].append(dict(m["projects"][0], name="other"))
        with self.assertRaises(ManifestError):
            build_payload(m)
        for bad in ("../x", "a/b", ".hidden", ""):
            with self.assertRaises(ManifestError):
                build_payload({"projects": [{"name": bad}]})

    def test_null_metadata_becomes_strings(self):
        p = build_payload({"version": None, "projects": [
            {"name": "a", "repo": None, "semgrep": fx("semgrep.json")}]})
        self.assertEqual((p["version"], p["generated_from"][0]["repo"]), ("", ""))


class Html(unittest.TestCase):
    def payload(self):
        return build_payload(load_manifest())

    def test_placeholder_in_title_cannot_inject_data(self):
        p = self.payload()
        p["title"] = "__DATA__ __TITLE__"
        p["version"] = "__DATA__"
        p["findings"][0]["msg"] = "<img src=x onerror=alert(1)>"
        out = render(p)
        self.assertNotIn("<img src=x", out)
        self.assertIn("<h1>__DATA__ __TITLE__</h1>", out)

    def test_script_breakouts_are_encoded(self):
        p = self.payload()
        p["findings"][0]["msg"] = "</script><!--<script>&amp;"
        out = render(p)
        data = out[out.index("const DATA"):]
        for s in ("</script><!--", "<!--<script", "&amp;"):
            self.assertNotIn(s, data.split("\n")[0])

    def test_measured_percent_uses_matching_projects_only(self):
        p = self.payload()
        p["generated_from"].append({"project": "B", "sonar": {"ncloc": "99999"}, "coverage": None,
                                    "sec_crit_high": 0, "security": 0, "sec_unrated": 0, "malware": 0})
        # Make every source look complete so the crit tile colour is not the question here.
        for v in p["sources"].values():
            v.update(collected=True, complete=True, optional=False)
        out = render(p)
        self.assertIn("<b>50.0</b><span>Codebase measured %", out)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        return subprocess.run([sys.executable, "-m", "qsd", *args], env=env, capture_output=True,
                              text=True)

    def test_digest_cli_and_strict(self):
        with tempfile.TemporaryDirectory() as d:
            out = os.path.join(d, "r.json")
            # Incomplete sources in the fixture: default --strict must fail.
            r = self.run_cli("digest", fx("manifest.json"), "--json-out", out, "--release", "v9")
            self.assertEqual(r.returncode, 2, r.stderr)
            r = self.run_cli("digest", fx("manifest.json"), "--json-out", out,
                             "--html-out", os.path.join(d, "r.html"), "--release", "v9",
                             "--lenient")
            self.assertEqual(r.returncode, 0, r.stderr)
            with open(out) as fh:
                p = json.load(fh)
            self.assertEqual((p["version"], len(p["findings"]), p["settings"]["dedup"]),
                             ("v9", 21, "exact,advisory"))
            self.assertEqual(p["schema_version"], "1.2")
            r = self.run_cli("digest", fx("manifest.json"), "--json-out", out, "--strict")
            self.assertEqual(r.returncode, 2)

    def test_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with open(os.path.join(HERE, "..", "schema", "report.schema.json")) as fh:
            schema = json.load(fh)
        jsonschema.validate(json.loads(json.dumps(build_payload(load_manifest()))), schema)


class Runner(unittest.TestCase):
    def test_config_validation(self):
        from qsd.runner import ConfigError, _inside, validate
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ConfigError):
                validate({"projects": [{"name": "../../x", "path": "."}]}, d)
            with self.assertRaises(ConfigError):
                _inside(d, "../outside")
            validate({"projects": [{"name": "ok", "path": "."}]}, d)

    def test_sonar_args_cannot_redirect_the_token(self):
        from qsd.runner import ConfigError, validate
        with tempfile.TemporaryDirectory() as d:
            ok = {"name": "a", "path": ".", "sonar_args": ["-Dsonar.exclusions=**/dist/**", "-Dsonar.sources=a,b"]}
            validate({"projects": [ok]}, d)
            for bad in ("-Dsonar.host.url=http://evil", "-Dsonar.token=x", "-Dsonar.login=x",
                        "-Dsonar.projectKey=other", "-Dsonar.scanner.javaExePath=/usr/src/evil",
                        "-Dsonar.scanner.dumpToFile=/tmp/x", "-Dsonar.python.pylint=/usr/src/evil",
                        "-Dsonar.javascript.node=/usr/src/evil",
                        "-Dsonar.javascript.file.suffixes=.qqq",
                        "--rm", "sonar.sources=x", "-Xmx1g"):
                with self.assertRaises(ConfigError, msg=bad):
                    validate({"projects": [dict(ok, sonar_args=[bad])]}, d)

    def test_semgrep_ci_mode_never_falls_back_to_public_rules(self):
        from qsd import runner
        orig_have, orig_env = runner.have, os.environ.pop("SEMGREP_APP_TOKEN", None)
        runner.have = lambda t: True
        try:
            with tempfile.TemporaryDirectory() as d:
                cfg = {"projects": [{"name": "a", "path": "."}], "semgrep_mode": "ci"}
                manifest, _ = runner.scan(cfg, d, os.path.join(d, "out"), tools=("semgrep",))
                self.assertIn("SEMGREP_APP_TOKEN not set", manifest["projects"][0]["notes"]["Semgrep"])
                self.assertEqual(manifest["settings"]["semgrep"], "not scanned: SEMGREP_APP_TOKEN not set")
                src = build_payload(manifest)["sources"]["a: Semgrep"]
                self.assertEqual((src["collected"], src["complete"]), (False, False))
                with self.assertRaises(runner.ConfigError):
                    runner.validate({"projects": cfg["projects"], "semgrep_mode": "bogus"}, d)
        finally:
            runner.have = orig_have
            if orig_env is not None:
                os.environ["SEMGREP_APP_TOKEN"] = orig_env

    def test_coverage_may_be_absolute_or_inside_the_checkout(self):
        from qsd import runner
        with tempfile.TemporaryDirectory() as d:
            ext = os.path.join(d, "elsewhere.json")
            for cov, want in ((ext, ext), ("coverage.xml", os.path.realpath(os.path.join(d, "coverage.xml")))):
                m, _ = runner.scan({"projects": [{"name": "a", "path": ".", "coverage": cov}]}, d,
                                   os.path.join(d, "out"), tools=())
                self.assertEqual(m["projects"][0]["coverage"], want)
            with self.assertRaises(runner.ConfigError):
                runner.scan({"projects": [{"name": "a", "path": ".", "coverage": "../x.xml"}]}, d,
                            os.path.join(d, "out"), tools=())

    def test_missing_tool_never_reads_an_old_file(self):
        from qsd import runner
        with tempfile.TemporaryDirectory() as d:
            cfg = {"projects": [{"name": "a", "path": "."}]}
            orig = runner.have
            runner.have = lambda t: False
            try:
                m1, r1 = runner.scan(cfg, d, os.path.join(d, "out"), tools=("semgrep",))
                m2, r2 = runner.scan(cfg, d, os.path.join(d, "out"), tools=("semgrep",))
            finally:
                runner.have = orig
            self.assertNotEqual(r1, r2)
            self.assertEqual(oct(os.stat(r2).st_mode & 0o777), "0o700")
            p = build_payload(m2)
            self.assertEqual(p["sources"]["a: Semgrep"],
                             {"collected": False, "complete": False, "note": "semgrep not on PATH",
                              "suppressed": 0, "partial": 0, "optional": False})
            # Tools left out of --tools still appear, marked optional so --strict ignores them.
            self.assertTrue(p["sources"]["a: ClamAV"]["optional"])
            self.assertEqual(p["sources"]["a: ClamAV"]["note"], "skipped: not in --tools")

    def test_html_crit_zero_is_not_green_when_sources_gap(self):
        p = build_payload(load_manifest())
        for s in p["generated_from"]:
            s["sec_crit_high"] = 0
        out = render(p)
        # Incomplete required sources: the crit tile must not wear the ok (green) class.
        self.assertIn("Security crit + high", out)
        self.assertNotIn('class="tile ok"><b>0</b><span>Security crit + high', out)
        self.assertIn("required source(s) incomplete", out)

    def test_packaged_schema_matches_repo_schema(self):
        from importlib import resources
        pkg = (resources.files("qsd") / "data" / "report.schema.json").read_text(encoding="utf-8")
        with open(os.path.join(HERE, "..", "schema", "report.schema.json"), encoding="utf-8") as fh:
            self.assertEqual(pkg, fh.read())


class ReviewFixes(unittest.TestCase):
    """Regressions for the independent review of PR #1; each fails if its fix is reverted."""

    def payload(self, manifest, **kw):
        return build_payload(manifest, **kw)

    # -- optional is structural, never read from a note's wording
    def test_a_skipped_note_alone_never_makes_a_failed_source_optional(self):
        d = tempfile.mkdtemp()
        base = {"name": "a", "semgrep": os.path.join(d, "missing.json"),
                "notes": {"Semgrep": "skipped: semgrep crashed"}}
        src = self.payload({"projects": [base]})["sources"]["a: Semgrep"]
        self.assertEqual((src["collected"], src["optional"]), (False, False))
        src = self.payload({"projects": [dict(base, skipped=["Semgrep"])]})["sources"]["a: Semgrep"]
        self.assertTrue(src["optional"])

    def test_strict_gate_fails_on_a_note_only_skip_and_passes_on_a_declared_skip(self):
        d = tempfile.mkdtemp()
        def run(manifest):
            path = os.path.join(d, "m.json")
            with open(path, "w") as fh:
                json.dump(manifest, fh)
            env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
            return subprocess.run([sys.executable, "-m", "qsd", "digest", path, "--json-out",
                                   os.path.join(d, "r.json")], env=env, capture_output=True, text=True)
        ok = os.path.join(FIX, "semgrep.json")
        base = {"name": "a", "semgrep": ok, "dependabot": os.path.join(d, "none.json"),
                "notes": {"Dependabot": "skipped: token expired"}}
        self.assertEqual(run({"projects": [base]}).returncode, 2)
        self.assertEqual(run({"projects": [dict(base, skipped=["Dependabot"])]}).returncode, 0)

    def test_runner_records_skips_structurally_and_lists_guarddog_even_when_unconfigured(self):
        from qsd import runner
        with tempfile.TemporaryDirectory() as d:
            m, _ = runner.scan({"projects": [{"name": "a", "path": "."}]}, d, os.path.join(d, "o"),
                               tools=("guarddog",))
            proj = m["projects"][0]
            self.assertIn("Semgrep", proj["skipped"])
            self.assertIn("GuardDog (not configured)", proj["skipped"])
            src = build_payload(m)["sources"]
            self.assertIn("a: GuardDog (not configured)", src)
            self.assertTrue(src["a: GuardDog (not configured)"]["optional"])
            self.assertTrue(src["a: Semgrep"]["optional"])
            self.assertFalse(src["a: Semgrep"]["collected"])

    # -- ids and tracks
    def test_id_of_a_row_without_a_column_is_unchanged_since_v030(self):
        import hashlib
        from qsd.model import fingerprint
        r = row(ref="r", loc="f.py", line=3, msg="m")
        old = hashlib.sha256("\x1f".join(
            [r["project_id"], "Snyk", "Dependency", "r", "f.py", "3", "m"]).encode()).hexdigest()[:16]
        self.assertEqual(fingerprint(r), old)
        self.assertNotEqual(fingerprint(row(ref="r", loc="f.py", line=3, msg="m", col=9)), old)
        self.assertNotEqual(fingerprint(row(ref="r", loc="f.py", line=3, msg="m", col=9)),
                            fingerprint(row(ref="r", loc="f.py", line=3, msg="m", col=10)))

    def test_track_is_unique_even_when_identity_collides(self):
        t = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS-0031", "Message": "secret in ENV API_KEY", "Severity": "HIGH",
             "CauseMetadata": {"StartLine": 7}},
            {"ID": "DS-0031", "Message": "secret in ENV DB_PASSWORD", "Severity": "HIGH",
             "CauseMetadata": {"StartLine": 7}}]}]}
        f = tmpjson(t)
        m = {"projects": [{"name": "a", "trivy": {"Config": f}}]}
        for passes in (("exact", "advisory"), ()):
            rows = build_payload(m, passes=passes)["findings"]
            self.assertEqual(len(rows), 2)
            self.assertEqual(len({r["track"] for r in rows}), 2, passes)
            self.assertEqual(len({r["id"] for r in rows}), 2)

    def test_track_of_an_uncolliding_row_ignores_its_message(self):
        mk = lambda msg: build_payload({"projects": [{"name": "a", "trivy": {"Config": tmpjson(
            {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": [
                {"ID": "DS-1", "Message": msg, "Severity": "HIGH",
                 "CauseMetadata": {"StartLine": 2}}]}]})}}]})["findings"][0]["track"]
        self.assertEqual(mk("old title"), mk("reworded title"))

    def test_identical_rows_with_dedup_off_still_get_distinct_tracks(self):
        rows = build_payload(load_manifest(), passes=())["findings"]
        self.assertEqual(len({r["track"] for r in rows}), len(rows))

    # -- unknown stays unknown
    def test_commit_dirty_is_null_unless_known(self):
        get = lambda **kw: build_payload({"projects": [dict(
            {"name": "a", "semgrep": fx("semgrep.json")}, **kw)]})["generated_from"][0]["commit_dirty"]
        self.assertIsNone(get())
        self.assertIsNone(get(commit_dirty=None))
        self.assertIs(get(commit_dirty=False), False)
        self.assertIs(get(commit_dirty=True), True)
        self.assertIs(get(commit_dirty=1), True)
        self.assertIs(get(commit_dirty="false"), False)
        self.assertIs(get(commit_dirty="true"), True)
        self.assertIsNone(get(commit_dirty="maybe"))
        html = render(build_payload({"projects": [{"name": "a", "semgrep": fx("semgrep.json")}]}))
        self.assertIn("unknown dirty state", html)

    # -- Dependabot fetch
    def test_dependabot_fetch_asks_for_open_and_waived_alerts_exactly(self):
        from qsd.runner import _dependabot_cmd
        cmd = _dependabot_cmd("o/r")
        self.assertIn("/repos/o/r/dependabot/alerts?state=open,dismissed,auto_dismissed&per_page=100", cmd)
        self.assertIn("--paginate", cmd)

    def test_dependabot_failure_is_noted_and_stderr_is_logged(self):
        from qsd import runner
        real_run, real_have = subprocess.run, runner.have

        def fake(cmd, *a, **kw):
            if cmd[0] != "gh":
                return real_run(cmd, *a, **kw)
            kw["stderr"].write("gh: HTTP 403 boom\n")
            return subprocess.CompletedProcess(cmd, 1)
        runner.have, subprocess.run = (lambda t: True), fake
        try:
            with tempfile.TemporaryDirectory() as d:
                m, run_dir = runner.scan({"projects": [{"name": "a", "path": ".", "repo": "o/r"}]}, d,
                                         os.path.join(d, "o"), tools=("dependabot",))
                self.assertIn("gh api exited 1", m["projects"][0]["notes"]["Dependabot"])
                with open(os.path.join(run_dir, "logs", "a.dependabot.log")) as fh:
                    self.assertIn("HTTP 403 boom", fh.read())
                src = build_payload(m)["sources"]["a: Dependabot"]
                self.assertEqual((src["collected"], src["optional"]), (False, False))
        finally:
            runner.have, subprocess.run = real_have, real_run

    def test_dependabot_parser_reads_concatenated_pages(self):
        rows, st = dependabot.load(fx("dependabot.json"), "API")
        self.assertTrue(st["ok"])
        self.assertGreater(len(rows), 1)

    # -- SonarQube hardening
    def test_sonar_allowlist_cannot_change_scm_behaviour(self):
        from qsd.runner import ConfigError, validate
        with tempfile.TemporaryDirectory() as d:
            for bad in ("-Dsonar.scm.disabled=false", "-Dsonar.scm.provider=git",
                        "-Dsonar.scanner.javaExePath=/tmp/x"):
                with self.assertRaises(ConfigError, msg=bad):
                    validate({"projects": [{"name": "a", "path": ".", "sonar_args": [bad]}]}, d)
            validate({"projects": [{"name": "a", "path": ".", "sonar_args": [
                "-Dsonar.scm.exclusions=**/gen/**", "-Dsonar.sourceEncoding=UTF-8",
                "-Dsonar.projectName=My App"]}]}, d)

    def test_scanner_pins_the_host_on_the_command_line(self):
        from qsd import runner
        seen = {}
        real = runner.run
        def fake(cmd, logfile, cwd=None, env=None):
            seen.update(cmd=cmd)
            open(logfile, "w").close()
            return 1
        runner.run = fake
        try:
            with tempfile.TemporaryDirectory() as d:
                s = runner.Sonar(d)
                try:
                    s.scan(d, "k", os.path.join(d, "x.log"))
                except runner.SonarError:
                    pass
                finally:
                    shutil_rmtree(s.secret_dir)
        finally:
            runner.run = real
        self.assertIn("-Dsonar.host.url=http://sonarqube:9000", seen["cmd"])
        # A PATH, not the bare command name: `node` is read as a file name and the JS/TS
        # analysis then fails with "Node.js executable file does not exist".
        self.assertIn("-Dsonar.nodejs.executable=/usr/bin/node", seen["cmd"])
        self.assertNotIn("-Dsonar.nodejs.executable=node", seen["cmd"])

    def test_checkout_sonar_properties_cannot_set_an_executable(self):
        from qsd import runner
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write("sonar.scanner.javaExePath=/usr/src/evil\n")
            with self.assertRaises(runner.SonarError) as ctx:
                runner._reject_dangerous_sonar_properties(d)
            self.assertIn("javaExePath", str(ctx.exception))
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write("sonar.sources=.\nsonar.sourceEncoding=UTF-8\n")
            runner._reject_dangerous_sonar_properties(d)  # harmless keys OK

    def test_an_analysis_of_zero_lines_is_incomplete_not_clean(self):
        doc = {"issues": {"issues": [], "total": 0}, "hotspots": {"hotspots": [], "total": 0},
               "measures": {"component": {"measures": [{"metric": "ncloc", "value": "0"}]}}}
        _, st, _ = sonarqube.to_rows(doc, "A")
        self.assertIn("no lines of code analysed", st["note"])
        doc["measures"]["component"]["measures"][0]["value"] = "120"
        self.assertEqual(sonarqube.to_rows(doc, "A")[1]["note"], "")

    # -- CLI and the rest of the review's mutation list
    def test_strict_and_lenient_together_is_an_error(self):
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        r = subprocess.run([sys.executable, "-m", "qsd", "digest", fx("manifest.json"),
                            "--strict", "--lenient"], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)
        self.assertIn("contradict", r.stderr)

    def test_unrated_security_is_counted_separately_from_crit_high(self):
        r = {"CRITICAL": 0}
        d = tempfile.mkdtemp()
        f = os.path.join(d, "s.json")
        with open(f, "w") as fh:
            json.dump({"results": [{"check_id": "ssc-1", "path": "p.lock", "start": {"line": 1},
                                    "extra": {"severity": "UNKNOWN", "message": "x", "metadata": {},
                                              "sca_info": {"dependency_match": {"found_dependency": {
                                                  "package": "p"}}}}}]}, fh)
        s = build_payload({"projects": [{"name": "a", "semgrep": f}]})["generated_from"][0]
        self.assertEqual((s["sec_unrated"], s["sec_crit_high"]), (1, 0))
        del r

    def test_crit_tile_is_green_only_when_every_required_source_is_complete(self):
        p = build_payload(load_manifest())
        for v in p["sources"].values():
            v.update(complete=True, collected=True, optional=False)
        for s in p["generated_from"]:
            s["sec_crit_high"] = 0
        self.assertIn('tile ok"><b>0</b><span>Security crit + high', render(p))
        next(iter(p["sources"].values())).update(complete=False)
        html_gap = render(p)
        self.assertNotIn('tile ok"><b>0</b><span>Security crit + high', html_gap)
        self.assertNotIn('tile bad"><b>0</b><span>Security crit + high', html_gap)

    def test_a_freshclam_failure_marker_makes_clamav_incomplete(self):
        f = os.path.join(tempfile.mkdtemp(), "c.txt")
        with open(f, "w") as fh:
            fh.write("# qsd clamav\n# qsd: freshclam failed\n")
        _, st = clamav.load(f, "A")
        self.assertIn("freshclam failed", st["note"])
        self.assertFalse(st.get("complete", True))


def shutil_rmtree(path):
    import shutil
    shutil.rmtree(path, ignore_errors=True)


class ReviewRound2(unittest.TestCase):
    """Second independent review: each test fails if its fix is reverted."""

    def partial_manifest(self, n=91):
        f = tmpjson({"results": [], "errors": [{"level": "warn"}] * n})
        return {"projects": [{"name": "a", "semgrep": f}]}

    def run_cli(self, manifest, *extra):
        d = tempfile.mkdtemp()
        path = os.path.join(d, "m.json")
        with open(path, "w") as fh:
            json.dump(manifest, fh)
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        return subprocess.run([sys.executable, "-m", "qsd", "digest", path, "--json-out",
                               os.path.join(d, "r.json"), "--html-out", os.path.join(d, "r.html"),
                               *extra], env=env, capture_output=True, text=True), d

    # -- a partial scan is passed by strict, but never silent
    def test_partly_parsed_semgrep_passes_strict_yet_is_announced_as_a_partial_scan(self):
        r, d = self.run_cli(self.partial_manifest(91))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("!! PARTIAL SCAN", r.stderr)
        self.assertIn("a: Semgrep: 91 file(s) only partly scanned", r.stderr)
        with open(os.path.join(d, "r.json")) as fh:
            src = json.load(fh)["sources"]["a: Semgrep"]
        self.assertEqual((src["complete"], src["partial"]), (True, 91))
        with open(os.path.join(d, "r.html")) as fh:
            page = fh.read()
        self.assertIn("PARTIAL SCAN", page)
        self.assertIn("not a full-scan result", page)

    def test_a_full_scan_prints_no_partial_warning(self):
        r, _ = self.run_cli(self.partial_manifest(0))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("PARTIAL SCAN", r.stderr)

    def test_opting_in_makes_partly_parsed_files_fail_strict(self):
        m = self.partial_manifest(3)
        m["projects"][0]["semgrep_partial_is_gap"] = True
        self.assertEqual(self.run_cli(m)[0].returncode, 2)

    def test_the_html_never_paints_a_partial_scan_green(self):
        full = render(build_payload(self.partial_manifest(0)))
        part = render(build_payload(self.partial_manifest(5)))
        self.assertIn('tile ok"><b>0</b><span>Security crit + high', full)
        self.assertNotIn('tile ok"><b>0</b><span>Security crit + high', part)
        self.assertIn("◐ a: Semgrep — PARTIAL SCAN: 5 file(s) only partly scanned", part)
        self.assertNotIn("PARTIAL SCAN", full)

    def test_the_subtitle_prints_booleans_in_lowercase(self):
        p = build_payload(self.partial_manifest(0))
        p["settings"]["semgrep_partial_is_gap"] = True
        page = render(p)
        self.assertIn("semgrep_partial_is_gap: true", page)
        self.assertNotIn("semgrep_partial_is_gap: True", page)

    # -- digest-path holes
    def test_a_project_with_no_sources_or_a_misspelled_snyk_product_is_an_error(self):
        ok = os.path.join(FIX, "semgrep.json")
        with self.assertRaises(ManifestError) as c:
            build_payload({"projects": [{"name": "a", "semgrep": ok}, {"name": "b"}]})
        self.assertIn("lists no sources", str(c.exception))
        with self.assertRaises(ManifestError) as c:
            build_payload({"projects": [{"name": "c", "snyk": {"OpenSource": ok}}]})
        self.assertIn("OpenSource", str(c.exception))

    def test_a_skip_never_hides_a_source_that_ran(self):
        d = tempfile.mkdtemp()
        hard = tmpjson({"results": [], "errors": [{"level": "error"}]})
        s = build_payload({"projects": [{"name": "a", "semgrep": hard, "skipped": ["Semgrep"]}]})
        self.assertFalse(s["sources"]["a: Semgrep"]["optional"])
        s = build_payload({"projects": [{"name": "a", "semgrep": os.path.join(d, "none.json"),
                                         "skipped": ["Semgrep"]}]})
        self.assertTrue(s["sources"]["a: Semgrep"]["optional"])

    # -- sonar-project.properties: parsed by Java's rules, and only what is not pinned
    def test_properties_keys_follow_java_rules(self):
        from qsd.runner import _properties_keys
        text = ("# c\nsonar.projectKey=myapp\nsonar.scanner.javaExePath:/x\n"
                "sonar.scanner.javaExePath /y\nsonar.sources=src,\\\n   lib\n"
                "sonar.sc\\u0061nner.javaExePath=/z\n ! also a comment\na\\:b=1\n")
        self.assertEqual(_properties_keys(text), [
            "sonar.projectKey", "sonar.scanner.javaExePath", "sonar.scanner.javaExePath",
            "sonar.sources", "sonar.scanner.javaExePath", "a:b"])

    def test_every_separator_form_of_a_forbidden_key_is_refused_and_pinned_keys_are_not(self):
        from qsd import runner
        for line in ("sonar.scanner.javaExePath=/x", "sonar.scanner.javaExePath:/x",
                     "sonar.scanner.javaExePath /x", "sonar.sc\\u0061nner.javaExePath=/x",
                     "sonar.login=t", "sonar.nodejs.forceExecutable=/x"):
            d = tempfile.mkdtemp()
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write(line + "\n")
            with self.assertRaises(runner.SonarError, msg=line):
                runner._reject_dangerous_sonar_properties(d)
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
            fh.write("sonar.projectKey=myapp\nsonar.organization=o\nsonar.host.url=http://x\n"
                     "sonar.sources=src\n")
        runner._reject_dangerous_sonar_properties(d)  # command line pins these, so they are harmless

    def test_the_scanner_checks_the_properties_file_before_it_runs_anything(self):
        from qsd import runner
        calls = []
        real = runner.run
        runner.run = lambda *a, **k: calls.append(a) or 0
        try:
            d = tempfile.mkdtemp()
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write("sonar.scanner.javaExePath:/evil\n")
            s = runner.Sonar(d)
            try:
                with self.assertRaises(runner.SonarError):
                    s.scan(d, "k", os.path.join(d, "x.log"))
            finally:
                shutil_rmtree(s.secret_dir)
        finally:
            runner.run = real
        self.assertEqual(calls, [])

    def test_one_projects_refused_properties_do_not_blank_the_others(self):
        from qsd import runner

        class FakeSonar:
            def __init__(self, logs): pass
            def up(self): pass
            def down(self): pass
            def wait(self, key): pass
            def scan(self, path, key, logfile, extra=()):
                if key == "bad":
                    raise runner.SonarError("sonar-project.properties sets sonar.scanner.javaExePath")
            def export(self, key, raw):
                return {"issues": os.path.join(raw, f"{key}.json")}
        real_sonar, real_have = runner.Sonar, runner.have
        runner.Sonar, runner.have = FakeSonar, (lambda t: True)
        try:
            with tempfile.TemporaryDirectory() as d:
                for n in ("good", "bad"):
                    os.mkdir(os.path.join(d, n))
                m, _ = runner.scan({"projects": [{"name": "good", "path": "good"},
                                                  {"name": "bad", "path": "bad"}]},
                                   d, os.path.join(d, "o"), tools=("sonarqube",))
        finally:
            runner.Sonar, runner.have = real_sonar, real_have
        good, bad = m["projects"]
        self.assertNotIn("SonarQube", good["notes"])
        self.assertTrue(good["sonarqube"])
        self.assertIn("javaExePath", bad["notes"]["SonarQube"])
        self.assertEqual(bad["sonarqube"], {})

    # -- waived issues
    def test_waived_issues_are_accepted_or_false_positive_never_fixed(self):
        from qsd.parsers import sonarqube as sq
        seen = []

        def fake(host, token, path, params):
            seen.append(params)
            return {"paging": {"total": 7}}
        real = sq.api
        sq.api = fake
        try:
            self.assertEqual(sq.waived_count("h", "t", "k"), (7, ""))
        finally:
            sq.api = real
        self.assertEqual(seen[0]["issueStatuses"], "ACCEPTED,FALSE_POSITIVE")
        self.assertNotIn("resolved", seen[0])

    def test_an_older_server_falls_back_and_a_failure_is_never_reported_as_zero(self):
        from qsd.parsers import sonarqube as sq
        calls = []

        def old_server(host, token, path, params):
            calls.append(params)
            if "issueStatuses" in params:
                raise sq.SonarError("HTTP 400")
            return {"paging": {"total": 3}}
        real = sq.api
        try:
            sq.api = old_server
            self.assertEqual(sq.waived_count("h", "t", "k"), (3, ""))
            self.assertEqual(calls[1]["resolutions"], "FALSE-POSITIVE,WONTFIX")
            sq.api = lambda *a, **k: (_ for _ in ()).throw(sq.SonarError("HTTP 500"))
            count, err = sq.waived_count("h", "t", "k")
        finally:
            sq.api = real
        self.assertIsNone(count)
        self.assertIn("HTTP 500", err)
        doc = {"issues": {"issues": [], "total": 0}, "hotspots": {"hotspots": [], "total": 0},
               "measures": {"component": {"measures": [{"metric": "ncloc", "value": "5"}]}},
               "suppressed": 0, "suppressed_error": err}
        _, st, _ = sq.to_rows(doc, "A")
        self.assertIn("waived-issue count unavailable", st["note"])
        self.assertTrue(st["complete"])  # informational, not a gap in the findings

    def test_a_live_fetch_records_why_the_waived_count_is_missing(self):
        from qsd.parsers import sonarqube as sq

        def api(host, token, path, params):
            if path.endswith("measures/component"):
                return {"component": {"measures": [{"metric": "ncloc", "value": "9"}]}}
            raise sq.SonarError("HTTP 500")
        real = (sq.api, sq.fetch_all)
        sq.api, sq.fetch_all = api, (lambda *a, **k: ([], 0))
        try:
            doc = sq.fetch("https://h", "t", "k")
        finally:
            sq.api, sq.fetch_all = real
        self.assertEqual(doc["suppressed"], 0)
        self.assertIn("HTTP 500", doc["suppressed_error"])

    def test_a_waived_count_is_exported_by_qsd_scan_too(self):
        from qsd import runner
        real = (runner.fetch_all, runner.api, runner.waived_count)
        runner.fetch_all = lambda *a, **k: ([], 0)
        runner.api = lambda *a, **k: {"component": {"measures": []}}
        runner.waived_count = lambda *a, **k: (4, "")
        d = tempfile.mkdtemp()
        s = runner.Sonar(d)
        try:
            out = s.export("k", d)
            with open(out["issues"]) as fh:
                self.assertEqual(json.load(fh)["suppressed"], 4)
        finally:
            runner.fetch_all, runner.api, runner.waived_count = real
            shutil_rmtree(s.secret_dir)


class ReviewRound3(unittest.TestCase):
    """Final review: each test fails if its fix is reverted."""

    def tj(self, doc):
        return tmpjson(doc)

    # -- properties file bypasses
    def test_a_continued_line_at_the_end_of_the_file_is_still_checked(self):
        from qsd import runner
        for text in ("sonar.scanner.javaExePath=/x\\", "sonar.scanner.javaExePath=/x\\\n",
                     "sonar.sources=a\nsonar.scanner.javaExePath=/x\\"):
            d = tempfile.mkdtemp()
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write(text)
            with self.assertRaises(runner.SonarError, msg=repr(text)):
                runner._reject_dangerous_sonar_properties(d)
        self.assertEqual(runner._properties_keys("a=1\\\n  b=2"), ["a"])

    def test_a_symlinked_properties_file_is_refused_even_when_it_dangles(self):
        from qsd import runner
        for target in ("/usr/src/payload.properties", "real.properties"):
            d = tempfile.mkdtemp()
            with open(os.path.join(d, "real.properties"), "w") as fh:
                fh.write("sonar.sources=.\n")
            os.symlink(target, os.path.join(d, "sonar-project.properties"))
            with self.assertRaises(runner.SonarError, msg=target):
                runner._reject_dangerous_sonar_properties(d)

    # -- optional / skipped and empty declarations
    def test_a_parse_failure_is_never_excused_by_skipped(self):
        d = tempfile.mkdtemp()
        ok = os.path.join(FIX, "semgrep.json")
        bad = tmpjson({"error": "scan failed"})
        m = {"projects": [{"name": "a", "semgrep": ok},
                          {"name": "b", "semgrep": bad, "skipped": ["Semgrep"]}]}
        p = build_payload(m)
        self.assertFalse(p["sources"]["b: Semgrep"]["optional"])
        path = os.path.join(d, "m.json")
        with open(path, "w") as fh:
            json.dump(m, fh)
        env = dict(os.environ, PYTHONPATH=os.path.join(HERE, "..", "src"))
        r = subprocess.run([sys.executable, "-m", "qsd", "digest", path, "--json-out",
                            os.path.join(d, "r.json")], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 2)

    def test_a_source_nobody_supplied_is_optional_only_when_skipped(self):
        d = tempfile.mkdtemp()
        none = os.path.join(d, "none.json")
        ok = os.path.join(FIX, "semgrep.json")
        for skipped, want in (([], False), (["Dependabot"], True)):
            s = build_payload({"projects": [{"name": "a", "semgrep": ok, "dependabot": none,
                                             "skipped": skipped}]})["sources"]["a: Dependabot"]
            self.assertEqual(s["optional"], want)

    def test_declared_but_empty_sources_are_errors(self):
        ok = os.path.join(FIX, "semgrep.json")
        for extra in ({"snyk": {}}, {"sonarqube": None}, {"trivy": {}}, {"guarddog": {}},
                      {"semgrep": ""}):
            with self.assertRaises(ManifestError, msg=extra):
                build_payload({"projects": [{"name": "a", "semgrep": ok},
                                            dict({"name": "b", "coverage": ok}, **extra)]})

    def test_the_runners_empty_sonarqube_with_a_note_is_still_accepted(self):
        ok = os.path.join(FIX, "semgrep.json")
        p = build_payload({"projects": [{"name": "a", "semgrep": ok, "sonarqube": {},
                                         "notes": {"SonarQube": "docker not on PATH"}}]})
        s = p["sources"]["a: SonarQube"]
        self.assertEqual((s["collected"], s["optional"], s["note"]), (False, False, "docker not on PATH"))
        p = build_payload({"projects": [{"name": "a", "semgrep": ok, "sonarqube": {},
                                         "notes": {"SonarQube": "skipped: not in --tools"},
                                         "skipped": ["SonarQube"]}]})
        self.assertTrue(p["sources"]["a: SonarQube"]["optional"])

    def test_two_sources_with_the_same_key_never_overwrite_each_other(self):
        ok = os.path.join(FIX, "semgrep.json")
        part = tmpjson({"results": [], "errors": [{"level": "warn", "path": "a.py"}]})
        for order in (False, True):
            projects = [{"name": "p1", "label": "A", "trivy": {"X: Semgrep": ok}},
                        {"name": "p2", "label": "A: Trivy X", "semgrep": part}]
            with self.assertRaises(ManifestError):
                build_payload({"projects": projects[::-1] if order else projects})

    # -- the waived count survives export -> digest
    def test_a_sonar_export_round_trips_through_the_digest(self):
        from qsd import runner
        from qsd.parsers import sonarqube as sq
        real = (runner.fetch_all, runner.api, runner.waived_count)
        runner.fetch_all = lambda *a, **k: ([], 0)
        runner.api = lambda *a, **k: {"component": {"measures": [{"metric": "ncloc", "value": "5"}]}}
        results = {}
        try:
            for name, answer in (("count", (7, "")), ("error", (None, "HTTP 500"))):
                runner.waived_count = lambda *a, **k: answer
                d = tempfile.mkdtemp()
                s = runner.Sonar(d)
                try:
                    out = s.export("k", d)
                finally:
                    shutil_rmtree(s.secret_dir)
                results[name] = sq.to_rows(sq.load_files(out), "A")[1]
        finally:
            runner.fetch_all, runner.api, runner.waived_count = real
        self.assertEqual(results["count"]["suppressed"], 7)
        self.assertIn("unavailable", results["error"]["note"])
        self.assertTrue(results["error"]["complete"])

    # -- partial counts distinct files
    def test_partial_counts_distinct_files_not_warnings(self):
        w = lambda *paths: semgrep.load(tmpjson({"results": [], "errors": [
            {"level": "warn", **({"path": p} if p else {})} for p in paths]}), "A")[1]
        self.assertEqual(w("x.py", "x.py")["partial"], 1)
        self.assertEqual(w("x.py", "y.py", "x.py")["partial"], 2)
        self.assertEqual(w(None, None, "x.py")["partial"], 3)  # a warning with no file counts alone
        self.assertIn("1 file(s)", w("x.py", "x.py")["note"])

    # -- behaviours the review found nothing guarding
    def test_snyk_and_zizmor_waivers_and_dependabot_auto_dismissed_are_counted(self):
        sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [
            {"ruleId": "r", "message": {"text": "x"}, "suppressions": [{"kind": "external"}]},
            {"ruleId": "r2", "message": {"text": "y"}, "suppressions": [{"kind": "inSource"}]}]}]}
        self.assertEqual(snyk.load(tmpjson(sarif), "Code", "A")[1]["suppressed"], 2)
        zz = [{"ident": "i", "desc": "d", "url": "u", "ignored": True,
               "determinations": {"severity": "High", "confidence": "High"}, "locations": []}] * 3
        self.assertEqual(zizmor.load(tmpjson(zz), "A")[1]["suppressed"], 3)
        alert = lambda state: {"state": state, "security_advisory": {"ghsa_id": "GHSA-a-b-" + state,
            "severity": "low", "summary": "s", "identifiers": []},
            "security_vulnerability": {"package": {"name": "p"}}, "dependency": {"manifest_path": "m"}}
        st = dependabot.load(tmpjson([alert("open"), alert("dismissed"), alert("auto_dismissed"),
                                      alert("fixed")]), "A")[1]
        self.assertEqual(st["suppressed"], 2)

    def test_the_column_is_extracted_by_every_parser_that_has_one(self):
        sg = semgrep.load(tmpjson({"results": [{"check_id": "x", "path": "a.py",
            "start": {"line": 3, "col": 9}, "extra": {"severity": "INFO", "message": "m"}}],
            "errors": []}), "A")[0][0]
        self.assertEqual(sg["col"], 9)
        sarif = {"runs": [{"tool": {"driver": {"rules": []}}, "results": [{
            "ruleId": "r", "message": {"text": "x"}, "locations": [{"physicalLocation": {
                "artifactLocation": {"uri": "a.py"}, "region": {"startLine": 2, "startColumn": 5}}}]}]}]}
        self.assertEqual(snyk.load(tmpjson(sarif), "Code", "A")[0][0]["col"], 5)
        zz = [{"ident": "i", "desc": "d", "url": "u", "determinations": {"severity": "High", "confidence": "High"},
               "locations": [{"symbolic": {"key": {"Local": {"verbatim_path": "w.yml"}}, "kind": "Primary"},
                              "concrete": {"location": {"start_point": {"row": 1, "column": 7}}}}]}]
        self.assertEqual(zizmor.load(tmpjson(zz), "A")[0][0]["col"], 7)
        hs = {"issues": {"issues": [], "total": 0}, "hotspots": {"hotspots": [{
            "vulnerabilityProbability": "LOW", "message": "m", "component": "p:a.py", "line": 1,
            "ruleKey": "r", "textRange": {"startOffset": 11}}], "total": 1},
            "measures": {"component": {"measures": [{"metric": "ncloc", "value": "3"}]}}}
        self.assertEqual(sonarqube.to_rows(hs, "A")[0][0]["col"], 11)

    def test_a_merged_rows_other_sightings_keep_their_column(self):
        rows, _ = dedup([row(ids=["CVE-1"], package="a", col=4),
                         row(src="Dependabot", ids=["CVE-1"], package="a", col=9)])
        self.assertEqual(rows[0]["also"][0]["col"], 9)

    def test_semgrep_public_mode_drops_the_token_and_ci_mode_forwards_the_branch(self):
        from qsd import runner
        seen = {}
        real_run, real_env = runner.run, dict(os.environ)
        runner.run = lambda cmd, logfile, cwd=None, env=None: (seen.update(cmd=cmd, env=env) or 2)
        os.environ["SEMGREP_APP_TOKEN"] = "secret-token"
        try:
            d = tempfile.mkdtemp()
            notes = {}
            runner._semgrep({"name": "a", "repo": "o/r", "semgrep_branch": "release/v1"}, d,
                            os.path.join(d, "o.json"), os.path.join(d, "l.log"), notes, "public")
            self.assertNotIn("SEMGREP_APP_TOKEN", seen["env"])
            self.assertEqual(seen["cmd"][:2], ["semgrep", "scan"])
            runner._semgrep({"name": "a", "repo": "o/r", "semgrep_branch": "release/v1"}, d,
                            os.path.join(d, "o.json"), os.path.join(d, "l.log"), notes, "ci")
            self.assertEqual(seen["env"]["SEMGREP_BRANCH"], "release/v1")
            self.assertEqual(seen["cmd"][:2], ["semgrep", "ci"])
        finally:
            runner.run = real_run
            os.environ.clear()
            os.environ.update(real_env)

    def test_the_clamav_container_command_reports_a_freshclam_failure(self):
        from qsd import runner
        seen = {}
        real = (runner.have, runner._clamav_db_ready, subprocess.run)
        runner.have = lambda t: t == "docker"
        runner._clamav_db_ready = lambda: False
        subprocess.run = lambda cmd, **kw: (seen.update(cmd=cmd) or subprocess.CompletedProcess(cmd, 0))
        try:
            d = tempfile.mkdtemp()
            runner._clamav(d, os.path.join(d, "c.txt"), os.path.join(d, "l.log"), {})
        finally:
            runner.have, runner._clamav_db_ready, subprocess.run = real
        self.assertIn("# qsd: freshclam failed", " ".join(seen["cmd"]))


class ReviewRound4(unittest.TestCase):
    """Opus final review: each test fails if its fix is reverted."""

    def reject(self, text):
        from qsd import runner
        d = tempfile.mkdtemp()
        with open(os.path.join(d, "sonar-project.properties"), "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        runner._reject_dangerous_sonar_properties(d)

    def test_lines_end_only_at_the_characters_java_ends_them(self):
        from qsd import runner
        # Python's str.splitlines() also splits on these; Java does not. A comment ending in
        # one of them plus a trailing backslash must not swallow the next (forbidden) key.
        for ch in ("\x0c", "\x0b", "\x85", "\u2028", "\u2029", "\x1c", "\x1d", "\x1e"):
            text = f"# harmless comment{ch}see below \\\nsonar.scanner.proxyHost=attacker\nsonar.sources=x\n"
            with self.assertRaises(runner.SonarError, msg=repr(ch)):
                self.reject(text)
        self.assertEqual(runner._properties_keys("a=1\r\nb=2\rc=3\nd=4"), ["a", "b", "c", "d"])

    def test_a_key_split_across_a_continuation_with_leading_spaces_is_still_found(self):
        from qsd import runner
        self.assertEqual(runner._properties_keys("sonar.lo\\\n   gin=x\n"), ["sonar.login"])
        with self.assertRaises(runner.SonarError):
            self.reject("sonar.lo\\\n   gin=x\n")

    def test_the_scanner_user_home_is_pinned_and_forbidden_in_the_file(self):
        from qsd import runner
        seen = {}
        real = runner.run
        def fake(cmd, logfile, cwd=None, env=None):
            seen["cmd"] = cmd
            open(logfile, "w").close()
            return 1
        runner.run = fake
        try:
            d = tempfile.mkdtemp()
            s = runner.Sonar(d)
            try:
                s.scan(d, "k", os.path.join(d, "x.log"))
            except runner.SonarError:
                pass
            finally:
                shutil_rmtree(s.secret_dir)
        finally:
            runner.run = real
        self.assertIn("-Dsonar.userHome=/tmp/.sonar", seen["cmd"])
        with self.assertRaises(runner.SonarError):
            self.reject("sonar.userHome=/usr/src/evil\n")

    def test_clamav_needs_its_scan_summary_to_count_as_a_finished_scan(self):
        mk = lambda text: os.path.join(tempfile.mkdtemp(), "c.txt")
        for content in ("", "{}", "hello", "# qsd clamav\n"):
            f = mk(content)
            with open(f, "w") as fh:
                fh.write(content)
            _, st = clamav.load(f, "A")
            self.assertFalse(st["complete"], repr(content))
            self.assertIn("no scan summary", st["note"])
        f = mk("")
        with open(f, "w") as fh:
            fh.write("----------- SCAN SUMMARY -----------\nScanned files: 0\nInfected files: 0\n")
        _, st = clamav.load(f, "A")
        self.assertFalse(st["complete"])
        self.assertIn("scanned 0 files", st["note"])
        self.assertTrue(clamav.load(fx("clamav.txt"), "A")[1]["complete"])

    def test_clamav_commands_keep_the_summary_on(self):
        from qsd import runner
        for native in (True, False):
            seen = {}
            real = (runner.have, runner._clamav_db_ready, subprocess.run)
            runner.have = lambda t: True
            runner._clamav_db_ready = lambda n=native: n
            subprocess.run = lambda cmd, **kw: (seen.update(cmd=cmd) or subprocess.CompletedProcess(cmd, 0))
            try:
                d = tempfile.mkdtemp()
                runner._clamav(d, os.path.join(d, "c.txt"), os.path.join(d, "l.log"), {})
            finally:
                runner.have, runner._clamav_db_ready, subprocess.run = real
            self.assertNotIn("--no-summary", " ".join(seen["cmd"]), native)

    def test_the_manifest_settings_default_governs_partly_parsed_files(self):
        f = tmpjson({"results": [], "errors": [{"level": "warn", "path": "a.py"}]})
        mk = lambda settings, **proj: build_payload({"settings": settings, "projects": [
            dict({"name": "a", "semgrep": f}, **proj)]})["sources"]["a: Semgrep"]["complete"]
        self.assertTrue(mk({}))
        self.assertFalse(mk({"semgrep_partial_is_gap": True}))
        self.assertTrue(mk({"semgrep_partial_is_gap": True}, semgrep_partial_is_gap=False))

    def test_colliding_tracks_differ_by_message_not_by_an_ordinal(self):
        t = {"SchemaVersion": 2, "Results": [{"Target": "Dockerfile", "Misconfigurations": [
            {"ID": "DS-1", "Message": "secret A", "Severity": "HIGH", "CauseMetadata": {"StartLine": 7}},
            {"ID": "DS-1", "Message": "secret B", "Severity": "HIGH", "CauseMetadata": {"StartLine": 7}}]}]}
        tracks = [r["track"] for r in build_payload({"projects": [
            {"name": "a", "trivy": {"Config": tmpjson(t)}}]})["findings"]]
        self.assertEqual(len(set(tracks)), 2)
        self.assertFalse(any(x.endswith(("-2", "-3")) for x in tracks), tracks)


class GitCheckoutsInContainers(unittest.TestCase):
    """Gitleaks scans a worktree or submodule from a container: git needs its git directory."""

    def worktree(self):
        d = tempfile.mkdtemp()
        common = os.path.join(d, "main", ".git", "modules", "be")
        gitdir = os.path.join(common, "worktrees", "wt")
        os.makedirs(gitdir)
        with open(os.path.join(gitdir, "commondir"), "w") as fh:
            fh.write("../..\n")
        checkout = os.path.join(d, "wt")
        os.mkdir(checkout)
        with open(os.path.join(checkout, ".git"), "w") as fh:
            fh.write(f"gitdir: {gitdir}\n")
        return checkout, common, gitdir

    def test_a_worktree_mounts_its_common_git_dir_at_the_path_the_dotgit_file_expects(self):
        from qsd.runner import _git_mounts
        checkout, common, _ = self.worktree()
        self.assertEqual(_git_mounts(checkout), ["-v", f"{common}:{common}:ro"])

    def test_a_submodule_mounts_its_relative_gitdir_where_the_container_will_look(self):
        from qsd.runner import _git_mounts
        d = tempfile.mkdtemp()
        host = os.path.join(d, ".git", "modules", "x")
        os.makedirs(host)
        checkout = os.path.join(d, "sub")
        os.mkdir(checkout)
        with open(os.path.join(checkout, ".git"), "w") as fh:
            fh.write("gitdir: ../.git/modules/x\n")
        self.assertEqual(_git_mounts(checkout), ["-v", f"{host}:/.git/modules/x:ro"])

    def test_a_plain_repository_or_no_repository_needs_no_extra_mount(self):
        from qsd.runner import _git_mounts
        plain = tempfile.mkdtemp()
        os.mkdir(os.path.join(plain, ".git"))
        self.assertEqual(_git_mounts(plain), [])
        self.assertEqual(_git_mounts(tempfile.mkdtemp()), [])
        odd = tempfile.mkdtemp()
        with open(os.path.join(odd, ".git"), "w") as fh:
            fh.write("not a gitdir line")
        self.assertEqual(_git_mounts(odd), [])

    def test_the_gitleaks_container_command_carries_those_mounts(self):
        from qsd import runner
        checkout, common, _ = self.worktree()
        seen = {}
        real = (runner.have, subprocess.run)
        runner.have = lambda t: t == "docker"
        subprocess.run = lambda cmd, **kw: (seen.update(cmd=cmd) or subprocess.CompletedProcess(cmd, 0))
        try:
            d = tempfile.mkdtemp()
            runner._gitleaks({"name": "a"}, checkout, os.path.join(d, "g.json"),
                             os.path.join(d, "l.log"), {})
        finally:
            runner.have, subprocess.run = real
        cmd = seen["cmd"]
        self.assertIn(f"{common}:{common}:ro", cmd)
        self.assertIn(f"{checkout}:/repo:ro", cmd)
        self.assertLess(cmd.index(f"{common}:{common}:ro"), cmd.index(runner.GITLEAKS_IMAGE))


if __name__ == "__main__":
    unittest.main()
