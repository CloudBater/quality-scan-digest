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
        # Partly parsed files are a coverage gap by default; opt out with partial_is_gap=False.
        warn = tmpjson({"results": [], "errors": [{"level": "warn"}]})
        _, st = semgrep.load(warn, "A")
        self.assertEqual((st["complete"], st["note"]),
                         (False, "incomplete: 1 file(s) only partly parsed"))
        _, st = semgrep.load(warn, "A", partial_is_gap=False)
        self.assertEqual((st["complete"], st["note"]), (True, "1 file(s) only partly parsed"))
        # A hard error is a gap either way.
        hard = tmpjson({"results": [], "errors": [{"level": "error"}, {"level": "warn"}]})
        for gap in (False, True):
            self.assertFalse(semgrep.load(hard, "A", partial_is_gap=gap)[1]["complete"])

    def test_semgrep_partial_parse_setting_reaches_the_report_and_the_manifest(self):
        from qsd import runner
        f = tmpjson({"results": [], "errors": [{"level": "warn"}]})
        # Omitted → default gap (complete False). Explicit False keeps complete.
        src = build_payload({"projects": [{"name": "a", "semgrep": f}]})["sources"]["a: Semgrep"]
        self.assertFalse(src["complete"])
        for flag in (False, True):
            src = build_payload({"projects": [{"name": "a", "semgrep": f,
                                               "semgrep_partial_is_gap": flag}]})["sources"]["a: Semgrep"]
            self.assertEqual(src["complete"], not flag)
        with tempfile.TemporaryDirectory() as d:
            m, _ = runner.scan({"projects": [{"name": "a", "path": "."}]}, d, os.path.join(d, "o"),
                               tools=())
            self.assertIs(m["projects"][0]["semgrep_partial_is_gap"], True)
            self.assertIs(m["settings"]["semgrep_partial_is_gap"], True)
            m2, _ = runner.scan({"projects": [{"name": "a", "path": "."}],
                                 "semgrep_partial_is_gap": False}, d, os.path.join(d, "o2"), tools=())
            self.assertIs(m2["settings"]["semgrep_partial_is_gap"], False)
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
        self.assertEqual(self.p["schema_version"], "1.1")
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
        self.assertEqual(set(src), {"collected", "complete", "note", "suppressed", "optional"})

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
        p = build_payload({"version": None, "projects": [{"name": "a", "repo": None}]})
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
            self.assertEqual(p["schema_version"], "1.1")
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
                              "suppressed": 0, "optional": False})
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
        get = lambda **kw: build_payload({"projects": [dict({"name": "a"}, **kw)]})[
            "generated_from"][0]["commit_dirty"]
        self.assertIsNone(get())
        self.assertIsNone(get(commit_dirty=None))
        self.assertIs(get(commit_dirty=False), False)
        self.assertIs(get(commit_dirty=True), True)
        self.assertIs(get(commit_dirty=1), True)
        self.assertIs(get(commit_dirty="false"), False)
        self.assertIs(get(commit_dirty="true"), True)
        self.assertIsNone(get(commit_dirty="maybe"))
        html = render(build_payload({"projects": [{"name": "a"}]}))
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
        self.assertIn("-Dsonar.nodejs.executable=node", seen["cmd"])

    def test_checkout_sonar_properties_cannot_set_an_executable(self):
        from qsd import runner
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "sonar-project.properties"), "w") as fh:
                fh.write("sonar.nodejs.executable=/usr/src/evil\n")
            with self.assertRaises(runner.SonarError) as ctx:
                runner._reject_dangerous_sonar_properties(d)
            self.assertIn("nodejs.executable", str(ctx.exception))
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


if __name__ == "__main__":
    unittest.main()
