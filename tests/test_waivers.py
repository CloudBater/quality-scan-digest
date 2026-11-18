"""The waiver file (.qsdignore): parsing, matching, the guardrails, and what the report says."""

import datetime as dt
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src"))

from qsd import waivers  # noqa: E402
from qsd.html_report import render  # noqa: E402
from qsd.report import build_payload  # noqa: E402
from qsd.runner import ConfigError, validate as validate_config  # noqa: E402
from tests.test_digest import FIX, fx, load_manifest  # noqa: E402

TODAY = dt.date(2026, 11, 18)
OK = 'reason="why" until=2027-05-01'
# Rows of the fixture report used below.
SMELL = 'src=Semgrep ref="python.lang.best-practice.open-never-closed"'      # rank 2, one scanner
SMELL_LOC = "app/io.py"
HIGH_IAC = "ref=SNYK-CC-K8S-1"                                              # rank 1


def lines(*ls):
    return "\n".join(ls) + "\n"


def tmpfile(text, suffix=".qsdignore"):
    fd, path = tempfile.mkstemp(suffix=suffix)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def build(text, today=TODAY, **extra):
    m = load_manifest()
    m["ignore_file"] = tmpfile(text)
    m.update(extra)
    return build_payload(m, today=today)


def by_ref(p, ref):
    return [r for r in p["findings"] if r["ref"] == ref]


class Parse(unittest.TestCase):
    def parse(self, text):
        return waivers.parse(text, TODAY)

    def bad(self, text, *needles):
        with self.assertRaises(waivers.WaiverError) as cm:
            self.parse(text)
        for n in needles:
            self.assertIn(n, str(cm.exception))

    def test_a_complete_line_parses(self):
        (w,) = self.parse(f'ignore {SMELL} loc="app/*" expect=2 {OK} ticket=PROJ-1\n')
        self.assertEqual((w.verb, w.src, w.loc, w.expect, w.ticket, w.line),
                         ("ignore", "Semgrep", "app/*", 2, "PROJ-1", 1))
        self.assertEqual(w.until, dt.date(2027, 5, 1))

    def test_comments_blank_lines_and_quoting(self):
        ws = self.parse("# a comment\n\n"
                        f'ignore ref="a # b" {OK}  # trailing comment\n'
                        f"track ref=x ticket=P-1 reason='single quoted, ok' until=2027-05-01\n")
        self.assertEqual([w.line for w in ws], [3, 4])
        self.assertEqual(ws[0].ref, "a # b")
        self.assertEqual(ws[1].reason, "single quoted, ok")

    def test_required_fields(self):
        self.bad("ignore ref=x until=2027-05-01\n", "line 1", "reason is required")
        self.bad('ignore ref=x reason="r"\n', "until is required")
        self.bad(f"track ref=x {OK}\n", "track needs a ticket")

    def test_the_first_word_must_be_a_verb(self):
        self.bad(f"skip ref=x {OK}\n", "ignore or track")
        self.bad(f"ref=x {OK}\n", "ignore or track")

    def test_a_line_that_matches_nothing_in_particular_is_refused(self):
        self.bad(f"ignore {OK}\n", "at least one of")
        self.bad(f"ignore project=api {OK}\n", "project", "everything")

    def test_unknown_duplicate_and_empty_keys(self):
        self.bad(f"ignore ref=x {OK} colour=red\n", "colour=red")
        self.bad(f"ignore ref=x ref=y {OK}\n", "ref is given twice")
        self.bad(f'ignore ref= {OK}\n', "ref is empty")
        self.bad(f"ignore ref=x {OK} stray\n", "stray")
        self.bad(f'ignore ref=x {OK} line=12\n', "line=12")   # no line numbers: they drift

    def test_src_must_be_a_real_scanner(self):
        self.bad(f"ignore src=Semgerp {OK}\n", "not a scanner")

    def test_the_expiry_is_a_real_date_and_at_most_12_months_away(self):
        self.bad('ignore ref=x reason=r until=2027/05/01\n', "date like")
        self.bad('ignore ref=x reason=r until=2027-02-30\n', "not a real date")
        limit = TODAY + dt.timedelta(days=366)
        self.parse(f"ignore ref=x reason=r until={limit}\n")
        self.bad(f"ignore ref=x reason=r until={limit + dt.timedelta(days=1)}\n", "12 months")

    def test_expect_is_a_positive_whole_number(self):
        for v in ("0", "-1", "two", "1.5"):
            self.bad(f"ignore ref=x {OK} expect={v}\n", "expect")

    def test_reason_and_ticket_limits(self):
        self.bad(f'ignore ref=x until=2027-05-01 reason="{"x" * 301}"\n', "300")
        self.bad(f'ignore ref=x {OK} ticket="two words"\n', "ticket")

    def test_an_unterminated_quote_names_its_line(self):
        self.bad(f'ignore ref=x {OK}\nignore ref="oops {OK}\n', "line 2")

    def test_source_names_match_the_schema(self):
        with open(os.path.join(FIX, "..", "..", "schema", "report.schema.json")) as fh:
            enum = json.load(fh)["$defs"]["finding"]["properties"]["src"]["enum"]
        self.assertEqual(set(enum), waivers.SOURCES)


class Apply(unittest.TestCase):
    def test_ignore_keeps_the_row_marks_it_and_leaves_it_out_of_the_counts(self):
        base = build("")
        p = build(f"ignore {SMELL} loc={SMELL_LOC} expect=1 {OK}\n")
        (row,) = by_ref(p, "python.lang.best-practice.open-never-closed")
        self.assertEqual(row["waiver"], {"status": "ignore", "reason": "why", "ticket": "",
                                         "until": "2027-05-01", "line": 1})
        self.assertEqual(len(p["findings"]), len(base["findings"]))      # never removed
        a, b = p["generated_from"][0], base["generated_from"][0]
        self.assertEqual((a["findings"], a["waived"]), (b["findings"] - 1, 1))
        self.assertEqual(a["by_source"]["Semgrep"], b["by_source"]["Semgrep"] - 1)
        self.assertEqual((a["security"], a["sec_crit_high"]), (b["security"], b["sec_crit_high"]))

    def test_ignoring_a_security_finding_lowers_the_security_counts(self):
        base = build("")["generated_from"][0]
        p = build(lines(f"ignore {HIGH_IAC} {OK} ticket=P-9"))
        a = p["generated_from"][0]
        self.assertEqual((a["security"], a["sec_crit_high"], a["untracked_crit_high"]),
                         (base["security"] - 1, base["sec_crit_high"] - 1,
                          base["untracked_crit_high"] - 1))

    def test_track_is_still_counted_and_is_not_untracked(self):
        base = build("")["generated_from"][0]
        p = build(lines(f"track {HIGH_IAC} {OK} ticket=P-9"))
        a = p["generated_from"][0]
        (row,) = by_ref(p, "SNYK-CC-K8S-1")
        self.assertEqual(row["waiver"]["status"], "track")
        self.assertEqual(row["waiver"]["ticket"], "P-9")
        self.assertEqual((a["findings"], a["security"], a["sec_crit_high"]),
                         (base["findings"], base["security"], base["sec_crit_high"]))
        self.assertEqual((a["tracked"], a["waived"], a["untracked_crit_high"]),
                         (1, 0, base["untracked_crit_high"] - 1))

    def test_without_a_file_nothing_changes_but_the_new_fields(self):
        p = build_payload(load_manifest())
        self.assertIsNone(p["waivers"])
        self.assertTrue(all(r["waiver"] is None for r in p["findings"]))
        a = p["generated_from"][0]
        self.assertEqual((a["waived"], a["tracked"]), (0, 0))
        self.assertEqual(a["untracked_crit_high"], a["sec_crit_high"])

    def test_a_line_that_covers_more_than_expect_waives_nothing_and_is_an_error(self):
        p = build(f"ignore src=Semgrep {OK} ticket=P-1 expect=1\n")     # selects every Semgrep-only row
        self.assertTrue(all(r["waiver"] is None for r in p["findings"]))
        self.assertEqual(len(p["waivers"]["errors"]), 1)
        self.assertIn("expect=1", p["waivers"]["errors"][0])

    def test_expect_equal_to_the_matches_is_fine(self):
        n = sum(1 for r in build("")["findings"] if r["by"] == ["Semgrep"])
        p = build(f"ignore src=Semgrep {OK} ticket=P-1 expect={n}\n")
        self.assertEqual(p["waivers"]["errors"], [])

    def test_an_expired_waiver_applies_to_nothing_and_is_listed(self):
        text = f"ignore {SMELL} reason=r until=2027-01-01 expect=1\n"
        p = build(text, today=dt.date(2027, 1, 2))
        self.assertTrue(all(r["waiver"] is None for r in p["findings"]))
        self.assertEqual(p["waivers"]["expired"], [1])
        self.assertIn("expired", p["waivers"]["errors"][0])
        # The last day still counts.
        q = build(text, today=dt.date(2027, 1, 1))
        self.assertEqual(q["generated_from"][0]["waived"], 1)

    def test_a_line_that_matches_nothing_is_reported_as_stale_not_an_error(self):
        p = build(f"ignore ref=NO-SUCH-RULE {OK}\n")
        self.assertEqual(p["waivers"]["stale"], [1])
        self.assertEqual(p["waivers"]["errors"], [])

    def test_the_first_matching_line_owns_a_row(self):
        p = build(f"track {SMELL} {OK} ticket=P-1\nignore {SMELL} {OK}\n")
        (row,) = by_ref(p, "python.lang.best-practice.open-never-closed")
        self.assertEqual(row["waiver"]["line"], 1)
        self.assertEqual(p["waivers"]["stale"], [2])        # the redundant line says so

    def test_src_does_not_waive_a_row_another_scanner_also_saw(self):
        # SNYK-PYTHON-DJANGO-0001 was seen by Snyk, Semgrep, OSV-Scanner and Dependabot.
        p = build(f"ignore src=Snyk ref=SNYK-PYTHON-DJANGO-0001 {OK} ticket=P-1\n")
        (row,) = by_ref(p, "SNYK-PYTHON-DJANGO-0001")
        self.assertIsNone(row["waiver"])
        self.assertEqual(p["waivers"]["stale"], [1])

    def test_ref_also_matches_advisory_ids_and_loc_is_a_glob(self):
        p = build(f"ignore ref=CVE-2099-0002 loc='requests@*' {OK} ticket=P-1\n")
        (row,) = by_ref(p, "SNYK-PYTHON-REQUESTS-0002")
        self.assertEqual(row["waiver"]["status"], "ignore")
        q = build(f"ignore ref=CVE-2099-0002 loc='flask@*' {OK} ticket=P-1\n")
        self.assertIsNone(by_ref(q, "SNYK-PYTHON-REQUESTS-0002")[0]["waiver"])

    def test_glob_is_case_sensitive_and_anchored(self):
        p = build(f"ignore ref='python.lang.*' {OK}\n")
        self.assertIsNotNone(by_ref(p, "python.lang.best-practice.open-never-closed")[0]["waiver"])
        for pat in ("PYTHON.lang.*", "lang.best*", "python.lang"):
            q = build(f"ignore ref='{pat}' {OK}\n")
            self.assertIsNone(by_ref(q, "python.lang.best-practice.open-never-closed")[0]["waiver"], pat)

    def test_project_narrows_a_line(self):
        p = build(f"ignore {SMELL} project=api {OK}\n")
        self.assertEqual(p["generated_from"][0]["waived"], 1)
        q = build(f"ignore {SMELL} project=other {OK}\n")
        self.assertEqual(q["generated_from"][0]["waived"], 0)

    def test_the_exact_track_key_selects_one_row(self):
        base = build("")
        key = by_ref(base, "python.lang.best-practice.open-never-closed")[0]["track"]
        p = build(f"ignore track={key} {OK}\n")
        self.assertEqual(p["generated_from"][0]["waived"], 1)
        self.assertEqual(sum(1 for r in p["findings"] if r["waiver"]), 1)

    def test_high_and_above_need_a_ticket(self):
        with self.assertRaises(waivers.WaiverError) as cm:
            build(f"ignore {HIGH_IAC} {OK}\n")
        self.assertIn("ticket", str(cm.exception))
        self.assertIn("line 1", str(cm.exception))
        build(f"ignore {HIGH_IAC} {OK} ticket=P-1\n")                # with one: fine

    def test_a_pattern_cannot_waive_a_secret_or_malware_only_its_exact_key_can(self):
        for ref in ("github-pat", "Eicar-Test-Signature", "MAL-2099-1"):
            with self.assertRaises(waivers.WaiverError, msg=ref) as cm:
                build(f"ignore ref={ref} {OK} ticket=P-1\n")
            self.assertIn("one by one", str(cm.exception))
        base = build("")
        key = by_ref(base, "github-pat")[0]["track"]
        p = build(f"ignore track={key} {OK} ticket=P-1\n")
        self.assertEqual(by_ref(p, "github-pat")[0]["waiver"]["status"], "ignore")
        self.assertEqual(p["generated_from"][0]["malware"], base["generated_from"][0]["malware"])

    def test_the_waivers_block_and_the_file_sha(self):
        text = f"# header\nignore {SMELL} {OK} expect=1\ntrack {HIGH_IAC} {OK} ticket=P-9\n"
        path = tmpfile(text)
        m = load_manifest()
        m["ignore_file"] = path
        p = build_payload(m, today=TODAY)
        w = p["waivers"]
        with open(path, "rb") as fh:
            self.assertEqual(w["sha256"], hashlib.sha256(fh.read()).hexdigest())
        self.assertEqual(w["file"], os.path.basename(path))          # a name, never a path
        self.assertNotIn(os.path.dirname(path), json.dumps(p))
        self.assertEqual([(x["line"], x["status"], x["matched"]) for x in w["lines"]],
                         [(2, "ignore", 1), (3, "track", 1)])

    def test_an_unreadable_or_oversized_file_is_an_error_not_no_waivers(self):
        m = load_manifest()
        m["ignore_file"] = "/no/such/file"
        with self.assertRaises(waivers.WaiverError):
            build_payload(m, today=TODAY)
        big = tmpfile("#" * (waivers.MAX_BYTES + 1))
        with self.assertRaises(waivers.WaiverError):
            waivers.load(big, TODAY)
        binary = tmpfile("")
        with open(binary, "wb") as fh:
            fh.write(b"\xff\xfe\x00")
        with self.assertRaises(waivers.WaiverError):
            waivers.load(binary, TODAY)

    def test_the_file_is_never_found_by_itself(self):
        # A waiver file lying next to the manifest, or in the working directory, is not read.
        for where in (FIX, os.getcwd()):
            path = os.path.join(where, ".qsdignore")
            self.assertFalse(os.path.exists(path), "test precondition")
        old = os.getcwd()
        d = tempfile.mkdtemp()
        with open(os.path.join(d, ".qsdignore"), "w") as fh:
            fh.write(f"ignore ref=NO-SUCH {OK}\n")
        os.chdir(d)
        try:
            self.assertIsNone(build_payload(load_manifest(), today=TODAY)["waivers"])
        finally:
            os.chdir(old)

    def test_a_waiver_file_inside_a_scanned_checkout_is_refused(self):
        base = tempfile.mkdtemp()
        os.makedirs(os.path.join(base, "repo", "sub"))
        for inside in ("repo/.qsdignore", "repo/sub/x", "./repo/../repo/.qsdignore"):
            with open(os.path.join(base, "repo", ".qsdignore"), "w") as fh:
                fh.write("")
            cfg = {"projects": [{"name": "api", "path": "repo"}], "ignore_file": inside}
            if inside == "repo/sub/x":
                open(os.path.join(base, inside), "w").close()
            with self.assertRaises(ConfigError, msg=inside) as cm:
                validate_config(cfg, base)
            self.assertIn("inside the scanned checkout", str(cm.exception))
        outside = os.path.join(base, "owner.qsdignore")
        open(outside, "w").close()
        validate_config({"projects": [{"name": "api", "path": "repo"}], "ignore_file": outside}, base)

    def test_a_symlink_into_the_checkout_does_not_get_around_that(self):
        base = tempfile.mkdtemp()
        os.makedirs(os.path.join(base, "repo"))
        open(os.path.join(base, "repo", ".qsdignore"), "w").close()
        os.symlink(os.path.join(base, "repo", ".qsdignore"), os.path.join(base, "link"))
        with self.assertRaises(ConfigError):
            validate_config({"projects": [{"name": "api", "path": "repo"}], "ignore_file": "link"}, base)


class Output(unittest.TestCase):
    def test_the_html_lists_waived_rows_in_their_own_section_and_tiles(self):
        p = build(f"ignore {SMELL} {OK} expect=1\ntrack {HIGH_IAC} {OK} ticket=P-9\n")
        page = render(p)
        self.assertIn("Untracked crit + high", page)
        self.assertIn("Ignored by waiver file", page)
        self.assertIn('id="waived"', page)
        self.assertIn("P-9", page)
        plain = render(build_payload(load_manifest()))
        self.assertNotIn("Untracked crit + high", plain)
        self.assertIn('id="waived" class="waived" hidden', plain)    # the section stays hidden

    def test_the_html_escapes_the_waiver_text(self):
        p = build('ignore ref=\'python.lang.*\' reason="<img src=x onerror=alert(1)>" until=2027-05-01\n')
        page = render(p)
        self.assertNotIn("<img src=x", page)
        self.assertIn("\\u003cimg src=x", page)      # inside the JSON in the script

    def test_a_waiver_error_shows_as_a_banner(self):
        p = build(f"ignore src=Semgrep {OK} ticket=P-1 expect=1\n")
        self.assertIn("Waiver problem", render(p))

    def test_the_payload_still_validates_against_the_schema(self):
        try:
            import jsonschema
        except ImportError:
            self.skipTest("jsonschema not installed")
        with open(os.path.join(FIX, "..", "..", "schema", "report.schema.json")) as fh:
            schema = json.load(fh)
        for text in ("", f"ignore {SMELL} {OK}\ntrack {HIGH_IAC} {OK} ticket=P-9\n"):
            jsonschema.validate(json.loads(json.dumps(build(text))), schema)


class Cli(unittest.TestCase):
    def run_cli(self, *args):
        env = dict(os.environ, PYTHONPATH=os.path.join(os.path.dirname(__file__), "..", "src"))
        return subprocess.run([sys.executable, "-m", "qsd", *args], capture_output=True, text=True,
                              env=env)

    def digest(self, text, *flags, today_ok=True):
        out = os.path.join(tempfile.mkdtemp(), "r.json")
        r = self.run_cli("digest", fx("manifest.json"), "--json-out", out, "--ignore-file",
                         tmpfile(text), "--lenient", *flags)
        return r, out

    def test_the_flag_applies_the_file(self):
        r, out = self.digest(f"ignore {SMELL} {OK} expect=1\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("1 ignored, 0 tracked", r.stderr)
        with open(out) as fh:
            self.assertEqual(json.load(fh)["generated_from"][0]["waived"], 1)

    def test_a_bad_file_is_an_error_exit_1_and_writes_no_report(self):
        r, out = self.digest("ignore nonsense\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("error: waiver file line 1", r.stderr)
        self.assertFalse(os.path.exists(out))

    def complete_manifest(self):
        """The fixture without its one missing source, so strict fails only for waivers."""
        m = load_manifest()
        del m["projects"][0]["snyk"]["Container"]
        path = os.path.join(tempfile.mkdtemp(), "manifest.json")
        with open(path, "w") as fh:
            json.dump(m, fh)
        return path

    def test_strict_fails_on_an_over_broad_or_expired_waiver_but_lenient_reports_it(self):
        manifest = self.complete_manifest()
        out = os.path.join(tempfile.mkdtemp(), "r.json")
        text = f"ignore src=Semgrep {OK} ticket=P-1 expect=1\n"
        clean = self.run_cli("digest", manifest, "--json-out", out, "--strict")
        self.assertEqual(clean.returncode, 0, clean.stderr)           # precondition
        for flags, code in (("--strict", 2), ("--lenient", 0)):
            r = self.run_cli("digest", manifest, "--json-out", out, "--ignore-file", tmpfile(text),
                             flags)
            self.assertEqual(r.returncode, code, r.stderr)
            self.assertIn("waiver error", r.stderr)
        self.assertIn("waiver problem", r.stderr + self.run_cli(
            "digest", manifest, "--json-out", out, "--ignore-file", tmpfile(text), "--strict").stderr)

    def test_strict_passes_with_a_healthy_waiver_file(self):
        out = os.path.join(tempfile.mkdtemp(), "r.json")
        r = self.run_cli("digest", self.complete_manifest(), "--json-out", out, "--ignore-file",
                         tmpfile(f"ignore {SMELL} {OK} expect=1\n"), "--strict")
        self.assertEqual(r.returncode, 0, r.stderr)


if __name__ == "__main__":
    unittest.main()
