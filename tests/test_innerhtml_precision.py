"""Separating an XSS hole from a line of ordinary DOM code.

The old rule matched any `.innerHTML =` that wasn't a bare literal, and fired
on 82% of a 189-repo corpus — which is close to "this app is written in
JavaScript". A number that large stops being a finding and becomes a fact
about the language, and putting it at the top of a list of security problems
is how a scanner teaches people to skim past it.

The split is on evidence, not on guessing. If the line names a source an
attacker chooses — the URL, a form field, a request, browser storage — that
is a demonstrated path from stranger to page and it stays a finding. If the
value's origin isn't visible, the pattern is still reported, at low, titled
as what it actually is.

Under-reporting matters more than over-reporting here, so the vague case is
demoted rather than dropped: a real hole the scanner can't prove is still
worth a look.
"""

import unittest

from vibecheck.scanner import scan_files


def scan(line, path="src/app.js"):
    return scan_files([(path, line + "\n")]).findings


def one(line, path="src/app.js"):
    found = scan(line, path)
    assert len(found) == 1, f"expected exactly one finding, got {found}"
    return found[0]


class TestUntrustedSourcesEscalate(unittest.TestCase):
    """Each of these names where the value came from."""

    def assertUntrusted(self, line):
        found = one(line)
        self.assertEqual(found.rule_id, "innerhtml-untrusted-input", line)
        self.assertEqual(found.severity, "medium")

    def test_the_url(self):
        self.assertUntrusted("el.innerHTML = location.hash.slice(1)")
        self.assertUntrusted("el.innerHTML = new URLSearchParams(location.search).get('q')")

    def test_a_request(self):
        self.assertUntrusted("box.innerHTML = req.query.name")
        self.assertUntrusted("box.innerHTML = request.body.comment")

    def test_a_form_field(self):
        self.assertUntrusted("out.innerHTML = document.getElementById('n').value")

    def test_browser_storage(self):
        self.assertUntrusted("d.innerHTML = localStorage.getItem('draft')")
        self.assertUntrusted("d.innerHTML = sessionStorage.getItem('draft')")

    def test_router_params(self):
        self.assertUntrusted("el.innerHTML = useParams().slug")

    def test_a_decoded_url_component(self):
        self.assertUntrusted("el.innerHTML = decodeURIComponent(raw)")

    def test_react_with_an_untrusted_value(self):
        self.assertUntrusted(
            "<div dangerouslySetInnerHTML={{__html: req.body.html}} />")


class TestEverythingElseIsDemotedNotDropped(unittest.TestCase):
    """Still reported — the scanner can't see where a variable came from."""

    def assertPattern(self, line):
        found = one(line)
        self.assertEqual(found.rule_id, "innerhtml-assignment", line)
        self.assertEqual(found.severity, "low")

    def test_a_value_of_unknown_origin(self):
        self.assertPattern("el.innerHTML = renderTemplate(rows)")
        self.assertPattern("el.innerHTML = `<b>${count}</b>`")

    def test_react_with_its_own_content(self):
        self.assertPattern("<div dangerouslySetInnerHTML={{__html: marked(body)}} />")

    def test_it_is_reported_rather_than_silently_dropped(self):
        # The demotion must not become a suppression: a real hole the scanner
        # cannot prove is still worth surfacing.
        self.assertTrue(scan("el.innerHTML = buildRow(item)"))

    def test_a_plain_literal_is_still_nothing_at_all(self):
        self.assertEqual(scan("el.innerHTML = '<p>Loading…</p>'"), [])
        self.assertEqual(scan("el.innerHTML = ''"), [])


class TestTheTitlesSayWhichIsWhich(unittest.TestCase):
    """The report has to distinguish them, or the split buys nothing."""

    def test_they_do_not_share_a_title(self):
        risky = one("el.innerHTML = location.hash")
        vague = one("el.innerHTML = renderTemplate(rows)")
        self.assertNotEqual(risky.title, vague.title)
        self.assertIn("user-controlled", risky.title)
        self.assertNotIn("XSS", vague.title)

    def test_the_escalated_fix_prompt_names_the_real_problem(self):
        found = one("el.innerHTML = req.query.q")
        self.assertIn("outside the app", found.fix_prompt)
        self.assertIn("DOMPurify", found.fix_prompt)


class TestContextStillApplies(unittest.TestCase):
    def test_a_test_file_demotes_the_escalated_one_too(self):
        found = one("el.innerHTML = location.hash", path="tests/dom.test.js")
        self.assertEqual(found.severity, "info")

    def test_python_files_do_not_get_the_escalated_rule(self):
        # innerHTML is a browser API; the escalated variant is JS-only.
        self.assertEqual(scan("x.innerHTML = request.args", path="app.py"), [])


if __name__ == "__main__":
    unittest.main()
