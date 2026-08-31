"""Tests for turning the filled writeup into a page.

The renderer exists to remove a copy-and-paste from the chain between
research/aggregate.json and the published URL, because that is where a number
drifts one last time. So the failures worth guarding against are the quiet
ones: a paragraph silently dropped because its markdown isn't supported, an
unfilled placeholder reaching a reader, markup in the source becoming markup
in the page.
"""

import contextlib
import importlib.util
import io
import re
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location(
    "render_post", ROOT / "scripts" / "render_post.py")
rp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(rp)


class TestBlocks(unittest.TestCase):
    def test_headings(self):
        self.assertIn("<h1>Title</h1>", rp.render_body("# Title"))
        self.assertIn("<h2>Section</h2>", rp.render_body("## Section"))

    def test_a_wrapped_paragraph_becomes_one_paragraph(self):
        out = rp.render_body("one line\nand its continuation\n")
        self.assertEqual(out.count("<p>"), 1)
        self.assertIn("one line and its continuation", out)

    def test_a_list(self):
        out = rp.render_body("- first\n- second\n")
        self.assertIn("<li>first</li>", out)
        self.assertIn("<li>second</li>", out)

    def test_a_wrapped_list_item_stays_one_item(self):
        out = rp.render_body("- first part\n  second part\n- other\n")
        self.assertIn("<li>first part second part</li>", out)
        self.assertEqual(out.count("<li>"), 2)

    def test_a_code_fence_is_not_reflowed(self):
        out = rp.render_body("```\npython3 -m vibecheck .\npython3 -m vibecheck --url x\n```")
        self.assertIn("python3 -m vibecheck .\npython3 -m vibecheck --url x", out)

    def test_a_rule(self):
        self.assertIn("<hr>", rp.render_body("---"))

    def test_comments_are_dropped(self):
        out = rp.render_body("<!-- a note to the author -->\nvisible text\n")
        self.assertNotIn("note to the author", out)
        self.assertIn("visible text", out)


class TestInline(unittest.TestCase):
    def test_code_link_and_emphasis(self):
        self.assertIn("<code>innerHTML</code>", rp.inline("`innerHTML`"))
        self.assertIn('<a href="https://x.dev">x</a>', rp.inline("[x](https://x.dev)"))
        self.assertIn("<strong>bold</strong>", rp.inline("**bold**"))
        self.assertIn("<em>quiet</em>", rp.inline("*quiet*"))

    def test_emphasis_can_span_a_wrapped_line(self):
        # The signoff is italic across two source lines.
        out = rp.render_body("*i'm Joel. i build small tools,\nmostly in the evenings.*")
        self.assertIn("<em>", out)
        self.assertNotIn("*", out)

    def test_markup_in_the_text_is_escaped_not_executed(self):
        out = rp.inline("a <script>alert(1)</script> in prose")
        self.assertNotIn("<script>", out)
        self.assertIn("&lt;script&gt;", out)

    def test_code_contents_are_escaped_too(self):
        out = rp.render_body("```\n<img onerror=x>\n```")
        self.assertNotIn("<img", out)
        self.assertIn("&lt;img", out)


class TestItRefusesRatherThanDropping(unittest.TestCase):
    """Silently losing content is the failure nobody notices."""

    def test_an_unsupported_construct_is_an_error(self):
        for source in ("> a blockquote", "| a | table |", "1. an ordered item"):
            with self.subTest(source):
                with self.assertRaises(ValueError):
                    rp.render_body(source)

    def test_an_unterminated_fence_is_an_error(self):
        with self.assertRaises(ValueError):
            rp.render_body("```\nnever closed\n")

    def test_the_error_names_the_line(self):
        with self.assertRaises(ValueError) as caught:
            rp.render_body("fine\n\n> not fine\n")
        self.assertIn("3", str(caught.exception))


class TestTheRealWriteup(unittest.TestCase):
    """The template is the thing this exists to render."""

    def filled(self):
        template = (ROOT / "content" / "scanned-vibe-coded-apps.md").read_text(
            encoding="utf-8")
        _, _, body = template.partition("-->")
        return re.sub(r"\{\{[A-Z0-9_]+\}\}", "42", body)

    def test_it_renders_without_hitting_an_unsupported_construct(self):
        body = rp.render_body(self.filled())
        self.assertIn("<h1>", body)
        self.assertIn("<h2>", body)
        self.assertIn("<ul>", body)
        self.assertIn("<pre><code>", body)

    def test_no_markdown_syntax_survives_into_the_page(self):
        body = rp.render_body(self.filled())
        for leftover in ("**", "`", "](", "<!--"):
            with self.subTest(leftover):
                self.assertNotIn(leftover, body)

    def test_every_paragraph_of_the_source_reaches_the_page(self):
        # The count guards against a construct being skipped rather than
        # raising — the whole point of refusing on unknown syntax.
        source = self.filled()
        blocks = rp.blocks(source)
        self.assertGreater(len(blocks), 25)


class TestEndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def run_it(self, source, *extra):
        src = self.dir / "post.md"
        src.write_text(source, encoding="utf-8")
        out = self.dir / "post.html"
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = rp.main([str(src), "--slug", "a-post", "--title", "A Post",
                            "--description", "d" * 60, "--out", str(out), *extra])
        return code, out, buf.getvalue()

    def test_a_page_comes_out_in_the_house_style(self):
        code, out, _ = self.run_it("# Hi\n\nsome prose.\n")
        self.assertEqual(code, 0)
        page = out.read_text(encoding="utf-8")
        self.assertIn('<link rel="stylesheet" href="/guide.css">', page)
        self.assertIn('<link rel="canonical" href="https://psychosecurity.io/posts/a-post">', page)
        self.assertIn('<meta property="og:url" content="https://psychosecurity.io/posts/a-post">', page)
        self.assertIn("vibe<span>check</span>", page)

    def test_an_unfilled_placeholder_is_refused(self):
        code, out, output = self.run_it("# Hi\n\nthe median was {{MEDIAN_SCORE}}.\n")
        self.assertEqual(code, 1)
        self.assertIn("MEDIAN_SCORE", output)
        self.assertFalse(out.exists(), "wrote a page containing a placeholder")

    def test_a_missing_source_is_an_error_not_a_traceback(self):
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
            code = rp.main([str(self.dir / "nope.md"), "--slug", "s",
                            "--title", "t", "--description", "d" * 60])
        self.assertEqual(code, 1)

    def test_it_says_that_committing_is_publishing(self):
        # The repository is public, so the render step is not the risky one.
        _, _, output = self.run_it("# Hi\n\nprose.\n")
        self.assertIn("committing it is publishing it", output)

    def test_the_page_links_back_to_the_guides_and_the_tool(self):
        _, out, _ = self.run_it("# Hi\n\nprose.\n")
        page = out.read_text(encoding="utf-8")
        self.assertIn('href="/guides/api-key-leaked"', page)
        self.assertIn('class="btn" href="/"', page)


if __name__ == "__main__":
    unittest.main()
