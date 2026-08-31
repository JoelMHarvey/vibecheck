"""Every guide has to be wired into four places, and forgetting one is silent.

A guide that isn't in sitemap.xml is invisible to search, which is the entire
point of writing it. A guide that isn't in devserver.py's routing table 404s
locally while working fine in production, so the mistake surfaces as
"the dev server is broken" rather than as itself. A guide with the wrong
canonical URL tells Google the page is a copy of a different one.

None of that fails a build or looks wrong on screen. So it gets asserted here
instead — cheaply, with no browser and no network.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GUIDES = sorted(ROOT.glob("guides/*.html"))
# Empty until the research post is published; the repository is public, so
# committing it is publishing it. These checks apply the moment it lands.
POSTS = sorted(ROOT.glob("posts/*.html"))
SITEMAP = (ROOT / "sitemap.xml").read_text(encoding="utf-8")
DEVSERVER = (ROOT / "scripts" / "devserver.py").read_text(encoding="utf-8")
INDEX = (ROOT / "index.html").read_text(encoding="utf-8")

SITE = "https://psychosecurity.io"


def text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def tag(html: str, pattern: str) -> str:
    found = re.search(pattern, html)
    return found.group(1).strip() if found else ""


class TestGuidesAreWiredIn(unittest.TestCase):
    def test_there_are_guides_to_check(self):
        # Guards against the glob silently matching nothing and every test
        # below passing vacuously.
        self.assertGreaterEqual(len(GUIDES), 8)

    def test_every_guide_is_in_the_sitemap(self):
        for guide in GUIDES:
            with self.subTest(guide.name):
                self.assertIn(f"{SITE}/guides/{guide.stem}<", SITEMAP)

    def test_every_guide_is_routed_by_the_dev_server(self):
        for guide in GUIDES:
            with self.subTest(guide.name):
                self.assertIn(f'"/guides/{guide.stem}": ("guides/{guide.name}"', DEVSERVER)

    def test_every_guide_is_linked_from_the_home_page(self):
        for guide in GUIDES:
            with self.subTest(guide.name):
                self.assertIn(f'href="/guides/{guide.stem}"', INDEX)

    def test_the_sitemap_lists_nothing_that_does_not_exist(self):
        listed = set(re.findall(rf"{re.escape(SITE)}/guides/([\w-]+)<", SITEMAP))
        self.assertEqual(listed - {g.stem for g in GUIDES}, set())


class TestPostsAreWiredIn(unittest.TestCase):
    """A post gets the same treatment as a guide, for the same reasons.

    Nothing here runs until posts/ has a file in it. That is deliberate: the
    research post can't be committed before its disclosure window closes,
    because this repository is public and committing it is publishing it. The
    checks are written now so the page can't land unwired on the day.
    """

    def test_every_post_is_in_the_sitemap(self):
        for post in POSTS:
            with self.subTest(post.name):
                self.assertIn(f"{SITE}/posts/{post.stem}<", SITEMAP)

    def test_every_post_is_reachable_locally(self):
        # Discovered by the dev server rather than listed, so this asserts the
        # discovery still works rather than that somebody remembered.
        for post in POSTS:
            with self.subTest(post.name):
                self.assertIn('ROOT.glob("posts/*.html")', DEVSERVER)

    def test_canonical_matches_the_filename(self):
        for post in POSTS:
            with self.subTest(post.name):
                self.assertEqual(tag(text(post), r'<link rel="canonical" href="([^"]+)"'),
                                 f"{SITE}/posts/{post.stem}")

    def test_open_graph_url_agrees_with_the_canonical(self):
        for post in POSTS:
            html = text(post)
            with self.subTest(post.name):
                self.assertEqual(
                    tag(html, r'<meta property="og:url" content="([^"]+)"'),
                    tag(html, r'<link rel="canonical" href="([^"]+)"'))

    def test_a_post_carries_no_unfilled_placeholder(self):
        for post in POSTS:
            with self.subTest(post.name):
                self.assertNotIn("{{", text(post))

    def test_a_post_sends_the_reader_somewhere(self):
        # The post is the top of the funnel; a dead end wastes the traffic.
        for post in POSTS:
            html = text(post)
            with self.subTest(post.name):
                self.assertIn('href="/guides/', html)


class TestGuideMetadata(unittest.TestCase):
    def test_canonical_matches_the_filename(self):
        # A wrong canonical is the one SEO mistake that actively hurts: it
        # tells Google this page is a duplicate of another one.
        for guide in GUIDES:
            with self.subTest(guide.name):
                canonical = tag(text(guide), r'<link rel="canonical" href="([^"]+)"')
                self.assertEqual(canonical, f"{SITE}/guides/{guide.stem}")

    def test_every_guide_has_a_title_and_a_description(self):
        for guide in GUIDES:
            html = text(guide)
            with self.subTest(guide.name):
                self.assertTrue(tag(html, r"<title>(.+?)</title>"))
                description = tag(html, r'<meta name="description" content="([^"]+)"')
                self.assertGreater(len(description), 50, "too short to be a real snippet")
                self.assertLess(len(description), 200, "will be truncated in results")

    def test_open_graph_url_agrees_with_the_canonical(self):
        for guide in GUIDES:
            html = text(guide)
            with self.subTest(guide.name):
                self.assertEqual(
                    tag(html, r'<meta property="og:url" content="([^"]+)"'),
                    tag(html, r'<link rel="canonical" href="([^"]+)"'),
                )

    def test_stylesheet_is_the_shared_one(self):
        for guide in GUIDES:
            with self.subTest(guide.name):
                self.assertIn('<link rel="stylesheet" href="/guide.css">', text(guide))


class TestInternalLinks(unittest.TestCase):
    """Cross-links between guides are hand-written, so they rot silently."""

    def routes(self):
        known = {f"/guides/{g.stem}" for g in GUIDES}
        known |= {f"/posts/{p.stem}" for p in POSTS}
        known |= {"/", "/guide.css", "/og.png", "/robots.txt", "/sitemap.xml",
                  "/rules.json", "/index.html"}
        return known

    def test_no_guide_links_to_a_page_that_does_not_exist(self):
        known = self.routes()
        for guide in GUIDES + [ROOT / "index.html"]:
            html = text(guide)
            for href in re.findall(r'(?:href|src)="(/[^"#?]*)"', html):
                with self.subTest(f"{guide.name} -> {href}"):
                    self.assertIn(href, known)

    def test_no_guide_only_links_to_itself(self):
        # A page with no outbound links to its siblings is a dead end for both
        # readers and crawlers.
        for guide in GUIDES:
            html = text(guide)
            outbound = {h for h in re.findall(r'href="(/guides/[\w-]+)"', html)
                        if h != f"/guides/{guide.stem}"}
            with self.subTest(guide.name):
                self.assertGreaterEqual(len(outbound), 3)


if __name__ == "__main__":
    unittest.main()
