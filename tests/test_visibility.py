"""Visibility mode: each check against small fake sites, plus the safety
rules the plan says must ship with phase 1. No network."""

from __future__ import annotations

import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))

from vis_fakes import (  # noqa: E402
    LLMS, NOW, ROBOTS, SITEMAP, FakeSite, Fetched, good_home, healthy_site, html, png, sub_page, text,
)

from vibecheck.checks.visibility import config, scan_visibility  # noqa: E402
from vibecheck.core import fetcher as vfetch  # noqa: E402
from vibecheck.checks.visibility.page import fingerprint, parse_page  # noqa: E402
from vibecheck.core.report import render_markdown, render_terminal  # noqa: E402
from vibecheck.checks.visibility.rules import PASSES, RULES  # noqa: E402
from vibecheck.checks.visibility.scan import image_size, parse_sitemap  # noqa: E402

FIXTURES = Path(__file__).resolve().parent.parent / "vibecheck" / "checks" / "visibility" / "fixtures"
BASE = "https://groomly.test"


def run(site, url="groomly.test"):
    return scan_visibility(url, site.fetch, now=NOW)


def ids(result):
    return {f.id for f in result.problems}


def passes(result):
    return {p.id for p in result.passes}


def finding(result, rule_id):
    return next(f for f in result.findings if f.id == rule_id)


class HealthySiteTest(unittest.TestCase):
    def test_a_well_made_site_scores_full_marks(self):
        result = run(healthy_site())
        self.assertEqual(result.problems, [])
        self.assertEqual(result.total, 100)
        self.assertEqual(result.grade, "A")
        self.assertEqual(result.meta["pages_crawled"], 5)

    def test_phase_one_fills_three_categories_and_says_so(self):
        result = run(healthy_site())
        cats = result.category_scores
        self.assertEqual([k for k, v in cats.items() if v is not None], list(config.PHASE1_CATEGORIES))
        self.assertIsNone(cats["positioning"])
        self.assertIn("deeper check", render_terminal(result, use_color=False))

    def test_passes_are_reported(self):
        got = passes(run(healthy_site()))
        for expected in ("server-rendered", "llms-ok", "og-complete", "robots-ok", "sitemap-ok",
                         "https-ok", "host-ok", "org-ok", "trust-ok"):
            self.assertIn(expected, got)


class LovableTemplateTest(unittest.TestCase):
    """A fresh Lovable build: an empty #root, and an SPA host that answers
    every path (robots.txt aside) with index.html."""

    def setUp(self):
        index = (FIXTURES / "lovable-template.html").read_text(encoding="utf-8")
        base = "https://pawprint.test"
        robots = ("User-agent: Googlebot\nAllow: /\n\nUser-agent: Bingbot\nAllow: /\n\n"
                  "User-agent: Twitterbot\nAllow: /\n\nUser-agent: *\nAllow: /\n")
        self.site = FakeSite({
            f"{base}/robots.txt": text(f"{base}/robots.txt", robots),
            f"{base}/": html(f"{base}/", index),
            f"{base}/sitemap.xml": html(f"{base}/sitemap.xml", index),  # SPA fallback
            f"{base}/llms.txt": html(f"{base}/llms.txt", index),
        })
        self.result = scan_visibility("pawprint.test", self.site.fetch, now=NOW)

    def test_flags_the_blank_page_as_high(self):
        f = finding(self.result, "csr-vite")
        self.assertEqual(f.severity, "high")
        self.assertIn("Lovable", f.evidence)
        self.assertIn('<div id="root"> is empty', f.evidence)
        self.assertIn("Vite + React", f.fix_prompt, "the fix prompt is tailored to the builder")
        self.assertNotIn("server-rendered", passes(self.result))

    def test_spa_fallback_is_not_mistaken_for_files(self):
        got = ids(self.result)
        self.assertIn("sitemap-missing", got)
        self.assertIn("llms-missing", got)

    def test_body_checks_dont_pile_on_a_blank_page(self):
        # The blank page is one finding, not ten ("no H1", "no contact", ...).
        got = ids(self.result)
        for noisy in ("h1-missing", "trust-missing", "fragment-sections", "few-internal-links"):
            self.assertNotIn(noisy, got)

    def test_head_checks_still_run(self):
        got = ids(self.result)
        self.assertIn("description-length", got)   # "Lovable Generated Project"
        self.assertIn("canonical-missing", got)
        self.assertIn("og-incomplete", got)          # no og:url


class RobotsTest(unittest.TestCase):
    def site_with(self, robots):
        site = healthy_site()
        site.add(f"{BASE}/robots.txt", text(f"{BASE}/robots.txt", robots))
        return site

    def test_disallow_everything_is_critical_and_stops_the_crawl(self):
        site = self.site_with("User-agent: *\nDisallow: /\n")
        result = run(site)
        f = finding(result, "robots-blocks-search")
        self.assertEqual(f.severity, "critical")
        self.assertIn("Googlebot", f.evidence)
        self.assertIn("robots-blocks-us", ids(result))
        # We obey it ourselves: only the crawl files were read.
        fetched = {u for _m, u in site.requests}
        self.assertNotIn(f"{BASE}/", fetched)
        self.assertNotIn(f"{BASE}/pricing", fetched)
        self.assertLess(result.total, 75)

    def test_our_agent_blocked_but_google_allowed(self):
        site = self.site_with("User-agent: vibecheck-visibility\nDisallow: /\n\nUser-agent: *\nAllow: /\n")
        result = run(site)
        self.assertIn("robots-blocks-us", ids(result))
        self.assertNotIn("robots-blocks-search", ids(result))
        self.assertNotIn(f"{BASE}/", {u for _m, u in site.requests})

    def test_disallowed_pages_are_not_crawled(self):
        site = self.site_with("User-agent: *\nDisallow: /about\nAllow: /\n")
        run(site)
        self.assertNotIn(f"{BASE}/about", {u for _m, u in site.requests})

    def test_ai_crawlers_are_reported_not_scored(self):
        site = self.site_with(ROBOTS + "\nUser-agent: GPTBot\nDisallow: /\n\nUser-agent: CCBot\nDisallow: /\n")
        result = run(site)
        f = finding(result, "ai-crawlers-blocked")
        self.assertEqual(f.severity, "info")
        self.assertIn("GPTBot", f.evidence)
        self.assertIn("ClaudeBot", f.evidence)   # listed as allowed
        self.assertNotIn("ai-search-blocked", ids(result), "GPTBot is a training crawler")
        self.assertEqual(result.total, 100, "blocking AI crawlers is a choice, not a fault")

    def test_ai_search_crawlers_are_reported_apart_from_training(self):
        site = self.site_with(ROBOTS + "\nUser-agent: OAI-SearchBot\nDisallow: /\n")
        result = run(site)
        f = finding(result, "ai-search-blocked")
        self.assertEqual(f.severity, "info")
        self.assertIn("OAI-SearchBot", f.evidence)
        self.assertIn("Claude-SearchBot", f.evidence)   # listed as allowed
        self.assertNotIn("ai-crawlers-blocked", ids(result))
        self.assertNotIn("ai-crawlers-allowed", ids(result))
        self.assertEqual(result.total, 100, "reported, not scored")

    def test_missing_robots_and_html_robots_both_count_as_missing(self):
        site = healthy_site()
        del site.responses[f"{BASE}/robots.txt"]
        self.assertIn("robots-missing", ids(run(site)))
        site = healthy_site()
        site.add(f"{BASE}/robots.txt", html(f"{BASE}/robots.txt", good_home()))
        self.assertIn("robots-missing", ids(run(site)))


class AppPagesAndNoindexTest(unittest.TestCase):
    """Account screens and noindex pages aren't content, so they aren't judged."""

    BLANK = ('<!doctype html><html lang="en"><head><title>Sign in</title></head><body>'
             '<div id="root"></div><script type="module" src="/assets/index-abc.js"></script></body></html>')

    def test_sign_in_and_sign_up_pages_are_not_crawled(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body=(
            '<a href="/sign-in">Sign in</a> <a href="/signup">Start free</a> '
            '<a href="/en/login">Log in</a> <a href="/sign-in/sso-callback">x</a>'))))
        for path in ("/sign-in", "/signup", "/en/login", "/sign-in/sso-callback"):
            site.add(f"{BASE}{path}", html(f"{BASE}{path}", self.BLANK))
        result = run(site)
        fetched = {u for _m, u in site.requests}
        for path in ("/sign-in", "/signup", "/en/login", "/sign-in/sso-callback"):
            self.assertNotIn(f"{BASE}{path}", fetched)
        self.assertEqual(result.problems, [])

    def test_a_page_called_signing_or_authors_is_still_content(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body='<a href="/authors">Authors</a>')))
        site.add(f"{BASE}/authors", html(f"{BASE}/authors", sub_page(f"{BASE}/authors", "Authors")))
        run(site)
        self.assertIn(f"{BASE}/authors", {u for _m, u in site.requests})

    def test_a_noindex_page_is_left_out_of_the_content_checks(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body='<a href="/thanks">x</a>')))
        site.add(f"{BASE}/thanks", html(f"{BASE}/thanks", '<!doctype html><html lang="en"><head>'
                                         '<meta name="robots" content="noindex, nofollow"></head>'
                                         '<body><p>Thanks.</p></body></html>'))
        result = run(site)
        self.assertEqual(result.problems, [], "no title, H1 or description findings for /thanks")

    def test_an_x_robots_tag_header_counts_too(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body='<a href="/draft">x</a>')))
        site.add(f"{BASE}/draft", html(f"{BASE}/draft", "<!doctype html><html><body>tiny</body></html>",
                                       headers={"x-robots-tag": "googlebot: noindex"}))
        self.assertEqual(run(site).problems, [])

    def test_a_noindex_home_page_is_critical(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_head='<meta name="robots" content="noindex">')))
        f = finding(run(site), "home-noindex")
        self.assertEqual(f.severity, "critical")
        self.assertIn("meta", f.evidence)

    def test_a_noindex_header_on_the_home_page_is_critical(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(), headers={"x-robots-tag": "noindex"}))
        self.assertIn("X-Robots-Tag", finding(run(site), "home-noindex").evidence)


class RenderingTest(unittest.TestCase):
    def test_fingerprints(self):
        cases = {
            '<html><head><meta name="author" content="Lovable"></head><body><div id="root"></div></body></html>': "Lovable",
            '<html><body><script id="__NEXT_DATA__"></script></body></html>': "Next.js",
            '<html><body><script type="module" crossorigin src="/assets/index-abc123.js"></script></body></html>': "Vite",
            '<html><body><p>hello</p></body></html>': "",
        }
        for raw, label in cases.items():
            with self.subTest(label):
                _family, got = fingerprint(parse_page("https://x.test/", raw))
                self.assertIn(label, got)

    def test_next_blank_page_gets_the_next_prompt(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", '<html lang="en"><head><title>x</title></head><body>'
                                              '<div id="__next"></div><script src="/_next/static/a.js"></script></body></html>'))
        f = finding(run(site), "csr-next")
        self.assertIn("server components", f.fix_prompt)

    def test_noscript_text_does_not_count_as_content(self):
        raw = "<html><body><noscript>" + "You need to enable JavaScript to run this app. " * 10 + "</noscript><div id=app></div></body></html>"
        self.assertEqual(parse_page("https://x.test/", raw).text, "")


class HeadAndContentTest(unittest.TestCase):
    def test_titles_descriptions_and_duplicates(self):
        site = healthy_site()
        same = sub_page(f"{BASE}/about", "Features")  # same title as /features
        site.add(f"{BASE}/about", html(f"{BASE}/about", same.replace('<meta name="description"', '<meta name="x"')))
        long_title = sub_page(f"{BASE}/pricing", "Pricing " + "and plans " * 8)
        site.add(f"{BASE}/pricing", html(f"{BASE}/pricing", long_title))
        result = run(site)
        got = ids(result)
        self.assertIn("title-duplicate", got)
        self.assertIn("title-long", got)
        self.assertIn("description-missing", got)
        self.assertIn("/about", finding(result, "description-missing").evidence)

    def test_findings_on_many_pages_are_one_finding(self):
        site = healthy_site()
        for path in ("/pricing", "/features", "/about"):
            page = sub_page(f"{BASE}{path}", path[1:].title()).replace('<html lang="en-GB">', "<html>")
            site.add(f"{BASE}{path}", html(f"{BASE}{path}", page))
        result = run(site)
        lang = [f for f in result.findings if f.id == "lang-missing"]
        self.assertEqual(len(lang), 1)
        self.assertIn("(+2 more)", lang[0].path)

    def test_canonical_pointing_elsewhere(self):
        site = healthy_site()
        page = sub_page(f"{BASE}/pricing", "Pricing").replace(f'href="{BASE}/pricing"', f'href="{BASE}/"')
        site.add(f"{BASE}/pricing", html(f"{BASE}/pricing", page))
        self.assertIn("canonical-elsewhere", ids(run(site)))

    def test_h1_and_heading_order(self):
        site = healthy_site()
        page = sub_page(f"{BASE}/about", "About").replace("<h1>About</h1>", "<h1>A</h1><h1>B</h1><h4>deep</h4>")
        site.add(f"{BASE}/about", html(f"{BASE}/about", page))
        got = ids(run(site))
        self.assertIn("h1-multiple", got)
        self.assertIn("heading-skip", got)

    def test_clever_headline_that_names_nothing(self):
        site = healthy_site()
        home = good_home().replace("<h1>Booking software for dog groomers</h1>", "<h1>Less faff. More wag.</h1>")
        site.add(f"{BASE}/", html(f"{BASE}/", home))
        self.assertIn("h1-off-topic", ids(run(site)))

    def test_missing_alt_text(self):
        site = healthy_site()
        imgs = "".join(f'<img src="/p{i}.jpg">' for i in range(5))
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body=imgs)))
        f = finding(run(site), "img-alt-missing")
        self.assertIn("5 of 6", f.evidence)

    def test_a_plainly_free_product_has_stated_its_price(self):
        site = healthy_site()
        home = good_home().replace("It costs £12 a month, flat, with no commission on anything you earn.",
                                   "Groomly is free to use, with no commission on anything you earn.") \
                          .replace('<a href="/pricing">Pricing</a>', "")
        site.add(f"{BASE}/", html(f"{BASE}/", home))
        self.assertNotIn("trust-missing", ids(run(site)))
        # A free trial is not a price.
        site.add(f"{BASE}/", html(f"{BASE}/", home.replace("Groomly is free to use", "Start a free trial")))
        self.assertIn("prices", finding(run(site), "trust-missing").evidence)

    def test_trust_signals(self):
        site = healthy_site()
        bare = good_home().replace('<a href="mailto:hi@groomly.test">Contact</a>', "") \
                          .replace('<a href="/privacy">Privacy</a> Groomly Ltd, registered in England.', "")
        bare = bare.replace('"name":"Groomly Ltd",', '"name":"Groomly",')
        site.add(f"{BASE}/", html(f"{BASE}/", bare))
        f = finding(run(site), "trust-missing")
        self.assertIn("contact", f.evidence)
        self.assertIn("privacy", f.evidence)
        self.assertNotIn("prices", f.evidence)  # "£12 a month" is on the page


class LinkPreviewTest(unittest.TestCase):
    def test_wrong_shape_and_broken_image(self):
        site = healthy_site()
        site.add(f"{BASE}/og.png", Fetched(url=f"{BASE}/og.png", status=200,
                                           headers={"content-type": "image/png"}, body=png(800, 800)))
        result = run(site)
        self.assertIn("800x800", finding(result, "og-image-size").evidence)
        self.assertNotIn("og-complete", passes(result))

        site = healthy_site()
        del site.responses[f"{BASE}/og.png"]
        self.assertIn("og-image-broken", ids(run(site)))

    def test_image_size_reader(self):
        import base64
        self.assertEqual(image_size(png(1200, 630)), (1200, 630))
        self.assertEqual(image_size(b"GIF89a" + (300).to_bytes(2, "little") + (200).to_bytes(2, "little")), (300, 200))
        # A real 1x1 JPEG.
        jpeg = base64.b64decode(
            "/9j/4AAQSkZJRgABAQEASABIAAD/2wBDAP//////////////////////////////////////////////////////////////////////////////////////"
            "wgALCAABAAEBAREA/8QAFBABAAAAAAAAAAAAAAAAAAAAAP/aAAgBAQABPxA=")
        self.assertEqual(image_size(jpeg), (1, 1))
        self.assertIsNone(image_size(b"not an image"))


class ArchitectureTest(unittest.TestCase):
    def test_sections_behind_fragments(self):
        site = healthy_site()
        nav = "".join(f'<a href="#{n}">{n}</a>' for n in ("booking", "invoices", "reminders", "reports", "team"))
        home = good_home().replace('<a href="/features">Features</a> <a href="/about">About</a>', nav)
        site.add(f"{BASE}/", html(f"{BASE}/", home))
        f = finding(run(site), "fragment-sections")
        self.assertIn("5 sections", f.evidence)
        self.assertIn("#booking", f.fix_prompt)

    def test_skip_links_are_not_sections(self):
        site = healthy_site()
        nav = "".join(f'<a href="#{n}">x</a>' for n in ("top", "main", "content", "skip"))
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body=nav)))
        self.assertNotIn("fragment-sections", ids(run(site)))

    def test_internal_links_that_redirect(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body='<a href="/team/">Team</a>')))
        site.add(f"{BASE}/team/", html(f"{BASE}/team", sub_page(f"{BASE}/team", "Team"),
                                       chain=[(f"{BASE}/team/", 308)]))
        result = run(site)
        self.assertIn("/team/ -> /team", finding(result, "internal-link-redirects").evidence)
        self.assertIn("/team", finding(result, "sitemap-incomplete").evidence)


class SitemapTest(unittest.TestCase):
    def test_incomplete_and_orphans_and_broken(self):
        site = healthy_site()
        sm = SITEMAP.replace("</urlset>", "<url><loc>https://groomly.test/old</loc></url>"
                                          "<url><loc>https://groomly.test/hidden</loc></url></urlset>")
        sm = sm.replace("<url><loc>https://groomly.test/about</loc></url>", "")
        site.add(f"{BASE}/sitemap.xml", text(f"{BASE}/sitemap.xml", sm, ctype="application/xml"))
        site.add(f"{BASE}/hidden", html(f"{BASE}/hidden", sub_page(f"{BASE}/hidden", "Hidden")))
        site.add(f"{BASE}/old", html(f"{BASE}/old", "gone", status=404))
        result = run(site)
        self.assertIn("Not listed: /about", finding(result, "sitemap-incomplete").evidence)
        self.assertIn("/hidden", finding(result, "sitemap-orphans").evidence)
        self.assertIn("/old (404)", finding(result, "sitemap-broken-urls").evidence)

    def test_lastmod_older_than_the_content(self):
        site = healthy_site()
        home = good_home(extra_body="<p>Prices checked 13 October 2026.</p>")
        site.add(f"{BASE}/", html(f"{BASE}/", home))
        sm = SITEMAP.replace("2026-10-20", "2026-09-28")
        site.add(f"{BASE}/sitemap.xml", text(f"{BASE}/sitemap.xml", sm, ctype="application/xml"))
        f = finding(run(site), "sitemap-lastmod-stale")
        self.assertIn("lastmod 2026-09-28", f.evidence)
        self.assertIn("13 October 2026", f.evidence)

    def test_future_dates_and_server_headers_dont_count(self):
        # An event next year isn't an edit; a static host's Last-Modified is a deploy.
        site = healthy_site()
        home = good_home(extra_body="<p>Conference on 3 March 2027.</p>")
        site.add(f"{BASE}/", html(f"{BASE}/", home, headers={"last-modified": "Tue, 27 Oct 2026 10:00:00 GMT"}))
        self.assertNotIn("sitemap-lastmod-stale", ids(run(site)))

    def test_sitemap_index_is_followed(self):
        site = healthy_site()
        index = ('<?xml version="1.0"?><sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
                 '<sitemap><loc>https://groomly.test/pages.xml</loc></sitemap></sitemapindex>')
        site.add(f"{BASE}/sitemap.xml", text(f"{BASE}/sitemap.xml", index, ctype="application/xml"))
        site.add(f"{BASE}/pages.xml", text(f"{BASE}/pages.xml", SITEMAP, ctype="application/xml"))
        result = run(site)
        self.assertIn("sitemap-ok", passes(result))
        self.assertNotIn("sitemap-incomplete", ids(result))

    def test_entity_declarations_are_refused(self):
        bomb = b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]><urlset>&a;</urlset>'
        with self.assertRaises(ValueError):
            parse_sitemap(bomb)

    def test_invalid_and_missing(self):
        site = healthy_site()
        site.add(f"{BASE}/sitemap.xml", text(f"{BASE}/sitemap.xml", "<urlset><url>", ctype="application/xml"))
        self.assertIn("sitemap-invalid", ids(run(site)))
        site = healthy_site()
        del site.responses[f"{BASE}/sitemap.xml"]
        self.assertIn("sitemap-missing", ids(run(site)))

    def test_sitemap_not_named_in_robots(self):
        site = healthy_site()
        site.add(f"{BASE}/robots.txt", text(f"{BASE}/robots.txt", "User-agent: *\nAllow: /\n"))
        self.assertIn("sitemap-not-in-robots", ids(run(site)))


class AiReadinessTest(unittest.TestCase):
    def test_llms_txt_shape(self):
        site = healthy_site()
        site.add(f"{BASE}/llms.txt", text(f"{BASE}/llms.txt", "Groomly is booking software.\n"))
        f = finding(run(site), "llms-incomplete")
        self.assertIn("summary", f.evidence)
        self.assertIn("/guides/llms-txt", RULES["llms-incomplete"].guide)

    def test_structured_data(self):
        site = healthy_site()
        home = good_home().replace('"sameAs":["https://x.com/groomly"]', '"foundingDate":"2026"') \
                          .replace(',"offers":{"@type":"Offer","price":"12","priceCurrency":"GBP"}', "")
        site.add(f"{BASE}/", html(f"{BASE}/", home))
        result = run(site)
        self.assertEqual(finding(result, "org-incomplete").evidence, "sameAs")
        self.assertIn("Groomly", finding(result, "offer-missing").evidence)

    def test_broken_and_absent_json_ld(self):
        site = healthy_site()
        broken = good_home().replace('"name":"Groomly Ltd",', '"name":"Groomly Ltd",,')
        site.add(f"{BASE}/", html(f"{BASE}/", broken))
        self.assertIn("jsonld-invalid", ids(run(site)))

        site = healthy_site()
        import re
        bare = re.sub(r'<script type="application/ld\+json">.*?</script>', "", good_home(), flags=re.S)
        site.add(f"{BASE}/", html(f"{BASE}/", bare))
        got = ids(run(site))
        self.assertIn("jsonld-missing", got)
        self.assertNotIn("product-schema-missing", got, "no structured data at all is one finding, not two")

    def test_questions_without_faq_schema(self):
        site = healthy_site()
        faq = "".join(f"<details><summary>Question {i}?</summary><p>Yes.</p></details>" for i in range(3))
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body=faq)))
        self.assertIn("faq-schema-missing", ids(run(site)))


class HostsTest(unittest.TestCase):
    def test_both_forms_serving_is_duplicate_content(self):
        site = healthy_site()
        site.add("https://www.groomly.test/", html("https://www.groomly.test/", good_home()))
        self.assertIn("host-duplicate", ids(run(site)))

    def test_other_form_missing_or_temporary(self):
        site = healthy_site()
        del site.responses["https://www.groomly.test/"]
        self.assertIn("host-unreachable", ids(run(site)))
        site = healthy_site()
        site.add("https://www.groomly.test/", html(f"{BASE}/", good_home(), chain=[("https://www.groomly.test/", 302)]))
        self.assertIn("host-redirect-temporary", ids(run(site)))

    def test_plain_http_served(self):
        site = healthy_site()
        site.add("http://groomly.test/", html("http://groomly.test/", good_home()))
        f = finding(run(site), "http-not-redirected")
        self.assertEqual(f.severity, "high")

    def test_redirect_chain(self):
        site = healthy_site()
        site.add("http://groomly.test/", html(f"{BASE}/", good_home(),
                                              chain=[("http://groomly.test/", 301), ("https://www.groomly.test/", 301)]))
        self.assertIn("2 hops", finding(run(site), "redirect-chain").evidence)

    def test_starting_from_www_follows_the_site(self):
        site = healthy_site()
        site.add("https://www.groomly.test/robots.txt", text(f"{BASE}/robots.txt", ROBOTS))
        result = scan_visibility("https://www.groomly.test", site.fetch, now=NOW)
        self.assertEqual(result.target.url, BASE)
        self.assertEqual(result.problems, [])

    def test_same_sites_linked_with_and_without_www(self):
        site = healthy_site()
        site.add(f"{BASE}/", html(f"{BASE}/", good_home(extra_body='<a href="https://partner.test/">Partner</a>')))
        site.add(f"{BASE}/llms.txt", text(f"{BASE}/llms.txt", LLMS + "- [Partner](https://www.partner.test/)\n"))
        site.add("https://partner.test/", html("https://www.partner.test/", "<html></html>",
                                               chain=[("https://partner.test/", 308)]))
        f = finding(run(site), "external-host-mixed")
        self.assertIn("partner.test in page links", f.evidence)
        self.assertIn("www.partner.test in llms.txt", f.evidence)
        self.assertIn("the site serves www.partner.test", f.evidence)

    def test_heavy_images(self):
        site = healthy_site()
        site.add(f"HEAD {BASE}/team.jpg", Fetched(url=f"{BASE}/team.jpg", status=200,
                                                   headers={"content-type": "image/jpeg", "content-length": "912000"}))
        self.assertIn("912 KB", finding(run(site), "img-oversized").evidence)


class UnreachableTest(unittest.TestCase):
    def test_dead_site(self):
        result = scan_visibility("dead.test", FakeSite().fetch, now=NOW)
        self.assertIsNone(result.total)
        self.assertEqual(set(result.category_scores.values()), {None})
        self.assertEqual(result.grade, "–")
        self.assertEqual(ids(result), {"site-unreachable"})
        render_terminal(result, use_color=False)
        render_markdown(result)


class RuleTableTest(unittest.TestCase):
    def test_every_rule_formats_and_has_prose(self):
        for rule in RULES.values():
            with self.subTest(rule.id):
                self.assertIn(rule.severity, ("critical", "high", "medium", "low", "info"))
                self.assertIn(rule.category, {c.id for c in config.CATEGORIES})
                self.assertTrue(rule.title and rule.description and rule.verify)
                for tpl in (rule.description, rule.fix_prompt):
                    tpl.format(path="/x", excerpt="e", line=0)  # raises on a stray brace

    def test_guides_exist(self):
        root = Path(__file__).resolve().parent.parent
        for rule in RULES.values():
            if rule.guide:
                with self.subTest(rule.id):
                    self.assertTrue((root / (rule.guide.lstrip("/") + ".html")).exists())

    def test_every_pass_emitted_has_a_title(self):
        for p in run(healthy_site()).passes:
            self.assertIn(p.id, PASSES)
            self.assertEqual(p.category, PASSES[p.id][1])

    def test_every_category_has_a_weight(self):
        self.assertTrue(all(c.weight > 0 for c in config.CATEGORIES))


class ReportTest(unittest.TestCase):
    def test_json_shape(self):
        site = healthy_site()
        site.add(f"{BASE}/llms.txt", text(f"{BASE}/llms.txt", "nothing\n"))
        d = run(site).to_dict()
        self.assertEqual(d["check_id"], "visibility")
        self.assertEqual(len(d["category_scores"]), 6)
        f = d["findings"][0]
        for key in ("id", "check_id", "category", "severity", "title", "why_it_matters", "evidence",
                    "fix_prompt", "verify_hint", "guide_url"):
            self.assertIn(key, f)
        json.dumps(d)

    def test_markdown_has_fix_and_check(self):
        site = healthy_site()
        del site.responses[f"{BASE}/llms.txt"]
        md = render_markdown(run(site))
        self.assertIn("## Visibility: ", md)
        self.assertIn("**Fix prompt**", md)
        self.assertIn("**Check it worked:**", md)
        self.assertIn("## Working", md)
        self.assertIn("Search Console", md)


class FetcherSafetyTest(unittest.TestCase):
    """The hosted crawl must refuse private targets at every hop, and connect
    to the address it vetted."""

    PUBLIC = "93.184.216.34"

    def resolver(self, mapping):
        return lambda host: [mapping[host]]

    def test_private_target_is_refused_without_connecting(self):
        fetch = vfetch.build_fetcher(guard=True, resolver=self.resolver({"internal.test": "10.0.0.5"}))
        with mock.patch.object(vfetch, "_pinned_request") as req:
            self.assertIsNone(fetch("https://internal.test/"))
            self.assertIsNone(fetch("http://169.254.169.254/latest/meta-data/"))
            self.assertIsNone(fetch("http://[::ffff:10.0.0.1]/"))
            req.assert_not_called()

    def test_redirect_into_a_private_network_is_refused(self):
        fetch = vfetch.build_fetcher(guard=True, resolver=self.resolver({"nice.test": self.PUBLIC}))
        hop = (302, {"location": "http://169.254.169.254/latest/meta-data/"}, b"", False)
        with mock.patch.object(vfetch, "_pinned_request", return_value=hop) as req:
            self.assertIsNone(fetch("https://nice.test/"))
            self.assertEqual(req.call_count, 1, "the private hop must never be requested")

    def test_connects_to_the_vetted_address(self):
        fetch = vfetch.build_fetcher(guard=True, resolver=self.resolver({"nice.test": self.PUBLIC}))
        ok = (200, {"content-type": "text/html"}, b"<html></html>", False)
        with mock.patch.object(vfetch, "_pinned_request", return_value=ok) as req:
            resp = fetch("https://nice.test/")
        self.assertEqual(resp.status, 200)
        self.assertEqual(req.call_args[0][1], self.PUBLIC)

    def test_pinned_connection_ignores_a_fresh_dns_answer(self):
        conn = vfetch._PinnedHTTP("rebind.test", self.PUBLIC, port=80, timeout=1)
        with mock.patch("socket.create_connection") as create:
            conn.connect()
        self.assertEqual(create.call_args[0][0], (self.PUBLIC, 80))

    def test_redirects_are_capped(self):
        fetch = vfetch.build_fetcher(guard=True, resolver=self.resolver({"loop.test": self.PUBLIC}))
        hop = (301, {"location": "https://loop.test/again"}, b"", False)
        with mock.patch.object(vfetch, "_pinned_request", return_value=hop) as req:
            self.assertIsNone(fetch("https://loop.test/"))
        self.assertEqual(req.call_count, config.MAX_REDIRECTS + 1)

    def test_identifies_itself(self):
        # The plugin asks the shared fetcher for its own user agent and limits.
        from vibecheck.checks.visibility import CHECK
        from vibecheck.core.models import Context, Target

        with mock.patch.object(vfetch, "build_fetcher", return_value=healthy_site().fetch) as built:
            CHECK.run(Target(url="https://groomly.test"), Context(guard=True, now=NOW))
        kwargs = built.call_args.kwargs
        self.assertTrue(kwargs["guard"])
        self.assertEqual(kwargs["user_agent"], "vibecheck-visibility/1.0 (+https://psychosecurity.io/visibility)")
        self.assertEqual((kwargs["timeout"], kwargs["max_bytes"], kwargs["max_redirects"]), (10.0, 2_000_000, 5))

    def test_response_size_is_capped(self):
        stream = io.BytesIO(b"x" * 5000)
        body, truncated = vfetch._read_capped(stream, 1000, deadline=1e18)
        self.assertEqual(len(body), 1000)
        self.assertTrue(truncated)

    def test_limits_match_the_plan(self):
        self.assertEqual(config.TIMEOUT, 10.0)
        self.assertEqual(config.MAX_BYTES, 2_000_000)
        self.assertEqual(config.MAX_REDIRECTS, 5)
        self.assertEqual(config.MAX_PAGES, 20)


class CliTest(unittest.TestCase):
    def run_cli(self, site, *extra):
        from vibecheck import cli
        out = io.StringIO()
        with mock.patch.object(vfetch, "build_fetcher", return_value=site.fetch), redirect_stdout(out):
            code = cli.main(["--visibility", "https://groomly.test", "--no-color", *extra])
        return code, out.getvalue()

    def test_clean_site_exits_zero(self):
        code, out = self.run_cli(healthy_site())
        self.assertEqual(code, 0)
        self.assertIn("VISIBILITY: 100/100", out)

    def test_high_finding_exits_one(self):
        site = healthy_site()
        site.add("http://groomly.test/", html("http://groomly.test/", good_home()))
        code, _out = self.run_cli(site)
        self.assertEqual(code, 1)

    def test_json_to_stdout(self):
        code, out = self.run_cli(healthy_site(), "--json")
        self.assertEqual(json.loads(out)["total"], 100)

    def test_markdown_file(self):
        import tempfile
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.md"
            self.run_cli(healthy_site(), "--markdown", str(path))
            self.assertIn("vibecheck visibility report", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
