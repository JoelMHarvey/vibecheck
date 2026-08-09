"""Tests for the hosted API handlers (badge SVG + URL-scan validation).

These exercise the handler modules directly rather than over HTTP, so no
server or network is needed.
"""

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "api"))

import importlib.util  # noqa: E402


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / "api" / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


badge = load("badge_api", "badge.py")


class BadgeTest(unittest.TestCase):
    def test_grade_boundaries(self):
        self.assertEqual(badge.grade_for(100), "A")
        self.assertEqual(badge.grade_for(90), "A")
        self.assertEqual(badge.grade_for(89), "B")
        self.assertEqual(badge.grade_for(60), "C")
        self.assertEqual(badge.grade_for(39), "F")

    def test_renders_valid_svg(self):
        svg = badge.render_badge(94)
        self.assertTrue(svg.startswith("<svg"))
        self.assertTrue(svg.endswith("</svg>"))
        self.assertIn("94/100 A", svg)

    def test_score_is_clamped(self):
        self.assertIn("100/100 A", badge.render_badge(9999))
        self.assertIn("0/100 F", badge.render_badge(-50))

    def test_no_injection_via_score(self):
        # Score is coerced to int, so markup can never reach the SVG body.
        svg = badge.render_badge(True)  # bool is an int subclass -> 1
        self.assertNotIn("<script", svg)
        self.assertIn("1/100 F", svg)


class UrlScanEndpointTest(unittest.TestCase):
    """The endpoint must refuse SSRF targets before fetching anything."""

    def test_guard_rejects_internal_targets(self):
        from vibecheck.netguard import check_url

        for bad in ("http://169.254.169.254/", "http://localhost/", "http://10.0.0.1/"):
            ok, reason = check_url(bad)
            self.assertFalse(ok, f"{bad} should be rejected")
            self.assertTrue(reason)


if __name__ == "__main__":
    unittest.main()
