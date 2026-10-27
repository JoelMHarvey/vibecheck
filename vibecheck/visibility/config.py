"""Every tunable number for the visibility scan, in one place.

Scoring: a category starts at 10 and loses CATEGORY_PENALTY points per
finding in it, floored at 0. The total is the weighted mean of the categories
that ran, scaled to 0-100. A category with no checks yet (phases 2-4) scores
None and is left out of the mean, not counted as zero.
"""

from __future__ import annotations

# (key, label). Order is the order they're shown in.
CATEGORIES = [
    ("technical", "Technical"),
    ("ai", "AI readiness"),
    ("content", "Content & keywords"),
    ("positioning", "Positioning"),
    ("offsite", "Off-site"),
    ("brand", "Brand clarity"),
]

# Relative weights in the total. They needn't sum to 1; the total divides by
# the sum of the weights of the categories that ran.
CATEGORY_WEIGHTS = {
    "technical": 0.20,
    "ai": 0.15,
    "content": 0.20,
    "positioning": 0.20,
    "offsite": 0.10,
    "brand": 0.15,
}

# Categories phase 1 can score. The rest say "run the deeper check".
PHASE1_CATEGORIES = ("technical", "ai", "content")

CATEGORY_PENALTY = {"critical": 10, "high": 4, "medium": 2, "low": 1, "info": 0}

# Crawl limits.
USER_AGENT = "vibecheck-visibility/1.0 (+https://psychosecurity.io/visibility)"
ROBOTS_AGENT = "vibecheck-visibility"
MAX_PAGES = 20            # internal pages beyond the home page
MAX_IMAGES = 12           # images sized with HEAD requests
MAX_SITEMAPS = 3          # child sitemaps followed from a sitemap index
TIMEOUT = 10.0            # seconds, per request
MAX_BYTES = 2_000_000     # per response
MAX_REDIRECTS = 5
WORKERS = 6               # requests in flight at once
BUDGET = 40.0             # seconds for the whole crawl

# Thresholds.
MIN_BODY_TEXT = 200       # characters of text in the raw HTML
TITLE_MAX = 60
DESCRIPTION_MIN = 70
DESCRIPTION_MAX = 160
IMAGE_MAX_BYTES = 300_000
ALT_COVERAGE_MIN = 0.9
LASTMOD_SLACK_DAYS = 3    # content newer than lastmod by more than this is stale
FRAGMENT_SECTIONS_MIN = 4

# AI crawlers whose access is reported (never scored).
AI_CRAWLERS = ("GPTBot", "ClaudeBot", "PerplexityBot", "Google-Extended", "CCBot")
SEARCH_CRAWLERS = ("Googlebot", "Bingbot")

CACHE_SECONDS = 24 * 3600
