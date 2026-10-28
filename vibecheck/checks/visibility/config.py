"""Every tunable number for the visibility scan, in one place.

Scoring: a category starts at 10 and loses points per finding in it
(vibecheck.core.scoring.CATEGORY_PENALTY, the same for every check), floored at 0. The total is the weighted mean of the categories
that ran, scaled to 0-100. A category with no checks yet (phases 2-4) scores
None and is left out of the mean, not counted as zero.
"""

from __future__ import annotations

from ...core.models import Category

# Order is the order they're shown in. Weights are relative: the total
# divides by the sum of the weights of the categories that ran.
CATEGORIES = [
    Category("technical", "Technical", 0.20),
    Category("ai", "AI readiness", 0.15),
    Category("content", "Content & keywords", 0.20),
    Category("positioning", "Positioning", 0.20),
    Category("offsite", "Off-site", 0.10),
    Category("brand", "Brand clarity", 0.15),
]

# Categories phase 1 can score. Positioning is phase 2 (positioning.py): it
# runs when the check is given a reviewer. The rest say "run the deeper check".
PHASE1_CATEGORIES = ("technical", "ai", "content")

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

# Sign-in, sign-up and other account screens. They're app, not content: a
# login form rendered in the browser is normal and nobody needs it to rank,
# so the crawl doesn't spend its page budget on them or judge their copy.
APP_PATHS = (r"^/(?:[a-z]{2}(?:-[a-z]{2})?/)?(?:log-?in|sign-?in|sign-?up|register|log-?out|sign-?out"
             r"|forgot(?:-password)?|reset(?:-password)?|password-reset|auth|sso|oauth|callback)(?:/|$)")

# Thresholds.
MIN_BODY_TEXT = 200       # characters of text in the raw HTML
TITLE_MAX = 60
DESCRIPTION_MIN = 70
DESCRIPTION_MAX = 160
IMAGE_MAX_BYTES = 300_000
ALT_COVERAGE_MIN = 0.9
LASTMOD_SLACK_DAYS = 3    # content newer than lastmod by more than this is stale
FRAGMENT_SECTIONS_MIN = 4

# AI crawlers whose access is reported (never scored). Training crawlers
# gather data for future models; search crawlers decide whether an assistant
# can cite the site when it answers. Names as each company documents them.
AI_TRAINING_CRAWLERS = ("GPTBot", "ClaudeBot", "Google-Extended", "Applebot-Extended", "CCBot")
AI_SEARCH_CRAWLERS = ("OAI-SearchBot", "Claude-SearchBot", "PerplexityBot")
AI_CRAWLERS = AI_TRAINING_CRAWLERS + AI_SEARCH_CRAWLERS
SEARCH_CRAWLERS = ("Googlebot", "Bingbot")

