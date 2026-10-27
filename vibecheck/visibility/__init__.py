"""Visibility mode: "Is anyone finding it?"

A scan of how a site looks to search engines and AI crawlers, with the same
plain-English findings and fix prompts as the security scan. See
docs/visibility-design.md.
"""

from .scan import Pass, VisibilityResult, scan_visibility  # noqa: F401
