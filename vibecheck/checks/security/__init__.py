"""The security check: leaked keys and vibe-coding mistakes, in code or on a
live site.

The scanner itself (scanner.py, rules/, urlscan.py) is unchanged; this
module is the plugin that runs it for the framework and turns its result
into a CheckResult. The total is the Vibe Score, computed exactly as
before, so no score or badge shifts with the move. Category scores are shown
alongside it.
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from ...core.models import Category, CheckResult, Context, Finding, Target, iso
from ...core.scoring import category_scores
from .scanner import ScanResult, _finalize, scan, scan_files
from .urlscan import scan_url

CATEGORIES = [
    Category("secrets", "Secrets", 0.4),
    Category("exposure", "Browser exposure", 0.2),
    Category("injection", "Injection", 0.2),
    Category("config", "Configuration", 0.2),
]

# Every rule the scanner can emit, by category. tests/test_framework.py fails
# if a rule is added without one.
RULE_CATEGORY: Dict[str, str] = {
    **{r: "secrets" for r in (
        "anthropic-api-key", "openai-api-key", "stripe-live-key", "stripe-test-key", "aws-access-key-id",
        "google-api-key", "github-token", "slack-token", "telegram-bot-token", "private-key-block",
        "mongodb-uri-credentials", "postgres-uri-credentials", "jwt-secret-hardcoded", "hardcoded-jwt",
        "hardcoded-password", "supabase-service-role-key", "supabase-anon-key", "env-file-not-gitignored",
        "exposed-env-file", "exposed-git-dir", "exposed-aws-credentials", "exposed-config",
    )},
    **{r: "exposure" for r in (
        "public-env-var-holds-secret", "dangerously-allow-browser", "llm-api-call-in-frontend",
        "exposed-source-map",
    )},
    **{r: "injection" for r in (
        "sql-string-building", "shell-command-interpolation", "subprocess-shell-true",
        "innerhtml-assignment", "innerhtml-untrusted-input", "eval-usage",
    )},
    **{r: "config" for r in (
        "flask-debug-enabled", "cors-allow-all", "tls-verification-disabled", "missing-hsts", "missing-xcto",
        "missing-csp", "missing-xfo", "cors-wildcard-live", "robots-leaks-paths", "no-https", "site-unreachable",
    )},
}

GUIDES: Dict[str, str] = {
    "supabase-service-role-key": "/guides/supabase-service-role-key-exposed",
    "supabase-anon-key": "/guides/supabase-service-role-key-exposed",
    "stripe-live-key": "/guides/stripe-secret-key-exposed",
    "stripe-test-key": "/guides/stripe-secret-key-exposed",
    "openai-api-key": "/guides/openai-api-key-exposed",
    "anthropic-api-key": "/guides/openai-api-key-exposed",
    "dangerously-allow-browser": "/guides/openai-api-key-exposed",
    "llm-api-call-in-frontend": "/guides/openai-api-key-exposed",
}
SECRET_GUIDE = "/guides/api-key-leaked"

VERIFY: Dict[str, str] = {
    "secrets": "Re-run the scan and check the finding has gone. Then confirm the old key no longer "
               "works at the provider: deleting it from the code doesn't un-leak it.",
    "exposure": "Re-run the scan, then open your site with DevTools' Network tab: no request from the "
                "browser should carry a secret key.",
    "injection": "Re-run the scan, then try the input that would have broken it (a quote, a semicolon, "
                 "a <script> tag) and check it's treated as plain text.",
    "config": "Re-run the scan, or check the response headers with 'curl -sI https://yoursite.com'.",
}

# The deployed-site scan kept tighter limits than the visibility crawl.
URL_FETCH = dict(user_agent="vibecheck/0.1 (+https://psychosecurity.io)",
                 timeout=6.0, max_bytes=600_000, max_redirects=3)
URL_CATEGORIES = {"secrets", "exposure", "config"}


class SecurityCheck:
    id = "security"
    version = "1.0.0"
    title = "Security"
    inputs = {"url", "repo"}
    categories = CATEGORIES
    not_run = "needs your code"
    footer = ("Deleting a key from your code does not un-leak it. Rotate every exposed "
              "credential at its provider.")

    @property
    def blurbs(self) -> Dict[str, str]:
        from ...report import GRADE_BLURB  # lazily: report.py imports the rules this package holds

        return {**GRADE_BLURB, "–": "We couldn't reach the site, so nothing was checked."}

    def run(self, target: Target, ctx: Context) -> CheckResult:
        parts: List[ScanResult] = []
        ran: Set[str] = set()
        if target.files is not None:
            parts.append(scan_files(target.files, root_label=target.label or "uploaded project",
                                    exclude=ctx.exclude))
            ran |= {c.id for c in CATEGORIES}
        elif target.repo:
            parts.append(scan(target.repo, exclude=ctx.exclude))
            ran |= {c.id for c in CATEGORIES}
        unreachable = False
        if target.url:
            url_result = scan_url(target.url, ctx.fetcher(**URL_FETCH))
            unreachable = any(f.rule_id == "site-unreachable" for f in url_result.findings)
            if not unreachable:
                ran |= URL_CATEGORIES
            parts.append(url_result)
        merged = ScanResult(root=" + ".join(p.root for p in parts))
        for p in parts:
            merged.findings.extend(p.findings)
            merged.files_scanned += p.files_scanned
        _finalize(merged)
        return self.to_result(merged, target, iso(ctx.timestamp()), ran,
                              nothing_checked=unreachable and not ran)

    def to_result(self, legacy: ScanResult, target: Target, scanned_at: str,
                  ran: Optional[Set[str]] = None, nothing_checked: bool = False) -> CheckResult:
        """A legacy ScanResult as a CheckResult. Used by the plugin and by the
        hosted endpoints, which still return the legacy shape as well."""
        findings = [self.finding(f) for f in legacy.findings]
        ran = {c.id for c in CATEGORIES} if ran is None else ran
        return CheckResult(
            check_id=self.id,
            check_version=self.version,
            target=target,
            scanned_at=scanned_at,
            category_scores=category_scores(findings, CATEGORIES, ran),
            total=None if nothing_checked else legacy.score,
            findings=findings,
            meta={"files_scanned": legacy.files_scanned} if target.inputs & {"repo"} else {},
        )

    @staticmethod
    def finding(f) -> Finding:
        category = RULE_CATEGORY.get(f.rule_id, "config")
        guide = GUIDES.get(f.rule_id) or (SECRET_GUIDE if category == "secrets" else None)
        return Finding(
            id=f.rule_id, check_id="security", category=category, severity=f.severity, title=f.title,
            why_it_matters=f.description, evidence=f.excerpt, fix_prompt=f.fix_prompt,
            verify_hint=VERIFY[category] if f.fix_prompt else "", guide_url=guide, path=f.path, line=f.line,
        )


CHECK = SecurityCheck()
