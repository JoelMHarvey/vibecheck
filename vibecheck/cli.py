"""Command-line entry point.

    vibecheck [path]                                   the security scan, as it always was
    vibecheck --url https://myapp.com                  the security scan of a live site
    vibecheck <path-or-url> --checks security,visibility
                                                       any checks, one report, one exit code
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

from . import __version__
from .report import render_json, render_markdown, render_terminal
from .rules import SEVERITY_ORDER
from .scanner import scan


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="vibecheck",
        description=(
            "Security scanner for AI-built apps. Finds exposed keys and common "
            "vibe-coding mistakes, and gives you a fix prompt to paste straight "
            "back into your AI coding tool."
        ),
    )
    parser.add_argument("path", nargs="?", default=None,
                        help="project directory to scan, or a site's URL (default: current directory)")
    parser.add_argument(
        "--checks",
        metavar="LIST",
        help="comma-separated checks to run: security, visibility (default: security for a folder; "
             "every URL check for a URL). Exit code 1 on any high or critical across all of them.",
    )
    parser.add_argument(
        "--url",
        metavar="URL",
        help="scan a DEPLOYED site instead of a directory (checks for exposed .env, source maps, missing security headers, open CORS, robots.txt leaks)",
    )
    parser.add_argument(
        "--visibility",
        metavar="URL",
        help="check how a DEPLOYED site looks to search engines and AI crawlers (rendering, robots.txt, sitemap, llms.txt, structured data, titles, link previews)",
    )
    parser.add_argument("--positioning", action="store_true",
                        help="with a visibility check, also review the home page's copy with Claude "
                             "(who it's for, price, differentiator, social proof, call to action). "
                             "Needs the anthropic package and your own ANTHROPIC_API_KEY; one small call per run.")
    parser.add_argument("--architecture", action="store_true",
                        help="with the integrity check, also send a capped, redacted digest of the code at its "
                             "boundaries (routes, webhooks, auth, database clients) to Claude for an architecture "
                             "read. Your own ANTHROPIC_API_KEY; cached on disk by content")
    parser.add_argument("--brand", metavar="NAME",
                        help="with a visibility check, also ask Claude (with web search) the questions buyers ask "
                             "about your category and see if it names you, and search for you off-site. "
                             "Needs --category, the anthropic package and your own ANTHROPIC_API_KEY; "
                             "seven web-searching calls per run")
    parser.add_argument("--category", metavar="TEXT",
                        help='what you are, as a buyer would ask for it: "practice software for therapists"')
    parser.add_argument("--country", metavar="CC", default="GB", help="two-letter country for the questions (default GB)")
    parser.add_argument("--competitor", metavar="NAME", action="append", default=[],
                        help="a competitor to measure against (up to three; repeatable)")
    parser.add_argument("--badge", action="store_true",
                        help="print badge Markdown for each check. From your machine it says self-reported; "
                             "in GitHub Actions it names the run. Only scans run on psychosecurity.io are signed.")
    parser.add_argument("--markdown", metavar="FILE", help="also write a Markdown report to FILE")
    parser.add_argument("--json", metavar="FILE", nargs="?", const="-",
                        help="also write a JSON report to FILE (no FILE: print JSON instead of the terminal report)")
    parser.add_argument(
        "--min-severity",
        choices=list(SEVERITY_ORDER),
        default="info",
        help="hide findings below this severity (default: show everything)",
    )
    parser.add_argument(
        "--fail-on",
        choices=list(SEVERITY_ORDER) + ["never"],
        default="high",
        help="exit with code 1 if any finding is at or above this severity (default: high; use 'never' to always exit 0)",
    )
    parser.add_argument(
        "--exclude",
        metavar="GLOB",
        action="append",
        default=[],
        help="skip paths matching this glob (repeatable). Patterns in a .vibecheckignore file at the project root are applied too.",
    )
    parser.add_argument("--no-color", action="store_true", help="disable colored output")
    parser.add_argument("--version", action="version", version=f"vibecheck {__version__}")
    args = parser.parse_args(argv)

    if args.visibility or args.checks or args.badge or args.positioning or args.brand or args.architecture or _looks_like_url(args.path):
        return _unified(parser, args)
    args.path = args.path or "."

    if args.url:
        from .urlscan import build_default_fetcher, scan_url

        result = scan_url(args.url, build_default_fetcher())
    else:
        target = Path(args.path)
        if not target.exists():
            parser.error(f"path does not exist: {args.path}")
        result = scan(str(target), exclude=args.exclude)

    threshold = SEVERITY_ORDER[args.min_severity]
    result.findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold]

    use_color = not args.no_color and sys.stdout.isatty()
    if args.json != "-":
        print(render_terminal(result, use_color=use_color))

    if args.markdown:
        Path(args.markdown).write_text(render_markdown(result), encoding="utf-8")
        print(f"  Markdown report written to {args.markdown}")
    if args.json == "-":
        print(render_json(result), end="")
    elif args.json:
        Path(args.json).write_text(render_json(result), encoding="utf-8")
        print(f"  JSON report written to {args.json}")

    if args.fail_on != "never":
        fail_threshold = SEVERITY_ORDER[args.fail_on]
        if any(SEVERITY_ORDER[f.severity] <= fail_threshold for f in result.findings):
            return 1
    return 0


CODE_EXTS = {"py", "js", "ts", "tsx", "jsx", "json", "md", "txt", "html", "yml", "yaml", "toml", "sh", "env", "rb", "go", "rs"}


def _looks_like_url(value) -> bool:
    if not value:
        return False
    if re.match(r"https?://", value):
        return True
    # A bare domain counts, but a missing file named like code ("app.py") is a
    # typo, not a site in Paraguay.
    host = value.split("/", 1)[0]
    if host.rsplit(".", 1)[-1].lower() in CODE_EXTS:
        return False
    return not Path(value).exists() and bool(re.fullmatch(r"[a-z0-9-]+(\.[a-z0-9-]+)+(/\S*)?", value, re.I))


def _unified(parser, args) -> int:
    from .core import registry
    from .core import report as core_report
    from .core.models import SEVERITY_ORDER as CORE_ORDER
    from .core.models import Context, Target
    from .core.walker import git_commit

    url = args.visibility or args.url
    repo = None
    if args.path and _looks_like_url(args.path):
        url = url or args.path
    elif args.path or not url:
        path = args.path or "."
        if not Path(path).exists():
            parser.error(f"path does not exist: {path}")
        repo = str(Path(path).resolve())
    if url and "://" not in url:
        url = "https://" + url
    target = Target(url=url, repo=repo, commit=git_commit(Path(repo)) if repo else None)

    if args.checks:
        wanted = [c.strip() for c in args.checks.split(",") if c.strip()]
    elif args.visibility:
        wanted = ["visibility"]
    elif args.architecture:
        wanted = ["integrity"]
    else:
        wanted = [c.id for c in registry.available_for(target)]
    try:
        checks = [registry.get(c) for c in wanted]
    except KeyError as e:
        parser.error(str(e.args[0]))
    runnable = [c for c in checks if c.inputs & target.inputs]
    for c in checks:
        if c not in runnable:
            needs = " or ".join(f"a {i}" for i in sorted(c.inputs))
            print(f"  skipping {c.id}: it needs {needs}", file=sys.stderr)
    if not runnable:
        parser.error("none of those checks can run on this target")

    # Unguarded, like --url always was: checking your own staging box from
    # your own machine is a fair use. The hosted endpoints always guard.
    reviewer = None
    if args.positioning:
        from .checks.visibility.positioning import ClaudeReviewer

        reviewer = ClaudeReviewer()
    options = {}
    if args.architecture:
        if not repo:
            parser.error("--architecture needs a folder to read")
        from .checks.integrity.architecture import ClaudeArchitect

        options["architecture"] = ClaudeArchitect()
    if args.brand:
        if not args.category:
            parser.error("--brand needs --category")
        if not url:
            parser.error("--brand needs a site: give --visibility URL")
        from urllib.parse import urlsplit

        from .checks.visibility.probe import ProbeInput
        from .checks.visibility.websearch import ClaudeSearch

        options["probe"] = (ClaudeSearch(), ProbeInput(args.brand, urlsplit(url).hostname or "", args.category,
                                                       args.country, args.competitor[:3]))
    ctx = Context(guard=False, exclude=args.exclude, provenance="self", llm=reviewer, options=options)
    results = [c.run(target, ctx) for c in runnable]

    threshold = CORE_ORDER[args.min_severity]
    for r in results:
        r.findings = [f for f in r.findings if f.severity == "pass" or CORE_ORDER[f.severity] <= threshold]

    if args.json == "-":
        print(core_report.render_json(results), end="")
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        print(core_report.render_combined_terminal(results, use_color=use_color))
    if args.markdown:
        Path(args.markdown).write_text(core_report.render_combined_markdown(results), encoding="utf-8")
        if args.json != "-":
            print(f"  Markdown report written to {args.markdown}")
    if args.json and args.json != "-":
        Path(args.json).write_text(core_report.render_json(results), encoding="utf-8")
        print(f"  JSON report written to {args.json}")

    if args.badge:
        _print_badges(results, json_to_stdout=args.json == "-")

    if args.fail_on != "never" and core_report.fails(results, args.fail_on):
        return 1
    return 0


def _print_badges(results, json_to_stdout: bool) -> None:
    import os

    from .core import badge

    out = sys.stderr if json_to_stdout else sys.stdout
    prov = badge.ci_provenance(os.environ)
    print("  Badges (paste into your README):", file=out)
    for r in results:
        if not r.target.url and not r.target.commit:
            print(f"  {r.check_id}: no badge, because a folder that isn't a git checkout has no "
                  "commit to pin it to", file=out)
            continue
        signed = badge.sign_result(r, None, prov)
        print(badge.badge_markdown(r.check_id, signed["badge"], [signed["report"]]), file=out)


if __name__ == "__main__":
    sys.exit(main())
