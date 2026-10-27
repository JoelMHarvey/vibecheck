"""Command-line entry point: vibecheck [path]"""

from __future__ import annotations

import argparse
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
    parser.add_argument("path", nargs="?", default=".", help="project directory to scan (default: current directory)")
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

    if args.visibility:
        return _visibility(args)

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


def _visibility(args) -> int:
    from .visibility import report as vreport
    from .visibility import scan_visibility
    from .visibility.fetch import build_fetcher

    # Unguarded, like --url: checking your own staging box from your own
    # machine is a fair use. The hosted endpoint always guards.
    result = scan_visibility(args.visibility, build_fetcher(guard=False))
    threshold = SEVERITY_ORDER[args.min_severity]
    result.findings = [f for f in result.findings if SEVERITY_ORDER[f.severity] <= threshold]

    if args.json == "-":
        print(vreport.render_json(result), end="")
    else:
        use_color = not args.no_color and sys.stdout.isatty()
        print(vreport.render_terminal(result, use_color=use_color))
    if args.markdown:
        Path(args.markdown).write_text(vreport.render_markdown(result), encoding="utf-8")
        if args.json != "-":
            print(f"  Markdown report written to {args.markdown}")
    if args.json and args.json != "-":
        Path(args.json).write_text(vreport.render_json(result), encoding="utf-8")
        print(f"  JSON report written to {args.json}")

    if args.fail_on != "never" and vreport.fails(result, args.fail_on):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
