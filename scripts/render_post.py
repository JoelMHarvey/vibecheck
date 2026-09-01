"""Render the filled writeup into a page in the site's own style.

    python3 scripts/render_post.py research/scanned-vibe-coded-apps.md \
        --slug i-scanned-190-vibe-coded-apps \
        --title "I scanned 190 vibe-coded apps. Here's what leaked." \
        --description "..." --out research/post.html

fill_writeup.py produces markdown. The site is static HTML. Bridging those by
hand means one more copy-and-paste of numbers we spent days making traceable —
and a copy-and-paste is exactly where the last one drifts. So the page is
generated from the same file, and the chain from research/aggregate.json to
the published URL never passes through a keyboard.

## Why a renderer rather than a markdown library

Zero dependencies is the scanner's whole pitch; a build step that pip-installs
something would be a strange thing to find in this repo. The writeup uses
eight constructs — headings, paragraphs, bullet lists, fenced code, inline
code, links, emphasis, a rule — and this handles those eight. Anything else in
the source is an error rather than silently-dropped text, because a paragraph
that vanishes between the markdown and the page is the kind of thing nobody
notices until a reader mentions it.

## What it refuses

A surviving `{{PLACEHOLDER}}`. fill_writeup already refuses to emit one, but
this reads whatever file it is handed — including one edited by hand after
filling, which is the expected workflow for trimming prose. Publishing
"{{MEDIAN_SCORE}}" would be worse than publishing nothing.
"""

from __future__ import annotations

import argparse
import html
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = "https://psychosecurity.io"
PLACEHOLDER_RE = re.compile(r"\{\{[A-Z0-9_]+\}\}")
COMMENT_RE = re.compile(r"<!--.*?-->", re.S)

# Inline markup, applied after escaping so the replacements are the only tags.
INLINE = (
    (re.compile(r"`([^`]+)`"), lambda m: f"<code>{m.group(1)}</code>"),
    (re.compile(r"\[([^\]]+)\]\(([^)\s]+)\)"),
     lambda m: f'<a href="{m.group(2)}">{m.group(1)}</a>'),
    (re.compile(r"\*\*(.+?)\*\*", re.S), lambda m: f"<strong>{m.group(1)}</strong>"),
    (re.compile(r"(?<!\*)\*([^*].*?)\*(?!\*)", re.S), lambda m: f"<em>{m.group(1)}</em>"),
)


def inline(text: str) -> str:
    out = html.escape(text, quote=False)
    for pattern, repl in INLINE:
        out = pattern.sub(repl, out)
    return out


def blocks(source: str):
    """Split into (kind, payload) blocks. Raises on anything unsupported."""
    source = COMMENT_RE.sub("", source)
    lines = source.splitlines()
    i, out = 0, []
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
        elif line.startswith("```"):
            i += 1
            body = []
            while i < len(lines) and not lines[i].startswith("```"):
                body.append(lines[i])
                i += 1
            if i >= len(lines):
                raise ValueError("unterminated code fence")
            i += 1
            out.append(("code", "\n".join(body)))
        elif re.match(r"^#{1,3} ", line):
            level = len(line) - len(line.lstrip("#"))
            out.append((f"h{level}", line[level:].strip()))
            i += 1
        elif line.strip() == "---":
            out.append(("hr", ""))
            i += 1
        elif line.startswith("- "):
            items = []
            while i < len(lines) and lines[i].startswith("- "):
                item = [lines[i][2:]]
                i += 1
                while i < len(lines) and lines[i].startswith("  ") and lines[i].strip():
                    item.append(lines[i].strip())
                    i += 1
                items.append(" ".join(item))
            out.append(("ul", items))
        elif line.startswith((">", "|", "    ")) or re.match(r"^\d+\. ", line):
            raise ValueError(
                f"line {i + 1}: unsupported markdown — {line.strip()[:60]!r}. "
                "Add it to render_post.py rather than letting it render as prose."
            )
        else:
            para = []
            while i < len(lines) and lines[i].strip() and not lines[i].startswith(
                    ("#", "- ", "```")) and lines[i].strip() != "---":
                para.append(lines[i].strip())
                i += 1
            out.append(("p", " ".join(para)))
    return out


def render_body(source: str) -> str:
    parts = []
    for kind, payload in blocks(source):
        if kind == "code":
            parts.append(f"  <pre><code>{html.escape(payload, quote=False)}</code></pre>")
        elif kind == "ul":
            items = "\n".join(f"    <li>{inline(x)}</li>" for x in payload)
            parts.append(f"  <ul>\n{items}\n  </ul>")
        elif kind == "hr":
            parts.append("  <hr>")
        elif kind.startswith("h"):
            parts.append(f"  <{kind}>{inline(payload)}</{kind}>")
        else:
            parts.append(f"  <p>{inline(payload)}</p>")
    return "\n\n".join(parts)


def url_for(slug: str) -> str:
    return f"{SITE}/posts/{slug}"


def page(body: str, slug: str, title: str, description: str,
         og_title: str, og_description: str) -> str:
    url = url_for(slug)
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} — vibecheck</title>
<meta name="description" content="{html.escape(description, quote=True)}">
<link rel="canonical" href="{url}">
<meta name="theme-color" content="#0b0e14">
<meta property="og:type" content="article">
<meta property="og:site_name" content="vibecheck">
<meta property="og:url" content="{url}">
<meta property="og:title" content="{html.escape(og_title, quote=True)}">
<meta property="og:description" content="{html.escape(og_description, quote=True)}">
<meta property="og:image" content="{SITE}/og.png">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:image" content="{SITE}/og.png">
<link rel="stylesheet" href="/guide.css">
</head>
<body>

<header>
  <div class="wrap">
    <a class="logo" href="/">vibe<span>check</span> 🔒</a>
    <div class="byline">a psychosecurity.io tool</div>
  </div>
</header>

<div class="wrap">
<article>
{body}

  <div class="cta">
    <h2>Scan your own</h2>
    <p>vibecheck is free and needs no signup. Point it at a folder or a live
    URL and it tells you what's wrong in plain English, with a fix prompt to
    paste back into whatever built the app.</p>
    <a class="btn" href="/">Scan my project — free</a>
  </div>

  <div class="related">
    <h2>The guides</h2>
    <ul>
      <li><a href="/guides/ai-app-security-checklist">The AI app security checklist</a></li>
      <li><a href="/guides/api-key-leaked">My API key leaked — what now?</a></li>
      <li><a href="/guides/supabase-service-role-key-exposed">Supabase <code>service_role</code></a> · <a href="/guides/stripe-secret-key-exposed">Stripe</a> · <a href="/guides/openai-api-key-exposed">OpenAI &amp; Anthropic</a></li>
      <li><a href="/guides/lovable-app-security">Lovable</a> · <a href="/guides/bolt-app-security">Bolt</a> · <a href="/guides/v0-app-security">v0</a> · <a href="/guides/cursor-claude-code-security">Cursor &amp; Claude Code</a> · <a href="/guides/firebase-app-security">Firebase</a></li>
    </ul>
  </div>
</article>

<footer>
  <p><strong>Two rules of thumb:</strong> browser code cannot keep a secret, and
  deleting a leaked key does not un-leak it — rotate it.</p>
  <p style="margin-top:8px">vibecheck · a <strong>psychosecurity.io</strong> tool</p>
</footer>
</div>

</body>
</html>
"""


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("source", help="the filled markdown from fill_writeup.py")
    parser.add_argument("--slug", required=True, help="the URL segment under /posts/")
    parser.add_argument("--title", required=True)
    parser.add_argument("--description", required=True,
                        help="the search snippet, 50-200 characters")
    parser.add_argument("--og-title", help="defaults to --title")
    parser.add_argument("--og-description", help="defaults to --description")
    parser.add_argument("--out", help="defaults to research/<slug>.html")
    args = parser.parse_args(argv)

    source_path = Path(args.source)
    if not source_path.exists():
        print(f"no such file: {source_path} — run fill_writeup.py first", file=sys.stderr)
        return 1
    source = source_path.read_text(encoding="utf-8")

    left = PLACEHOLDER_RE.findall(source)
    if left:
        print("unfilled placeholders in the source: " + ", ".join(sorted(set(left))),
              file=sys.stderr)
        print("Fill them before rendering; a page must never ship one.", file=sys.stderr)
        return 1

    try:
        body = render_body(source)
    except ValueError as exc:
        print(f"cannot render: {exc}", file=sys.stderr)
        return 1

    out_path = Path(args.out) if args.out else ROOT / "research" / f"{args.slug}.html"
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(page(
        body, args.slug, args.title, args.description,
        args.og_title or args.title, args.og_description or args.description,
    ), encoding="utf-8")

    print(f"  rendered -> {out_path}")
    print(f"  it will live at {SITE}/posts/{args.slug}")
    print("\n  Not published until it is copied to posts/ and committed — this\n"
          "  repository is public, so committing it is publishing it.")
    print("\n  On the day, copy it in and add this to sitemap.xml, or the site\n"
          "  tests will refuse it:\n")
    print(f"""  <url>
    <loc>{url_for(args.slug)}</loc>
    <changefreq>yearly</changefreq>
    <priority>0.9</priority>
  </url>""")
    return 0


if __name__ == "__main__":
    sys.exit(main())
