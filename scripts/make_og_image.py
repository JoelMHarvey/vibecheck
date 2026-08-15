"""Render the social preview card to og.png.

Why a static image: shared reports live in the URL *fragment*, which is
never sent to a server, so no crawler or link unfurler can see what a
given report contains. A per-report card is impossible by construction —
that's the cost of the privacy design, and it's the right trade.

Needs Playwright and a Chromium (the repo image ships one):

    pip install playwright
    python3 scripts/make_og_image.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "og.png"

CARD = """
<!DOCTYPE html><html><head><meta charset="utf-8"><style>
  * { margin: 0; box-sizing: border-box; }
  body { width: 1200px; height: 630px; background: #0b0e14; color: #e6e9f0;
         font: 16px/1.5 system-ui, -apple-system, "Segoe UI", sans-serif;
         display: flex; flex-direction: column; justify-content: center;
         padding: 0 80px; position: relative; overflow: hidden; }
  .glow { position: absolute; width: 700px; height: 700px; right: -220px; top: -260px;
          background: radial-gradient(circle, rgba(94,234,212,.16), transparent 65%); }
  .logo { font: 700 26px ui-monospace, SFMono-Regular, Menlo, monospace; letter-spacing: -.01em; }
  .logo span { color: #5eead4; }
  h1 { font-size: 76px; line-height: 1.04; letter-spacing: -.03em; margin: 26px 0 0; }
  h1 em { font-style: normal; color: #5eead4; }
  p { font-size: 27px; color: #8b94a7; margin-top: 26px; max-width: 830px; }
  .row { display: flex; gap: 10px; margin-top: 40px; }
  .chip { font: 600 17px ui-monospace, SFMono-Regular, Menlo, monospace;
          border: 1px solid #232a38; border-radius: 99px; padding: 10px 18px; color: #8b94a7; }
  .foot { position: absolute; bottom: 46px; left: 80px; font-size: 21px; color: #5eead4;
          font-family: ui-monospace, SFMono-Regular, Menlo, monospace; }
</style></head><body>
  <div class="glow"></div>
  <div class="logo">vibe<span>check</span></div>
  <h1>You vibe-coded it.<br>Now <em>vibecheck</em> it.</h1>
  <p>Free security scan for apps built with Lovable, Bolt, Cursor and v0 —
  with a fix prompt you paste back into your AI tool.</p>
  <div class="row">
    <div class="chip">leaked keys</div>
    <div class="chip">Supabase RLS</div>
    <div class="chip">exposed .env</div>
    <div class="chip">XSS &amp; SQL</div>
  </div>
  <div class="foot">psychosecurity.io</div>
</body></html>
"""


def find_chromium():
    for candidate in sorted(Path("/opt/pw-browsers").glob("chromium-*/chrome-linux/chrome"), reverse=True):
        if candidate.exists():
            return str(candidate)
    return None


def main() -> int:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        print("playwright not installed — run: pip install playwright")
        return 1

    executable = find_chromium()
    with sync_playwright() as p:
        browser = p.chromium.launch(executable_path=executable) if executable else p.chromium.launch()
        page = browser.new_page(viewport={"width": 1200, "height": 630}, device_scale_factor=1)
        page.set_content(CARD, wait_until="load")
        page.screenshot(path=str(OUT))
        browser.close()

    print(f"wrote {OUT} ({OUT.stat().st_size // 1024} KB)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
