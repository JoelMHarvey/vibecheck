"""Ask the AI-answer probe's questions on two models, side by side.

    python3 scripts/compare_probe_models.py --config visibility.config.yaml --out compare/

For each site in a suite config (the format of projects/visibility-suite),
asks the five buyer questions on each model and writes what came back:
compare.json (every answer in full) and compare.md (a table per site, then
the answers). With SERPER_API_KEY set it also runs the off-site footprint
both ways, Claude's web search against plain Google searches, and lists the
directories each found.

It spends real money on your ANTHROPIC_API_KEY: about $0.35 a site on Claude
Opus 5.5 and a few pence on Claude Haiku 5.5. It stops before starting a
site once --budget dollars are spent.

--models takes model:searches pairs, comma-separated, first one the
baseline: the default compares Opus with 3 searches a question (what the
probe used to do) and Haiku with 2 (what it does now).
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import urlsplit

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from vibecheck.checks.visibility import probe as pr  # noqa: E402
from vibecheck.checks.visibility.footprint import run_footprint  # noqa: E402
from vibecheck.checks.visibility.serper import SerperSearch  # noqa: E402
from vibecheck.checks.visibility.websearch import ClaudeSearch, SearchUnavailable  # noqa: E402

# $ per million tokens: input, output, cache read. List prices, October 2026.
PRICES = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
}
PER_SEARCH = 0.01          # Claude web search, $10 per 1,000
PER_SERPER = 0.001         # Serper, about $1 per 1,000 on the smaller packs


def cost(model: str, usage: dict) -> float:
    i, o, r = PRICES.get(model, PRICES["claude-opus-5-5"])
    tokens = (usage["input_tokens"] * i + usage["cache_creation_input_tokens"] * i * 1.25
              + usage["cache_read_input_tokens"] * r + usage["output_tokens"] * o) / 1e6
    return tokens + usage["web_search_requests"] * PER_SEARCH


def load_apps(path: str):
    text = Path(path).read_text(encoding="utf-8")
    if path.endswith(".json"):
        return json.loads(text)["apps"]
    try:
        import yaml
    except ImportError:
        sys.exit("pip install pyyaml, or pass the config as JSON")
    return yaml.safe_load(text)["apps"]


def ask_all(model: str, searches: int, inp: pr.ProbeInput):
    search = ClaudeSearch(model=model)
    started = time.time()

    def one(q):
        try:
            return search.ask(q, country=inp.country, system=pr.SYSTEM, max_uses=searches)
        except SearchUnavailable as e:
            return e

    with ThreadPoolExecutor(max_workers=pr.QUESTIONS) as pool:
        answers = list(pool.map(one, pr.questions(inp)))
    out = []
    for q, a in zip(pr.questions(inp), answers):
        if isinstance(a, Exception):
            out.append({"q": q, "error": str(a)})
            continue
        r = pr.read(a, inp)
        out.append({"q": q, "mentioned": r.mentioned, "cited": r.cited, "position": r.position,
                    "competitors": r.competitors, "pages": r.cited_pages, "text": a.text})
    return {"model": model, "searches_cap": searches, "answers": out, "usage": dict(search.usage),
            "calls": search.calls, "seconds": round(time.time() - started, 1),
            "cost": round(cost(model, search.usage), 4)}


class _Scan:
    """Just enough of a scan for run_footprint to write to."""

    def __init__(self):
        self.added, self.passed, self.ran = [], [], set()
        self.llms_text, self.home = "", SimpleNamespace(description="")

    def add(self, rule, path, evidence, line=0):
        self.added.append((rule, evidence))

    def ok(self, rule, evidence):
        self.passed.append((rule, evidence))


def footprints(inp: pr.ProbeInput, baseline_model: str):
    out = {}
    claude = ClaudeSearch(model=baseline_model)
    s = _Scan()
    status = run_footprint(s, claude, inp.brand, inp.domain)
    out["claude"] = dict(getattr(s, "footprint", {}) or {}, status=status,
                         cost=round(cost(baseline_model, claude.usage), 4))
    key = os.environ.get("SERPER_API_KEY", "").strip()
    if key:
        serper = SerperSearch(key)
        s = _Scan()
        status = run_footprint(s, None, inp.brand, inp.domain, finder=serper)
        out["serper"] = dict(getattr(s, "footprint", {}) or {}, status=status,
                             cost=round(serper.searches * PER_SERPER, 4))
    return out


def _listed(fp: dict) -> str:
    if fp.get("listed"):
        return ", ".join(fp["listed"])
    return "none" if str(fp.get("status", "")).startswith("searched") else fp.get("status", "")


def tick(b):
    return "yes" if b else "no"


def render(results, models) -> str:
    base, *others = [m for m, _ in models]
    lines = ["# Probe models compared", "",
             "Each site was asked the same five buyer questions on each model. "
             "\"Named\" counts the answers that mention the brand; \"cited\" the ones that cite its site. "
             "Answers vary run to run on any model, so a difference of one is noise.", ""]
    head = "| Site | " + " | ".join(f"{m} named | cited" for m, _ in models) + " | Same answer on named? |"
    lines += [head, "|" + "---|" * (2 + 2 * len(models))]
    totals = {m: 0.0 for m, _ in models}
    for site in results:
        runs = {r["model"]: r for r in site["runs"]}
        cells = []
        for m, _ in models:
            ans = [a for a in runs[m]["answers"] if "error" not in a]
            cells.append(f"{sum(a['mentioned'] for a in ans)}/{len(ans)} | {sum(a['cited'] for a in ans)}")
            totals[m] += runs[m]["cost"]
        agree = sum(1 for i in range(pr.QUESTIONS)
                    if len({runs[m]["answers"][i].get("mentioned") for m, _ in models}) == 1)
        lines.append(f"| {site['brand']} | " + " | ".join(cells) + f" | {agree}/{pr.QUESTIONS} |")
    n = len(results) or 1
    lines += ["", "## Cost", ""]
    for m, s in models:
        lines.append(f"- **{m}** ({s} searches a question): ${totals[m]:.2f} for {len(results)} sites, "
                     f"${totals[m] / n:.3f} a site")
    fp = [s for s in results if s.get("footprint")]
    if fp:
        lines += ["", "## Off-site footprint", "",
                  "| Site | Claude found listed | Serper found listed | Other sites (Claude / Serper) |", "|---|---|---|---|"]
        for s in fp:
            c, g = s["footprint"].get("claude", {}), s["footprint"].get("serper", {})
            lines.append(f"| {s['brand']} | {_listed(c)} | {_listed(g) if g else 'no key'} | "
                         f"{len(c.get('elsewhere', []))} / {len(g.get('elsewhere', []))} |")
        cc = sum(s["footprint"].get("claude", {}).get("cost", 0) for s in fp)
        gc = sum(s["footprint"].get("serper", {}).get("cost", 0) for s in fp)
        lines += ["", f"Footprint cost: Claude ${cc:.2f}, Serper ${gc:.3f}, for {len(fp)} sites."]
    lines += ["", "## The answers", ""]
    for site in results:
        lines += [f"### {site['brand']}", "", f"{site['category']} ({site['country']}); competitors: "
                  + (", ".join(site["competitors"]) or "none given"), ""]
        runs = {r["model"]: r for r in site["runs"]}
        for i, q in enumerate(pr.questions(pr.ProbeInput(site["brand"], site["domain"], site["category"],
                                                         site["country"], site["competitors"]))):
            lines += [f"**{q}**", ""]
            for m, _ in models:
                a = runs[m]["answers"][i]
                if "error" in a:
                    lines.append(f"- *{m}*: not answered ({a['error']})")
                    continue
                text = " ".join(a["text"].split())
                lines.append(f"- *{m}* (named {tick(a['mentioned'])}, cited {tick(a['cited'])}"
                             + (f", position {a['position']}" if a["position"] else "")
                             + f"): {text[:700]}{'…' if len(text) > 700 else ''}")
            lines.append("")
    return "\n".join(lines) + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--config", required=True, help="suite config (.yaml or .json)")
    p.add_argument("--out", default="compare", help="folder for compare.json and compare.md")
    p.add_argument("--models", default="claude-opus-5-5:3,claude-haiku-5-5:2")
    p.add_argument("--only", action="append", default=[], help="a site slug (repeatable)")
    p.add_argument("--budget", type=float, default=10.0, help="stop before a site once this many dollars are spent")
    p.add_argument("--no-footprint", action="store_true")
    args = p.parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        sys.exit("needs ANTHROPIC_API_KEY")
    models = [(m.split(":")[0], int(m.split(":")[1]) if ":" in m else pr.SEARCHES) for m in args.models.split(",")]
    apps = [a for a in load_apps(args.config) if not args.only or a["slug"] in args.only]
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    results, spent = [], 0.0
    for app in apps:
        if spent >= args.budget:
            print(f"budget reached (${spent:.2f}); stopping before {app['slug']}")
            break
        host = (urlsplit(app["url"]).hostname or "").lower()
        inp = pr.ProbeInput(app["brand"], host, app["category"], app.get("country") or "GB",
                            list(app.get("competitors") or [])).clean()
        with ThreadPoolExecutor(max_workers=len(models) + 1) as pool:
            runs_f = [pool.submit(ask_all, m, s, inp) for m, s in models]
            fp_f = None if args.no_footprint else pool.submit(footprints, inp, models[0][0])
            runs = [f.result() for f in runs_f]
            fp = fp_f.result() if fp_f else None
        spent += sum(r["cost"] for r in runs) + sum(v.get("cost", 0) for v in (fp or {}).values())
        site = {"slug": app["slug"], "brand": inp.brand, "domain": inp.domain, "category": inp.category,
                "country": inp.country, "competitors": inp.competitors, "runs": runs, "footprint": fp}
        results.append(site)
        print(f"{app['slug']}: " + ", ".join(
            f"{r['model']} named {sum(a.get('mentioned', False) for a in r['answers'])}/5 ${r['cost']:.3f}"
            for r in runs) + f"  (spent ${spent:.2f})", flush=True)
        (out / "compare.json").write_text(json.dumps({"models": models, "sites": results}, indent=2), encoding="utf-8")
        (out / "compare.md").write_text(render(results, models), encoding="utf-8")
    print(f"wrote {out / 'compare.md'}; spent about ${spent:.2f}")


if __name__ == "__main__":
    main()
