/* The report component: renders any CheckResult (or several side by side),
   and builds share links, badge Markdown and Markdown downloads for them.

   A CheckResult is what /api/visibility returns, and what /api/scan and
   /api/scan-url return under "result". Share links carry only the facts of a
   result; the words come from each check's manifest (rules.json,
   visibility-rules.json), so a link stays short enough to paste in a chat.

   Everything is built with textContent: nothing from a result is ever
   parsed as HTML. */
(function () {
  "use strict";

  const PROBLEMS = ["critical", "high", "medium", "low", "info"];
  const NOT_RUN = "not checked";  // a manifest's own not_run wording wins
  const FIX_LABEL = "FIX PROMPT — PASTE INTO CURSOR / CLAUDE CODE / LOVABLE / BOLT";
  const MANIFEST_URLS = { security: "/rules.json", visibility: "/visibility-rules.json" };
  // Points a category loses per finding: vibecheck/core/scoring.py.
  const PENALTY = { critical: 10, high: 4, medium: 2, low: 1, info: 0, pass: 0 };
  const manifests = {};

  async function manifest(checkId) {
    if (!manifests[checkId]) {
      const url = MANIFEST_URLS[checkId];
      if (!url) throw new Error("unknown check " + checkId);
      const res = await fetch(url);
      if (!res.ok) throw new Error("couldn't load the descriptions for " + checkId);
      manifests[checkId] = await res.json();
    }
    return manifests[checkId];
  }

  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text !== undefined && text !== null) n.textContent = text;
    return n;
  }

  function gradeFor(total) {
    if (total === null || total === undefined) return "–";
    for (const [t, g] of [[90, "A"], [75, "B"], [60, "C"], [40, "D"]]) if (total >= t) return g;
    return "F";
  }

  function loc(f) { return f.line ? `${f.path}:${f.line}` : f.path; }

  function describeTarget(t) {
    const parts = [t.repo, t.url && t.url.replace(/^https?:\/\//, "").replace(/\/$/, "")].filter(Boolean);
    let s = parts.join(" + ") || "your project";
    if (t.commit) s += ` (commit ${t.commit.slice(0, 7)})`;
    return s;
  }

  function when(iso) {
    const d = new Date(iso);
    return isNaN(d) ? "" : d.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function counts(r) {
    const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of r.findings) if (f.severity in c) c[f.severity] += 1;
    return c;
  }

  async function copy(btn, text, original) {
    try {
      await navigator.clipboard.writeText(text);
      btn.textContent = "Copied ✓"; btn.classList.add("done");
    } catch {
      btn.textContent = "Press ⌘C to copy";
      window.prompt("Copy:", text);
    }
    setTimeout(() => { btn.textContent = original; btn.classList.remove("done"); }, 1800);
  }

  /* ---------- drawing ---------- */

  // ids: on a page showing one result, the dial and lists keep the ids the
  // home page always had (tests/test_browser.py drives them).
  function dial(total, ids) {
    const d = el("div", "vr-dial");
    d.style.setProperty("--vr-pct", total || 0);
    d.style.setProperty("--vr-dial", total >= 90 ? "var(--accent)" : total >= 60 ? "var(--vr-medium)" : "var(--vr-critical)");
    const inner = el("div", "vr-inner"); const box = el("div");
    const num = el("div", "vr-num", total === null || total === undefined ? "–" : String(total));
    const g = gradeFor(total);
    const grade = el("div", "vr-grade", g === "–" ? "" : "grade " + g);
    if (ids) { num.id = "scoreNum"; grade.id = "scoreGrade"; }
    box.append(num, grade);
    inner.appendChild(box); d.appendChild(inner);
    return d;
  }

  function scorecard(r, m, ids) {
    const card = el("div", "vr-card");
    const meta = el("div", "vr-meta");
    meta.append(el("h3", "", describeTarget(r.target)));
    meta.append(el("p", "", (m.blurbs || {})[gradeFor(r.total)] || ""));
    const bits = [];
    if (r.meta && "files_scanned" in r.meta) bits.push(`${r.meta.files_scanned} files scanned`);
    if (r.meta && "pages_crawled" in r.meta) bits.push(`${r.meta.pages_crawled} page${r.meta.pages_crawled === 1 ? "" : "s"} crawled`);
    const scores = Object.values(r.category_scores);
    const ran = scores.filter(s => s !== null).length;
    if (ran && ran < scores.length) bits.push(`score based on ${ran} of ${scores.length} categories`);
    bits.push(when(r.scanned_at));
    meta.append(el("p", "", bits.filter(Boolean).join(" · ")));
    const pills = el("div", "vr-pills");
    const c = counts(r);
    for (const sev of PROBLEMS) if (c[sev]) pills.appendChild(el("span", "vr-pill " + sev, `${c[sev]} ${sev}`));
    meta.append(pills);
    card.append(dial(r.total, ids), meta);
    return card;
  }

  function categoryGrid(r, m) {
    const grid = el("div", "vr-cats");
    for (const [id, label] of m.categories) {
      const s = r.category_scores[id];
      const none = s === null || s === undefined;
      const box = el("div", "vr-cat"); const top = el("div", "vr-top");
      top.append(el("span", "", label), el("span", none ? "vr-val none" : "vr-val", none ? (m.not_run || NOT_RUN) : `${s}/10`));
      const bar = el("div", "vr-bar"); const fill = el("span");
      fill.style.width = (none ? 0 : s * 10) + "%";
      bar.appendChild(fill); box.append(top, bar); grid.appendChild(box);
    }
    return grid;
  }

  function findingCard(f) {
    const div = el("div", "vr-finding finding " + f.severity);
    const row = el("div", "vr-frow");
    row.append(el("h3", "", f.title), el("span", "vr-sev " + f.severity, f.severity.toUpperCase()));
    div.append(row, el("div", "vr-loc", loc(f)));
    if (f.evidence) div.append(el("div", "vr-excerpt", f.evidence));
    if (f.why_it_matters) div.append(el("div", "vr-label", "WHY IT MATTERS"), el("p", "vr-desc", f.why_it_matters));
    if (f.fix_prompt) {
      const fix = el("div", "vr-fix fixwrap");
      const btn = el("button", "vr-copy", "Copy fix prompt");
      btn.type = "button";
      btn.addEventListener("click", () => copy(btn, f.fix_prompt, "Copy fix prompt"));
      fix.append(el("div", "vr-label", FIX_LABEL), el("p", "", f.fix_prompt), btn);
      div.append(fix);
    }
    if (f.verify_hint) div.append(el("div", "vr-label", "HOW TO CHECK IT WORKED"), el("p", "", f.verify_hint));
    if (f.guide_url) {
      const p = el("p"); const a = el("a", "", "Read the guide →");
      a.href = f.guide_url; p.appendChild(a); div.append(p);
    }
    return div;
  }

  function section(r, m, opts) {
    const sec = el("section", "vr-section");
    sec.id = "check-" + r.check_id;
    const ids = !opts.many;
    if (opts.many) sec.append(el("h2", "", m.title));
    sec.append(scorecard(r, m, ids), categoryGrid(r, m));
    const problems = r.findings.filter(f => f.severity !== "pass");
    const passes = r.findings.filter(f => f.severity === "pass");
    if (problems.length) {
      sec.append(el("h4", "vr-head", "To fix"));
      const list = el("div", "vr-findings");
      if (ids) list.id = "findings";
      for (const f of problems) list.appendChild(findingCard(f));
      sec.append(list);
    } else if (r.total !== null && r.total !== undefined) {
      const ok = el("div", "vr-finding vr-clean");
      ok.append(el("h3", "", "✓ Nothing found. Nice."));
      ok.append(el("p", "vr-desc", "This covers common mistakes, not everything. Re-run it after every big change."));
      const list = el("div", "vr-findings"); list.appendChild(ok); sec.append(list);
    }
    if (passes.length) {
      sec.append(el("h4", "vr-head", "Working"));
      const ul = el("ul", "vr-passes");
      for (const p of passes) {
        const li = el("li"); const body = el("span");
        body.append(el("strong", "", p.title), el("span", "vr-ev", p.evidence));
        li.append(el("span", "vr-tick", "✓"), body); ul.appendChild(li);
      }
      sec.append(ul);
    }
    if (m.footer) sec.append(el("p", "vr-footer", m.footer));
    return sec;
  }

  function summary(results, ms) {
    const row = el("div", "vr-summary");
    results.forEach((r, i) => {
      const a = el("a", "vr-mini"); a.href = "#check-" + r.check_id;
      const text = el("div");
      text.append(el("strong", "", ms[i].title), el("span", "", (ms[i].blurbs || {})[gradeFor(r.total)] || ""));
      a.append(dial(r.total), text);
      row.appendChild(a);
    });
    return row;
  }

  /* opts: { shared, shareNote, onRecheck, pageUrl } */
  async function render(container, results, opts) {
    opts = opts || {};
    const ms = await Promise.all(results.map(r => manifest(r.check_id)));
    container.replaceChildren();
    container.classList.add("vr");
    if (opts.shared) {
      const b = el("div", "vr-banner"); b.id = "sharedBanner";
      b.append("📄 You're viewing a ", el("strong", "", "shared report"),
               ". The findings are encoded in this link; nothing was stored on a server. ");
      const a = el("a", "", "Run your own scan →"); a.href = location.pathname;
      b.append(a); container.append(b);
    }
    const many = results.length > 1;
    if (many) container.append(summary(results, ms));
    if (!opts.shared) container.append(sharePanel(results, opts));
    results.forEach((r, i) => container.append(section(r, ms[i], { many })));
    container.style.display = "block";
    container.scrollIntoView({ behavior: opts.shared ? "auto" : "smooth" });
  }

  function sharePanel(results, opts) {
    const box = el("div", "vr-share"); box.id = "sharePanel";
    box.append(el("h3", "", "Share this report"));
    box.append(el("p", "vr-note", opts.shareNote || "The link carries the whole report inside the URL. We store nothing."));
    const row = el("div", "vr-row");
    const share = el("button", "", "Copy share link"); share.type = "button"; share.id = "shareBtn";
    share.addEventListener("click", async () => {
      const url = await shareUrl(results);
      if (url.length > 30000) { alert("This report is too big for a link. Use the Markdown download."); return; }
      history.replaceState(null, "", url.slice(url.indexOf("#")));
      copy(share, url, "Copy share link");
    });
    const badge = el("button", "ghost", "Copy badge (Markdown)"); badge.type = "button"; badge.id = "badgeBtn";
    badge.addEventListener("click", () => copy(badge, badgeMarkdown(results, opts.pageUrl), "Copy badge (Markdown)"));
    const md = el("button", "ghost", "Download report (Markdown)"); md.type = "button"; md.id = "downloadBtn";
    md.addEventListener("click", () => downloadMarkdown(results));
    row.append(share, badge, md);
    if (opts.onRecheck) {
      const again = el("button", "ghost", "Check again now"); again.type = "button";
      again.addEventListener("click", opts.onRecheck);
      row.append(again);
    }
    box.append(row);
    return box;
  }

  function badgeMarkdown(results, pageUrl) {
    const page = pageUrl || location.origin + location.pathname;
    return results.filter(r => r.total !== null && r.total !== undefined).map(r => {
      const [alt, label] = r.check_id === "security" ? ["Vibe Score", "vibe"] : ["Visibility", "visibility"];
      return `[![${alt}](${location.origin}/api/badge?score=${r.total}&label=${label})](${page})`;
    }).join(" ");
  }

  /* ---------- Markdown ---------- */

  async function toMarkdown(results) {
    const ms = await Promise.all(results.map(r => manifest(r.check_id)));
    let md = results.length > 1 ? `# vibecheck report\n\n**Target:** ${describeTarget(results[0].target)}\n\n` : "";
    results.forEach((r, i) => {
      const m = ms[i]; const h = results.length > 1 ? "##" : "#";
      md += `${h} vibecheck ${m.title.toLowerCase()} report\n\n**Target:** ${describeTarget(r.target)} · ${r.scanned_at}\n\n`;
      md += r.total === null || r.total === undefined ? `${h}# ${m.title}: not checked\n\n`
        : `${h}# ${m.title}: ${r.total}/100 (grade ${gradeFor(r.total)})\n\n`;
      md += "| Category | Score |\n|---|---|\n";
      for (const [id, label] of m.categories) {
        const s = r.category_scores[id];
        md += `| ${label} | ${s === null || s === undefined ? "_" + (m.not_run || NOT_RUN) + "_" : s + "/10"} |\n`;
      }
      md += "\n";
      let sev = null;
      for (const f of r.findings.filter(x => x.severity !== "pass")) {
        if (f.severity !== sev) { sev = f.severity; md += `${h}# ${sev.toUpperCase()}\n\n`; }
        md += `${h}## ${f.title}\n\n\`${loc(f)}\`\n\n`;
        if (f.evidence) md += `> ${f.evidence}\n\n`;
        if (f.why_it_matters) md += `**Why it matters:** ${f.why_it_matters}\n\n`;
        if (f.fix_prompt) md += `**Fix prompt:**\n\n\`\`\`text\n${f.fix_prompt}\n\`\`\`\n\n`;
        if (f.verify_hint) md += `**Check it worked:** ${f.verify_hint}\n\n`;
        if (f.guide_url) md += `More: ${location.origin}${f.guide_url}\n\n`;
      }
      const passes = r.findings.filter(x => x.severity === "pass");
      if (passes.length) {
        md += `${h}# Working\n\n` + passes.map(p => `- ✓ **${p.title}** — ${p.evidence}`).join("\n") + "\n\n";
      }
      if (m.footer) md += `_${m.footer}_\n\n`;
    });
    return md + "---\n_Generated by vibecheck · psychosecurity.io_\n";
  }

  async function downloadMarkdown(results) {
    const blob = new Blob([await toMarkdown(results)], { type: "text/markdown" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = results.length > 1 ? "vibecheck-report.md" : `vibecheck-${results[0].check_id}.md`;
    a.click();
    URL.revokeObjectURL(a.href);
  }

  /* ---------- share links ----------
     The report is compressed into the URL fragment, which browsers never send
     to a server. v2 carries any number of results; v1 links (security only,
     from before the framework) still open. */

  function b64url(bytes) {
    let s = "";
    for (const b of bytes) s += String.fromCharCode(b);
    return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function unb64url(str) {
    let s = str.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    const bin = atob(s); const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  async function pipe(bytes, stream) {
    return new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
  }

  async function compact(r) {
    const m = await manifest(r.check_id);
    return {
      c: r.check_id, cv: r.check_version, t: r.target, at: r.scanned_at, s: r.total,
      cs: m.categories.map(([id]) => r.category_scores[id] ?? null), m: r.meta || {},
      f: r.findings.map(f => [f.id, f.severity, f.path || "", f.line || 0, f.evidence || ""]),
    };
  }

  async function encode(results) {
    const payload = { v: 2, r: await Promise.all(results.map(compact)) };
    const bytes = new TextEncoder().encode(JSON.stringify(payload));
    if (window.CompressionStream) return "z" + b64url(await pipe(bytes, new CompressionStream("gzip")));
    return "j" + b64url(bytes);
  }

  async function shareUrl(results) {
    return `${location.origin}${location.pathname}#r=${await encode(results)}`;
  }

  function fill(tpl, path, line, excerpt) {
    // Mirrors Python str.format with {path}, {line} and {excerpt}, then unescapes {{ }}.
    return String(tpl || "").split("{path}").join(path).split("{line}").join(String(line))
      .split("{excerpt}").join(excerpt).split("{{").join("{").split("}}").join("}");
  }

  function prose(m, checkId, [id, severity, path, line, evidence]) {
    const r = m.rules[id] || {};
    return {
      id, check_id: checkId, category: r.c || "", severity, title: r.t || id,
      why_it_matters: fill(r.d, path, line, evidence), evidence,
      fix_prompt: r.f ? fill(r.f, path, line, evidence) : "", verify_hint: r.v || "",
      guide_url: r.g || null, path, line,
    };
  }

  async function hydrate(c) {
    const m = await manifest(c.c);
    const scores = {};
    m.categories.forEach(([id], i) => { scores[id] = c.cs[i] ?? null; });
    return {
      check_id: c.c, check_version: c.cv, target: c.t || {}, scanned_at: c.at, total: c.s,
      category_scores: scores, meta: c.m || {}, findings: c.f.map(f => prose(m, c.c, f)),
    };
  }

  // v1: the security-only links from before the framework.
  async function hydrateV1(p) {
    const m = await manifest("security");
    const findings = p.f.map(f => prose(m, "security", f));
    const ran = p.k === "url" ? ["secrets", "exposure", "config"] : m.categories.map(([id]) => id);
    const scores = {};
    for (const [id] of m.categories) {
      if (!ran.includes(id)) { scores[id] = null; continue; }
      const pen = findings.filter(f => f.category === id).reduce((n, f) => n + PENALTY[f.severity], 0);
      scores[id] = Math.max(0, 10 - pen);
    }
    return {
      check_id: "security", check_version: m.check_version, scanned_at: "", total: p.s,
      target: p.k === "url" ? { url: "the site you scanned" } : { repo: "uploaded project" },
      category_scores: scores, meta: p.k === "url" ? {} : { files_scanned: p.n }, findings,
    };
  }

  async function decode(str) {
    let bytes = unb64url(str.slice(1));
    if (str[0] === "z") bytes = await pipe(bytes, new DecompressionStream("gzip"));
    else if (str[0] !== "j") throw new Error("unrecognised link format");
    const p = JSON.parse(new TextDecoder().decode(bytes));
    if (p.v === 1) return [await hydrateV1(p)];
    if (p.v === 2) return Promise.all(p.r.map(hydrate));
    throw new Error("this link is from a newer version of vibecheck");
  }

  /* Open a shared report if the page was loaded with one. Returns true if so. */
  async function boot(container, statusEl) {
    if (!location.hash.startsWith("#r=")) return false;
    try {
      if (statusEl) statusEl.textContent = "Loading shared report…";
      await render(container, await decode(location.hash.slice(3)), { shared: true });
      if (statusEl) statusEl.textContent = "";
    } catch (err) {
      if (statusEl) statusEl.textContent = "⚠ That shared link couldn't be read (" + err.message + ")";
    }
    return true;
  }

  window.VibeReport = { render, encode, decode, shareUrl, toMarkdown, boot, gradeFor };
})();
