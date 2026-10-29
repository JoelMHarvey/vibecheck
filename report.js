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
  const MANIFEST_URLS = { security: "/rules.json", visibility: "/visibility-rules.json", integrity: "/integrity-rules.json" };
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

  // Badge levels: vibecheck/core/scoring.py LEVELS.
  function levelFor(r) {
    if (r.total === null || r.total === undefined) return null;
    const open = new Set(r.findings.map(f => f.severity));
    if (r.total >= 85 && !open.has("critical") && !open.has("high")) return "gold";
    if (r.total >= 70 && !open.has("critical")) return "silver";
    if (r.total >= 50 && !open.has("critical")) return "bronze";
    return null;
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

  /* ---------- signatures ----------
     A signed result carries signed.report: {p, sig, kid}, where p is the
     canonical JSON claim. The signature covers a prefix plus the exact bytes
     of p, checked here with WebCrypto against /.well-known/vibecheck-key, or
     by /api/verify where the browser has no Ed25519. */

  const PREFIX = { report: "vibecheck/report/1\n", badge: "vibecheck/badge/1\n" };
  let keysPromise = null;

  function keys() {
    if (!keysPromise) {
      keysPromise = fetch("/.well-known/vibecheck-key").then(r => r.ok ? r.json() : { keys: [] })
        .then(d => d.keys || []).catch(() => []);
    }
    return keysPromise;
  }

  async function verify(env, kind) {
    if (!env || typeof env.p !== "string") return "tampered";
    if (!env.sig) return "unsigned";
    const key = (await keys()).find(k => k.kid === env.kid);
    if (!key) return "unknown-key";
    const data = new TextEncoder().encode(PREFIX[kind] + env.p);
    try {
      const pub = await crypto.subtle.importKey("raw", unb64url(key.x), { name: "Ed25519" }, false, ["verify"]);
      return (await crypto.subtle.verify({ name: "Ed25519" }, pub, unb64url(env.sig), data)) ? "verified" : "tampered";
    } catch {
      try {
        const res = await fetch("/api/verify", { method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ envelope: env, kind }) });
        return res.ok ? (await res.json()).status : "unchecked";
      } catch { return "unchecked"; }
    }
  }

  function claimOf(r) {
    try { return r.signed && r.signed.report ? JSON.parse(r.signed.report.p) : null; } catch { return null; }
  }

  function expired(r) {
    const c = claimOf(r);
    return Boolean(c && c.expires_at && new Date(c.expires_at) <= new Date());
  }

  function provenanceLine(r, status) {
    const c = claimOf(r);
    const by = c && c.provenance ? c.provenance.by : null;
    const p = el("p", "vr-prov");
    if (status === "verified") {
      p.classList.add("ok");
      p.append("✓ Verified: scanned by psychosecurity.io and signed; the signature matches every finding below. ");
      const a = el("a", "", "How this is checked"); a.href = "/report#how"; p.append(a);
    } else if (status === "tampered") {
      p.classList.add("bad");
      p.textContent = "⚠ Tampered: this report's signature doesn't match its contents. Don't trust anything below.";
    } else if (status === "unknown-key") {
      p.classList.add("bad");
      p.textContent = "⚠ Signed with a key psychosecurity.io doesn't publish. Treat it as unverified.";
    } else if (by === "ci" && c.provenance.run) {
      p.append("Reported by a GitHub Actions run, not by psychosecurity.io, so it isn't signed. Open the run to see its log: ");
      // An unsigned claim, so the link is whatever the sender wrote: only
      // ever make it a link to github.com (never javascript: or a lookalike).
      const run = String(c.provenance.run);
      if (/^https:\/\/github\.com\//.test(run)) {
        const a = el("a", "", run.replace("https://github.com/", "")); a.href = run; a.rel = "noopener nofollow";
        p.append(a);
      } else {
        p.append(run);
      }
    } else if (by === "self") {
      p.textContent = "Self-reported: run on someone's own machine with the command-line tool, so it isn't signed.";
    } else if (status === "unchecked") {
      p.textContent = "Couldn't check the signature just now. Reload to try again.";
    } else {
      p.textContent = "Not signed.";
    }
    return p;
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
    const pos = positioningSkipped(r);
    if (pos) bits.push(`positioning not reviewed: ${pos}`);
    const ai = probeSkipped(r);
    if (ai) bits.push(`AI answers not checked: ${ai}`);
    bits.push(when(r.scanned_at));
    meta.append(el("p", "", bits.filter(Boolean).join(" · ")));
    const pills = el("div", "vr-pills");
    const c = counts(r);
    for (const sev of PROBLEMS) if (c[sev]) pills.appendChild(el("span", "vr-pill " + sev, `${c[sev]} ${sev}`));
    const lvl = r.level !== undefined ? r.level : levelFor(r);
    if (expired(r)) pills.appendChild(el("span", "vr-pill vr-expired", "badge expired: rescan"));
    else if (lvl) pills.appendChild(el("span", "vr-pill vr-level " + lvl, `${lvl} badge`));
    meta.append(pills);
    if (r.signed) {
      const line = el("p", "vr-prov", "Checking the signature…");
      meta.append(line);
      verify(r.signed && r.signed.report, "report").then(status => line.replaceWith(provenanceLine(r, status)));
    }
    card.append(dial(r.total, ids), meta);
    return card;
  }

  // The visibility positioning review can be skipped for a reason worth
  // saying (over the daily cap, nothing to read); "not run: <why>" in meta.
  function positioningSkipped(r) {
    const p = r.meta && r.meta.positioning;
    return typeof p === "string" && p.startsWith("not run: ") ? p.slice(9) : "";
  }

  function probeSkipped(r) {
    const p = r.meta && r.meta.probe;
    const s = p && typeof p.status === "string" ? p.status : "";
    return s.startsWith("not run: ") ? s.slice(9) : "";
  }

  // The AI-answer probe's snapshot: what Claude said to each question.
  function aiAnswers(r) {
    const answers = (r.meta && r.meta.probe && Array.isArray(r.meta.probe.answers)) ? r.meta.probe.answers : [];
    if (!answers.length) return null;
    const box = el("div", "vr-answers");
    box.append(el("h4", "vr-head", "What the AI said"));
    box.append(el("p", "vr-note", "A snapshot: AI answers vary from run to run, so read these as a sample, not a ranking."));
    for (const a of answers) {
      const card = el("div", "vr-answer");
      const tag = el("span", a.mentioned ? "vr-tag ok" : "vr-tag no", a.mentioned ? (a.cited ? "named, cited" : "named") : "not named");
      card.append(tag, el("strong", "", " " + String(a.q || "")));
      if (Array.isArray(a.competitors) && a.competitors.length) card.append(el("p", "vr-ev", "Also named: " + a.competitors.join(", ")));
      if (a.snippet) card.append(el("blockquote", "", String(a.snippet)));
      box.appendChild(card);
    }
    return box;
  }

  function categoryGrid(r, m) {
    const grid = el("div", "vr-cats");
    for (const [id, label] of m.categories) {
      const s = r.category_scores[id];
      const none = s === null || s === undefined;
      const skipped = id === "positioning" ? positioningSkipped(r) : (id === "brand" || id === "offsite") ? probeSkipped(r) : "";
      const noneLabel = skipped ? "not run this time" : (m.not_run || NOT_RUN);
      const box = el("div", "vr-cat"); const top = el("div", "vr-top");
      top.append(el("span", "", label), el("span", none ? "vr-val none" : "vr-val", none ? noneLabel : `${s}/10`));
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
    const answers = aiAnswers(r);
    if (answers) sec.append(answers);
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
    badge.addEventListener("click", async () => copy(badge, await badgeMarkdown(results, opts.pageUrl), "Copy badge (Markdown)"));
    if (results.some(expired)) badge.disabled = true;
    const md = el("button", "ghost", "Download report (Markdown)"); md.type = "button"; md.id = "downloadBtn";
    md.addEventListener("click", () => downloadMarkdown(results));
    row.append(share, badge, md);
    if (canCombine(results)) {
      const both = el("button", "", "Copy vibechecked badge"); both.type = "button"; both.id = "vibecheckedBtn";
      both.addEventListener("click", async () => {
        try { copy(both, await combinedBadge(results), "Copy vibechecked badge"); }
        catch (err) { alert(err.message); }
      });
      row.append(both);
    }
    if (opts.onRecheck) {
      const again = el("button", "ghost", "Check again now"); again.type = "button";
      again.addEventListener("click", opts.onRecheck);
      row.append(again);
    }
    box.append(row);
    return box;
  }

  function utf8b64url(text) { return b64url(new TextEncoder().encode(text)); }

  async function reportLink(envelopes) {
    return `${location.origin}/report#r=${await encodeSigned(envelopes)}`;
  }

  // A signed badge per result where the server issued one; the plain score
  // badge otherwise (no signing key configured, or an older link).
  async function badgeMarkdown(results, pageUrl) {
    const page = pageUrl || location.origin + location.pathname;
    const lines = [];
    for (const r of results) {
      if (r.total === null || r.total === undefined) continue;
      if (r.signed && r.signed.badge && r.signed.report) {
        const claim = JSON.parse(r.signed.badge.p);
        const img = `${location.origin}/badge/${r.check_id}.svg?r=${utf8b64url(JSON.stringify(r.signed.badge))}`;
        lines.push(`[![vibecheck ${r.check_id}: ${claim.level || "no badge yet"}](${img})](${await reportLink([r.signed.report])})`);
      } else {
        const [alt, label] = { security: ["Vibe Score", "vibe"], integrity: ["Integrity", "integrity"] }[r.check_id] || ["Visibility", "visibility"];
        lines.push(`[![${alt}](${location.origin}/api/badge?score=${r.total}&label=${label})](${page})`);
      }
    }
    return lines.join(" ");
  }

  function canCombine(results) {
    return results.length > 1 && results.every(r => r.signed && r.signed.report && !expired(r)
      && ["bronze", "silver", "gold"].includes(r.level !== undefined ? r.level : levelFor(r)));
  }

  async function combinedBadge(results) {
    const res = await fetch("/api/vibechecked", { method: "POST", headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ reports: results.map(r => r.signed.report) }) });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "No combined badge.");
    const img = `${location.origin}/badge/vibechecked.svg?r=${utf8b64url(JSON.stringify(data.badge))}`;
    return `[![vibechecked: ${JSON.parse(data.badge.p).level}](${img})](${await reportLink(results.map(r => r.signed.report))})`;
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

  async function gz(obj) {
    const bytes = new TextEncoder().encode(JSON.stringify(obj));
    if (window.CompressionStream) return "z" + b64url(await pipe(bytes, new CompressionStream("gzip")));
    return "j" + b64url(bytes);
  }

  // v3: the server's signed envelopes, as they are. Rewritten, they'd fail.
  function encodeSigned(envelopes) { return gz({ v: 3, e: envelopes }); }

  async function encode(results) {
    if (results.every(r => r.signed && r.signed.report)) return encodeSigned(results.map(r => r.signed.report));
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

  // v3: a signed envelope. The claim is parsed to draw it; whether it can be
  // trusted is decided by verify(), shown on the scorecard.
  async function hydrateSigned(env) {
    const c = JSON.parse(env.p);
    const m = await manifest(c.check);
    return {
      check_id: c.check, check_version: c.check_version, target: c.target || {}, scanned_at: c.scanned_at,
      total: c.total, category_scores: c.category_scores || {}, meta: c.meta || {}, level: c.level,
      findings: (c.findings || []).map(f => prose(m, c.check, f)), signed: { report: env },
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
    if (p.v === 3) return Promise.all(p.e.map(hydrateSigned));
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

  window.VibeReport = { render, encode, decode, shareUrl, toMarkdown, boot, gradeFor, verify, levelFor };
})();
