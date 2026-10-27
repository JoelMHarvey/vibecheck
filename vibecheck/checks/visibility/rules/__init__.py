"""Visibility rules: the prose behind every finding and pass.

A finding carries only facts (rule id, page path, evidence). Everything a
reader sees beyond that lives here, so the share link can stay small and the
page can rehydrate it from visibility-rules.json.

Fix prompts may use {path} (the page) and {excerpt} (the evidence, e.g. the
hosts or sections involved). Literal braces are written {{ }}.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple

GUIDE_LOVABLE = "/guides/lovable-app-invisible-to-google"
GUIDE_LLMS = "/guides/llms-txt"


@dataclass(frozen=True)
class VisRule:
    id: str
    title: str
    severity: str
    category: str
    description: str   # why it matters
    fix_prompt: str
    verify: str        # how to check it worked
    guide: Optional[str] = None


_RULES = [
    # ---- Technical: can a crawler read it at all? ------------------------
    VisRule(
        "robots-blocks-search", "robots.txt blocks search engines", "critical", "technical",
        "Your robots.txt tells Google and Bing not to crawl your home page. They "
        "will drop the site from results, or show it with no description. This is "
        "usually a leftover from a staging setting.",
        "My robots.txt blocks search engines from my site ({excerpt}). Change it so "
        "search engines may crawl everything public: 'User-agent: *' then "
        "'Allow: /', and keep Disallow lines only for private areas like /admin. "
        "Add a 'Sitemap:' line with my sitemap's full URL. If my host or framework "
        "generates robots.txt (Next.js app/robots.ts, a Vercel or Netlify setting), "
        "fix it there.",
        "Open /robots.txt in a browser and read it. Then paste your home page into "
        "Google Search Console's URL Inspection and check 'Crawl allowed? Yes'.",
    ),
    VisRule(
        "robots-blocks-us", "This site asks crawlers like vibecheck to stay out", "info", "technical",
        "robots.txt disallows our crawler, so we only read the crawl files "
        "(robots.txt, sitemap.xml, llms.txt). Search engines may still be allowed; "
        "see the other findings.",
        "",
        "Allow the 'vibecheck-visibility' user agent in robots.txt if you want a "
        "full report, or run the CLI against your own site.",
    ),
    VisRule(
        "robots-missing", "No robots.txt", "low", "technical",
        "Search engines crawl fine without one, but robots.txt is where crawlers "
        "look for your sitemap, and the first place AI companies' crawlers check.",
        "My site has no robots.txt. Add one at the site root that allows "
        "everything ('User-agent: *' then 'Allow: /') and names my sitemap with a "
        "'Sitemap: https://<my domain>/sitemap.xml' line. If my framework "
        "generates it (Next.js app/robots.ts), use that.",
        "Open /robots.txt in a browser: it should be plain text, not your app's "
        "home page.",
    ),
    VisRule(
        "sitemap-missing", "No sitemap.xml", "medium", "technical",
        "A sitemap is the list of pages you want found. Without one, crawlers "
        "only find what they can reach by following links, and new pages take "
        "longer to show up.",
        "My site has no sitemap.xml. Generate one at /sitemap.xml listing every "
        "public page with its full URL and a <lastmod> date that changes when the "
        "page changes. Build it from my routes so new pages are added "
        "automatically (Next.js: app/sitemap.ts; Vite: a build step or "
        "vite-plugin-sitemap). Reference it from robots.txt.",
        "Open /sitemap.xml: it should be XML listing your pages. Then submit it "
        "in Google Search Console under Sitemaps and check it reads 'Success'.",
    ),
    VisRule(
        "sitemap-invalid", "sitemap.xml doesn't parse", "medium", "technical",
        "Your sitemap exists but isn't valid XML, so crawlers ignore it.",
        "My /sitemap.xml isn't valid sitemap XML ({excerpt}). Fix it so it is a "
        "standard <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"> "
        "with one <url><loc>full URL</loc><lastmod>YYYY-MM-DD</lastmod></url> per "
        "page, and make sure the server sends it as XML, not as my app's HTML.",
        "Paste /sitemap.xml into Google Search Console under Sitemaps and check "
        "it reads 'Success'.",
    ),
    VisRule(
        "sitemap-not-in-robots", "robots.txt doesn't point to the sitemap", "low", "technical",
        "Crawlers that don't know your sitemap's address find it through a "
        "'Sitemap:' line in robots.txt. Bing and most AI crawlers rely on it.",
        "Add a line to my robots.txt: 'Sitemap: ' followed by the full URL of my "
        "sitemap (for example https://example.com/sitemap.xml).",
        "Open /robots.txt and check the Sitemap line is there with a full URL.",
    ),
    VisRule(
        "sitemap-incomplete", "Pages missing from the sitemap", "low", "technical",
        "Your site links to pages your sitemap doesn't list. Crawlers can still "
        "find them by following links, but the sitemap is your statement of what "
        "matters, and pages left out of it get crawled less often.",
        "My sitemap.xml is missing pages my site links to ({excerpt}). Generate "
        "the sitemap from my routes rather than by hand, so every public page is "
        "listed, and leave out only pages that shouldn't be found (admin, "
        "thank-you pages).",
        "Open /sitemap.xml and check each page your navigation links to is listed.",
    ),
    VisRule(
        "sitemap-orphans", "Sitemap pages nothing links to", "low", "technical",
        "These pages are in your sitemap but no page we crawled links to them. "
        "Search engines treat a page with no internal links as unimportant.",
        "These pages are in my sitemap but nothing on my site links to them: "
        "{excerpt}. Link each one from a relevant page or the footer, or take it "
        "out of the sitemap if it shouldn't be found.",
        "Re-run this scan; the pages should no longer be listed as orphans.",
    ),
    VisRule(
        "sitemap-lastmod-stale", "Sitemap dates are older than the pages", "low", "technical",
        "Your sitemap says these pages last changed earlier than the server "
        "says they did. Crawlers use lastmod to decide what to re-read, so an old "
        "date means your changes are picked up late, or a wrong date teaches them "
        "to ignore it.",
        "The <lastmod> dates in my sitemap.xml are older than my pages ({excerpt}). "
        "Set each page's lastmod from when its content last changed (the file's "
        "git commit date or the record's updated_at), not a fixed date, and "
        "regenerate the sitemap on every deploy.",
        "Open /sitemap.xml after your next content change and check that page's "
        "lastmod moved.",
    ),
    VisRule(
        "sitemap-broken-urls", "Sitemap lists pages that don't load", "medium", "technical",
        "Your sitemap sends crawlers to pages that return errors or redirect. "
        "Search Console reports these, and enough of them make crawlers trust the "
        "sitemap less.",
        "My sitemap.xml lists URLs that don't return 200 ({excerpt}). Remove dead "
        "pages, and list redirected ones by their final URL.",
        "Re-run this scan, or check Search Console's Pages report for "
        "'Submitted URL not found'.",
    ),
    VisRule(
        "csr-vite", "Crawlers see a blank page", "high", "technical",
        "Your page's raw HTML has almost no text: the content is drawn by "
        "JavaScript after it loads. Google renders JavaScript eventually, later "
        "and less reliably. ChatGPT, Claude, Perplexity and most link previews "
        "don't run it at all, so to them your site is an empty page.",
        "My site is a client-side Vite + React app ({excerpt}), so crawlers and AI "
        "bots get an empty <div id=\"root\"> with no text. Make the public pages "
        "(home, pricing, about, each feature page) render real HTML at build time: "
        "prerender those routes to static HTML (vite-plugin-prerender, or "
        "react-snap), or move the marketing pages to a static site generator, and "
        "keep the logged-in app as it is. Every public page should have its own "
        "<title>, meta description and visible text in the HTML that's served.",
        "Run 'curl -s https://yoursite.com/ | grep -c \"<p\"' or view source "
        "(not Inspect) in your browser: your headline and copy should be in it. "
        "Then re-run this scan.",
        GUIDE_LOVABLE,
    ),
    VisRule(
        "csr-next", "Crawlers see a blank page", "high", "technical",
        "Your page's raw HTML has almost no text: the content is drawn by "
        "JavaScript after it loads. Google renders JavaScript eventually, later "
        "and less reliably. ChatGPT, Claude, Perplexity and most link previews "
        "don't run it at all, so to them your site is an empty page.",
        "My Next.js site ({excerpt}) sends crawlers HTML with no content, because "
        "the public pages render on the client. Make the marketing pages server "
        "components (remove 'use client' from the page and layout, move "
        "interactive bits into small client components), fetch their data on the "
        "server, and don't wrap the page in a provider that renders nothing until "
        "it mounts. Use static generation for pages that don't change per visitor.",
        "View source (not Inspect) on the page: your headline and copy should be "
        "in the HTML. Then re-run this scan.",
        GUIDE_LOVABLE,
    ),
    VisRule(
        "csr-generic", "Crawlers see a blank page", "high", "technical",
        "Your page's raw HTML has almost no text: the content is drawn by "
        "JavaScript after it loads. Google renders JavaScript eventually, later "
        "and less reliably. ChatGPT, Claude, Perplexity and most link previews "
        "don't run it at all, so to them your site is an empty page.",
        "My site renders its content with client-side JavaScript ({excerpt}), so "
        "crawlers get HTML with no text. Make the public pages serve real HTML: "
        "prerender them at build time or render them on the server, so each has "
        "its own <title>, meta description and visible copy in the HTML that's "
        "served. The logged-in app can stay client-side.",
        "View source (not Inspect) on the page: your headline and copy should be "
        "in the HTML. Then re-run this scan.",
        GUIDE_LOVABLE,
    ),
    VisRule(
        "canonical-missing", "No canonical URL", "low", "technical",
        "A canonical tag tells search engines which address is the real one when "
        "a page is reachable several ways (with and without www, a trailing "
        "slash, tracking parameters). Without it they guess, and can split your "
        "ranking between copies.",
        "Add <link rel=\"canonical\" href=\"...\"> to the <head> of every page, "
        "pointing at that page's own full URL on my main domain ({excerpt}). "
        "Generate it from the route so each page gets its own.",
        "View source on each page and check the canonical is the page's own "
        "address.",
    ),
    VisRule(
        "canonical-elsewhere", "Canonical points somewhere else", "medium", "technical",
        "These pages tell search engines that a different URL is the real one, so "
        "the page itself won't rank. Usually a copied <head> or a hard-coded home "
        "page URL.",
        "These pages have a canonical URL that isn't their own address: {excerpt}. "
        "Make every page's canonical its own full URL, on the same host form "
        "(www or not) the site actually serves.",
        "View source on each page listed and check the canonical matches the "
        "address bar.",
    ),
    VisRule(
        "lang-missing", "No language set", "low", "technical",
        "Without <html lang>, search engines and screen readers have to guess "
        "the page's language, and can show it to the wrong audience.",
        "Add a lang attribute to the <html> tag on every page ({excerpt}), for "
        "example <html lang=\"en-GB\">.",
        "View source and check the first tag reads <html lang=\"...\">.",
    ),
    VisRule(
        "viewport-missing", "No mobile viewport", "medium", "technical",
        "Without a viewport tag phones show the desktop layout shrunk down. "
        "Google indexes the mobile version first, so this costs rankings.",
        "Add <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> "
        "to the <head> of every page ({excerpt}).",
        "Open the site on a phone: text should be readable without zooming.",
    ),
    VisRule(
        "host-duplicate", "www and bare domain both serve the site", "medium", "technical",
        "Both addresses answer with the full site instead of one redirecting to "
        "the other. Search engines see two copies, split links between them and "
        "pick one to show, maybe not the one you'd choose.",
        "My site answers on both {excerpt} without redirecting. Pick one (the "
        "one my canonical tags use) and make the other return a permanent 301 or "
        "308 redirect to the same path on it. On Vercel or Netlify, set the "
        "other domain to redirect in the domain settings.",
        "Run 'curl -sI https://<the other form>/' and check for a 301 or 308 "
        "with a Location header on your main domain.",
    ),
    VisRule(
        "host-unreachable", "The other form of your domain doesn't load", "low", "technical",
        "People type www (or leave it off) out of habit. {excerpt} doesn't load "
        "at all, so they get an error instead of your site.",
        "{excerpt} doesn't load. Add it as a domain on my host with a DNS record "
        "pointing at it, and have it redirect permanently (301 or 308) to my main "
        "domain.",
        "Open the other form in a browser: it should land on your site.",
    ),
    VisRule(
        "host-redirect-temporary", "www/bare redirect is temporary", "low", "technical",
        "One form of your domain redirects to the other with a temporary (302 or "
        "307) redirect. Search engines keep the old address in mind for a "
        "temporary one, so links to it don't fully count.",
        "My domain redirects between www and the bare domain with a temporary "
        "redirect ({excerpt}). Make it permanent: 301 or 308.",
        "Run 'curl -sI' on the redirecting address and check the status is 301 "
        "or 308.",
    ),
    VisRule(
        "http-not-redirected", "Plain HTTP doesn't redirect to HTTPS", "high", "technical",
        "Your site loads over plain http:// without sending visitors to https://. "
        "Browsers mark it 'Not secure', and search engines may index the "
        "insecure copy.",
        "My site serves pages over plain HTTP ({excerpt}). Redirect every http:// "
        "request permanently (301 or 308) to the same path on https://, and add "
        "a Strict-Transport-Security header.",
        "Open http:// plus your domain: the address bar should end on https://.",
    ),
    VisRule(
        "redirect-chain", "Redirect chains", "low", "technical",
        "Getting to your page takes more than one redirect. Each hop slows the "
        "first visit and crawlers give up on long chains.",
        "These addresses take more than one redirect to reach my site: "
        "{excerpt}. Make each redirect go straight to the final https:// URL on "
        "my main domain in one hop.",
        "Run 'curl -sIL' on each address and count the Location lines: one at "
        "most.",
    ),
    VisRule(
        "internal-link-redirects", "Internal links that redirect", "low", "technical",
        "Links between your own pages go to an address that redirects. Every one "
        "costs a crawler an extra request and some of the link's value.",
        "My site links to its own pages at addresses that redirect: {excerpt}. "
        "Change those links to the final address (usually a trailing slash or "
        "the www/bare form).",
        "Re-run this scan; the links should no longer be listed.",
    ),
    VisRule(
        "internal-links-other-host", "Internal links use the other host form", "low", "technical",
        "Some links to your own pages use the other form of your domain (www or "
        "bare), so every click and crawl goes through a redirect, and the links "
        "point at an address you don't want indexed.",
        "Some of my internal links use the other host form: {excerpt}. Use "
        "relative links, or the same host my canonical tags use.",
        "Re-run this scan; the links should no longer be listed.",
    ),
    VisRule(
        "external-host-mixed", "Same sites linked with and without www", "low", "technical",
        "You link to the same sites by two different addresses (with and without "
        "www) in different places. One of each pair redirects, and to a crawler "
        "or an AI reading your llms.txt they look like separate sites.",
        "I link to these sites with both www and bare addresses: {excerpt}. Use "
        "the form each site actually serves (the one it doesn't redirect away "
        "from) everywhere: page links, llms.txt and structured data.",
        "Search your source for each domain and check every mention uses the "
        "same form.",
    ),
    VisRule(
        "img-oversized", "Heavy images", "low", "technical",
        "These images are over 300 KB. Large images slow the page, and speed is "
        "part of how Google ranks it, especially on phones.",
        "These images on my site are over 300 KB: {excerpt}. Resize them to the "
        "largest size they're displayed at, convert them to WebP or AVIF, and "
        "serve responsive sizes with srcset. Lazy-load anything below the fold.",
        "Re-run this scan, or check the images in PageSpeed Insights.",
    ),
    VisRule(
        "site-unreachable", "Site could not be reached", "info", "technical",
        "We couldn't load the home page, so no checks ran. Check the address and "
        "that the site is up.",
        "",
        "Open the address in a browser, then scan again.",
    ),

    # ---- AI readiness -------------------------------------------------------
    VisRule(
        "llms-missing", "No llms.txt", "low", "ai",
        "llms.txt is a short plain-text summary of your site for AI assistants: "
        "what it is, who it's for, and links to the pages that matter. It's a new "
        "convention, cheap to add, and gives an AI something accurate to quote.",
        "Create /llms.txt at my site root, in Markdown: a '# ' heading with the "
        "product name, a '> ' line saying in one sentence what it does and for "
        "whom, then '## ' sections with links to my key pages (pricing, features, "
        "docs, contact), each with a short description. State prices and plans "
        "plainly. Serve it as text/plain.",
        "Open /llms.txt in a browser: it should be plain text starting with "
        "'# ', not your app's home page.",
        GUIDE_LLMS,
    ),
    VisRule(
        "llms-incomplete", "llms.txt is missing a summary or links", "low", "ai",
        "Your llms.txt exists but doesn't follow the usual shape, so an AI "
        "reading it gets less out of it.",
        "My /llms.txt is missing {excerpt}. It should open with '# ' and the "
        "product name, then a '> ' line summarising what it does and for whom, "
        "then lists of Markdown links to my key pages with a short note on each.",
        "Open /llms.txt and check it has the heading, the '> ' summary and links.",
        GUIDE_LLMS,
    ),
    VisRule(
        "ai-crawlers-blocked", "Some AI crawlers are blocked", "info", "ai",
        "Your robots.txt blocks some AI companies' crawlers. That's a fair "
        "choice and we don't score it, but it means those assistants can't read "
        "your site, so they'll describe you from other people's pages or not "
        "at all.",
        "",
        "If you want them in, remove their Disallow lines in robots.txt. If you "
        "want them out, nothing to do.",
    ),
    VisRule(
        "jsonld-missing", "No structured data", "medium", "ai",
        "Structured data (JSON-LD) states in a machine-readable way who you are, "
        "what you sell and what it costs. Search engines use it for rich results; "
        "AI assistants use it to get facts like prices right.",
        "My home page has no JSON-LD structured data. Add a <script "
        "type=\"application/ld+json\"> block with an Organization (name, url, logo, "
        "sameAs links to my social and directory profiles) and, for what I sell, a "
        "SoftwareApplication or Product with an Offer (price, priceCurrency). Use "
        "only facts that are true and visible on the page.",
        "Paste the page into Google's Rich Results Test or validator.schema.org "
        "and check it finds your Organization and Product.",
    ),
    VisRule(
        "jsonld-invalid", "Structured data doesn't parse", "medium", "ai",
        "A JSON-LD block on your site isn't valid JSON, so search engines and AI "
        "ignore all of it.",
        "A JSON-LD block on {path} isn't valid JSON ({excerpt}). Fix the syntax "
        "(usually a trailing comma or an unescaped quote) and build the block with "
        "JSON.stringify rather than by hand.",
        "Paste the page into validator.schema.org and check it reports no errors.",
    ),
    VisRule(
        "org-missing", "No Organization in the structured data", "low", "ai",
        "Your structured data doesn't say who's behind the site. An Organization "
        "entry ties your name, logo and profiles together, which helps search "
        "engines and AI recognise you as one entity.",
        "Add an Organization to my JSON-LD with name, url, logo (a full image "
        "URL) and sameAs: the full URLs of my profiles elsewhere (LinkedIn, X, "
        "GitHub, Product Hunt, Crunchbase).",
        "Paste the page into validator.schema.org and check the Organization "
        "shows those fields.",
    ),
    VisRule(
        "org-incomplete", "Organization schema is missing fields", "low", "ai",
        "Your Organization structured data is missing {excerpt}. sameAs (links to "
        "your profiles elsewhere) is how search engines and AI connect your site to "
        "the rest of your presence.",
        "My Organization JSON-LD is missing {excerpt}. Add them: name, url, logo "
        "(full image URL) and sameAs as an array of full URLs to my profiles "
        "(LinkedIn, X, GitHub, Product Hunt, Crunchbase). Only list profiles that "
        "exist.",
        "Paste the page into validator.schema.org and check the fields appear.",
    ),
    VisRule(
        "offer-missing", "Products without prices in the structured data", "low", "ai",
        "Your structured data lists products or apps without an Offer, so the "
        "price you show on the page isn't machine-readable. AI assistants "
        "comparing prices will look elsewhere, or guess.",
        "My JSON-LD lists these without an Offer: {excerpt}. Add an 'offers' to "
        "each: {{\"@type\": \"Offer\", \"price\": \"15\", \"priceCurrency\": \"GBP\"}}, "
        "or an AggregateOffer with lowPrice and highPrice when there are several "
        "plans. Use the prices shown on the page.",
        "Paste the page into Google's Rich Results Test and check each product "
        "shows its price.",
    ),
    VisRule(
        "product-schema-missing", "Prices on the page, none in the structured data", "low", "ai",
        "Your page shows prices, but nothing in the structured data describes "
        "what's being sold. A SoftwareApplication or Product with an Offer makes "
        "the price machine-readable.",
        "My page shows prices but has no SoftwareApplication or Product in its "
        "JSON-LD. Add one per thing I sell, with name, description, url and "
        "offers ({{\"@type\": \"Offer\", \"price\": ..., \"priceCurrency\": ...}}), "
        "matching the prices on the page.",
        "Paste the page into Google's Rich Results Test and check it finds the "
        "product and its price.",
    ),
    VisRule(
        "faq-schema-missing", "Questions on the page, no FAQPage schema", "low", "ai",
        "Your page answers questions ({excerpt}) but doesn't mark them up. "
        "FAQPage structured data hands search engines and AI the question and "
        "answer pairs directly.",
        "My page {path} has a question-and-answer section. Add FAQPage JSON-LD "
        "with one Question (name) and acceptedAnswer (Answer, text) per item, "
        "using the same wording as the page.",
        "Paste the page into validator.schema.org and check it finds the "
        "FAQPage with every question.",
    ),
    VisRule(
        "data-files-missing", "No machine-readable data linked", "info", "ai",
        "Nothing on the site or in llms.txt links to a data file (JSON, CSV, "
        "Markdown). Not needed for most sites; useful when you publish prices, "
        "docs or a changelog that an AI should quote exactly.",
        "Publish the facts an AI should get exactly right (plans and prices, a "
        "changelog, docs) as a JSON or Markdown file on my site, and link it from "
        "llms.txt.",
        "Open llms.txt and check the link to the data file works.",
        GUIDE_LLMS,
    ),

    # ---- Content & keywords ---------------------------------------------
    VisRule(
        "title-missing", "Pages without a title", "high", "content",
        "The <title> is the blue link in search results and the name in every "
        "AI citation. Without one, search engines make one up.",
        "These pages have no <title>: {excerpt}. Give every page its own title, "
        "under 60 characters, leading with what the page is about and ending with "
        "the brand name.",
        "View source on each page and check the <title>.",
    ),
    VisRule(
        "title-long", "Titles over 60 characters", "low", "content",
        "Search results cut titles at about 60 characters, so the end of these "
        "is lost, and that's often where the brand name is.",
        "Shorten these page titles to 60 characters or fewer, keeping the "
        "words people search for at the front: {excerpt}.",
        "Re-run this scan.",
    ),
    VisRule(
        "title-duplicate", "Pages share the same title", "medium", "content",
        "Several pages have the same title, so search engines can't tell them "
        "apart and may show only one.",
        "These pages share a title: {excerpt}. Give each page a title that says "
        "what that page in particular is about.",
        "Re-run this scan.",
    ),
    VisRule(
        "description-missing", "Pages without a meta description", "medium", "content",
        "The meta description is the grey text under your link in search "
        "results. Without one, search engines lift a random sentence from the page.",
        "These pages have no meta description: {excerpt}. Write one per page, "
        "70 to 160 characters, saying who it's for and what they get, in plain "
        "words people would search for.",
        "View source and check each page has <meta name=\"description\">.",
    ),
    VisRule(
        "description-length", "Meta descriptions too short or too long", "low", "content",
        "Search results show about 160 characters. A longer description is cut "
        "off mid-sentence; a very short one wastes the space.",
        "Rewrite these meta descriptions to 70 to 160 characters: {excerpt}.",
        "Re-run this scan.",
    ),
    VisRule(
        "description-duplicate", "Pages share the same meta description", "low", "content",
        "Several pages have the same description, which tells search engines "
        "they're the same page.",
        "These pages share a meta description: {excerpt}. Write one for each "
        "that describes that page.",
        "Re-run this scan.",
    ),
    VisRule(
        "h1-missing", "Pages without an H1", "medium", "content",
        "The H1 is the page's headline as far as search engines are concerned. "
        "Without one, they lean on the title alone.",
        "These pages have no <h1>: {excerpt}. Give each page one H1 that says "
        "plainly what the page offers, using the words a customer would search for.",
        "View source and check each page has one <h1>.",
    ),
    VisRule(
        "h1-multiple", "Pages with more than one H1", "low", "content",
        "More than one H1 blurs what the page is about.",
        "These pages have more than one <h1>: {excerpt}. Keep one H1 for the "
        "page's main headline and make the rest H2s.",
        "Re-run this scan.",
    ),
    VisRule(
        "h1-off-topic", "The headline doesn't say what you sell", "low", "content",
        "Your H1 shares no words with your title or description. A clever "
        "headline is fine for people, but search engines and AI read the H1 to "
        "learn what the page is about, and these words aren't telling them.",
        "My home page H1 ({excerpt}) doesn't say what the product is. Keep the "
        "voice, but work in the category words people search for (what it is and "
        "who it's for), the same words my title and description use.",
        "Read the H1 aloud to someone who's never seen the site: can they say "
        "what you sell?",
    ),
    VisRule(
        "heading-skip", "Headings skip levels", "low", "content",
        "Headings jump a level (an H1 followed by an H3). Crawlers and screen "
        "readers use heading levels as the page's outline.",
        "Fix the heading order on these pages so each level follows the one "
        "above it (H1, then H2, then H3): {excerpt}. Change the tag, not the "
        "look; style with CSS.",
        "Re-run this scan.",
    ),
    VisRule(
        "og-incomplete", "Link previews are incomplete", "low", "content",
        "Open Graph and Twitter tags decide what a shared link looks like on "
        "LinkedIn, Slack, X, WhatsApp and iMessage. Missing ones give a bare URL "
        "with no picture.",
        "These pages are missing link-preview tags: {excerpt}. Add them to each "
        "page's <head>: og:title, og:description, og:url (the page's own full "
        "URL), og:image (a full URL to a 1200x630 image) and twitter:card set to "
        "summary_large_image. Generate them from the same title and description "
        "the page already uses.",
        "Paste the URL into opengraph.xyz or LinkedIn's Post Inspector.",
    ),
    VisRule(
        "og-image-broken", "Link preview image doesn't load", "medium", "content",
        "Your og:image points at an image that doesn't load, so every shared "
        "link shows a blank space where the picture should be.",
        "My og:image ({excerpt}) doesn't load. Point it at a full https:// URL "
        "of an image that exists, 1200x630, PNG or JPEG.",
        "Open the og:image URL in a browser, then check a preview at "
        "opengraph.xyz.",
    ),
    VisRule(
        "og-image-size", "Link preview image is the wrong shape", "low", "content",
        "Link previews are drawn at 1200x630 (1.91:1). Another shape gets "
        "cropped or shown as a small thumbnail.",
        "My og:image is {excerpt}. Make a 1200x630 version and point og:image "
        "at it, with og:image:width and og:image:height set.",
        "Check the preview at opengraph.xyz.",
    ),
    VisRule(
        "fragment-sections", "Key sections only exist as #fragments", "medium", "content",
        "Each part of your offer lives at a #section of one page rather than at "
        "its own URL. Search engines ignore everything after #, so one URL can "
        "only rank once: none of these sections can be the page that answers a "
        "search for it, and an AI can't cite or link one.",
        "My site keeps {excerpt}. Give each important section its own page "
        "with its own URL, <title>, meta description and H1 (for example "
        "/products/name), keep a short summary on the home page linking to it, "
        "and add the new pages to the sitemap.",
        "Each section should have its own address you can paste into Google's "
        "URL Inspection, and appear in /sitemap.xml.",
    ),
    VisRule(
        "few-internal-links", "Few links between pages", "low", "content",
        "The home page links to very few other pages on the site. Internal "
        "links are how crawlers find pages and how they judge which matter.",
        "My home page links to only {excerpt}. Link to my main pages from the "
        "navigation and footer, with link text that says what each page is.",
        "Re-run this scan.",
    ),
    VisRule(
        "img-alt-missing", "Images without alt text", "low", "content",
        "Alt text is what search engines and screen readers know about an image. "
        "Images without it can't rank in image search and say nothing to people "
        "who can't see them.",
        "Add alt text to these images: {excerpt}. Describe what each shows in a "
        "few words. Purely decorative images get alt=\"\" (empty), not no alt.",
        "Re-run this scan.",
    ),
    VisRule(
        "trust-missing", "Trust details not on the page", "low", "content",
        "People and AI assistants both look for signs a site is a real business "
        "before recommending it: a way to get in touch, a privacy policy, who "
        "runs it, and what it costs.",
        "My home page doesn't show {excerpt}. Add them, in the footer if nowhere "
        "else: a contact email or page, a link to the privacy policy, the "
        "company name (and registered number and address where the law asks for "
        "it), and prices or a link to pricing.",
        "Re-run this scan.",
    ),
]

RULES: Dict[str, VisRule] = {r.id: r for r in _RULES}

# Each check that can pass: (what the reader sees, category).
PASSES: Dict[str, Tuple[str, str]] = {
    "server-rendered": ("Content is in the raw HTML", "technical"),
    "robots-ok": ("robots.txt lets search engines in", "technical"),
    "ai-crawlers-allowed": ("AI crawlers are allowed", "ai"),
    "sitemap-ok": ("sitemap.xml is there and parses", "technical"),
    "llms-ok": ("llms.txt is there, with a summary and links", "ai"),
    "og-complete": ("Open Graph is complete", "content"),
    "https-ok": ("HTTP redirects to HTTPS", "technical"),
    "host-ok": ("One form of the domain redirects to the other", "technical"),
    "jsonld-ok": ("Structured data parses", "ai"),
    "org-ok": ("Organization schema is complete", "ai"),
    "titles-ok": ("Every page has a title of a sensible length", "content"),
    "descriptions-ok": ("Every page has a meta description", "content"),
    "h1-ok": ("One H1 per page", "content"),
    "canonical-ok": ("Canonical URLs point at their own page", "technical"),
    "alt-ok": ("Images have alt text", "content"),
    "trust-ok": ("Contact, privacy, company and pricing are on the page", "content"),
    "data-files-ok": ("Machine-readable data is linked", "ai"),
}

assert len(RULES) == len(_RULES), "duplicate visibility rule id"
