---
title: seo — technical-SEO audit with shallow internal crawl + letter grade
command: seo
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: medium
last-updated: 2026-05-26
related: [headers, recon, dirscan, tech, cookies, waf, fav]
---

# `seo` — technical-SEO audit with shallow internal crawl + letter grade

`seo` audits one URL plus up to 20 internal pages (configurable),
runs 16 rule checks per page covering the mechanical regressions
that hit a relaunched site, fetches `robots.txt` + `sitemap.xml`
alongside, optionally adds Core Web Vitals via Google's free
PageSpeed Insights API, and reports a letter grade A→F with
severity-grouped findings + a top-3 actionable-fixes summary.

The framing is **technical SEO audit**, not "tell me why my
rankings dropped." The latter depends on backlinks, content
quality decay, competitor moves, and Google algorithm updates —
none measurable from one HTML fetch. Backlink data and ranking
data live behind paid APIs (Ahrefs, SEMrush, Moz, $100+/month).
What this command offers is the technical-audit half: *"your new
template dropped the canonical tag, 12 images have no alt
attribute, your sitemap returns 404s, you've got three H1s on the
homepage, the robots.txt blocks /products which is the entire
catalog."*

That set of findings fixes the relaunched-site-tanked-rankings
case the majority of the time, because the cause usually *is* one
of those mechanical regressions. A new theme silently drops a
field that the old one populated; a CDN-migration script forgets
to copy `robots.txt`; a sitemap generator misfires after a path
change. The 16 audit rules in this command are calibrated against
those specific failure modes.

```
seo https://example.com                    # default: 20 pages, depth 2
seo https://example.com --no-crawl         # entry URL only
seo https://example.com --max=50 --depth=3 # deeper crawl
seo https://example.com --cwv              # add Core Web Vitals (~30s)
```

## What it does

For a single invocation:

1. **Fetch `robots.txt`** from the entry URL's host. Parse the
   user-agent rules, sitemap declarations. Use the rules to
   gate every subsequent crawl step.
2. **Fetch `sitemap.xml`** from `/sitemap.xml` (and recursively
   from any `<sitemapindex>` references, 3 levels deep, 200
   URLs total). Sample-probe up to 25 listed URLs with HEAD to
   catch dead-link regressions — a critical finding.
3. **BFS crawl** from the entry URL following internal links
   only. Depth + page caps configurable; default 20 pages,
   depth 2. Respect robots.txt — blocked URLs surface as
   findings, not silent skips. 1 request/second per host
   (politeness floor that doesn't make shared-hosting sites
   notice).
4. **Per page:** parse the HTML with `golang.org/x/net/html`,
   extract document-level + head-metadata + structure fields
   into a flat `pageData` struct, run all 16 rule checks.
   Each rule emits zero or more `finding` events with
   severity (`critical` / `medium` / `low`), stable rule code,
   human-readable title, and per-finding detail.
5. **(Opt-in) PageSpeed Insights** — if `--cwv` is set, call
   Google's free PSI API on the entry URL for real Core Web
   Vitals data (LCP, CLS, INP, performance score). Translate
   the numbers into findings using Google's documented
   thresholds. PSI takes 20-30s per page because it loads the
   page in a remote headless Chrome on Google's side — that's
   why it's opt-in.
6. **Aggregate** all findings → letter grade A→F using a
   severity-weighted formula normalised by page count + a
   top-3 actionable-fixes ranking (critical first, then
   most-recurring code).

## The 16 audit rules

The ruleset is deliberately scoped to **mechanical regressions a
relaunch / template change typically introduces**. Each rule has
a stable code (jq-filterable across runs) and one of three
severities.

### Critical — fix before next deploy

| Code              | Trigger                                                                |
|-------------------|------------------------------------------------------------------------|
| `title-missing`   | Page has no `<title>` tag at all                                       |
| `robots-noindex`  | `<meta name="robots" content="noindex">` — page excluded from search   |
| `robots-blocked`  | `robots.txt` disallows the URL from crawling                           |
| `sitemap-broken`  | `sitemap.xml` references a URL that returns 4xx/5xx                    |
| `mixed-content`   | HTTPS page loads HTTP scripts (Chrome blocks these silently)           |
| `http-error`      | The page itself returned a non-2xx status                              |
| `cwv-lcp-poor`    | `--cwv` only: LCP > 4s (Google "Poor" tier)                            |
| `cwv-cls-poor`    | `--cwv` only: CLS > 0.25 (severe layout shift)                         |
| `cwv-inp-poor`    | `--cwv` only: INP > 500ms (sluggish interaction)                       |

### Medium — fix this sprint

| Code                       | Trigger                                                  |
|----------------------------|----------------------------------------------------------|
| `title-too-short`          | `<title>` 10-29 chars (SERP looks empty)                 |
| `title-too-long`           | `<title>` > 60 chars (SERP truncates)                    |
| `description-missing`      | No `<meta name="description">` — Google fabricates one   |
| `canonical-missing`        | No `<link rel="canonical">` — duplicate-content risk     |
| `h1-missing`               | No `<h1>` tag on the page                                |
| `h1-multiple`              | Multiple `<h1>` tags (template-bug regression)           |
| `og-missing`               | No Open Graph metadata at all                            |
| `img-no-alt`               | One or more images missing `alt` attribute                |
| `viewport-missing`         | No `<meta name="viewport">` — mobile renders zoomed-out   |
| `robots-nofollow`          | Meta robots `nofollow` — links not followed              |
| `redirect-chain-long`      | ≥3 hops to reach this page (latency + signal decay)      |
| `content-thin`             | < 100 words of body content                              |
| `json-ld-invalid`          | JSON-LD block fails to parse as JSON                     |
| `cwv-lcp-needs-improvement`| `--cwv`: LCP 2.5-4s                                       |
| `cwv-cls-needs-improvement`| `--cwv`: CLS 0.1-0.25                                     |
| `cwv-inp-needs-improvement`| `--cwv`: INP 200-500ms                                    |
| `cwv-perf-low`             | `--cwv`: Lighthouse Performance score <50                |

### Low — polish

| Code                       | Trigger                                                  |
|----------------------------|----------------------------------------------------------|
| `title-short`              | `<title>` 30-29 chars (short but not broken)             |
| `description-short`        | Description < 70 chars                                   |
| `description-long`         | Description > 160 chars                                  |
| `canonical-malformed`      | Canonical is not absolute or root-relative               |
| `h2-missing`               | No `<h2>` on a content-heavy (>300 words) page           |
| `og-partial`               | Some OG tags present but missing 1-2 of the core three   |
| `twitter-card-missing`     | No Twitter Card + no OG fallback                         |
| `json-ld-missing`          | No structured data (rich-result eligibility)             |
| `img-no-dims`              | Image missing both `width` and `height` (CLS risk)        |
| `lang-missing`             | `<html>` has no `lang` attribute                          |
| `doctype-missing`          | No `<!DOCTYPE>` declaration                              |
| `doctype-legacy`           | Doctype isn't HTML5                                      |
| `external-no-noopener`     | >5 external links missing `rel="noopener"`               |

## What it answers

- After a relaunch, did the new template silently drop any
  SEO-critical fields?
- Is `robots.txt` accidentally blocking part of the catalog?
- Are sitemap URLs still resolvable, or did the path layout
  change without regenerating the sitemap?
- Are images missing `alt` attributes (accessibility +
  image-search rankings)?
- Does the page have one H1 or several? (template-component bug)
- Is the canonical URL pointing somewhere sensible?
- With `--cwv`: are the Core Web Vitals in Google's "Good"
  tier, or has page weight ballooned?

## How it works

### The 1 RPS politeness floor

The crawler walks one URL/second per host by default. That
matters because:

- Shared-hosting servers (typical for small/mid-sized
  businesses) can fall over under aggressive crawling.
- Some sites have rate-limit middleware (CloudFlare,
  ModSecurity) that will start serving 429s after a few
  rapid-fire requests, contaminating the audit.
- Cathedral's User-Agent is honest (`cathedral-seo/0.1 (+url)`)
  — if your friend's hosting provider greps logs, they see
  Cathedral crossing their site at 1 req/sec, not a
  scraper-bot at 100/sec.

The `--rps` flag overrides if you control the host and want
faster results.

### robots.txt enforcement, not just parsing

```go
if rb != nil && !rb.allowed(cfg.userAgent, path) {
    emit(event{
        "event":    "finding",
        "severity": SevCritical,
        "code":     "robots-blocked",
        "title":    "robots.txt blocks this URL from crawling",
    })
    continue
}
```

The seo command honours robots.txt — disallowed paths aren't
crawled. But it also surfaces the *fact* that a path is
blocked as a critical finding. The common regression: a
relaunched site's robots.txt has a stale `Disallow: /products`
left over from a staging environment, blocking the entire
catalog from search indexing while looking fine to a human
visiting the site directly. Cathedral catches this on the
first hit.

### Sitemap freshness probing

When a sitemap is found, the audit samples up to 25 of its
listed URLs with `HEAD` requests (falling back to `GET` on
servers that 405 on HEAD). Any URL that returns 4xx/5xx
produces a `sitemap-broken` critical finding.

This is the canonical regression after a URL-structure change:
old sitemap still references `/old-product/123/` but the
relaunched site only knows `/products/123/`. Google's
sitemap-parsing crawler will see hundreds of 404s and
gradually de-prioritise the site as "this sitemap is unreliable
data." The audit makes this visible from the first run.

### HTML parsing with `golang.org/x/net/html`

Real HTML parsing rather than regex — the standard library's
`html` package handles malformed input gracefully (missing
end tags, character-set quirks, embedded SVG fragments). The
parser walks the document tree once and pulls every field the
audit needs into a flat `pageData` struct:

```go
type pageData struct {
    title       string
    description string
    canonical   string
    robotsMeta  string
    viewport    string
    lang        string
    ogTags      map[string]string
    twitterTags map[string]string
    jsonLD      []string
    h1s         []string
    h2s         []string
    images      []imageRef
    scripts     []scriptRef
    links       []linkRef
    wordCount   int
    // …
}
```

The audit rules then operate on field lookups rather than
re-walking the DOM, which keeps each rule short and
testable.

### Letter grade computation

Severity-weighted formula normalised by page count:

```go
critPerPage := critical / pageCount
medPerPage  := medium / pageCount

switch {
case critPerPage >= 3:                            → F
case critPerPage >= 1.5 || medPerPage >= 10:     → D
case critPerPage >= 0.5 || medPerPage >= 5:      → C
case critPerPage > 0 || medPerPage >= 2:         → B
default:                                          → A
}
```

The per-page normalisation matters: a 1-page audit with 1
critical finding shouldn't grade worse than a 20-page audit
with 20 critical findings (same defect *rate*). A site where
every page is missing a canonical tag (20-page audit, 20
canonical-missing findings) scores worse than one where two
specific pages have multiple H1s (20-page audit, 2 h1-multiple
findings).

### Top-3 actionable fixes

Findings are clustered by `code`, ranked by severity-first
then occurrence-count-second:

```go
sort.SliceStable(gs, func(i, j int) bool {
    a, b := gs[i], gs[j]
    if sevRank(a.severity) != sevRank(b.severity) {
        return sevRank(a.severity) < sevRank(b.severity)
    }
    return a.count > b.count  // most occurrences first
})
```

The output reads like "fix this one type of issue and you'll
clean up 12 findings across the audit." That's the actionable
framing — operator picks one thing, fixes it once, watches the
finding-count drop across the next audit.

### PageSpeed Insights (opt-in `--cwv`)

`https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=…&strategy=mobile`
— Google's free PSI endpoint. No API key needed for moderate
use (25,000 queries/day per IP). The response is 200-500 KB of
nested JSON; the audit decodes just four fields:

- `audits.largest-contentful-paint.numericValue` → LCP ms
- `audits.cumulative-layout-shift.numericValue` → CLS
- `audits.first-contentful-paint.numericValue` → FCP ms
- `categories.performance.score` → 0-100 perf score

Plus the field-data INP percentile from `loadingExperience`.

PSI runs a real headless Chrome on Google's side, which is why
each call takes 20-30 seconds. Cathedral runs it on the entry
URL only — auditing CWV across 20 pages would push runtime
well past 10 minutes. For the entry-URL CWV, the audit pays
the latency once and gets the headline number Google itself
uses for ranking.

## What Cathedral doesn't do

- **No backlink analysis.** "Who links to this site, with what
  anchor text, from what domain authority?" — that's paid-API
  territory (Ahrefs, SEMrush, Moz, Majestic). The free APIs
  for backlinks don't exist; the data is built by walking
  most of the public web, which is expensive infrastructure.
  When a site's rankings drop because backlinks were lost
  (e.g. a popular blog post that linked to you got deleted),
  `seo` cannot see that.
- **No keyword-ranking checks.** "Where does this page rank
  for query X?" — also paid-API territory, and Google
  actively discourages programmatic ranking checks.
- **No content-quality scoring.** Readability metrics
  (Flesch-Kincaid, etc.) could be computed; Cathedral doesn't
  because Google's ranking signals around content quality are
  much richer than readability scores and a simple
  readability number can mislead.
- **No JavaScript-rendered content.** Cathedral fetches HTML
  as the server sends it. Single-page-app sites (React /
  Vue / Angular without server-side rendering) often have
  near-empty body HTML — Cathedral correctly reports the thin
  content but doesn't execute JS to see what gets rendered.
  Real SEO tools like Screaming Frog and Sitebulb have
  optional JS-rendering modes; that's what to reach for if
  your site is SPA-shaped.
- **No competitor comparison.** "How does my title length
  compare to my top-3 competitors?" — Cathedral audits one
  site at a time. Run it on each site separately and compare
  the outputs manually if needed.
- **No `hreflang` validation.** International multi-language
  sites use `<link rel="alternate" hreflang="…">` to declare
  language variants. Cathedral doesn't validate the
  hreflang graph for correctness (a common regression: pages
  declare themselves as canonical-of-X but X doesn't
  declare-back). Could be added; not in v1.
- **No structured-data validity beyond JSON-parse.** JSON-LD
  blocks are checked that they at least parse as JSON, but
  the Schema.org type semantics aren't validated. Google's
  Rich Results Test (search.google.com/test/rich-results) is
  the canonical validator for Schema.org compliance.
- **No image audit beyond alt + dimensions.** Image weight,
  format efficiency (WebP/AVIF vs JPEG), lazy-loading
  correctness, srcset/sizes presence — could all be audit
  rules; not in v1. The `--cwv` flag's LCP measurement
  captures the *impact* of bad image practices even if not
  the cause.

## Worked example

### Single-URL audit

```
operator@cathedral:~$ seo https://example-store.example --no-crawl
> auditing https://example-store.example
  host       : example-store.example
  crawl      : off

  robots.txt  ✓
  sitemap.xml ✓ (47 URLs)

[ SEO REPORT ]
  pages       : 1
  grade       : C   (1 critical · 3 medium · 4 low)

[ CRITICAL ]
  ✗ sitemap.xml references a URL that 4xx/5xxs
     https://example-store.example/old-product-uri-123

[ MEDIUM ]
  ! no <link rel="canonical"> set
     https://example-store.example
  ! 23 image(s) missing alt attribute
     https://example-store.example
  ! no <meta name="viewport">
     https://example-store.example

[ LOW ]
  · 18 image(s) missing width/height (CLS risk)
     https://example-store.example
  · meta description shorter than 70 chars
     https://example-store.example
  · no JSON-LD structured data
     https://example-store.example
  · no Twitter Card metadata + no Open Graph fallback
     https://example-store.example

[ TOP FIXES ]
  1. sitemap.xml references a URL that 4xx/5xxs
     https://example-store.example/old-product-uri-123
  2. no <link rel="canonical"> set
     duplicate-content protection requires canonical URLs
  3. 23 image(s) missing alt attribute
     https://example-store.example/img/product-1.jpg | …

seo audit complete — 1 pages · 8 findings
```

Single page, grade C. The critical finding is the sitemap.xml
regression — the most-likely cause of post-relaunch ranking
drops, because Google's crawler hits the dead URL and starts
treating the sitemap as untrustworthy. Fix that first; the
medium-tier items (canonical, viewport) are the next-pass
template fixes.

### Full crawl (default 20 pages)

```
operator@cathedral:~$ seo https://example-store.example
> auditing https://example-store.example
  host       : example-store.example
  crawl      : on (max 20 pages, depth 2)

  robots.txt  ✓
  sitemap.xml ✓ (47 URLs)

  crawling internal links…
    · https://example-store.example   (depth 0)
    · https://example-store.example/products   (depth 1)
    · https://example-store.example/products/used-thinkpad   (depth 1)
    · https://example-store.example/contact   (depth 1)
    · https://example-store.example/about   (depth 1)
    · https://example-store.example/products/used-macbook   (depth 1)
    …
  crawl complete — 20 pages

[ SEO REPORT ]
  pages       : 20
  grade       : D   (8 critical · 32 medium · 47 low)

[ CRITICAL ]
  ✗ no <title> tag   (×4 pages)
     https://example-store.example/products/used-thinkpad
     https://example-store.example/products/used-macbook
     https://example-store.example/products/used-tower
     … and 1 more
  ✗ sitemap.xml references a URL that 4xx/5xxs   (×3 pages)
     https://example-store.example/old-uri-1
     https://example-store.example/old-uri-2
     https://example-store.example/old-uri-3
  ✗ HTTP 404 on page   (×1 pages)
     https://example-store.example/products/discontinued

[ MEDIUM ]
  ! no <meta name="description">   (×18 pages)
     https://example-store.example
     https://example-store.example/products
     https://example-store.example/about
     … and 15 more
  ! no <link rel="canonical"> set   (×14 pages)
     …

[ LOW ]
  · 47 image(s) missing alt attribute   (across 12 pages)
     …

[ TOP FIXES ]
  1. no <title> tag (×4 across audit)
     page has no title — search engines fall back to URL / heading
  2. sitemap.xml references a URL that 4xx/5xxs (×3 across audit)
     https://example-store.example/old-uri-1
  3. no <meta name="description"> (×18 across audit)
     Google fabricates a snippet from page text when this is missing

seo audit complete — 20 pages · 87 findings
```

Grade D after the crawl — the entry URL looked OK in
isolation, but the product-detail template is silently missing
`<title>` tags on every product page. That's the kind of bug
that a single-page audit on the homepage *misses* and a
multi-page crawl catches immediately. The top-3 fixes are
ranked by occurrence count — fixing the product-detail
template's title tag eliminates 4 findings at once.

### With Core Web Vitals

```
operator@cathedral:~$ seo https://example-store.example --cwv
> auditing https://example-store.example
  host       : example-store.example
  crawl      : on (max 20 pages, depth 2)
  cwv        : on (PageSpeed Insights — slower)

  robots.txt  ✓
  sitemap.xml ✓ (47 URLs)
  …

[ CORE WEB VITALS ]
  LCP   : 3850 ms
  CLS   : 0.187
  INP   : 240 ms  (field data)
  perf  : 42/100

[ SEO REPORT ]
  pages       : 20
  grade       : D   (10 critical · 35 medium · 47 low)

[ CRITICAL ]
  ✗ Largest Contentful Paint 3.9s (target <2.5s)
     LCP in 'Needs Improvement' band approaching Poor — page weight excessive
  ✗ Cumulative Layout Shift 0.187 (target <0.1)
     common cause: images without width/height, dynamic ad insertion
  …

[ TOP FIXES ]
  1. no <title> tag (×4 across audit)
  2. Largest Contentful Paint 3.9s (target <2.5s)
  3. Cumulative Layout Shift 0.187 (target <0.1)
```

CWV pushed the grade from D to D (already in that band) but
added two new top-3 candidates. Importantly: the CLS finding
correlates with the `img-no-dims` low-severity rule from the
static audit — explicit image dimensions prevent layout shift,
and Cathedral catches both the *cause* (no dimensions) and the
*effect* (high CLS metric) in the same audit. Operator fixes
the image template, both findings disappear.

### Robots.txt blocking the catalog

```
operator@cathedral:~$ seo https://example-store.example
…
[ CRITICAL ]
  ✗ robots.txt blocks this URL from crawling   (×8 pages)
     /products
     /products/used-thinkpad
     /products/used-macbook
     … and 5 more
```

A regression you'd never spot by visiting the site as a user.
The relaunched site's robots.txt has a `Disallow: /products`
left over from staging, which means Google has stopped
indexing the entire catalog. This is the most painful
relaunch-tanked-rankings cause Cathedral exists to catch on
day one.

### Help

```
operator@cathedral:~$ seo --help
usage: seo <url> [flags]

  Technical SEO audit of one URL plus up to N internal pages following
  links. Catches the mechanical regressions that hit a site after a
  template change or relaunch: lost <title> tags, broken canonical,
  …

[ flags ]
  --max=N         max pages to crawl (default 20)
  --depth=N       max crawl depth from entry URL (default 2)
  --no-crawl      audit entry URL only; skip internal-link follow-up
  --cwv           fetch Core Web Vitals via Google PageSpeed (slower, ~30s)
  --rps=N         per-host request rate cap (default 1.0)
  --ua=STRING     override the User-Agent string

[ examples ]
  seo https://example.com
  seo https://example.com --no-crawl
  seo https://example.com --max=50 --depth=3
  seo https://example.com --cwv
```

## Output protocol

Line-oriented JSON. Event types:

| Event          | Fields                                                              |
|----------------|---------------------------------------------------------------------|
| `start`        | `url`, `host`, `max_pages`, `max_depth`, `crawl`, `cwv`, `user_agent` |
| `robots`       | `url`, `found`, `rules` (summary)                                   |
| `sitemap`      | `url`, `urls_found`                                                 |
| `crawl_start`  | `max`, `depth`                                                      |
| `crawl_fetch`  | `url`, `depth`                                                      |
| `crawl_done`   | `pages`, `queued`                                                   |
| `page`         | `url`, `status`, `depth`, `audit` (finding count), `redirects`       |
| `finding`      | `page`, `severity`, `code`, `title`, `detail`                       |
| `cwv`          | `url`, `lcp_ms`, `cls`, `inp_ms`, `score`                            |
| `grade`        | `letter` (A-F), `critical`, `medium`, `low`, `pages`                |
| `top_fix`      | `code`, `title`, `detail`                                           |
| `done`         | `pages_audited`, `findings_total`                                   |
| `warn`         | `message` — non-fatal (e.g. PSI failed)                              |
| `error`        | `message` — fatal pre-flight                                         |

Pipe-friendly with `jq`:

```
# Just the critical findings
seo https://example.com | jq -r '
  select(.event=="finding" and .severity=="critical") |
  "\(.code)\t\(.page)"
'

# Letter grade for scripting
seo https://example.com | jq -r 'select(.event=="grade") | .letter'

# All pages that returned non-200 status
seo https://example.com | jq -r '
  select(.event=="page" and .status >= 400) |
  "\(.status)\t\(.url)"
'

# How many distinct rules fired?
seo https://example.com | jq -r '
  select(.event=="finding") | .code
' | sort -u | wc -l

# CSV-ready findings export
seo https://example.com | jq -r '
  select(.event=="finding") |
  [.severity, .code, .page, .title] | @csv
'
```

## Limitations

- **No JavaScript rendering.** Single-page-app sites with
  client-side rendering will look thin to the audit even if
  the rendered DOM is rich. For SPAs, the audit reports the
  shipped HTML accurately but doesn't reflect what users /
  Googlebot's modern JS-rendering crawler ultimately see.
- **20-page default may miss long-tail issues.** A site with
  hundreds of templates may have regressions only on
  rarely-linked pages. Bump `--max` if you suspect this; the
  90-second total budget will cap somewhere.
- **No structured-data semantic validation.** JSON-LD blocks
  are checked for valid JSON, not for Schema.org type
  compliance. Use [Google's Rich Results Test](https://search.google.com/test/rich-results)
  for the semantic check.
- **PSI is rate-limited.** The free tier is 25,000
  queries/day per IP. Heavy use will start getting throttled;
  add your own API key via PSI's documented mechanism if
  needed (not currently exposed via a flag — could be added).
- **No HEAD-failure escalation.** When sitemap probing HEADs
  return 5xx (vs 4xx), they're treated the same as
  not-found — could be a transient server error rather than
  a dead URL. A retry or distinct severity tier could
  improve fidelity.
- **No CDN-aware filtering.** External-link inventory counts
  CDN/static asset URLs as outbound links. Doesn't
  significantly affect the audit but inflates the "external
  links" count for sites that load assets cross-domain.

## Authorized use

`seo` crawls a website — that puts it in **medium**-risk
dual-use territory, not low. The considerations:

- **Auditing your own site (or one you're employed to
  audit)** is the intended use. The 1 req/sec politeness floor
  + honest User-Agent + robots.txt enforcement match the
  behaviour of a responsible bot.
- **Auditing a competitor's site for competitive research**
  is a grey area. Technically fine if you respect robots.txt
  and rate-limit (which Cathedral does), but the resulting
  data lives behind the same legal lines as any other
  competitive-research collection. Don't use it to scrape
  product data; the audit looks at *meta-level structure*,
  not page content.
- **Auditing a third-party site at scale** (multiple sites in
  succession, or one site with high `--max` + `--rps`) starts
  pattern-matching as automated scraping from the target's
  side. Their abuse-detection middleware may rate-limit or
  block. Don't crank `--rps` above 2-3 against sites you
  don't control.
- **robots.txt is honoured by default.** Crawling a path the
  site explicitly disallows isn't supported. (If you need to
  override that — e.g. you're a forensic investigator with
  legal authorisation — drop down to `curl` directly. The
  audit tool itself stays polite.)
- **The User-Agent is honest.** `cathedral-seo/0.1
  (+https://crowned-phoenix.com)` identifies Cathedral as
  the source. Site owners can grep their access logs for
  this UA to see what Cathedral did and when. If you need
  to override (e.g. to verify the site behaves the same
  for Googlebot's UA), `--ua=STRING` is the flag, but use
  it deliberately.

## Further reading

- [Google Search Central — SEO Starter Guide](https://developers.google.com/search/docs/fundamentals/seo-starter-guide)
  — Google's own canonical guidance on what they consider
  important. The rules in this command are calibrated
  against this guide; if there's ever conflict between
  Cathedral's `seo` and Google's documentation, Google wins.
- [Google — Core Web Vitals](https://web.dev/vitals/)
  — the LCP / CLS / INP / FCP threshold documentation that
  the `--cwv` finding-generation uses. Bookmark this for the
  ranking-signal context; CWV thresholds shift roughly
  annually.
- [Google — Structured Data documentation](https://developers.google.com/search/docs/appearance/structured-data/intro-structured-data)
  — what JSON-LD types are eligible for rich results. The
  `seo` audit checks JSON-LD presence + parse-validity; the
  Schema.org type-conformance check belongs in Google's Rich
  Results Test.
- [RFC 9309 — Robots Exclusion Protocol](https://datatracker.ietf.org/doc/html/rfc9309)
  — the formalised robots.txt spec from 2022. Cathedral's
  parser implements the longest-prefix-match rule from this
  RFC; full wildcard support is a v2 candidate.
- [Sitemaps.org Protocol](https://www.sitemaps.org/protocol.html)
  — the sitemap.xml / sitemapindex schema. Cathedral's
  parser handles the canonical XML form + the legacy
  plain-text form some older sites use.
- [Open Graph Protocol](https://ogp.me/) — the OG metadata
  spec. The `og-missing` and `og-partial` findings are scoped
  to the three core tags (`og:title`, `og:description`,
  `og:image`); the full OG vocabulary is larger.
- [Twitter Cards documentation](https://developer.x.com/en/docs/twitter-for-websites/cards/overview/abouts-cards)
  — the twitter:* metadata Cathedral checks as a fallback to
  Open Graph.
- [`headers`](headers.md) — Cathedral's security-header audit
  is the sibling tool to `seo`. Where `seo` looks at
  content/structure regressions, `headers` looks at
  HSTS/CSP/X-Frame-Options. Run both on a relaunched site.
- [`recon`](recon.md) — breadth-first HTTP reconnaissance.
  Surfaces robots.txt + sitemap.xml + security.txt + common
  endpoint findings without doing the full SEO audit; useful
  as a fast first-pass before drilling into `seo`.
- [`tech`](tech.md) — fingerprints the underlying CMS /
  framework. Knowing "this is a freshly relaunched
  WordPress install" tells you which SEO plugins to check;
  pair with `seo` for the full picture.
