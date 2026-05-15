---
title: tech — web technology fingerprinter
command: tech
category: web
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [headers, waf, cookies, fav, recon, dirscan]
---

# `tech` — web technology fingerprinter

`tech` makes one HTTP request to a target and reads the response
for tell-tale fingerprints of the technology stack behind it —
web server, CDN, language, framework, CMS, JS libraries, analytics
trackers, payment widgets, anti-bot guards. Detections are
de-duplicated, grouped by category, and reported with a version
when the site volunteered one.

```
tech https://wordpress.org
tech https://anthropic.com
tech example.com           # https:// is added automatically
```

## What it does

One GET request to the target URL, up to 1 MB of body read, all
response headers and cookies inspected. Cathedral runs a curated
list of ~50 signatures against three detection surfaces:

| Surface       | What gets matched                                       |
|---------------|---------------------------------------------------------|
| **Headers**   | `Server`, `X-Powered-By`, `X-Generator`, `Cf-Ray`, `X-Aspnet-Version`, vendor-specific tells like `X-Vercel-Cache`, `X-Shopid` |
| **Body HTML** | `<meta generator>` tags, framework markers (`ng-version`, `__NUXT_DATA__`), script URLs (`/_next/static/`, `js.stripe.com`) |
| **Cookie names** | `PHPSESSID` for PHP, `_*_session` for Rails, `wp_` / `wp-` for WordPress |

Each detection emits a `tech` event with a category. Output is
sorted by architectural significance — server first, then CDN,
then language, then frameworks, CMS, JS libraries, CSS libraries,
analytics, payment, anti-bot. The order is a deliberate signal:
*what's running this site* before *what's pasted on top of it*.

| Category    | What it captures                                |
|-------------|-------------------------------------------------|
| `server`    | nginx, Apache, IIS, Caddy, LiteSpeed, OpenResty, lighttpd |
| `cdn`       | Cloudflare, Akamai, Fastly, CloudFront, Vercel, Netlify, GitHub Pages |
| `language`  | PHP, ASP.NET                                     |
| `framework` | Express, Rails, Next.js, Nuxt, Angular          |
| `cms`       | WordPress, Drupal, Joomla, Ghost, Hugo, Shopify |
| `js-lib`    | React, Vue.js, jQuery                            |
| `css-lib`   | Bootstrap, Tailwind CSS                          |
| `analytics` | Google Analytics, Plausible, Hotjar, Matomo     |
| `payment`   | Stripe                                           |
| `anti-bot`  | reCAPTCHA, hCaptcha                              |

## What it answers

**Defender:** *"Do I actually know what's running my site?"* The
canonical "we deployed this six years ago and the original
engineers are gone" question. `tech` against your own production
URL surfaces the stack quickly. If the report lists technologies
you didn't expect (a `jQuery 1.x` left over from 2014, an analytics
tag legal needs to sign off on, an old PHP version exposed in
`X-Powered-By`), those are findings.

**Recon (authorized testing only):** *"What attack surface am I
looking at?"* The first useful read of a target during a web audit.
A WordPress site has a very different threat shape from a Next.js
SPA from a Rails monolith from a static site on GitHub Pages —
each implies different default endpoints, different known CVE
patterns, different attack chains. `tech` narrows the field before
you spend time exploring.

**Evaluator:** *"Is this third party reasonable to integrate
with?"* Procurement-shaped question. A vendor's marketing site
running on bleeding-edge tech with multiple analytics and no anti-
bot suggests one operational posture. A vendor running ASP.NET on
IIS behind Cloudflare with reCAPTCHA on every form suggests
another. Neither is intrinsically wrong; both tell you something.

**Curiosity:** What's `news.ycombinator.com` running? *(One
detection. Hint: it's been that way for fifteen years.)*

## How it works

### Single request, three surfaces

`tech` makes exactly one HTTP GET. The detection happens against
what comes back; no follow-up requests, no path enumeration, no JS
execution.

That GET surfaces three independent matching contexts:

```go
type signature struct {
    Name, Category, Header string
    Kind                   sigKind         // matchHeader / matchBody / matchCookieName
    Pattern                *regexp.Regexp
}
```

Each signature is hand-picked to minimise false positives. The
regex capture group (when present) extracts the version. Three
canonical examples:

```go
// Header match with version capture
{Name: "PHP", Category: "language", Kind: matchHeader,
 Header: "X-Powered-By", Pattern: re(`(?i)PHP/(\S+)`)},

// Body match with version capture
{Name: "WordPress", Category: "cms", Kind: matchBody,
 Pattern: re(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s*([0-9.]+)?`)},

// Cookie-name match (no version, just presence)
{Name: "Ruby on Rails", Category: "framework", Kind: matchCookieName,
 Pattern: re(`^_(?:.+)_session$`)},
```

The cookie-name vector is the most underrated of the three. A
Rails session cookie named `_appname_session` is practically
unmistakable; `PHPSESSID` from any PHP application is a
unique-enough fingerprint that no false-positive case has been
seen in the wild. These are the signatures with near-zero
ambiguity.

### Multiple signals, single result

The same technology often leaves traces on more than one surface
— a WordPress site puts itself in the generator meta tag *and*
sets `wp-` cookies *and* serves URLs containing `/wp-content/`.
Three signature hits, one canonical answer:

```go
type detect struct { Name, Category, Version string }
seen := map[string]detect{}

tryAdd := func(d detect) {
    key := d.Name + "|" + d.Category
    prev, ok := seen[key]
    if !ok || (prev.Version == "" && d.Version != "") {
        seen[key] = d
    }
}
```

The dedup key is `Name|Category`. If the same name appears twice,
the entry with a captured version wins. This handles the common
case where one surface hit has a version (`WordPress 6.4`) and
another doesn't (`/wp-content/` URL match) — the versioned one is
kept, the bare one discarded.

### Category-ordered output

After dedup, results are sorted by `categoryRank` — a fixed
priority that puts the architecturally important things first:

```
server → cdn → language → framework → cms → js-lib → css-lib →
analytics → payment → anti-bot → (other)
```

The reasoning: a reader scanning the output should see *what's
running this site* (server, CDN) before *what frontend stack it
ships* (frameworks, libraries) before *what's pasted on top of it*
(analytics, payment widgets, captchas). Reverse-order would bury
the load-bearing facts under tracker noise.

### TLS fallback

`tech` shares the `tls_fallback.go` helper with `headers`,
`dirscan`, and the other web tools. On a clean TLS handshake the
fetch proceeds normally. On a chain-verification failure (self-
signed cert, expired cert, hostname mismatch), Cathedral retries
with verification disabled and emits a `tls_warning` event
carrying the original error.

This is the right trade for a fingerprinting tool: an internal
service behind a self-signed cert is still worth fingerprinting,
and the warning makes the cert posture visible rather than
silently downgrading.

### Body cap at 1 MB

The body read is capped at `io.LimitReader(resp.Body, 1<<20)` — one
megabyte. Most production pages are between 50 KB and 500 KB; a
1 MB cap covers virtually all real sites while protecting against
pathological payloads. Signatures that match late in the page
(beyond the first MB) will be missed; in practice the high-signal
markers — generator meta tag, framework root scripts, library
imports — all live in the first few KB.

## Worked example

Two real targets, contrasting deliberately. The first is rich
with detections; the second is deliberately bare.

```
$ tech https://wordpress.org
> fingerprinting https://wordpress.org
  url    : https://wordpress.org
  status : 200    169610 bytes

[ server ]
  · nginx
[ cms ]
  · WordPress  7.1
[ analytics ]
  · Google Analytics
```

WordPress.org runs *on* WordPress, which is meta-perfect for a
worked example. Three detections:

- **`nginx`** — the standard `Server: nginx` header. No version,
  because the site doesn't expose `nginx/1.27.4` — version
  suppression in the `Server` header is a long-standing security
  best practice and most production sites follow it now.
- **`WordPress 7.1`** — captured from the `<meta generator>` tag
  in the response body. WordPress itself sets this by default;
  hardened deployments strip it via filter.
- **`Google Analytics`** — body match against `googletagmanager.com`
  / `google-analytics.com` URLs in the script tags.

Contrast with a heavily-hardened production site:

```
$ tech https://github.com
> fingerprinting https://github.com
  url    : https://github.com
  status : 200    570544 bytes

[ cdn ]
  · GitHub Pages
```

One detection. GitHub.com's HTML is half a megabyte of dynamic
content, but the only architectural tell that survives all the
headers and meta scrubbing is the `Server: github.com` header
itself, which Cathedral recognises as the GitHub-served signature.
Everything else — language, framework, CDN topology, JS stack —
is invisible to a single GET. That's not a flaw in `tech`; it's
a posture choice by GitHub, and the empty output is itself a
finding: *this site does not volunteer its stack*.

The reader's natural next step in each case is different too —
WordPress.org → check for WordPress version vulnerabilities,
default endpoints (`/wp-login.php`, `/wp-admin/`), exposed
`xmlrpc.php`. GitHub.com → `tech` told you nothing useful, move
on to `headers` for the security posture or `dns` / `ssl` for
edge-layer attribution.

## Output protocol

```
{"event":"start",       "target":"…"}
{"event":"tls_warning", "message":"…"}?
{"event":"response",    "url":"…","status":N,"server":"…","bytes":N}
{"event":"tech",        "name":"…","category":"…","version":"…"}*
{"event":"done",        "total":N}
```

`tech` events arrive in category-ranked order (server first,
anti-bot last). One per (Name, Category) pair after dedup.
`version` is the empty string when no version was captured.

Pull just the high-priority detections:

```
$ tech https://target.example.com -j |
    jq -r 'select(.event=="tech" and (.category | IN("server","cdn","language","framework","cms"))) |
           "\(.category)\t\(.name)\t\(.version)"'
```

Build a CSV inventory across a list of URLs:

```
$ for u in $(cat sites.txt); do
    tech "$u" -j |
      jq -r --arg url "$u" 'select(.event=="tech") | [$url,.category,.name,.version] | @csv'
  done
```

## Limitations

- **GET only.** No POST endpoints, no API discovery, no
  authenticated routes. `tech` fingerprints the URL you give it,
  period. For multi-path coverage, run against `/`, `/login`,
  `/admin`, `/api/health` separately.
- **No JS execution.** Single-page apps that render their
  content client-side (React/Vue/Angular SPAs with thin
  server-side HTML shells) expose only the loader script
  references to `tech` — not the components they render. Apps
  that ship their stack in the loader (Next.js's `/_next/static/`
  URLs are a giveaway) still detect; apps that hide it via
  bundlers may not.
- **Curated signature list of ~50 entries.** New frameworks,
  niche CMS platforms, and bespoke stacks won't match. Cathedral
  v1 ships a stable hand-curated set rather than a plugin system
  that could become a maintenance burden.
- **Header suppression is standard production hygiene.** A site
  exposing `Server: nginx/1.27.5` and `X-Powered-By: PHP/8.2.10`
  is essentially advertising its CVE history. Most modern
  production sites strip both headers; expect empty version
  fields on well-managed targets.
- **Body cap at 1 MB.** Signatures that match deeper in the page
  body (rare, but possible on extremely heavy pages) are missed.
  No flag exposes the cap currently.
- **TLS fallback hides cert problems by default.** Self-signed and
  expired certs trigger the `tls_warning` event but don't stop
  the fetch. Treat the warning as a finding rather than as noise.
  For dedicated TLS analysis, see [`ssl`](ssl.md).
- **Regex-based detection has false-positive corners.** Hand-
  curation minimises but doesn't eliminate them. A meta-tag
  containing the word "WordPress" inside a blog post discussing
  WordPress will match the CMS signature; the version capture
  will be empty so the dedup logic won't elevate it. Inspect the
  page when a detection seems unlikely.

## Authorized use

`tech` makes one HTTP GET to a public URL. Same risk profile as
`curl`. No probes, no auth bypass, no payload mutation, no
brute-force. Running `tech` against an arbitrary website is no
more remarkable than visiting it in a browser; the User-Agent
identifies as `cathedral-tech/0.1` rather than a browser, which
is honest about what's making the request.

The output is information the target voluntarily included in
their response. Anything `tech` reports was sent to your browser
on the same request — Cathedral just labels it.

## Further reading

- [Wappalyzer signature library](https://github.com/wappalyzer/wappalyzer) — the largest open technology-fingerprint dataset, reference for new signatures
- [HTTP `Server` header conventions](https://www.rfc-editor.org/rfc/rfc9110#name-server) — the standard tells `tech` reads
- [WordPress generator-tag removal recipe](https://wordpress.org/documentation/article/wordpress-security/) — the canonical hardening for the most-fingerprinted CMS
- Related Cathedral commands: [`headers`](headers.md) (security-header audit and grading),
  [`waf`](waf.md) (Web Application Firewall identification),
  [`cookies`](cookies.md) (cookie-flag security analysis),
  [`fav`](fav.md) (favicon hash — fingerprinting from a different vector),
  [`recon`](recon.md) (robots.txt, sitemap, security.txt),
  [`dirscan`](dirscan.md) (path enumeration after fingerprinting)
