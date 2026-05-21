---
title: fav — favicon hashing for infrastructure pivot
command: fav
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [tech, recon, http, asn, whois]
---

# `fav` — favicon hashing for infrastructure pivot

`fav` fetches a site's favicon and computes three hashes against
it — the canonical **Shodan mmh3** (used as
`http.favicon.hash:<n>` to find every other host serving the
same icon), plus generic **MD5** and **SHA-256**. The technique
is one of the highest-leverage moves in modern reconnaissance:
most organisations update their TLS certificates, their HTTP
banners, their server software, and their hostnames — but
almost nobody rotates their corporate favicon. A single hash
becomes the pivot that surfaces all of a target's internet-
reachable infrastructure regardless of how the rest of the
stack varies.

For defenders, the same technique flips: hash your own favicon,
search Shodan for it, and find every host that's *supposed* to
be yours plus the ones nobody told the security team about.

```
fav https://acme-supplies.example
fav acme-supplies.example                  # https:// auto-prefixed
fav https://app.acme-supplies.example      # specific subdomain
```

## What it does

For a single URL, Cathedral:

1. Fetches the target HTML and looks for a `<link rel="icon">`
   or `<link rel="shortcut icon">` tag.
2. If found, resolves the `href` against the page URL and
   fetches that. If not found, falls back to `/favicon.ico` at
   the site root.
3. If the discovered URL returns non-200, tries `/favicon.ico`
   as a final fallback.
4. Computes three hashes against the favicon bytes and emits
   them.

The Shodan-style hash is the one that *pivots*. Drop it into
Shodan's web search as `http.favicon.hash:<value>` and you get
the list of every internet-reachable host whose favicon
produces the same hash. ZoomEye uses the same convention with
the `iconhash` keyword; Censys exposes the same primitive via
its own filter. The MD5 and SHA-256 are general-purpose digests
useful for IOC matching against private databases.

## What it answers

**Defender:** *"What other infrastructure is serving our
favicon?"* The intended infrastructure (production, staging,
docs, blog) presumably all share the corporate favicon. Hash
your own and search — the result is the union of:

- Hosts you expect (the production fleet),
- Hosts you forgot about (decommissioned but still routing),
- Hosts somebody else set up (shadow IT, abandoned proof-of-
  concepts, contractors' personal copies of your brand),
- Hosts impersonating you (phishing kits often blindly copy
  the target's favicon, which makes them findable the moment
  they go live).

Periodic favicon-hash sweeps against your own brand catch
shadow IT and impersonation campaigns earlier than most
purpose-built monitoring.

**Recon (authorized testing only):** *"What else does this
organisation run?"* The target's main site's favicon hash is
the index into Shodan that surfaces their other public-facing
hosts — admin portals, regional deployments, monitoring
dashboards, dev environments that ended up indexed. Each
discovered host is a separate engagement-shape decision: is
it in scope, is it interesting, what does it expose?

**Investigation:** *"Who owns this server?"* When the only
identifying signal on a host is its favicon (the HTTP banner
is generic nginx, the TLS cert is generic Let's Encrypt, the
content is minimal), `fav` produces the hash and a Shodan
lookup answers the question. Many phishing servers carry the
target's favicon — that's the entire identifier.

**Identification:** *"Is this part of a known cluster?"* A
favicon hash that matches a known-bad pattern (a CTF box, a
phishing kit, a default install of a vulnerable product) is
itself attribution. Public favicon-hash databases like
favicondb.com catalogue these.

## How it works

### Why favicons fingerprint

Three properties make favicons unusually good fingerprints:

- **They're public-by-design.** Every site that serves a
  favicon does so to anonymous clients on the canonical path.
  No authentication, no rate limit beyond the host's general
  HTTP rate limit, no detection footprint beyond "someone
  fetched the favicon", which is the most-common request
  pattern on the internet.
- **They're rarely rotated.** A favicon change requires
  re-uploading the file, updating asset pipelines, dealing
  with browser caches, and getting design approval. Most
  organisations change their favicon once every several years
  at most, often only on major rebrands. The hash is *stable*.
- **They're identical across the fleet.** A company's
  favicon ships in the same binary form on the marketing
  site, the customer portal, the internal admin dashboard,
  the staging environment, and the developer's accidentally-
  public demo box. The hash matches across all of them.

The combination is unusual. Most other fingerprintable things
(TLS certs, JS bundles, error pages) vary subtly across
deployments and change as software gets updated. Favicons
just don't.

### Favicon discovery

Two paths, in order:

```go
var iconLinkRe = regexp.MustCompile(
    `(?i)<link[^>]+rel=["'](?:shortcut\s+)?icon["'][^>]*href=["']([^"']+)["']`)
```

The HTML scan reads the first 64 KB of the page (more than
enough for any reasonable `<head>`) and looks for a `<link
rel="icon">` or `<link rel="shortcut icon">` tag with an
`href` attribute. The discovered `href` is resolved against
the page URL:

```go
ref, _ := url.Parse(href)
return base.ResolveReference(ref).String()
```

This handles every form the href can take: an absolute URL
(`https://cdn.example.com/icon.png`), a root-relative path
(`/static/favicon.ico`), a relative path (`favicon.png`), or
an `apple-touch-icon` redirect. The `ResolveReference` call
matches browser semantics exactly.

When no `<link>` tag matches, Cathedral falls back to
`<target>/favicon.ico`. This is the path browsers fall back to
when no link is declared and the convention every site is
expected to honour. If that fallback also returns non-200,
Cathedral tries one more time against the root — covers the
case where the discovered href points at a stale or wrong
location.

### The Shodan mmh3 recipe

The Shodan favicon hash is not a hash *of the favicon bytes*
— it's a hash of the **base64-encoded, MIME-line-wrapped**
favicon bytes. The recipe matters because Shodan published it
with a specific Python sequence, and any deviation produces a
different number:

```go
func shodanFaviconHash(body []byte) int32 {
    enc := base64.StdEncoding.EncodeToString(body)
    var b strings.Builder
    for i := 0; i < len(enc); i += 76 {
        end := i + 76
        if end > len(enc) {
            end = len(enc)
        }
        b.WriteString(enc[i:end])
        b.WriteByte('\n')
    }
    return int32(murmur3_32([]byte(b.String()), 0))
}
```

Three steps that each matter:

1. **Base64 encoding** — the favicon's raw bytes get
   standard-base64 encoded into ASCII.
2. **MIME line wrapping** — the base64 string is broken
   into 76-character lines separated by `\n` (with a final
   `\n` after the last line). This is exactly what Python's
   `base64.encodebytes` does — *not* `base64.b64encode`,
   which produces a single line without wrapping. Most
   recipes you find online get this wrong; the 76-char
   wrap is load-bearing.
3. **MurmurHash3 32-bit, seed 0** — the wrapped ASCII string
   is hashed with the classic MurmurHash3 32-bit variant,
   then *reinterpreted as a signed int32* because Shodan's
   database stores it that way.

The Murmur3 implementation in `fav` is the canonical one
(constants `0xcc9e2d51`, `0x1b873593`, finalization mix steps
included). It matches Shodan's reference implementation and
the popular Python `mmh3` package byte-for-byte.

The Shodan filter syntax accepts both signed and unsigned
representations, but Shodan's web UI displays the signed
form. Cathedral matches.

### MD5 and SHA-256

The other two hashes are direct digests of the favicon bytes
themselves — no encoding step, no wrapping. They're useful
for:

- **Cross-referencing private IOC databases.** Many security-
  intel feeds publish favicon SHA-256 or MD5 for known-bad
  patterns (phishing kits, exploit-server templates,
  cryptocurrency-scam frontends).
- **Local snapshot-and-diff.** Save the SHA-256 of your own
  favicon today; alert if it changes (a successful defacement
  often replaces the favicon).
- **Multi-engine search.** Some specialised tools index by
  MD5 instead of Shodan-mmh3; having both makes cross-engine
  enrichment trivial.

The MD5/SHA-256 of the bytes won't match Shodan; the Shodan
mmh3 won't match SHA-256 IOC lists. Three hashes, three
purposes.

### TLS auto-fallback

Same pattern as elsewhere — strict cert verification first,
fall back to `InsecureSkipVerify` on `x509:` errors, emit a
single `tls_warning` event. Both the HTML fetch and the
favicon fetch share the fallback state, so the warning fires
at most once per invocation.

## What Cathedral doesn't do

A few deliberate omissions:

- **Direct Shodan querying.** `fav` produces the hash; it
  doesn't query Shodan to enumerate matching hosts. Shodan
  requires an account and an API key; that integration is
  out of scope for a no-credentials Cathedral. Copy the hash,
  paste it into Shodan's web UI or `shodan` CLI.
- **Apple touch icons.** Cathedral picks the first
  `rel="icon"` (or `rel="shortcut icon"`) match. Sites that
  declare separate icons for iOS / Android / various sizes
  via additional `rel="apple-touch-icon"` or
  `rel="manifest"` directives are not enumerated. For
  per-icon hashing, point `fav` at each declared URL
  explicitly.
- **Manifest.json parsing.** Modern PWAs declare icons in a
  `manifest.json` referenced from `<link rel="manifest">`.
  Cathedral doesn't follow that link; the canonical `<link
  rel="icon">` and `/favicon.ico` paths are the standard.
- **Animated / multi-resolution ICO handling.** `.ico` files
  can contain multiple resolutions in one file (16x16,
  32x32, 48x48). Cathedral hashes the whole file as-is,
  which matches what Shodan does. Per-resolution hashing
  isn't useful here.
- **Generated favicons.** Some frameworks generate favicons
  dynamically (per-tenant SaaS apps, anti-pivot-counters).
  Cathedral hashes whatever the server returns; if the
  favicon varies per-request, the hash isn't a stable
  fingerprint.

## Worked example

A typical site, a custom location, and a fingerprint-from-the-
finding case.

### A typical site

```
operator@cathedral:~$ fav https://acme-supplies.example
> probing https://acme-supplies.example for favicon
  via html-link: https://acme-supplies.example/static/favicon.ico

  url      : https://acme-supplies.example/static/favicon.ico
  status   : 200    4286 bytes    image/vnd.microsoft.icon

  Shodan mmh3   1675847652
                 use as http.favicon.hash:<value> in Shodan
  MD5            7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
  SHA-256        3a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
```

The page declared `<link rel="icon" href="/static/favicon.ico">`,
Cathedral resolved that to a full URL, fetched 4 KB of `.ico`
bytes, and produced three hashes. The Shodan filter
`http.favicon.hash:1675847652` (paste into the Shodan web UI)
returns every internet-reachable host whose favicon hashes to
this value — which should be the entire ACME Supplies fleet.

For a self-audit, the resulting Shodan list is the **expected
inventory plus surprises**: any host on the list that the
security team doesn't recognise warrants investigation. For an
authorised engagement, the list is the **target's external
attack surface** at the favicon-fingerprint resolution.

### Custom favicon location (fallback path)

```
operator@cathedral:~$ fav https://docs.acme-supplies.example
> probing https://docs.acme-supplies.example for favicon
  via default: https://docs.acme-supplies.example/favicon.ico

  url      : https://docs.acme-supplies.example/favicon.ico
  status   : 200    1142 bytes    image/png

  Shodan mmh3   -841927185
                 use as http.favicon.hash:<value> in Shodan
  MD5            5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b
  SHA-256        7e8f9a0b1c2d3a4b5c6d7e8f9a0b1c2d7e8f9a0b1c2d3a4b5c6d7e8f9a0b1c2d
```

The docs subdomain doesn't declare a `<link rel="icon">` in
its HTML — common on auto-generated documentation sites
(MkDocs, Sphinx, Docusaurus defaults). Cathedral fell back to
`/favicon.ico` and found a 1.1 KB PNG. Note that the hash here
is **different** from the main site's hash (the docs site uses
a different favicon — possibly auto-generated, possibly a
sub-brand asset). Hosts running the same docs framework with
the same default favicon would all share this hash; querying
Shodan with it reveals every MkDocs / Sphinx instance using
the framework's default icon — a category, not the organisation.

The negative Shodan hash is normal; the value is a signed
int32 and roughly half the possible hashes are negative.
Shodan's filter syntax accepts negatives directly.

### Discovered URL returns non-200

```
operator@cathedral:~$ fav https://legacy.acme-supplies.example
> probing https://legacy.acme-supplies.example for favicon
  via html-link: https://legacy.acme-supplies.example/themes/old/favicon-v1.ico
  · primary returned 404; trying https://legacy.acme-supplies.example/favicon.ico

  url      : https://legacy.acme-supplies.example/favicon.ico
  status   : 200    318 bytes    image/x-icon

  Shodan mmh3   1675847652
                 use as http.favicon.hash:<value> in Shodan
  MD5            7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
  SHA-256        3a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d
```

The HTML declared a stale theme path — `/themes/old/favicon-
v1.ico` doesn't exist any more (the deploy that moved themes
to `new` didn't update the HTML). Cathedral noticed the 404
and fell back to the root path, which still serves the
canonical icon. Hash matches the main site — confirming this
*is* a legacy ACME Supplies host even though its declared
configuration is broken.

The 404-on-declared-URL detail is itself a finding: this site
has stale HTML pointing at a non-existent asset. Worth a note
during defender-side audits.

### A favicon match across unrelated infrastructure

A more advanced workflow than `fav` itself supports, but worth
documenting because it's the canonical follow-up:

```
$ hash=$(fav https://acme-supplies.example -j |
    jq -r 'select(.event=="hash" and .algo=="Shodan mmh3") | .value')

$ echo "$hash"
1675847652

# Now copy the hash into Shodan's web UI as:
#   http.favicon.hash:1675847652
# Or via the Shodan CLI:
#   shodan search "http.favicon.hash:$hash" --fields ip_str,port,hostnames

acme-supplies.example                      443 acme-supplies.example
shop.acme-supplies.example                 443 shop.acme-supplies.example
api.acme-supplies.example                  443 api.acme-supplies.example
staging-7.internal.acme-supplies.example   443 staging-7
198.51.100.42                              443 (unknown)
198.51.100.91                              8443 admin.dev
```

The first three hosts are expected — public corporate
infrastructure. The fourth is a *staging* host that's
internet-reachable but probably shouldn't be (the `staging-7`
hostname is typical of a forgotten test deployment). The
last two are IP-only hosts with no PTR record — almost
certainly shadow infrastructure: someone spun them up, gave
them the corporate favicon, and forgot they exist. Each is a
separate investigation thread.

This is the *point* of favicon pivoting. A single hash → a
list of hosts → a triage queue. None of these would have been
discovered by certificate transparency log scraping, by DNS
brute-forcing, or by subdomain enumeration tools — they don't
share a domain or a cert. They share a corporate identity, and
the favicon is the most stable expression of that identity.

## Output protocol

```
{"event":"start",       "target":"…"}
{"event":"tls_warning", "message":"x509: …"}                       # optional
{"event":"discovery",   "method":"html-link|default","url":"…"}
{"event":"info",        "message":"…"}                             # optional, fallback notices
{"event":"fetched",     "url":"…","status":N,"content_type":"…","bytes":N}
{"event":"hash",        "algo":"Shodan mmh3","value":N,"description":"…"}
{"event":"hash",        "algo":"MD5","value_hex":"…"}
{"event":"hash",        "algo":"SHA-256","value_hex":"…"}
{"event":"done"}
{"event":"error",       "message":"…"}
```

Extract just the Shodan hash for piping:

```
$ fav https://acme-supplies.example -j |
    jq -r 'select(.event=="hash" and .algo=="Shodan mmh3") | .value'
1675847652
```

Hash a portfolio of hosts and group by shared favicon:

```
$ for h in $(cat hosts.txt); do
    hash=$(fav "https://$h" -j |
      jq -r 'select(.event=="hash" and .algo=="Shodan mmh3") | .value')
    printf '%s\t%s\n' "$hash" "$h"
  done | sort | awk '
    { if ($1==prev) print "  " $2; else { print $1; print "  " $2 } prev=$1 }
  '
1675847652
  acme-supplies.example
  api.acme-supplies.example
  shop.acme-supplies.example
-841927185
  docs.acme-supplies.example
  blog.acme-supplies.example
1923847123
  status.acme-supplies.example
```

Hosts that share a favicon group together; the singletons at
the bottom may be using a different favicon for legitimate
reasons (different sub-brand, different framework defaults)
or they may be misconfigured.

## Limitations

- **No direct Shodan / ZoomEye / Censys enumeration.** `fav`
  produces hashes; it doesn't query the search engines. Each
  has its own auth model that's out of scope here.
- **First `<link rel="icon">` only.** Sites with multiple
  declared icons (size variants, theme variants, apple-touch-
  icon for iOS) aren't enumerated. Point `fav` at each
  declared URL explicitly.
- **No manifest.json following.** PWA-style icon declarations
  in `manifest.json` aren't read; the standard `<link
  rel="icon">` and `/favicon.ico` paths are the supported
  ones.
- **Stable-favicon assumption.** Sites that serve dynamic
  favicons (per-tenant SaaS, anti-fingerprint counter-
  measures, A/B-tested branding) produce different hashes per
  request. The hash is only useful as an identifier if the
  favicon is the same on every fetch.
- **Multi-resolution `.ico` hashing.** `.ico` files containing
  multiple resolutions hash as a whole — matches Shodan. No
  per-resolution breakout.
- **1 MB body cap.** Favicons larger than 1 MB get truncated,
  which changes the hash. In practice, favicons over 100 KB
  are vanishingly rare; the cap is generous.
- **TLS auto-fallback.** Self-signed and expired certs
  silently tolerated with one `tls_warning`. For cert posture
  use the planned `ssl`.
- **Default User-Agent.** Some CDN configurations serve
  different content (including different favicons) to
  non-browser User-Agents. Override is not currently exposed.
- **HTML parsing is regex-based.** The `<link rel="icon">`
  match doesn't handle commented-out tags or quoting edge
  cases. Reliable for ~99% of real-world HTML.

## Authorized use

`fav` is **passive inspection of public assets**. One or two
GET requests for files that the target deliberately publishes
to the world. Risk profile matches [`headers`](headers.md) and
[`cookies`](cookies.md) — indistinguishable from a normal
browser hit, modulo the User-Agent string.

The follow-up step (querying Shodan / ZoomEye / Censys with
the resulting hash) is also passive — those services pre-
crawled the internet on their own schedule; you're querying
their index, not probing the live targets. No requests reach
the discovered hosts unless you specifically follow up against
each.

The *output* of a successful favicon pivot is the part that
needs care. The discovered host list often includes
infrastructure the target's security team hasn't seen before
(shadow IT, abandoned hosts, accidentally-exposed staging
environments). Treat that information the way you'd treat any
asset-inventory finding: report responsibly if the engagement
isn't yours; act on it if it is.

## Further reading

- [Shodan's favicon hashing](https://www.shodan.io/host/favicon) — the original hashing recipe documentation
- [Shodan search filters](https://www.shodan.io/search/filters) — the `http.favicon.hash:` filter reference
- [ZoomEye search syntax](https://www.zoomeye.org/doc) — the `iconhash:` equivalent
- [Censys search](https://search.censys.io/) — favicon search via `services.http.response.favicons.md5_hash`
- [favfreak](https://github.com/devanshbatham/FavFreak) — Python-based bulk favicon hasher and Shodan dorker
- [CalidogSec — Discovering Phishing Dashboards with Favicons](https://calidog.io/blog/discovering-phishing-dashboards-using-favicons/) — the writeup that established the technique
- [MurmurHash3 reference](https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.cpp) — the canonical implementation Cathedral matches
- Related Cathedral commands: [`tech`](tech.md) (full-stack fingerprinting — favicon is one of its inputs),
  [`recon`](recon.md) (breadth-first HTTP probe — surfaces the favicon URL among its findings),
  [`http`](http.md) (single-endpoint deep inspection),
  [`asn`](asn.md) (BGP attribution for hosts discovered via Shodan pivot),
  [`whois`](whois.md) (registry attribution for the same)
