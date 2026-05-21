---
title: recon — breadth-first HTTP reconnaissance for one target
command: recon
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: medium
last-updated: 2026-05-20
related: [http, headers, tech, banner, scan, dirscan]
---

# `recon` — breadth-first HTTP reconnaissance for one target

`recon` is the *first reach* against an HTTP target — the tool you
run before [`tech`](tech.md), [`headers`](headers.md), or
[`dirscan`](dirscan.md) to find out what kind of surface you're
looking at. One request to the root reveals the server banner and
the security-header posture; a small set of well-known-path probes
checks for robots.txt, sitemap, RFC 9116 security.txt, and the
two canonical "shouldn't be reachable" findings (`.git/HEAD`,
`.env`). The output is breadth-first and fast — typical sweep
completes in 3–5 seconds — and most of what you'd want from a
first look at an unfamiliar HTTP target is in it.

```
recon example.com                          # sweep the obvious paths on example.com
recon https://target.example.com           # explicit scheme (https or http)
```

## What it does

For a single target Cathedral issues one request to the root with
`HEAD` (falling back to `GET` if the server returns `405 Method
Not Allowed`), then `GET`s six well-known paths. The root response
contributes a small card of *interesting* headers (server banner,
security headers, frameworks-on-display); each well-known path
contributes a status + size + line-preview block.

| Probe                       | Why                                              | Lines previewed |
|-----------------------------|--------------------------------------------------|-----------------|
| `/` (HEAD then GET fallback)| server banner, security headers, status posture  | headers only    |
| `/robots.txt`               | crawler instructions — often leaks site structure| 40              |
| `/sitemap.xml`              | published URL inventory                          | 20              |
| `/.well-known/security.txt` | RFC 9116 vulnerability-disclosure contact        | 40              |
| `/humans.txt`               | informal credits — rare but harmless            | 20              |
| `/.git/HEAD`                | leaked git repository (a finding when present)   | 5               |
| `/.env`                     | leaked dotenv config (a finding when present)    | 5               |

The probe set is deliberately small and curated. For wordlist-style
path enumeration, see [`dirscan`](dirscan.md) — that's a different
tool for a different question.

## What it answers

**Defender:** *"What does my site expose at first glance to a
stranger?"* The breadth-first sweep mirrors the first thing an
attacker would do — see the server banner, check robots.txt for
hints about non-obvious paths, probe the two canonical
misconfiguration paths. Running `recon` on your own infrastructure
periodically catches the embarrassing surprises (a deployed `.env`
in production, a `.git/` directory left behind, a `Server: nginx/
1.10.0` advertising a known-vulnerable build) before someone else
does.

**Recon (authorized testing only):** *"What kind of HTTP target
am I looking at?"* The root + headers tells you the layer (CDN,
reverse proxy, application server), the framework if it's
advertised, and the security-header posture. The well-known paths
tell you which canonical files exist. After `recon` you know
enough to decide whether [`tech`](tech.md) (deeper fingerprint),
[`dirscan`](dirscan.md) (path enumeration), or [`http`](http.md)
(specific endpoint probes) is the right next reach.

**Investigation:** *"Has anything changed?"* Periodic snapshots
catch infrastructure rotations (server banner change → vendor
swap), security-header regressions (HSTS removed, CSP weakened),
and the appearance of new well-known files (a security.txt
arriving means the org has formalised their vulnerability-disclosure
program). The deterministic header ordering makes diffs cheap.

**Identification:** *"Is this hosted on what I think it's hosted
on?"* The server banner (`Server: cloudflare`, `Server: AmazonS3`,
`Server: nginx/1.24.0`, `Server: Microsoft-IIS/10.0`) plus the
`Via:` header (CDN routing) often pins down the hosting stack in
one round trip. Paired with [`asn`](asn.md) for the network-layer
view, the picture is complete.

## How it works

### The probe set

Recon tools live on a spectrum from *breadth* (a few well-chosen
probes that reveal the most useful surface) to *depth* (exhaustive
dictionary attacks). Cathedral's `recon` is firmly on the breadth
end:

- **Six probes**, not six hundred.
- **Two seconds of typical wall-clock**, not two minutes.
- **Public-by-design + canonical-misconfiguration** paths only.

The probe list is hard-coded:

```go
var reconPaths = []struct {
    path     string
    maxLines int
}{
    {"/robots.txt",                 40},
    {"/sitemap.xml",                20},
    {"/.well-known/security.txt",   40},
    {"/humans.txt",                 20},
    {"/.git/HEAD",                  5},
    {"/.env",                       5},
}
```

The first four are *intended to be public* — the entire purpose
of those files is to be served unauthenticated. The last two are
*intended to be absent* — neither belongs on a production HTTP
server, and the presence of either is a finding rather than just
data.

For wordlist enumeration (admin panels, backup archives, framework
config files, language-specific tells) the right tool is
[`dirscan`](dirscan.md). For full-stack fingerprinting (which CMS,
which JS framework, which analytics provider) it's
[`tech`](tech.md). `recon` is the first pass — the lookup that
*tells you which deeper tool to reach for*.

### Root inspection: HEAD with HTTPS-then-HTTP fallback

The root request uses `HEAD` to avoid downloading the homepage
body — recon only needs the headers from this hop:

```go
resp, _, err := fetch(client, "HEAD", base+"/")
if err != nil {
    if strings.HasPrefix(base, "https://") {
        httpBase := "http://" + strings.TrimPrefix(base, "https://")
        emit(event{"event": "info", "message":
            "https failed, falling back to http"})
        base = httpBase
        resp, _, err = fetch(client, "HEAD", base+"/")
    }
}
if resp.StatusCode == 405 {
    resp, _, err = fetch(client, "GET", base+"/")
}
```

Three fallback paths cover the most common failure modes:

- **HTTPS connection failure** (no port 443 listener, TLS
  handshake refused) → retry the same path over HTTP. An
  `info` event surfaces the fallback so it's visible in output.
- **`405 Method Not Allowed`** (some servers reject HEAD on /,
  notably older PHP-based stacks) → retry with GET, which gets
  the same headers plus a body that's discarded.
- **Anything else** (DNS failure, timeout, connection refused)
  → emit `error` and stop.

The base URL Cathedral ends up using is reported back in the
`start` event, so the operator can see whether the request went
to HTTPS or fell back to HTTP.

### Interesting headers

The root response carries dozens of headers; only some are useful
for a one-look summary. Cathedral curates 17:

```go
var interestingHeaders = []string{
    "Server", "X-Powered-By",
    "X-AspNet-Version", "X-AspNetMvc-Version",
    "X-Generator", "X-Drupal-Cache", "X-Drupal-Dynamic-Cache",
    "Via", "X-Forwarded-By",
    "Strict-Transport-Security", "Content-Security-Policy",
    "X-Frame-Options", "X-Content-Type-Options",
    "Referrer-Policy", "Permissions-Policy",
    "X-XSS-Protection", "Set-Cookie", "Content-Type",
}
```

Three categories in one list:

- **Server-software tells.** `Server:`, `X-Powered-By:`, plus the
  family-specific tells (`X-Drupal-*`, `X-AspNet-*`,
  `X-Generator:` for Joomla and others) reveal the layer running
  the response. Most production stacks suppress these in
  hardening guides; their presence is itself a signal.
- **Network-path tells.** `Via:` and `X-Forwarded-By:` reveal
  proxies / CDNs / load balancers in front of the origin.
- **Security-posture tells.** The full modern security-header set
  (HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-
  Policy) maps directly to the OWASP secure-headers baseline.
  Presence/absence of each is a quick posture readout.

Headers are sorted alphabetically before emission so the output
is byte-stable across reruns — important for diffing snapshots.

### The well-known paths in detail

**`/robots.txt`** (RFC 9309) — the crawler-instructions file. Read
the path patterns: `Disallow:` entries often point at non-obvious
endpoints the operator wanted to hide from search engines.
Surprisingly often, `Disallow:` paths reveal entire admin or
test areas that exist but aren't linked from anywhere else. Also
look for `Sitemap:` lines, which point at the canonical URL
inventory.

**`/sitemap.xml`** — the operator-published URL list. For
content-heavy sites it's huge and Cathedral previews only the first
20 lines; for application backends it's often missing entirely.
The presence of multiple `<sitemap>` entries pointing at sub-
sitemaps suggests a large site with section partitioning.

**`/.well-known/security.txt`** (RFC 9116) — the vulnerability-
disclosure contact. Look for `Contact:` (the right email or URL),
`Expires:` (records expire — an expired security.txt is a stale
disclosure path), `Encryption:` (PGP key for sensitive reports),
and `Policy:` (the org's disclosure policy URL). Increasingly
common on mature orgs; near-universal on US federal sites.

**`/humans.txt`** — informal credit roll. Rare in 2026 but
charming when present. Useful for attributing maintenance (the
file frequently lists who built the site, which can be helpful for
attribution research on small targets).

**`/.git/HEAD`** — a leaked git repository. If this file responds
200, the entire git history is probably reachable from the same
prefix. Cathedral reports the file's contents (typically `ref:
refs/heads/main` — one line, five bytes). The presence of this
file is the finding; tools like `git-dumper` exist specifically
to clone the leaked repo.

**`/.env`** — a leaked dotenv config. If reachable, contents
typically include database credentials, API keys, S3 access
secrets, and SMTP passwords — the highest-impact misconfiguration
finding on HTTP infrastructure. Cathedral shows the first 5 lines,
which is enough to confirm the find without dumping secrets to
the console; for capture, use the JSON output stream.

### TLS verification disabled

Recon disables certificate verification by default:

```go
Transport: &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
},
```

The rationale is the same as `http`'s strict-then-fallback
behaviour: certificate failures are *findings*, not stop signals.
A self-signed cert on a staging environment, an expired cert on a
neglected subdomain, a name-mismatch on multi-tenant
infrastructure are all things `recon` should *see* rather than
refuse to look at. The trade-off is that `recon` doesn't emit a
`tls_warning` event the way [`http`](http.md) does — the
certificate posture isn't surfaced separately. For dedicated
certificate inspection, use `ssl` (planned) or `banner` with
TLS.

### Size and line caps

Every fetch is capped at 64 KB:

```go
body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
```

Per-file line previews vary (5 to 40 lines depending on path
relevance). The cap protects against runaway responses (a
malformed `sitemap.xml` that streams forever, a deliberately-
huge robots.txt designed to exhaust the prober). Truncation is
explicit — when the line cap fires the output ends with
`…(truncated)` and the operator knows to use [`http`](http.md)
with `-v` for the full content.

## What Cathedral doesn't do

A few deliberate omissions:

- **Path enumeration / wordlists.** Six probes, not six hundred.
  Wordlist-based directory and file discovery is
  [`dirscan`](dirscan.md)'s job — a different tool because the
  authorization posture, the timing characteristics, and the
  detection footprint are all meaningfully different.
- **Full-stack fingerprinting.** Server banner identification is
  shallow; mapping a target to its full tech stack (CMS, JS
  frameworks, analytics, error trackers) is [`tech`](tech.md).
- **Authenticated probing.** No `-h` flag for cookies or tokens.
  Recon walks the unauthenticated surface only; for authenticated
  endpoints use [`http`](http.md) with explicit headers.
- **Subdomain enumeration.** `recon target.example` examines the
  *one* host you gave it. For finding *other* hosts under the
  same domain, use `subs` (planned).
- **Active vulnerability scanning.** Recon reports what's
  present; it doesn't try to *exploit* what's present. Even the
  `.git/HEAD` probe reports finding only — to clone the leaked
  repo you'd use a dedicated tool like `git-dumper`.
- **JavaScript rendering.** All responses are read as static HTTP.
  SPAs that render their content client-side will show empty or
  near-empty bodies; that's by design (recon is fast precisely
  because it doesn't spin up a browser).
- **Crawling / link following.** One target, fixed probe set, no
  outbound link extraction. For breadth-from-a-seed crawling,
  upstream tools like `gospider` or `katana` are appropriate.

## Worked example

A typical commercial site, a misconfiguration finding, and an
HTTP-only host.

### A typical commercial site

```
operator@cathedral:~$ recon acme-supplies.example
> recon acme-supplies.example  →  https://acme-supplies.example

[ server ]
  url     : https://acme-supplies.example/
  status  : 200
  server  : cloudflare
  powered : 

[ headers ]
  Content-Security-Policy          : default-src 'self'; script-src 'self' 'unsafe-inline' https://*.cloudflare.com; …
  Content-Type                     : text/html; charset=utf-8
  Referrer-Policy                  : strict-origin-when-cross-origin
  Server                           : cloudflare
  Set-Cookie                       : __cf_bm=…; path=/; expires=Wed, 20-May-26 17:12:11 GMT; HttpOnly; Secure
  Strict-Transport-Security        : max-age=31536000; includeSubDomains; preload
  X-Content-Type-Options           : nosniff
  X-Frame-Options                  : SAMEORIGIN

[ /robots.txt ]  status 200  ·  142 bytes
  User-agent: *
  Disallow: /admin/
  Disallow: /api/internal/
  Disallow: /staging/
  Sitemap: https://acme-supplies.example/sitemap.xml

[ /sitemap.xml ]  status 200  ·  1842 bytes
  <?xml version="1.0" encoding="UTF-8"?>
  <urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
    <url><loc>https://acme-supplies.example/</loc></url>
    <url><loc>https://acme-supplies.example/products</loc></url>
    <url><loc>https://acme-supplies.example/about</loc></url>
    …(truncated)

[ /.well-known/security.txt ]  status 200  ·  211 bytes
  Contact: mailto:security@acme-supplies.example
  Expires: 2027-01-01T00:00:00Z
  Encryption: https://acme-supplies.example/.well-known/security.pgp
  Policy: https://acme-supplies.example/security-policy
  Preferred-Languages: en

[ /humans.txt ]  status 404  ·  0 bytes

[ /.git/HEAD ]  status 404  ·  0 bytes

[ /.env ]  status 404  ·  0 bytes

recon complete.
```

The headline finding here is *normal*: Cloudflare in front,
modern security headers (HSTS with preload, CSP defined, X-Frame
SAMEORIGIN, no-sniff), a published security.txt with an unexpired
contact, and 404s on the two misconfiguration probes. The
`robots.txt` Disallows are mildly interesting — `/admin/`,
`/api/internal/`, `/staging/` are all paths someone might want to
investigate next, but they're public-by-design hints. The
`Sitemap:` line points at the canonical URL inventory.

### A misconfiguration finding

```
operator@cathedral:~$ recon dev-internal.acme-supplies.example
> recon dev-internal.acme-supplies.example  →  https://dev-internal.acme-supplies.example

[ server ]
  url     : https://dev-internal.acme-supplies.example/
  status  : 200
  server  : nginx/1.18.0 (Ubuntu)
  powered : PHP/7.4.3

[ headers ]
  Content-Type                     : text/html; charset=UTF-8
  Server                           : nginx/1.18.0 (Ubuntu)
  Set-Cookie                       : PHPSESSID=4c8a91d7e2b3f6a4; path=/
  X-Powered-By                     : PHP/7.4.3

[ /robots.txt ]  status 404  ·  0 bytes

[ /sitemap.xml ]  status 404  ·  0 bytes

[ /.well-known/security.txt ]  status 404  ·  0 bytes

[ /humans.txt ]  status 404  ·  0 bytes

[ /.git/HEAD ]  status 200  ·  23 bytes
  ref: refs/heads/main

[ /.env ]  status 200  ·  482 bytes
  APP_ENV=production
  APP_DEBUG=true
  DB_HOST=db.internal.acme-supplies.example
  DB_USERNAME=acme_app
  DB_PASSWORD=********

recon complete.
```

Three findings in one sweep. **The server banner** advertises
nginx 1.18.0 and PHP 7.4.3 — both end-of-life as of 2026, both
trivially attackable. **`/.git/HEAD` returns 200** — the
repository on disk is web-accessible, which means an attacker
can clone the entire commit history with `git-dumper` and read
the source. **`/.env` returns 200** with production database
credentials in plaintext — the highest-impact finding on a
recon sweep.

The host is named `dev-internal` and is presumably meant to be
inaccessible from the public internet. The presence of the
banner + `.git` + `.env` triad is the *canonical* "a dev
environment got accidentally exposed to the internet" pattern.

In a real engagement, this output is the entire engagement —
everything you need to demonstrate impact is here. Cathedral
shows the finding without exploiting it; capture-and-clone is a
separate next step using `git-dumper` or similar.

### HTTPS not available, downgrade

```
operator@cathedral:~$ recon legacy-portal.acme-supplies.example
> recon legacy-portal.acme-supplies.example  →  https://legacy-portal.acme-supplies.example
  · https failed, falling back to http

[ server ]
  url     : http://legacy-portal.acme-supplies.example/
  status  : 200
  server  : Apache/2.2.22 (Debian)
  powered : PHP/5.3.10

[ headers ]
  Content-Type                     : text/html
  Server                           : Apache/2.2.22 (Debian)
  Set-Cookie                       : PHPSESSID=…; path=/
  X-Powered-By                     : PHP/5.3.10

[ /robots.txt ]  status 200  ·  47 bytes
  User-agent: *
  Disallow: /

[ /sitemap.xml ]  status 404  ·  0 bytes

[ /.well-known/security.txt ]  status 404  ·  0 bytes

[ /humans.txt ]  status 404  ·  0 bytes

[ /.git/HEAD ]  status 404  ·  0 bytes

[ /.env ]  status 404  ·  0 bytes

recon complete.
```

HTTPS isn't available — the host accepts plaintext HTTP only.
The `info` event surfaces the fallback (`https failed, falling
back to http`) so the operator can see the downgrade happened.
The Apache 2.2.22 (released 2012, end-of-life since 2017) and
PHP 5.3.10 (EOL since 2014) banners are the headline: this is
genuinely legacy infrastructure. The `Disallow: /` robots.txt is
the operator's defensive gesture against search-engine
indexing — appropriate for a portal that shouldn't be public, but
robots.txt is advisory, not enforcement.

## Output protocol

```
{"event":"start", "target":"…","base":"https://…"}
{"event":"info",  "message":"…"}                                          # optional
{"event":"root",  "url":"…","status":N,"server":"…","poweredby":"…",
                  "content_type":"…","headers":[{"key":"…","value":"…"},…]}
{"event":"probe", "path":"/robots.txt","status":N,"size":N,
                  "lines":["…","…"],"truncated":true|false}              *
{"event":"probe", "path":"…","error":"…"}                                 # on failure
{"event":"done"}
{"event":"error", "message":"…"}
```

Pipe to extract just the security-header posture:

```
$ recon acme-supplies.example -j |
    jq -r 'select(.event=="root") | .headers[] |
           select(.key | test("Security|HSTS|Frame|Content-Type-Options|Referrer|Permissions")) |
           "\(.key): \(.value)"'
Content-Security-Policy: default-src 'self'; …
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
```

Find hosts in a portfolio with `.git/HEAD` or `.env` reachable:

```
$ for h in $(cat hosts.txt); do
    recon "$h" -j |
      jq -r --arg h "$h" \
        'select(.event=="probe" and (.path==".git/HEAD" or .path==".env")
                and .status==200) | "\($h)\t\(.path)\t\(.status)"'
  done
dev-internal.acme-supplies.example  /.git/HEAD  200
dev-internal.acme-supplies.example  /.env       200
staging-2.acme-supplies.example      /.git/HEAD  200
```

Snapshot a target's recon output for periodic comparison:

```
$ recon acme-supplies.example -j > /tmp/recon-today.json
# … weekly … then …
$ jq -r 'select(.event=="root") | .headers[] | "\(.key): \(.value)"' \
     /tmp/recon-today.json /tmp/recon-last-week.json | diff
```

## Limitations

- **Six probes only.** Recon is breadth-first. For depth, use
  [`dirscan`](dirscan.md).
- **TLS verification is disabled.** Self-signed and expired certs
  don't show as findings — they're silently accepted. For
  cert-posture work, use the planned `ssl` command.
- **Body cap 64 KB per probe.** Larger files are partial-read.
  For full content use [`http`](http.md) `-v`.
- **Line caps per probe** (5–40 lines depending on path). Larger
  previews are truncated with a `…(truncated)` marker.
- **No JS rendering.** SPAs render their content client-side;
  Cathedral sees the empty shell HTML.
- **One target per invocation.** For a list of targets, iterate
  in the shell (see jq recipe above).
- **No authentication.** All requests are unauthenticated. For
  authenticated recon use [`http`](http.md) with explicit
  `-h Cookie:…` or `-h Authorization:…`.
- **No User-Agent override.** The fixed `cathedral/recon (self-
  audit)` UA may be detected and treated differently by some
  WAFs than a browser UA. The "self-audit" tag is deliberate —
  it identifies the request as authorised first-party recon
  rather than masquerading as a normal browser.
- **No HTTP/3.** ALPN negotiates HTTP/2 over TLS when offered;
  QUIC is not supported.
- **Sequential probes.** Six requests in series, each with an
  8-second timeout. Worst-case wall time is ~50 seconds (one
  bad target); typical is 3–5 seconds.

## Authorized use

`recon` is **active probing of an HTTP target**. It generates
real requests to real endpoints; the target's logs see your IP.
Unlike pure DNS or whois recon, recon's `.git/HEAD` and `.env`
probes are the kind of request that lights up WAFs and pen-test
detection systems. The wire pattern is the wire pattern,
regardless of intent.

Three notes worth attaching:

**Your IP is logged.** Every probe arrives at the target with
your machine's source IP. There's no anonymisation layer. For
sensitive testing, route through a Burp/mitmproxy/authorised
testing proxy.

**The `.git/HEAD` and `.env` probes can trip detection.**
Modern WAFs (Cloudflare, Imperva, AWS WAF, F5) have rules that
specifically watch for these path patterns. A `recon` against a
WAF-protected target will be visible in their dashboards. For
authorised engagements this is fine; for any other context,
restrict yourself to the public-by-design probes (robots.txt,
sitemap, security.txt).

**Target only what you own or have written permission to test.**
The four public-by-design probes are unremarkable. The two
misconfiguration probes are tonally different — running them
against a target you're not authorised to test is the kind of
thing that draws attention. Cathedral enforces nothing here; the
constraints are policy and law, not technical.

## Further reading

- [RFC 9309 — Robots Exclusion Protocol](https://www.rfc-editor.org/rfc/rfc9309) — the spec for robots.txt
- [RFC 9116 — A File Format to Aid in Security Vulnerability Disclosure (security.txt)](https://www.rfc-editor.org/rfc/rfc9116) — the spec for `.well-known/security.txt`
- [Sitemaps XML format](https://www.sitemaps.org/protocol.html) — the operator-published URL inventory
- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) — the security-header baseline `recon` reports against
- [humans.txt](https://humanstxt.org/) — the informal credits convention
- Related Cathedral commands: [`http`](http.md) (single-endpoint deep inspection),
  [`headers`](headers.md) *(planned — depth-focused security header analysis)*,
  [`tech`](tech.md) (full-stack fingerprinting),
  [`banner`](banner.md) (single-port banner grab; the TCP/TLS layer below HTTP),
  [`scan`](scan.md) (TCP port scanner with banner grab),
  [`dirscan`](dirscan.md) (wordlist-driven path enumeration)
