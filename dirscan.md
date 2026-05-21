---
title: dirscan — concurrent wordlist-driven path enumerator
command: dirscan
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: high
last-updated: 2026-05-20
related: [recon, http, headers, tech, banner, scan]
---

# `dirscan` — concurrent wordlist-driven path enumerator

`dirscan` is the *depth* counterpart to [`recon`](recon.md): where
recon issues six well-chosen probes against the obvious paths,
dirscan issues hundreds — a wordlist-driven sweep that finds
admin panels, leftover backup files, undocumented API endpoints,
and the catalogue of misconfigurations that don't quite reach the
front door. The built-in list is ~200 high-signal paths curated
for the analyst use case; for thorough enumeration, point
`--wordlist=@file` at a SecLists-style dictionary and let it run.

The tool's character is shaped by two engineering choices: the
default is **HEAD requests**, which keeps each probe small and
fast; and the rate limiter is **adaptive**, reading `Retry-After`
on 429/503 responses and pausing every worker until the deadline
the server asked for. Both choices push `dirscan` toward
*responsible* enumeration — fast when the target can take it,
respectful when it can't.

```
dirscan https://target.example.com                            # default sweep
dirscan https://target.example.com --ext=.php,.bak,.zip       # plus extensions
dirscan https://target.example.com --conc=40 --rps=20         # tuned for fragile targets
dirscan https://internal.example.com:8443 -k                  # self-signed cert tolerated
dirscan https://api.example.com --show=200,401,403 --get      # API-style endpoints
dirscan https://x.example.com --wordlist=@/usr/share/wordlists/dirb/big.txt
```

## What it does

For a single target URL, Cathedral expands a wordlist into a
candidate-path list, then issues concurrent HEAD (or GET, with
`--get`) requests against each candidate. Responses that don't
match a hide-filter (default: hide 404) are reported as hits with
status, content length, and either the `Location:` header (on
redirects) or the `Content-Type:` header (on 200s) as the
right-side decoration. Adaptive throttling watches for 429/503
and pauses every worker for the server's requested `Retry-After`
window.

| Flag                | Meaning                                           | Default                     |
|---------------------|---------------------------------------------------|-----------------------------|
| `--wordlist=@file`  | custom wordlist (one path per line; `#` = comment)| built-in ~200 paths         |
| `--ext=.php,.bak,…` | extensions to also try for each word              | none                        |
| `--conc=N`          | concurrent workers (max 200)                      | `20`                        |
| `--timeout=MS`      | per-request timeout in ms (min 100)               | `5000`                      |
| `--show=200,403`    | allowlist of status codes                         | unset (everything except hide)|
| `--hide=404,400`    | blocklist of status codes                         | `404`                       |
| `--get`             | use GET requests instead of HEAD                  | HEAD                        |
| `--ua="…"`          | custom User-Agent                                 | `cathedral-dirscan/0.1`     |
| `-H Name:Value`     | extra header (repeatable)                         | none                        |
| `-k`                | suppress the "TLS chain unverified" warning       | off                         |
| `--rps=N`           | cap requests/second across all workers            | unlimited                   |
| `--no-backoff`      | don't auto-pause on 429/503                       | off (backoff is on)         |

The defaults are tuned for "give me the first useful sweep, fast,
without lighting a target on fire": HEAD requests so bodies don't
transfer, 20 workers so the load profile is moderate, automatic
backoff so well-behaved 429s pause us instead of triggering harder
ones. Override any of these when the target or the engagement
calls for it.

## What it answers

**Defender:** *"What's reachable on my web infrastructure that
shouldn't be?"* Periodic dirscan sweeps against your own hosts
find the gaps between "what we deployed" and "what's actually
exposed". Common findings: a backup `.zip` left in a docroot, an
older version of an admin path still routed but no longer linked,
a `phpinfo.php` from a debugging session, a `/test/` directory
nobody removed. Self-audit is the *defender's* use of this tool,
and arguably the most valuable one.

**Recon (authorized testing only):** *"What does this web app
actually expose?"* The output is the map of the application's
reachable surface — every path that resolves to anything other
than "not found" is a starting point for deeper inspection.
Common shapes: API endpoints discovered by their version-prefix
patterns (`/v1/`, `/api/`, `/graphql`), admin areas revealed by
their canonical names, frameworks identified by their tells
(`/wp-admin/`, `/_next/`, `/.well-known/apple-app-site-
association`).

**Investigation:** *"Is this app the same as it was last week?"*
Snapshot the hit set, diff against an earlier snapshot, and any
newly-appearing paths (or newly-disappearing ones) are signals.
Production environments shouldn't grow new admin paths
spontaneously; staging environments often do, and the diff
catches the deployment patterns.

## How it works

### The wordlist + extension expansion

The built-in wordlist is intentionally small — ~200 entries —
because most useful findings concentrate at the high-frequency
end of the path distribution:

```go
// Default wordlist — ~200 high-signal paths for security audits
// and recon. Curated to fit the analyst use case rather than full
// coverage; users can supply their own via --wordlist=@file for
// SecLists-style brute forcing.
```

The categories it covers, roughly: **auth/admin panels** (`admin`,
`login`, `oauth`, `sso`), **API surfaces** (`api`, `v1`, `v2`,
`graphql`, `swagger`), **backup files** (`.bak`, `.swp`, `.old`),
**config exposures** (`config.php`, `web.config`, `.env`,
`.git/HEAD`), **framework signatures** (`wp-admin`, `drupal/`,
`joomla/`), **dev/staging tells** (`test`, `dev`, `debug`,
`phpinfo.php`), and **static directories** (`uploads`, `files`,
`images`, `css`, `js`).

The wordlist is one input; the second is the `--ext` flag, which
appends extensions to each word:

```go
func expandPaths(words, exts []string) []string {
    out := make([]string, 0, len(words)*(1+len(exts)))
    seen := map[string]struct{}{}
    for _, w := range words {
        add(w)
        for _, ext := range exts {
            add(w + ext)
        }
    }
    return out
}
```

`--ext=.php,.bak` against the default wordlist of 200 words
expands to ~600 candidates (200 raw + 200 + 200). Deduplication
prevents `--ext=.php` plus a wordlist that already includes
`admin.php` from generating duplicates. The hard ceiling is
50 000 candidates after expansion — large enough for SecLists-
size dictionaries, low enough to refuse runaway combinations.

For exhaustive enumeration, SecLists is the canonical resource:
`--wordlist=@/usr/share/wordlists/seclists/Discovery/Web-Content/
directory-list-2.3-medium.txt` is the workhorse choice; it has
~220 000 paths but well under the cap.

### Concurrency and timeout

The worker pool is a semaphore-bounded goroutine fan-out:

```go
sem := make(chan struct{}, args.conc)
for _, p := range paths {
    sem <- struct{}{}
    wg.Add(1)
    go func(p string) {
        defer wg.Done()
        defer func() { <-sem }()
        // … do request …
    }(p)
}
wg.Wait()
```

Each request gets the configured timeout (default 5000 ms). The
maximum concurrency is hard-capped at 200 — beyond that, your
local OS networking stack typically becomes the bottleneck
rather than the target. For most engagements the default 20 is
both fast enough and conservative enough; bump to 50–100 for
sturdy CDN-fronted targets, drop to 5–10 for fragile origins.

The mutex on stdout serialises emitted events so concurrent
workers don't interleave JSON lines:

```go
var emu sync.Mutex
func emit(e event) {
    emu.Lock()
    defer emu.Unlock()
    _ = enc.Encode(e)
}
```

### Status filtering: `--show` and `--hide`

The interesting-vs-not split is operator-controlled. Two filter
modes:

- **`--hide=…`** (blocklist) — show every status *except* these.
  Default: `--hide=404`. The vast majority of dictionary probes
  return 404, and the noise would drown the signal otherwise.
- **`--show=…`** (allowlist) — show *only* these. Useful when
  you know exactly what you're looking for (e.g.
  `--show=200,403` for "I want resources that exist, including
  forbidden ones").

```go
func shouldShow(status int, show, hide map[int]bool) bool {
    if len(show) > 0 {
        return show[status]
    }
    return !hide[status]
}
```

The two modes are mutually exclusive — passing `--show=`
implicitly clears the default hide-404. Status-code colour is
based on the class: 2xx green, 3xx dim, 4xx amber, 5xx red.

### HEAD vs GET

HEAD is the default for three reasons:

- **Bandwidth.** No response body. A 1 GB file returns its
  Content-Length in 200 bytes rather than 1 GB.
- **Latency.** Most servers respond to HEAD faster than GET
  because they skip body composition.
- **Surface.** Many servers handle HEAD identically to GET for
  status purposes, so dirscan gets the same routing tree without
  the body.

The HEAD-vs-GET difference matters for routes where the server
specifically discriminates: PHP CGI on older configurations may
return 405 to HEAD on routes that handle GET, and SPA backends
sometimes serve different status codes for HEAD probes than for
GET. When you see suspicious 405s, retry the sweep with `--get`.

### TLS auto-fallback

Same pattern as [`http`](http.md) and [`recon`](recon.md): strict
verification first, retry with `InsecureSkipVerify` on `x509:`
errors, emit one `tls_warning` event for the first failure:

```go
if tlsWarn != "" && !args.insecureOK &&
    tlsWarned.CompareAndSwap(false, true) {
    emit(event{"event": "tls_warning", "message": tlsWarn})
}
```

The `CompareAndSwap` ensures the warning fires exactly once
across the whole concurrent sweep rather than once per worker.
`-k` silences it when the insecure-fallback is expected (a known
self-signed staging environment, an internal CA).

### Rate limiting: explicit `--rps` + adaptive backoff

Two independent layers:

**`--rps=N`** enforces a fixed token-bucket rate across all
workers via a single shared ticker:

```go
type rateLimit struct {
    ticker *time.Ticker
    // …
}
func (r *rateLimit) wait() {
    // adaptive backoff first
    if r.ticker != nil {
        <-r.ticker.C
    }
}
```

Combined with `--conc=N`, this gives precise control: a fragile
target might want `--conc=4 --rps=8` for a paced sweep that never
exceeds 8 requests per second even when the workers could go
faster.

**Adaptive backoff** is on by default and reads the server's
`Retry-After` header on 429/503 responses:

```go
if !args.noBackoff && (resp.StatusCode == 429 || resp.StatusCode == 503) {
    delay := parseRetryAfter(resp.Header.Get("Retry-After"))
    if delay <= 0 { delay = 10 * time.Second }
    rl.backoff(delay)
    emit(event{"event": "throttled", "status": resp.StatusCode,
        "path": p, "pause_ms": delay.Milliseconds()})
}
```

`parseRetryAfter` handles both the numeric (seconds) and
HTTP-date forms defined in RFC 7231 §7.1.3. The pause is shared
across all workers via a `pauseUntil` timestamp — once one worker
gets 429'd, every other worker stops at its next `wait()` call
until the deadline. The pause is monotonic (never shortened) so
multiple concurrent 429s within the same second don't trample
each other; if the server keeps 429'ing, the pause extends.

The pause is capped at 5 minutes — a server asking for an
hour-long pause gets the 5-minute cap, on the rationale that no
reasonable sweep should wait that long. Use `--no-backoff` to
disable adaptive behaviour entirely (against targets you control
during stress testing, for instance).

### Progress reporting

Milestone events fire at 25/50/75/100% completion via an atomic
gate:

```go
func bumpProgress(done, milestone *atomic.Int64, total int, hits *atomic.Int64) {
    d := done.Add(1)
    pct := int(d * 100 / int64(total))
    cur := milestone.Load()
    if int64(pct) >= cur+25 && milestone.CompareAndSwap(cur, cur+25) {
        emit(event{"event":"progress", "done":d, "total":total,
            "pct":pct, "hits":hits.Load()})
    }
}
```

The milestone gate is racy-but-fine: if two workers both notice
"we just crossed 50%" simultaneously, CompareAndSwap ensures only
one emits the event. Progress events are deliberately sparse —
four total per sweep — to keep the visible output readable. For
fine-grained progress on long sweeps, watch the JSON stream
directly (`hit` and `throttled` events are unbroken).

## What Cathedral doesn't do

A few deliberate omissions:

- **Recursive descent.** Cathedral probes one level; finding
  `/admin/` doesn't trigger an automatic sweep against
  `/admin/{wordlist}`. For recursive enumeration, run dirscan
  again with the discovered path appended to the base URL.
  Recursive sweeps multiply request count quickly; making it
  manual keeps the engagement deliberate.
- **Authentication helpers.** No `--basic`, no `--bearer` — pass
  credentials via `-H Authorization:…`. The lack of an auth
  abstraction is intentional: surprises in request headers cost
  more than the convenience saves.
- **Response-body inspection.** HEAD returns no body; `--get`
  fetches the body but Cathedral discards it. To match on body
  content, use a separate pass with [`http`](http.md) against
  the discovered paths.
- **Status-code grouping.** Each hit is one line; Cathedral
  doesn't group by 200/301/403/etc. into sections. The JSON
  output supports any grouping you want via jq.
- **Differential mode.** No "show only paths that exist on
  target A but not target B" mode. Capture both as JSON and
  diff externally.
- **Built-in form fuzzing.** Dirscan is path enumeration only —
  query strings, POST bodies, and form fields are out of scope.
  For parameter fuzzing, `ffuf` is the dedicated tool.
- **JavaScript-rendered paths.** Static HTTP only. SPAs whose
  routes only exist after client-side rendering won't be
  discovered.
- **Subdomain enumeration.** `dirscan host` examines paths on
  *that one host*. For subdomain discovery use `subs` (planned)
  or upstream tools like `subfinder`.

## Worked example

A default sweep that finds the expected surface, a custom-
wordlist sweep with extensions, an API-only sweep with status
filters, and the 429-backoff case.

### Default sweep on a small WordPress site

```
operator@cathedral:~$ dirscan https://acme-blog.example
> HEAD sweep against https://acme-blog.example/    218 paths    conc 20

  [301]  wp-admin                                0 B   →  /wp-admin/
  [200]  wp-login.php                         4112 B   text/html; charset=UTF-8
  [301]  wp-content                              0 B   →  /wp-content/
  [200]  wp-content/uploads/                  2841 B   text/html; charset=UTF-8
  [403]  wp-config.php                          14 B   text/html; charset=iso-8859-1
  [200]  xmlrpc.php                             42 B   text/html; charset=UTF-8
  [200]  feed                                47128 B   application/rss+xml
  [200]  robots.txt                            181 B   text/plain
  [301]  wp-json                                 0 B   →  /wp-json/
  · 50%   (109/218, 8 hits so far)
  [200]  wp-json/wp/v2/users                 18421 B   application/json
  · 75%   (164/218, 9 hits so far)
  [403]  admin                                 199 B   text/html
  [200]  readme.html                          7821 B   text/html

dirscan complete — 11 hits / 218 paths in 14s
```

The path pattern is canonical WordPress: `/wp-admin/`,
`/wp-login.php`, `/wp-content/`, the XML-RPC endpoint, the
REST API at `/wp-json/`, the readme file. The interesting finds
on this sweep are the **enumerable `/wp-json/wp/v2/users`
endpoint** (an authenticated-user list is queryable without
auth — a well-known WordPress finding that requires plugin
hardening to suppress) and the **directory listing on
`/wp-content/uploads/`** (the 2.8 KB body is the auto-generated
Apache index page — file enumeration is reachable from the
upload root). The `xmlrpc.php` returning 200 is the third tell;
on hardened installs that endpoint is disabled or restricted.

### Custom wordlist with extensions

```
operator@cathedral:~$ dirscan https://api-staging.acme-supplies.example \
    --wordlist=@/usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints.txt \
    --ext=.json,.yaml \
    --conc=40 \
    --rps=30
> HEAD sweep against https://api-staging.acme-supplies.example/    3214 paths    conc 40   rps 30

  [200]  health                                 87 B   application/json
  [200]  status                                142 B   application/json
  [200]  metrics                              2841 B   text/plain; charset=utf-8
  [200]  openapi.json                        47821 B   application/json
  [200]  swagger.json                        47821 B   application/json
  [403]  admin                                  19 B   application/json
  · 25%   (804/3214, 6 hits so far)
  [200]  v1/healthz                             87 B   application/json
  [200]  v1/version                            142 B   application/json
  [401]  v1/users                              112 B   application/json
  · 50%   (1607/3214, 9 hits so far)
  [200]  internal/debug                       3142 B   application/json
  [200]  internal/config.yaml                 1842 B   text/yaml
  · 75%   (2410/3214, 11 hits so far)

dirscan complete — 12 hits / 3214 paths in 2m 14s
```

The API-endpoint wordlist plus `.json,.yaml` extensions reveals
several useful patterns. **`/openapi.json` and `/swagger.json`
both 200** — the API publishes its own spec, which downstream
fuzzing tools can consume as input. **`/metrics` returns
plaintext** — almost certainly a Prometheus exposition endpoint
that shouldn't be public-reachable on a staging environment.
The **two `/internal/` endpoints** are the headline: the name
itself signals "operators only", and both return 200 with usable
content. `/internal/config.yaml` exposing configuration is the
kind of finding that escalates a report immediately.

### API endpoint sweep with status filter

```
operator@cathedral:~$ dirscan https://api.acme-supplies.example/v1/ \
    --show=200,401,403 \
    --get \
    -H "Authorization: Bearer eyJhbGc…"
> GET sweep against https://api.acme-supplies.example/v1/    218 paths    conc 20

  [200]  health                                 87 B   application/json
  [200]  users                                3142 B   application/json
  [200]  products                             5821 B   application/json
  [200]  orders                              18421 B   application/json
  [403]  admin                                 142 B   application/json
  [403]  admin/users                           142 B   application/json
  [403]  internal                              142 B   application/json
  [401]  reports                                87 B   application/json

dirscan complete — 8 hits / 218 paths in 12s
```

`--show=200,401,403` filters to the three operational shapes for
API enumeration. **200**s are reachable as the bearer-token user;
**401**s reveal endpoints the token doesn't authorise but exist
(e.g. `/reports` would resolve for an admin token); **403**s
identify endpoints that exist but are forbidden categorically
(`/admin`, `/internal`). The distinction is useful: a 401 means
"try a better token"; a 403 means "this needs a different
mechanism entirely". The presence of `/admin/users` as a 403 is
informative — the admin namespace mirrors the public namespace,
so privileged paths can be inferred from public ones.

### Adaptive backoff

```
operator@cathedral:~$ dirscan https://target.example.com --conc=50
> HEAD sweep against https://target.example.com/    218 paths    conc 50

  [301]  login                                   0 B   →  /login
  [200]  api                                  1842 B   application/json
  ! throttled by server (status 429 on /admin) — pausing 30.0s
  [301]  api/v1                                  0 B   →  /api/v1/
  · 25%   (54/218, 4 hits so far)
  ! throttled by server (status 429 on /backup) — pausing 60.0s
  · 50%   (109/218, 5 hits so far)

dirscan complete — 7 hits / 218 paths in 3m 41s
```

The target's WAF returned 429 with `Retry-After: 30` on `/admin`
(probably because the path matched a known-bad pattern), then a
second 429 with `Retry-After: 60` on `/backup`. The adaptive
backoff parses each `Retry-After`, pauses every worker for the
requested window, and resumes after — the sweep completes
without escalating to an outright block. Without `--no-backoff`,
this is the *responsible* behaviour. With `--no-backoff`, the
same sweep would have hammered through and almost certainly hit
a longer-lived block.

For very fragile targets — origins behind a small reverse proxy,
self-hosted infrastructure on a constrained line — combine
`--conc=4 --rps=8 --timeout=10000` for a paced sweep that
spreads load across ~30 seconds rather than ~3 seconds.

## Output protocol

```
{"event":"start",      "target":"…","method":"HEAD|GET","paths":N,
                       "conc":N,"timeout_ms":N,"rps":N,"backoff":true|false}
{"event":"tls_warning","message":"x509: …"}                              # at most one
{"event":"hit",        "path":"…","url":"…","status":N,"length":N,
                       "location":"…",      # optional, on 3xx
                       "content_type":"…"}  # optional, on 2xx                *
{"event":"throttled",  "status":429|503,"path":"…","pause_ms":N}            *
{"event":"progress",   "done":N,"total":N,"pct":25|50|75|100,"hits":N}      *
{"event":"done",       "total":N,"hits":N}
{"event":"error",      "message":"…"}
```

Pipe to a status-grouped summary:

```
$ dirscan https://target.example.com -j |
    jq -r 'select(.event=="hit") | "\(.status)\t\(.path)"' |
    sort | uniq -c | sort -rn
     4 200  api/v1/…
     3 301  …
     2 403  admin
     1 401  reports
```

Find paths that exist on staging but not on production:

```
$ dirscan https://prod.example.com -j |
    jq -r 'select(.event=="hit") | .path' | sort > /tmp/prod.txt
$ dirscan https://staging.example.com -j |
    jq -r 'select(.event=="hit") | .path' | sort > /tmp/staging.txt
$ comm -23 /tmp/staging.txt /tmp/prod.txt
debug-toolbar
internal/dev-login
sql-console
```

Cross-check `dirscan` findings against the `recon` baseline:

```
$ dirscan https://target.example.com -j |
    jq -r 'select(.event=="hit") | .path' | sort > /tmp/dirscan.txt
$ recon target.example.com -j |
    jq -r 'select(.event=="probe" and .status!=404) | .path' | sort \
    > /tmp/recon.txt
$ comm -23 /tmp/dirscan.txt /tmp/recon.txt | head
```

## Limitations

- **One level deep.** No recursive enumeration. Re-run against
  discovered prefixes for depth.
- **HEAD vs GET difference.** Some servers return different
  statuses to HEAD than to GET. If `dirscan` shows unexpected
  405s or 404s, retry with `--get`.
- **No body inspection.** HEAD by default returns no body;
  `--get` discards the body. Content-matching is out of scope
  for `dirscan` — use [`http`](http.md) against the discovered
  paths.
- **Wordlist quality dominates.** A small high-signal wordlist
  (Cathedral's default) finds common things fast. A massive
  SecLists-style wordlist finds long-tail things slowly. Choose
  for the engagement.
- **WAF blocking and rate limits.** CDN-fronted targets
  (Cloudflare, Akamai, Imperva) frequently rate-limit or
  outright block dictionary sweeps. The adaptive backoff helps
  with cooperative 429s but does nothing if the WAF returns 403
  on every request. Use `--conc=4 --rps=8` and accept a slow
  sweep, or test from an authorised IP.
- **TLS verification is auto-fallback.** Self-signed certs are
  silently tolerated with one `tls_warning` event. For
  certificate-posture audits, `ssl` (planned) is the right tool.
- **No URL encoding handling.** Wordlist entries are URL-joined
  literally; spaces and special characters in the wordlist are
  not encoded. For paths with weird characters, hand-build the
  wordlist with the correct encoding.
- **No HTTP/3.** ALPN negotiates HTTP/2 when offered; QUIC is
  not supported.
- **50 000 candidate ceiling.** Wordlist × extensions must fit;
  larger combinations refuse.

## Authorized use

`dirscan` is **active enumeration**. The request pattern
(sequential probes of dictionary paths) is the canonical
fingerprint of unauthorised scanning, and every WAF/IDS/SIEM in
production has rules tuned for it. Running `dirscan` against
infrastructure you don't own or aren't explicitly authorised to
test is:

- detectable within seconds (the timing pattern alone is enough),
- almost certainly logged with full request detail,
- legally exposed under most jurisdictions' computer-misuse
  statutes.

The constraints are policy and law, not technical. Cathedral
enforces nothing. Get authorization first.

Three notes worth attaching:

**Your IP is the source.** No proxy abstraction, no source
rotation. The target sees your IP on every request and can
correlate the sweep to whatever they know about you. For
authorised engagements, route through a Burp or mitmproxy proxy
that records the engagement provenance.

**Backoff is the default for a reason.** Many WAFs respond to
429s with progressively-harsher behaviour: longer rate limits
first, then per-IP bans, then per-ASN bans, then notification
to the IP's abuse-contact. Respecting `Retry-After` keeps you
in the cooperative zone of that escalation; `--no-backoff` opts
out of it. Use `--no-backoff` only against targets you control
or have explicit permission to stress.

**Document the scope.** Dirscan output is the *list of paths
you probed* as much as it is the *list of paths that responded*.
For audit trails (your own as much as anyone else's), keep the
JSON output — the `target` field on `start` records the URL,
the wordlist file path is in your command history, and the hit
list reproduces the engagement step-for-step.

## Further reading

- [DIRB documentation](https://dirb.sourceforge.net/) — the original directory brute-forcer; `dirscan` is in the same shape
- [gobuster](https://github.com/OJ/gobuster) — feature-rich modern equivalent; helpful when `dirscan` is too minimal
- [ffuf](https://github.com/ffuf/ffuf) — fast web fuzzer with parameter-fuzzing capabilities; complements `dirscan` for query-string and form-field work
- [SecLists / Discovery / Web-Content](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) — the canonical wordlist collection
- [RFC 7231 §7.1.3 — Retry-After](https://www.rfc-editor.org/rfc/rfc7231#section-7.1.3) — the header format the backoff logic parses
- Related Cathedral commands: [`recon`](recon.md) (the breadth-first first pass before `dirscan`),
  [`http`](http.md) (single-endpoint deep inspection of discovered paths),
  [`headers`](headers.md) *(planned — header analysis of discovered endpoints)*,
  [`tech`](tech.md) (full-stack fingerprinting),
  [`banner`](banner.md) (TCP-level banner grab — the layer below HTTP),
  [`scan`](scan.md) (TCP port scanner with banner grab)
