---
title: headers — security-header audit with letter grade
command: headers
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [http, recon, tech, ssl]
---

# `headers` — security-header audit with letter grade

`headers` reads the seven HTTP response headers that matter most
for transport security and client-side defence — HSTS, CSP,
X-Frame-Options, X-Content-Type-Options, Referrer-Policy,
Permissions-Policy, and Cross-Origin-Opener-Policy — grades each
one against the modern baseline, and rolls the result up into a
coarse letter grade A–F. Where [`recon`](recon.md) sees these
headers as part of a wider sweep and [`http`](http.md) shows
them verbatim, `headers` is the *posture readout*: a glanceable
summary of whether the target is following the OWASP secure-
headers baseline and where the gaps are.

```
headers https://github.com
headers acme-supplies.example                          # https:// auto-prefixed
headers https://10.0.0.1:8443                          # internal w/ self-signed cert
```

## What it does

For a single URL, Cathedral issues one GET request and inspects
the response headers against a fixed set of seven checks. Each
check returns one of four grades:

| Grade   | Meaning                                                      |
|---------|--------------------------------------------------------------|
| `good`  | Header present and configured correctly                      |
| `warn`  | Header present but suboptimal, or missing where it's expected|
| `bad`   | Header missing where its absence is a security regression    |
| `info`  | Header missing but absence is acceptable for this site type  |

The per-header verdicts feed into a letter grade computed from
the warn / bad counts — A for clean, F for a wall of bads. The
goal is *one screen, one decision*: do I need to look closer, or
is this baseline-clean and I can move on?

## What it answers

**Defender:** *"Is my site's transport-security posture
baseline-clean?"* Run `headers` against every public host you
own once a quarter and the report tells you in 30 seconds where
the regressions are. The most common drift findings: an HSTS
header that lost `includeSubDomains` during an Nginx config
refresh, a CSP that grew `unsafe-inline` during a frontend
migration, a missing `Permissions-Policy` after an upgrade
that didn't carry forward the old header set.

**Recon (authorized testing only):** *"How seriously does this
target take its hardening?"* The letter grade is a rough proxy
for security maturity. A-graded sites typically employ security
engineering as a discipline; F-graded sites typically don't.
That's not a vulnerability assessment — an F-grade site might
be perfectly secure in ways `headers` can't measure — but it
correlates well with what deeper audits eventually find.

**Investigation:** *"Did the security headers change after a
deployment?"* Snapshot the JSON output, deploy, re-snapshot,
diff. Header regressions are common during refactors and rarely
caught by functional tests. The before/after diff catches them
immediately.

## How it works

### The seven headers

Cathedral picks seven from the larger set of response headers
that *could* be relevant. Each addresses a specific class of
attack or information leak:

| Header                      | Mitigates                                              |
|-----------------------------|--------------------------------------------------------|
| `Strict-Transport-Security` | HTTPS downgrade attacks (forced HTTP via active MITM)  |
| `Content-Security-Policy`   | Cross-site scripting (XSS) via untrusted script origins|
| `X-Frame-Options`           | Clickjacking via iframe embedding                      |
| `X-Content-Type-Options`    | MIME-sniffing confusion attacks                        |
| `Referrer-Policy`           | URL leakage to cross-origin destinations               |
| `Permissions-Policy`        | Unrestricted access to camera/mic/geolocation/etc.    |
| `Cross-Origin-Opener-Policy`| Cross-origin process isolation (Spectre, side-channels)|

Two things *not* in this set, intentionally:

- **`X-XSS-Protection`** is deprecated. Chrome and Edge removed
  support in 2019, Firefox never honoured it, and the cases where
  it triggers are mostly net-harmful (it can introduce
  vulnerabilities of its own). Modern recommendation is to set it
  to `0` if anything, but presence/absence isn't a useful signal.
- **`Public-Key-Pins`** (HPKP) is also deprecated — universally
  removed from browsers between 2017 and 2020. Sites that still
  publish it are doing nothing operationally.

CORS headers (`Access-Control-Allow-Origin` and friends),
`Cache-Control` privacy attributes, and per-cookie attributes
(`HttpOnly`, `Secure`, `SameSite`) are all important but
*context-dependent* — grading them without knowing the
application's intent produces false positives. Those are out of
scope; for cookie auditing specifically, `cookies` (planned) is
the right tool.

### Grading rules per header

The eval function for each header is a small chunk of Go. The
HSTS check is representative:

```go
{
    Name: "Strict-Transport-Security",
    Eval: func(v, _ string) checkResult {
        if v == "" {
            return checkResult{"bad",
                "missing — clients can be downgrade-attacked"}
        }
        lower := strings.ToLower(v)
        if !strings.Contains(lower, "max-age") {
            return checkResult{"warn", "no max-age directive"}
        }
        notes := []string{}
        if strings.Contains(lower, "includesubdomains") {
            notes = append(notes, "subdomains")
        }
        if strings.Contains(lower, "preload") {
            notes = append(notes, "preload")
        }
        if len(notes) == 0 {
            return checkResult{"warn",
                "max-age set, but no includeSubDomains/preload"}
        }
        return checkResult{"good",
            "max-age + " + strings.Join(notes, "+")}
    },
},
```

The rules across all seven, summarised:

- **HSTS** — missing is bad (downgrade exposure). Present with
  `max-age` but no `includeSubDomains`/`preload` is warn (subdomain
  attacks still possible). Both directives is good.
- **CSP** — missing is bad (XSS mitigation absent). Present with
  `unsafe-inline` or `unsafe-eval` is warn (~half of XSS
  mitigation neutered). Present without those is good.
- **X-Frame-Options** — missing is warn (CSP `frame-ancestors`
  may compensate; we can't tell from this header alone). `DENY`
  or `SAMEORIGIN` is good. Anything else is warn.
- **X-Content-Type-Options** — missing is bad (MIME sniffing
  enabled). `nosniff` is good. Anything else is warn.
- **Referrer-Policy** — missing is warn (default behaviour leaks
  full URL cross-origin). Any value is good.
- **Permissions-Policy** — missing is warn. Any value is good.
- **COOP** — missing is *info* (only required for cross-origin
  isolation, which most sites don't need). Any value is good.

The grading deliberately doesn't try to be sophisticated. CSP
specifically has dozens of directives and configuration nuance —
a perfect CSP review would parse every directive, check source
lists, flag inline event handlers, and so on. Cathedral's check
is shallow: present and not-obviously-broken is good. For deeper
CSP analysis, a dedicated tool (Google's `CSP Evaluator`) is the
right reach.

### The letter grade

The roll-up is intentionally coarse:

```go
letter := "A"
switch {
case bad >= 3:
    letter = "F"
case bad >= 2:
    letter = "D"
case bad == 1:
    letter = "C"
case warn >= 3:
    letter = "B"
}
```

Five buckets, weighted toward bad-vs-warn distinction:

- **A** — zero bads, two or fewer warns. The site is
  baseline-clean.
- **B** — zero bads, three or more warns. Headers are
  configured but not optimally.
- **C** — one bad. A single material gap.
- **D** — two bads. Two material gaps.
- **F** — three or more bads. The baseline is genuinely
  missing.

The `info` grade (for COOP-absent cases) doesn't count toward
either bucket — sites that don't need cross-origin isolation
aren't penalised for omitting it.

The grade is a rough indicator, not a verdict. An A-graded site
can still be vulnerable to XSS through application logic; an
F-graded site can still be perfectly secure if its threat model
doesn't include the things the missing headers mitigate. Use the
grade as a *first signal*, not as a final answer.

### TLS auto-fallback

Same pattern as [`http`](http.md), [`recon`](recon.md), and
[`dirscan`](dirscan.md): strict verification first, retry with
`InsecureSkipVerify` on `x509:` errors, emit `tls_warning` for
the operator to see. Self-signed staging environments and
expired-cert legacy hosts are *findings* (worth seeing the
headers of) rather than reasons to refuse the request.

The `https:` field on the `response` event tracks the final URL
scheme after any redirects. A site that responds on `http://`
without redirecting to `https://` shows `https: no` and the line
renders in warn colour — distinct from "HTTPS works but headers
are missing", which is a different posture entirely.

## What Cathedral doesn't do

A few deliberate omissions:

- **CSP directive analysis.** Cathedral checks for
  `unsafe-inline` / `unsafe-eval` and otherwise treats CSP as
  binary. Full CSP analysis (source-list expansion, hashing,
  inline-handler detection, fallback-directive completeness)
  is a much larger problem; Google's `CSP Evaluator` is the
  dedicated tool.
- **Cookie attribute auditing.** `Set-Cookie` attributes
  (`HttpOnly`, `Secure`, `SameSite`, `Path`, `Domain`,
  `__Host-` / `__Secure-` prefixes) deserve their own check;
  they're out of scope here. `cookies` (planned) is the
  intended tool.
- **CORS posture.** `Access-Control-Allow-Origin: *` with
  credentials is a vulnerability; `Access-Control-Allow-Origin:
  https://trusted.example.com` is not. Distinguishing them
  requires application context Cathedral doesn't have.
- **TLS configuration assessment.** The cert-chain check is
  auto-fallback only; full cert/cipher-suite/protocol analysis
  is `ssl` (planned). For an immediate posture check, this and
  `ssl` together would form the cert+headers pair.
- **Multiple URLs.** One target per invocation. Iterate in the
  shell for portfolios.
- **Authenticated probing.** No headers added; no cookies sent.
  Some sites serve different security headers to authenticated
  vs unauthenticated requests — for those, use [`http`](http.md)
  with explicit cookies and grade the output manually.
- **HSTS preload-list verification.** The check sees the
  `preload` directive but doesn't confirm the domain is
  actually on the browsers' preload list. `https://
  hstspreload.org/` is the authoritative reference.
- **Per-route differences.** `headers` audits the *one* URL you
  give it. SPAs and CMSes sometimes serve different headers on
  different routes (`/admin` may be locked down where `/` isn't);
  audit each route of interest separately.

## Worked example

An A, a B, and an F.

### An A-grade hardened site

```
operator@cathedral:~$ headers https://acme-supplies.example
> auditing https://acme-supplies.example

[ server ]
  url     : https://acme-supplies.example/
  status  : 200
  server  : cloudflare
  https   : yes

[ headers ]
  [ ✓ ] Strict-Transport-Security    max-age + subdomains+preload
         max-age=63072000; includeSubDomains; preload
  [ ✓ ] Content-Security-Policy      policy in place
         default-src 'self'; script-src 'self' https://*.cloudflare.com; style-src 'self' …
  [ ✓ ] X-Frame-Options              SAMEORIGIN
         SAMEORIGIN
  [ ✓ ] X-Content-Type-Options       nosniff
         nosniff
  [ ✓ ] Referrer-Policy              strict-origin-when-cross-origin
         strict-origin-when-cross-origin
  [ ✓ ] Permissions-Policy           policy declared
         camera=(), microphone=(), geolocation=(), payment=()
  [ ✓ ] Cross-Origin-Opener-Policy   same-origin
         same-origin

summary  ·  7 good  ·  0 warn  ·  0 bad  ·  grade A
```

Every header configured. HSTS has the full triple (`max-age` +
`includeSubDomains` + `preload`) which means the domain is a
candidate for the browser preload list — once
`hstspreload.org` confirms it, the protection is global. CSP
doesn't use `unsafe-inline`, which is the difficult bar most
production sites can't clear without a JavaScript build that
moves inline handlers to event listeners. Permissions-Policy
explicitly disables four sensitive features. COOP is set to
`same-origin`, giving the page cross-origin isolation. This is
*the* posture sites aim for; in practice perhaps 5–10% of the
top-1M reach it.

### A typical commercial site (B)

```
operator@cathedral:~$ headers https://shop.acme-supplies.example
> auditing https://shop.acme-supplies.example

[ server ]
  url     : https://shop.acme-supplies.example/
  status  : 200
  server  : nginx
  https   : yes

[ headers ]
  [ ✓ ] Strict-Transport-Security    max-age + subdomains
         max-age=31536000; includeSubDomains
  [ ! ] Content-Security-Policy      uses unsafe-inline / unsafe-eval
         default-src 'self' 'unsafe-inline' 'unsafe-eval'; script-src 'self' 'unsafe-inline' …
  [ ✓ ] X-Frame-Options              SAMEORIGIN
         SAMEORIGIN
  [ ✓ ] X-Content-Type-Options       nosniff
         nosniff
  [ ! ] Referrer-Policy              missing — defaults leak full URL cross-origin
  [ ! ] Permissions-Policy           missing — features (camera/mic/geo) not restricted
  [ · ] Cross-Origin-Opener-Policy   missing — required only for cross-origin isolation

summary  ·  3 good  ·  3 warn  ·  0 bad  ·  grade B
```

Three good, three warn, no bads. The pattern is canonical:

- **HSTS is partial.** `includeSubDomains` is set but not
  `preload`, which is the most common in-between state — the
  operator decided HSTS was important but didn't commit to the
  irreversible preload step (preload is hard to undo once
  browsers cache it).
- **CSP exists but uses `unsafe-inline`/`unsafe-eval`.** The
  most common CSP shape on commercial sites — a CSP was added
  for compliance reasons but the codebase wasn't refactored to
  remove inline event handlers or `eval()`-based templating, so
  the unsafes are still in the policy. Removing them is a real
  engineering project.
- **Referrer-Policy and Permissions-Policy are missing.** Both
  are easy wins — neither requires application changes, just
  adding a header. Their absence on a B-graded site is
  typically just "nobody got around to it".

Letter grade B because no header is fully missing where it
should be present, but three are suboptimal.

### A site missing the basics (F)

```
operator@cathedral:~$ headers https://legacy-portal.acme-supplies.example
> auditing https://legacy-portal.acme-supplies.example

[ server ]
  url     : http://legacy-portal.acme-supplies.example/
  status  : 200
  server  : Apache/2.2.22 (Debian)
  https   : no

[ headers ]
  [ ✗ ] Strict-Transport-Security    missing — clients can be downgrade-attacked
  [ ✗ ] Content-Security-Policy      missing — XSS mitigation absent
  [ ! ] X-Frame-Options              missing — clickjacking exposure (CSP frame-ancestors may compensate)
  [ ✗ ] X-Content-Type-Options       missing — MIME sniffing enabled
  [ ! ] Referrer-Policy              missing — defaults leak full URL cross-origin
  [ ! ] Permissions-Policy           missing — features (camera/mic/geo) not restricted
  [ · ] Cross-Origin-Opener-Policy   missing — required only for cross-origin isolation

summary  ·  0 good  ·  3 warn  ·  3 bad  ·  grade F
```

Everything graded warn or bad, and the connection itself is
HTTP — `https: no` highlights the most fundamental issue. With
three bads (HSTS, CSP, XCTO all missing) and three warns
(XFO, Referrer-Policy, Permissions-Policy missing), the letter
grade is F. The Apache 2.2.22 banner (from the same target as
the [`recon`](recon.md) cookbook entry's downgrade example) is
end-of-life since 2017 — the missing security headers are
consistent with the overall infrastructure age.

This is the *finding* case: a portal exposed on plaintext HTTP
with no security headers, running an EOL Apache. Each finding
on its own is actionable; together they're a clear "this needs
attention" signal.

### A self-signed staging environment

```
operator@cathedral:~$ headers https://staging.acme-supplies.example -k
> auditing https://staging.acme-supplies.example
  ! TLS chain UNVERIFIED — continuing insecure
    x509: certificate signed by unknown authority

[ server ]
  url     : https://staging.acme-supplies.example/
  status  : 200
  server  : nginx
  https   : yes

[ headers ]
  [ ✓ ] Strict-Transport-Security    max-age + subdomains+preload
  [ ! ] Content-Security-Policy      uses unsafe-inline / unsafe-eval
  [ ✓ ] X-Frame-Options              SAMEORIGIN
  [ ✓ ] X-Content-Type-Options       nosniff
  [ ✓ ] Referrer-Policy              strict-origin-when-cross-origin
  [ ✓ ] Permissions-Policy           policy declared
  [ · ] Cross-Origin-Opener-Policy   missing — required only for cross-origin isolation

summary  ·  5 good  ·  1 warn  ·  0 bad  ·  grade A
```

The TLS warning fires because staging environments typically use
an internal CA that isn't in the system trust store. The strict
verification fails, Cathedral retries insecurely, and the audit
proceeds. The single warn (CSP `unsafe-inline`) is the only gap;
the letter grade still rounds to A because that's the threshold.
This is the *useful* finding pattern: staging-vs-production
header parity is verifiable, modulo the TLS chain.

## Output protocol

```
{"event":"start",       "target":"https://…"}
{"event":"tls_warning", "message":"x509: …"}                          # optional
{"event":"response",    "url":"…","status":N,"server":"…","https":true|false}
{"event":"header",      "name":"…","value":"…","grade":"good|warn|bad|info","note":"…"}  *7
{"event":"summary",     "good":N,"warn":N,"bad":N,"grade":"A|B|C|D|F"}
{"event":"error",       "message":"…"}
```

Pipe to extract the grade for many hosts:

```
$ for h in $(cat hosts.txt); do
    grade=$(headers "https://$h" -j |
      jq -r 'select(.event=="summary") | .grade')
    printf '%-40s %s\n' "$h" "$grade"
  done | sort -k2
acme-supplies.example                    A
api.acme-supplies.example                A
shop.acme-supplies.example               B
status.acme-supplies.example             B
docs.acme-supplies.example               C
legacy-portal.acme-supplies.example      F
```

Find only the bads across a portfolio:

```
$ for h in $(cat hosts.txt); do
    headers "https://$h" -j |
      jq -r --arg h "$h" \
        'select(.event=="header" and .grade=="bad") | "\($h)\t\(.name)\t\(.note)"'
  done
legacy-portal.acme-supplies.example  Strict-Transport-Security  missing — clients can be downgrade-attacked
legacy-portal.acme-supplies.example  Content-Security-Policy    missing — XSS mitigation absent
legacy-portal.acme-supplies.example  X-Content-Type-Options     missing — MIME sniffing enabled
old-redirect.acme-supplies.example   Strict-Transport-Security  missing — clients can be downgrade-attacked
```

Compare before-and-after a deployment:

```
$ headers https://prod.example.com -j > /tmp/headers-before.json
# deploy …
$ headers https://prod.example.com -j > /tmp/headers-after.json
$ diff <(jq -r 'select(.event=="header") | "\(.name) \(.value)"' /tmp/headers-before.json) \
       <(jq -r 'select(.event=="header") | "\(.name) \(.value)"' /tmp/headers-after.json)
```

## Limitations

- **One URL per invocation.** No portfolio mode; iterate in the
  shell (see jq recipes above).
- **Seven headers only.** CORS posture, cookie attributes,
  Cache-Control privacy, X-XSS-Protection (deprecated), HPKP
  (deprecated) are all out of scope. Some of these will land
  in dedicated tools (`cookies`, `ssl`).
- **Letter grade is coarse.** A/B/C/D/F doesn't capture nuance
  like "good CSP but suboptimal HSTS" vs "great HSTS but
  unsafe-inline CSP". Use the per-header verdicts for nuance;
  the letter is for sorting.
- **Shallow CSP analysis.** `unsafe-inline` / `unsafe-eval`
  detection only. For directive-level CSP review, Google's CSP
  Evaluator is the dedicated tool.
- **No HSTS-preload-list lookup.** The `preload` directive is
  detected; whether the domain is *actually* on the browser
  preload list isn't verified. Check `hstspreload.org`.
- **No CSP frame-ancestors compensation.** Missing
  `X-Frame-Options` is graded warn even if a CSP
  `frame-ancestors` directive provides equivalent protection.
  The compensation requires CSP parsing, which Cathedral doesn't
  do.
- **No HTTP/3.** ALPN negotiates HTTP/2 over TLS; QUIC is not
  supported.
- **Default User-Agent.** Sites that serve different headers to
  different UAs may behave unexpectedly. Override is not
  currently exposed.
- **Single GET on `/`.** SPAs and routed apps that serve
  different headers per-route need per-route audits.

## Authorized use

`headers` is **passive inspection**. One GET request to a public
endpoint, no enumeration, no body-content fetching beyond what
the server returns. The request pattern is indistinguishable
from a normal browser hit, modulo the User-Agent string. Risk
profile is the same as visiting the page once.

Two notes worth attaching:

**You're the source IP.** Single request, but it's logged. For
high-volume portfolio sweeps (hundreds of hosts), the aggregate
visibility may be higher than expected — route through an
authorised proxy for engagement-bound auditing.

**The User-Agent identifies the tool.** `cathedral-headers/0.1`
is the default UA. Sites with WAFs may treat that differently
from a browser UA; the difference rarely matters for single
inspections but is worth knowing about.

## Further reading

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/) — the canonical baseline `headers` grades against
- [RFC 6797 — HTTP Strict Transport Security (HSTS)](https://www.rfc-editor.org/rfc/rfc6797) — HSTS spec
- [W3C — Content Security Policy Level 3](https://www.w3.org/TR/CSP3/) — the current CSP spec
- [MDN — Permissions-Policy](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy) — feature-policy directives
- [hstspreload.org](https://hstspreload.org/) — HSTS preload list submission + verification
- [Google CSP Evaluator](https://csp-evaluator.withgoogle.com/) — deep CSP analysis (complement to Cathedral's shallow check)
- Related Cathedral commands: [`http`](http.md) (single-endpoint deep inspection; verbatim headers),
  [`recon`](recon.md) (breadth-first sweep that also surfaces these headers),
  [`tech`](tech.md) (full-stack fingerprinting),
  [`ssl`](ssl.md) *(planned — TLS certificate and cipher posture)*,
  [`cookies`](cookies.md) *(planned — Set-Cookie attribute audit)*
