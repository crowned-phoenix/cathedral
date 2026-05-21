---
title: cookies — Set-Cookie attribute audit
command: cookies
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [headers, http, recon, waf, tech]
---

# `cookies` — Set-Cookie attribute audit

`cookies` reads every `Set-Cookie` header a URL returns and grades
each cookie against the modern hardening baseline: `Secure`,
`HttpOnly`, `SameSite`, and the `__Host-` / `__Secure-` name
prefixes. Where [`headers`](headers.md) audits the response
headers as a set, `cookies` is the *per-cookie* drill-down — one
row per `Set-Cookie`, one column of flags per cookie, one verdict
per row, one summary at the bottom.

Cookie misconfiguration is a long tail of subtle posture issues —
a session token without `HttpOnly` is exposed to XSS, a session
token without `SameSite` is exposed to CSRF, a session token
without `Secure` leaks over any plaintext subrequest. None of
these are visible from `Cf-Ray` headers or letter grades on the
overall site posture; they live one layer down, on the cookies
themselves. `cookies` makes them visible.

```
cookies https://github.com
cookies acme-supplies.example                # https:// auto-prefixed
cookies https://app.acme-supplies.example/login
```

## What it does

For a single URL, Cathedral issues one GET request and inspects
every `Set-Cookie` header on the response. Each cookie is parsed
and the following attributes are checked:

| Attribute            | What it does                                              |
|----------------------|-----------------------------------------------------------|
| `Secure`             | cookie sent only over HTTPS                               |
| `HttpOnly`           | cookie inaccessible to JavaScript (`document.cookie`)     |
| `SameSite`           | cross-site request inclusion (`Strict` / `Lax` / `None`)  |
| `__Host-` prefix     | enforces `Secure`, `Path=/`, no `Domain` (strongest)      |
| `__Secure-` prefix   | enforces `Secure` (weaker, easier to deploy)              |
| Expiry               | session, fixed duration, or deleted                       |

Each cookie collects an issue list and gets a per-row grade
(good / warn / bad), then the summary aggregates totals. The
grading is coarse on purpose — zero issues is good, one or two
warn, three or more bad. Names matter too: cookies starting with
`csrf`/`xsrf` or `_ga`/`_gid` are exempt from the "missing
HttpOnly" check (CSRF tokens need to be readable from JavaScript,
GA cookies need to be readable for the GA script).

## What it answers

**Defender:** *"Are my session cookies configured the way they
should be?"* The cookies behind a login form are the highest-
stakes credentials in the application — every browser request
sends them; an attacker who reads or fixes them has the
user's session. Running `cookies` against your authenticated
endpoints surfaces the gaps that pen tests would otherwise find
later: missing `HttpOnly` on a session cookie, missing
`SameSite` on a CSRF-protection cookie, `Domain=.example.com`
on something that should be host-scoped only.

**Recon (authorized testing only):** *"What cookie posture is
this app running?"* The cookie flags give a quick picture of
how seriously the team takes session hygiene. Modern apps with
`__Host-`-prefixed session cookies on `Secure`+`HttpOnly`+
`SameSite=Strict` are doing the work; apps with bare session
cookies on `Set-Cookie: SESSION=abc; Path=/` are not.

**Investigation:** *"Did the cookie posture change?"* Snapshot
the JSON output, deploy, re-snapshot, diff. A session token that
lost `HttpOnly` during a framework upgrade is an instantly
actionable finding; the diff catches it.

## How it works

### The cookie attributes that matter

A `Set-Cookie` header looks like:

```
Set-Cookie: session=abc123; Path=/; Domain=example.com;
            Secure; HttpOnly; SameSite=Lax; Max-Age=86400
```

Five flags after the `name=value` pair can change everything
about how the cookie behaves:

- **`Secure`** — the browser only sends this cookie on HTTPS
  connections. Without it, any plaintext subrequest (an HTTP
  redirect, mixed-content image, downgrade-attacked load
  balancer) will leak the cookie in the clear. RFC 6265bis.
- **`HttpOnly`** — JavaScript cannot read this cookie via
  `document.cookie`. An XSS payload running in the user's
  browser can't exfiltrate it. The single most important
  attribute on session tokens.
- **`SameSite`** — controls whether the cookie is sent on
  cross-site requests. Three values:
  - **`Strict`** — never sent cross-site. Strongest CSRF
    defence; breaks some legitimate flows (a link from an email
    that loads the site won't carry the existing session, so
    the user appears logged out on first arrival).
  - **`Lax`** — sent only on top-level cross-site GET
    navigations. The browser default since Chrome 80 (2020).
    Good middle ground; protects against CSRF for state-
    changing methods while preserving navigation UX.
  - **`None`** — sent on every cross-site request. Required
    for embedded third-party use cases (e.g. an SSO iframe).
    Must be paired with `Secure` or the browser ignores the
    `None`.
- **`__Host-` prefix** — browsers refuse to set a cookie whose
  name starts with `__Host-` unless it also has `Secure`,
  `Path=/`, and *no* `Domain` attribute. The prefix is a
  *name-based contract*: a server that tries to weaken any of
  those constraints can't even set the cookie. Defends against
  subdomain-takeover and path-override attacks.
- **`__Secure-` prefix** — browsers refuse to set a
  `__Secure-`-named cookie without `Secure`. Weaker than
  `__Host-` (it doesn't pin Path or Domain) but easier to
  deploy without breaking subdomain flows.

The expiry is implicit: cookies without `Max-Age` or `Expires`
are *session cookies* (deleted on browser close); cookies with
either get human-readable formatting (`30d`, `2y`, `session`).
A `Max-Age` ≤ 0 means the cookie is being deleted in this
response.

### Per-cookie audit rules

```go
issues := []string{}
if https && !c.Secure {
    issues = append(issues, "missing Secure")
}
if !c.HttpOnly && !looksLikeClientSideCookie(c.Name) {
    issues = append(issues, "missing HttpOnly")
}
if a.SameSite == "" {
    issues = append(issues, "SameSite unset")
}
if a.SameSite == "None" && !c.Secure {
    issues = append(issues, "SameSite=None requires Secure")
}
if a.Prefix == "__Host-" {
    if !c.Secure || c.Path != "/" || c.Domain != "" {
        issues = append(issues, "violates __Host- prefix rules")
    }
}
if a.Prefix == "__Secure-" && !c.Secure {
    issues = append(issues, "__Secure- prefix without Secure flag")
}
```

The rules tier by severity:

- **Always issues**, regardless of cookie purpose:
  - SameSite unset
  - SameSite=None without Secure (browser ignores it anyway)
  - __Host- prefix violations
  - __Secure- prefix without Secure flag
- **Conditional on context**:
  - missing Secure flags only when the page itself is HTTPS
    (a plain-HTTP page can't honour Secure regardless of how
    it's set)
  - missing HttpOnly is suppressed for cookies whose names
    suggest they're meant to be readable from JavaScript

### The HttpOnly heuristic (CSRF and analytics)

Not every cookie *should* have `HttpOnly`. The double-submit-
cookie CSRF protection pattern requires the server to set a
CSRF token in a cookie *and* have the client-side JavaScript
read that token and include it in a request header — the
browser sending the cookie plus the JS sending the header
proves the request came from a page on the same origin (an
attacker on a different origin can't read the cookie). For
that pattern to work, the CSRF cookie must be JS-readable, i.e.
*not* `HttpOnly`.

Similarly, Google Analytics' `_ga` and `_gid` cookies are read
by GA's JavaScript to construct tracking calls; if marked
`HttpOnly`, GA can't see its own cookies.

Cathedral's heuristic:

```go
func looksLikeClientSideCookie(name string) bool {
    lower := strings.ToLower(name)
    return strings.Contains(lower, "csrf") ||
        strings.Contains(lower, "xsrf") ||
        strings.HasPrefix(lower, "_ga") ||
        strings.HasPrefix(lower, "_gid")
}
```

Names containing `csrf` or `xsrf`, or starting with `_ga` or
`_gid`, are exempt from the missing-HttpOnly issue. The
heuristic is necessarily approximate — a cookie named
`__Host-token` that's actually a CSRF token would still ding
for missing HttpOnly under these rules, and a cookie named
`xsrf_token` that's actually a session token would skip the
HttpOnly check it should have failed. But for the common cases
(Django's `csrftoken`, Rails' `_csrf_token`, every GA
deployment's `_ga`/`_gid`/`_gat`) the heuristic is right
~95% of the time.

### `__Host-` and `__Secure-` prefixes

The prefix system is one of the most underused defences in
modern cookie hygiene. The mechanics:

- **`__Host-cookiename`** — the browser refuses to set this
  cookie *unless* the `Secure` attribute is present, `Path=/`
  is set, and `Domain` is *not* set. The `Domain`-absent rule
  means the cookie is host-scoped (only sent to the exact
  origin that set it, not to subdomains). The `Path=/` rule
  means it's sent for every path on that host, not just a
  specific subtree.
- **`__Secure-cookiename`** — the browser refuses unless
  `Secure` is present. Domain and Path are unconstrained;
  this is the looser cousin.

The defence is *namespace-based*: a server can't accidentally
set a `__Host-` cookie without the required constraints,
because the browser will drop the `Set-Cookie` entirely. The
prefix is the contract; the cookie either follows it or
doesn't exist. For session-token cookies on apps that
don't share state across subdomains, `__Host-` is the right
default.

Cookies *with* the prefix but *violating* the rules (rare —
typically a misconfiguration) are flagged explicitly:
"violates __Host- prefix rules" or "__Secure- prefix without
Secure flag". These shouldn't happen in production but
sometimes do during development handoffs.

### Grading: 0 / 1–2 / 3+

```go
switch {
case len(issues) == 0:
    a.Grade = "good"
case len(issues) >= 3:
    a.Grade = "bad"
default:
    a.Grade = "warn"
}
```

Coarse on purpose. A session cookie with one issue (say, just
"SameSite unset") is warn; an analytics cookie with the same
issue is also warn. The grade doesn't distinguish severity per
issue, only count.

The summary at the bottom aggregates: total cookies, count of
good / warn / bad. A site with one session cookie graded bad
and three analytics cookies graded good is "one bad" in the
summary — the cookie that matters is the one to look at
first.

### TLS auto-fallback

Same pattern as elsewhere — strict first, retry insecure on
`x509:` errors, emit `tls_warning` once. Self-signed staging
environments still get audited; the warning surfaces the
caveat.

## What Cathedral doesn't do

A few deliberate omissions:

- **Redirect-chain cookies.** Cathedral inspects only the
  cookies set on the *final* response. A login page that
  sets a session cookie on the POST handler and then 302s to
  `/dashboard` would have the session cookie on the redirect
  response — but if `cookies` is pointed at `/dashboard`
  directly, it sees a different cookie set (or no cookies at
  all). For full-flow auditing, follow the chain manually
  with [`http`](http.md) and inspect each response.
- **JavaScript-set cookies.** Cookies set by client-side
  `document.cookie =` calls are invisible to a server-side
  HTTP client. Cathedral sees only what `Set-Cookie` headers
  declare. For client-set cookies, browser devtools is the
  right reach.
- **Authenticated cookie sets.** No way to pass an existing
  session to see how it gets refreshed or augmented. Cathedral
  only sees the *unauthenticated* cookies — login forms,
  CSRF tokens, anonymous-user analytics. For
  authenticated cookie auditing, use [`http`](http.md) with
  an explicit `-h Cookie:` header and inspect the response.
- **Cookie usage patterns.** When and where each cookie gets
  sent is determined by the browser at runtime, not by static
  inspection. The audit covers *how* the cookie was declared,
  not *how* it gets used.
- **Per-cookie security implications.** Cathedral flags
  missing `HttpOnly` regardless of whether the cookie is a
  session token or an A/B-test bucket assignment. The
  heuristic exempts a few common patterns (CSRF, GA) but
  doesn't try to classify every cookie's purpose.
- **Domain / Path constraints beyond prefix rules.** A cookie
  with `Domain=.example.com` (sent to every subdomain) might
  be a posture issue for security-sensitive cookies but is
  fine for analytics. Cathedral doesn't grade on Domain/Path
  outside the prefix rules.

## Worked example

A modern app with strong cookie hygiene, a typical mixed bag,
and a finding case.

### A modern hardened app

```
operator@cathedral:~$ cookies https://app.acme-supplies.example
> fetching https://app.acme-supplies.example
  url    : https://app.acme-supplies.example/
  https  : yes

[ cookies ]
  [ ✓ ] __Host-session              Secure HttpOnly SameSite=Strict [__Host-]   exp: session
  [ ✓ ] __Secure-csrf-token         Secure SameSite=Strict [__Secure-]          exp: 1.0h
  [ ✓ ] _ga                         (no flags)                                  exp: 2.0y
  [ ✓ ] _gid                        (no flags)                                  exp: 24h

summary  ·  4 total  ·  4 good  ·  0 warn  ·  0 bad
```

The session cookie is named with the `__Host-` prefix — the
browser will only accept it with `Secure`, `Path=/`, and no
`Domain`. The CSRF token uses `__Secure-` (less strict, since
CSRF tokens are often subdomain-scoped) and is marked
`SameSite=Strict` to prevent any cross-site inclusion. Both
have `HttpOnly` only where appropriate — the session token is
HttpOnly (browsers' JS can't read it); the CSRF token is *not*
HttpOnly (the page's JS reads it to populate the X-CSRF-Token
header on AJAX requests, the canonical double-submit-cookie
pattern). The `_ga` and `_gid` cookies are exempt from the
HttpOnly check; their no-flags state is normal for analytics.

This is the *good* shape for cookie hygiene. Reproducing it
across an org's apps is a real engineering project, but the
end state is unambiguously correct.

### A typical mixed bag

```
operator@cathedral:~$ cookies https://shop.acme-supplies.example
> fetching https://shop.acme-supplies.example
  url    : https://shop.acme-supplies.example/
  https  : yes

[ cookies ]
  [ ! ] session                     Secure HttpOnly                             exp: 30d
         · SameSite unset
  [ ! ] cart                        Secure HttpOnly                             exp: 7d
         · SameSite unset
  [ ! ] csrf_token                  Secure                                      exp: 1.0h
         · SameSite unset
  [ ✓ ] _ga                         (no flags)                                  exp: 2.0y

summary  ·  4 total  ·  1 good  ·  3 warn  ·  0 bad
```

The three application cookies all have `Secure` and (where
appropriate) `HttpOnly`, but none of them set `SameSite`.
This is the *pre-2020* default: browsers historically treated
unset SameSite as "send on all cross-site requests", which is
the wide-open CSRF posture. Chrome 80 (Feb 2020) changed the
default to treat unset as `Lax`, mitigating much of the risk —
but the cookies themselves are still ungraded. Setting
`SameSite=Lax` explicitly on each would move all three to
good. (Setting `Strict` on the session would be even stronger
but might break some cross-site link-from-email flows.)

The `csrf_token` is correctly *not* HttpOnly (Cathedral
exempts it from the check via the name heuristic), so that
isn't flagged.

### A finding case

```
operator@cathedral:~$ cookies https://legacy-portal.acme-supplies.example
> fetching https://legacy-portal.acme-supplies.example
  url    : http://legacy-portal.acme-supplies.example/
  https  : no

[ cookies ]
  [ ✗ ] PHPSESSID                   (no flags)                                  exp: session
         · missing HttpOnly
         · SameSite unset
  [ ! ] tracking                    HttpOnly                                    exp: 1.0y
         · SameSite unset
  [ ✗ ] admin_token                 (no flags)                                  exp: 30d
         · missing HttpOnly
         · SameSite unset

summary  ·  3 total  ·  0 good  ·  1 warn  ·  2 bad
```

The findings are immediate. The connection isn't HTTPS at all
(`https: no` on the response — Cathedral suppresses the
"missing Secure" check on plain HTTP because the browser can't
honor it regardless, but the absence of HTTPS is itself the
finding). Both `PHPSESSID` and `admin_token` lack `HttpOnly` —
on a site without HTTPS, that means any XSS payload (or any
network observer) can read the session token. Neither sets
`SameSite`, so CSRF protection relies entirely on the
browser's default-Lax behaviour.

The two-bad summary is the right characterisation: the
session and admin cookies are the credentials of the
application, and both are configured below the modern minimum.

### A misconfigured prefix

```
operator@cathedral:~$ cookies https://app.example.com
> fetching https://app.example.com
  url    : https://app.example.com/
  https  : yes

[ cookies ]
  [ ! ] __Host-session              HttpOnly SameSite=Strict [__Host-]          exp: session
         · violates __Host- prefix rules
  [ ✓ ] _ga                         (no flags)                                  exp: 2.0y

summary  ·  2 total  ·  1 good  ·  1 warn  ·  0 bad
```

The session cookie *uses* the `__Host-` prefix but doesn't
satisfy the contract: it's missing `Secure`. In reality, a
browser receiving this `Set-Cookie` header would simply refuse
to store the cookie at all — the user would land on the next
page with no session. The "violates __Host- prefix rules"
issue is Cathedral's way of saying *this cookie is broken in
production*. Likely root cause: the dev team added the prefix
during a security-hardening pass without verifying the
attributes; the broken cookies have probably been silently
failing for users on certain browsers.

This is exactly the kind of finding that only surfaces by
auditing cookies specifically — it doesn't appear in
[`headers`](headers.md), in [`tech`](tech.md), or in any
external scanner that grades on overall site posture.

## Output protocol

```
{"event":"start",       "target":"…"}
{"event":"tls_warning", "message":"x509: …"}                                # optional
{"event":"response",    "url":"…","status":N,"https":true|false}
{"event":"cookie",      "name":"…","domain":"…","path":"…",
                        "secure":true|false,"http_only":true|false,
                        "same_site":"Strict|Lax|None|","prefix":"__Host-|__Secure-|",
                        "expires_in":"…","value_len":N,
                        "issues":["…"],"grade":"good|warn|bad"}              *per cookie
{"event":"summary",     "total":N,"good":N,"warn":N,"bad":N}
{"event":"done"}
{"event":"error",       "message":"…"}
```

Extract just the bad cookies across a portfolio:

```
$ for h in $(cat hosts.txt); do
    cookies "https://$h" -j |
      jq -r --arg h "$h" \
        'select(.event=="cookie" and .grade=="bad") |
         "\($h)\t\(.name)\t\(.issues | join(\", \"))"'
  done
legacy-portal.example.com  PHPSESSID     missing HttpOnly, SameSite unset
legacy-portal.example.com  admin_token   missing HttpOnly, SameSite unset
old-shop.example.com       SESSION       missing Secure, missing HttpOnly, SameSite unset
```

Find session cookies that aren't HttpOnly:

```
$ for h in $(cat hosts.txt); do
    cookies "https://$h" -j |
      jq -r --arg h "$h" \
        'select(.event=="cookie"
                and (.name | test("session|sess|sid|auth"; "i"))
                and .http_only==false) |
         "\($h)\t\(.name)"'
  done
```

Compute cookie-hygiene summary across a portfolio:

```
$ for h in $(cat hosts.txt); do
    cookies "https://$h" -j |
      jq -r --arg h "$h" 'select(.event=="summary") |
         "\($h)\t\(.total)\t\(.good)\t\(.warn)\t\(.bad)"'
  done
```

## Limitations

- **One URL, one response.** No redirect-chain following, no
  authenticated cookie sets.
- **No JavaScript-set cookies.** `document.cookie =` calls
  are invisible to a server-side HTTP client.
- **HttpOnly heuristic is approximate.** Cookies named with
  `csrf` / `xsrf` / `_ga` / `_gid` are exempt; everything else
  gets the check. False positives and negatives both possible
  for unusual naming.
- **No severity per issue.** "Missing HttpOnly" on a session
  cookie is the same issue-count as "SameSite unset" on an
  analytics cookie; the grading is by issue count, not weight.
- **No domain-attribute analysis.** A cookie with
  `Domain=.example.com` (subdomain-broadcast) might be a
  finding for security-sensitive cookies but is fine for
  analytics. Cathedral doesn't grade on Domain/Path beyond
  the prefix rules.
- **TLS auto-fallback hides cert errors.** Self-signed certs
  are silently tolerated with one `tls_warning`.
- **Default User-Agent.** Sites that serve different cookies
  to different UAs may produce unexpected output.
- **Single GET on `/` only.** SPAs and authenticated apps that
  set cookies on specific routes need per-route audits.

## Authorized use

`cookies` is **passive inspection**. One GET request, no
enumeration. Risk profile matches [`headers`](headers.md) —
indistinguishable from a normal browser hit, modulo the User-
Agent string. No specific authorization needed beyond the
"don't probe what you can't" baseline.

One note worth attaching: the *output* of `cookies` may
include session token values (in the `value_len` field —
length only, never the contents) and cookie names that
themselves reveal implementation choices. If you're recording
output for a public report, double-check that nothing in the
JSON event stream leaks information about the target's
auth scheme that you didn't mean to share.

## Further reading

- [RFC 6265 — HTTP State Management Mechanism](https://www.rfc-editor.org/rfc/rfc6265) — the canonical cookie spec
- [draft-ietf-httpbis-rfc6265bis — Cookies: HTTP State Management Mechanism](https://datatracker.ietf.org/doc/draft-ietf-httpbis-rfc6265bis/) — the modernised spec that introduces SameSite and prefixes
- [OWASP — HTTP Strict Transport Security and Cookies](https://owasp.org/www-community/controls/SecureCookieAttribute) — cookie attribute guidance
- [MDN — Using HTTP cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies) — browser-side cookie behaviour
- [SameSite cookies explained](https://web.dev/articles/samesite-cookies-explained) — Chrome team writeup on the 2020 default change
- Related Cathedral commands: [`headers`](headers.md) (security-header audit — complements per-cookie audit at the response level),
  [`http`](http.md) (single-endpoint inspection with explicit headers and cookies),
  [`recon`](recon.md) (breadth-first HTTP probe; surfaces `Set-Cookie` as one of the interesting headers),
  [`waf`](waf.md) (some WAFs set their own tracking cookies — `cookies` surfaces them),
  [`tech`](tech.md) (full-stack fingerprinting — uses cookies as fingerprints)
