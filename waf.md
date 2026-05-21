---
title: waf — Web Application Firewall fingerprinting
command: waf
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: medium
last-updated: 2026-05-20
related: [headers, tech, recon, http, dirscan]
---

# `waf` — Web Application Firewall fingerprinting

`waf` answers *"is there a WAF in front of this site, and which
one?"* by sending two requests — a baseline GET and a probe GET
carrying an obvious-but-harmless attack pattern — and matching
the responses against fingerprints for fourteen common
WAF/CDN-WAF products. The two-request design distinguishes WAFs
that are *present* (CDN-WAF combos like Cloudflare always
announce themselves) from WAFs that are *active* (returning 403
on the probe specifically, with reference-number error pages or
WAF-specific cookies in the response).

Knowing what's in front of a target shapes everything that
follows. Cloudflare in passive-cache mode behaves differently
from Cloudflare with Bot Fight on; AWS WAF with managed
rule-sets blocks different patterns than an unconfigured one;
Akamai's Bot Manager fingerprints the client browser in ways
that fail for `curl` requests. `waf` is the *first reach* on a
hardened target — the lookup that tells you whether the rest of
your toolkit will pass through cleanly.

```
waf https://target.example.com
waf acme-supplies.example                # https:// auto-prefixed
```

## What it does

For one URL, Cathedral issues:

1. **A baseline GET** to the bare target URL. The response
   headers, cookies, and body are matched against every
   fingerprint in the table.
2. **A probe GET** to the same URL with `?_waf=<payload>`
   appended (or `&_waf=…` if the URL already has a query
   string). The payload is the deliberately-obvious string
   `<script>alert(1)</script> UNION SELECT * FROM users WHERE
   1=1` — a syntactically blatant XSS-plus-SQLi pattern that
   any tuned WAF will flag.

Each response is independently fingerprinted. A match on the
baseline alone means *"a WAF/CDN is present"*; a match on the
probe specifically means *"the WAF actively blocked or modified
the response"*. The probe is considered blocked when its
response status is ≥ 400 but not 404 — the 404 exception keeps
"this query param doesn't exist on this route" from being
counted as a WAF response.

| Element                | Default                                        |
|------------------------|------------------------------------------------|
| Method                 | GET, twice (no override)                       |
| Scheme                 | `https://` auto-prefixed                       |
| Timeout                | 12 s per request                               |
| TLS verification       | strict, with auto-fallback on `x509:` errors   |
| User-Agent             | `cathedral-waf/0.1`                            |
| Body cap               | 256 KB per response                            |

## What it answers

**Defender:** *"Does our WAF actually fire on the payload it's
supposed to fire on?"* The probe is the simplest possible
positive control — if `waf` against your own host reports
`probe ... [BLOCKED]` with your WAF named, the protection chain
is intact. If the probe sails through with `status 200` despite
the obvious payload, something in the WAF chain (rule set,
managed-rule subscription, recently-changed config) is no longer
firing.

**Recon (authorized testing only):** *"What's in front of this
target?"* Knowing whether you're punching at the origin or at a
CDN-WAF in front of one changes the engagement shape entirely.
A Cloudflare-fronted target requires different posture than a
raw-origin host. The vendor name tells you what defences are
deployed; the *active vs passive* distinction tells you whether
those defences are reacting.

**Investigation:** *"Did the WAF posture change?"* New WAF
deployments and removals are usually invisible from outside
(security teams don't typically announce them) but appear
immediately in `waf` output. A target that was passive-CDN-only
last quarter and now blocks the probe has had a WAF turned on
in between.

## How it works

### The two-phase probe

A passive observation (just looking at headers and cookies) is
enough to detect CDN-WAF products that always announce
themselves — Cloudflare emits `Cf-Ray` on every response,
Akamai sets `Server: AkamaiGHost`, Fastly sets
`X-Fastly-Request-Id`. But many of those products also operate
in modes where the *WAF features* aren't activated — they're
just acting as caching CDNs. A baseline detection doesn't
distinguish "Cloudflare is in front" from "Cloudflare is in
front and actively filtering".

The active probe forces the question:

```go
const probeQuery = `<script>alert(1)</script> UNION SELECT * FROM users WHERE 1=1`
```

A WAF with default rule-sets enabled blocks this on sight. The
response Cathedral receives carries the WAF's distinctive 403
error page (with reference number, branded "Access Denied",
WAF-specific cookies). A WAF in monitor-only mode lets it
through but may log it; from the client's perspective it looks
the same as no WAF. A WAF that's been bypassed by a previous
attack and is no longer responding to anything also looks the
same.

The probe is *deliberately obvious*. Stealth probes are out of
scope — Cathedral isn't trying to evade detection, it's trying
to *trigger* it. Real evasion is a category of its own
(rule-discovery, payload obfuscation, header-based bypasses)
and lives in deeper offensive tooling, not in fingerprinting.

### The fingerprint table

Fourteen entries, each with four possible match dimensions:

```go
type wafSig struct {
    Name      string
    HeaderEq  map[string]*regexp.Regexp // header → regex on value
    HasHeader []string                  // header presence (any value)
    Cookie    *regexp.Regexp            // cookie name regex
    Body      *regexp.Regexp            // body substring regex
}
```

Any one match is enough — fingerprints aren't required to fire
on all dimensions. The Cloudflare signature, as a representative
example:

```go
{
    Name:      "Cloudflare",
    HeaderEq:  map[string]*regexp.Regexp{"Server": r(`(?i)cloudflare`)},
    HasHeader: []string{"Cf-Ray", "Cf-Cache-Status"},
    Cookie:    r(`(?i)^__cf_(?:bm|chl)|^cf_clearance$`),
    Body:      r(`(?i)Attention Required! \| Cloudflare|cloudflare-nginx|cf-error-details`),
},
```

Four ways to identify a Cloudflare response: `Server:
cloudflare` header value, presence of `Cf-Ray` or
`Cf-Cache-Status` header, a `__cf_bm` / `cf_clearance` cookie,
or the canonical "Attention Required!" body string from the
block page. Any single match flags Cloudflare; all four
together raise confidence but don't change the outcome.

The covered products span three categories:

- **CDN-WAFs** (always in path, may or may not be filtering):
  Cloudflare, AWS WAF / CloudFront, Akamai, Fastly, Imperva /
  Incapsula, Azure Front Door, StackPath.
- **Inline / appliance WAFs** (specific to an application or
  data centre): F5 BIG-IP, FortiWeb, Barracuda, Sucuri,
  ModSecurity.
- **Plugin-style WAFs** (WordPress in particular): Wordfence,
  Sucuri CloudProxy.

The long tail beyond these fourteen — Citrix NetScaler, Radware,
DotDefender, dozens of regional / vertical / cloud-specific
products — isn't covered. The fourteen handle ~90% of WAF
deployments encountered in the wild; for the rest, the absence
of a match isn't proof of "no WAF", just "no fingerprint we
recognise".

### The detection signal: baseline vs probe

The output distinguishes the two phases explicitly:

```go
for n := range baseDetections { all[n] = false }   // baseline only
for n := range probeDetections { all[n] = true }   // reacted on probe
```

The `on_probe: true` case is the stronger signal — the WAF
actively responded to the malicious payload, which is what a
WAF is *for*. The `on_probe: false` case (baseline match, no
probe reaction) typically means the CDN-WAF is in path but the
WAF features aren't fully enabled, or the payload doesn't match
the WAF's current rule set, or the WAF runs in monitor-only
mode that logs without blocking.

For Cloudflare specifically the distinction is meaningful:
*every* Cloudflare-fronted site shows the Cloudflare
fingerprint on baseline (the `Cf-Ray` header is universal). But
only sites with the WAF feature actually enabled show the
probe block. The two-phase output lets you tell.

### TLS auto-fallback

Same pattern as elsewhere — strict first, retry insecure on
`x509:` errors, emit `tls_warning` once. Self-signed staging
environments and expired-cert legacy hosts still get probed;
the output records that the chain wasn't verified.

### What the probe doesn't try

Three deliberate non-attempts:

- **Header-based attacks.** The probe goes in the URL query
  string only. WAFs that watch specific request headers
  (`X-Forwarded-For` injection, `User-Agent` bypasses, custom
  application headers) may not see anything malicious.
- **Body-based attacks.** GET-only, no POST body. WAFs tuned
  for POST payloads (form submissions, JSON API bodies) may not
  fire.
- **Multiple variants.** One probe, one payload. WAFs that pass
  XSS but block SQLi (or vice versa) will produce ambiguous
  signal. The combined payload is deliberately blatant for both
  classes — most tuned WAFs catch *something* — but a more
  rigorous test would probe each class separately.

The single-payload single-query design is intentional. The goal
is fingerprinting, not bypass; for thorough WAF rule discovery,
dedicated tools (`wafw00f`, `lightbulb-framework`) probe with
dozens of payloads across multiple injection points.

## What Cathedral doesn't do

A few deliberate omissions:

- **WAF bypass discovery.** Cathedral fingerprints WAFs; it
  doesn't try to evade them. Bypass research is a category of
  its own (rule-set enumeration, payload obfuscation,
  protocol-level tricks) and lives in dedicated tools.
- **Long-tail fingerprints.** Fourteen products is the
  practical-coverage minimum, not the comprehensive list.
  `wafw00f` carries ~150 signatures; if Cathedral's table
  misses, fall back to that.
- **Active rule-set enumeration.** Once a WAF is identified,
  knowing *which rules* are active is a deeper question that
  requires payload-by-payload probing. Out of scope here.
- **Authentication-aware probing.** No cookies, no auth headers.
  WAFs that behave differently for authenticated requests
  (e.g. higher rate limits, different rule sets) won't be
  characterised in their authenticated state.
- **Multiple probe variants.** One payload, one query
  parameter, one method. A WAF that blocks XSS in body but
  not in URL params (or vice versa) produces ambiguous signal.
- **Logging into a CSV/report.** The JSON event stream is the
  audit trail. For formal reports, pipe through jq.

## Worked example

A passive CDN, an active WAF, a no-WAF origin, and an aggressive
Imperva deployment.

### Passive CDN (Cloudflare, WAF features off)

```
operator@cathedral:~$ waf https://blog.acme-supplies.example
> probing https://blog.acme-supplies.example for WAF fingerprints

  baseline GET    status 200    matches: Cloudflare
  probe GET       status 200    matches: Cloudflare

  · WAF: Cloudflare  (present at baseline)

1 WAF fingerprint(s) matched.
```

Cloudflare is fingerprinted on both requests (the `Cf-Ray`
header is universal on Cloudflare-fronted traffic), but the
probe sailed through with 200. This is the *passive CDN*
pattern — Cloudflare's caching and DNS layer are in path, but
the WAF rule-set isn't actively filtering the obvious payload.
Common shapes that produce this: small sites on the
Cloudflare Free tier with the WAF feature not enabled, sites
that have explicitly placed the malicious query param on an
allowlist, or sites where the rule sensitivity is dialed down
to "obvious-only" excluding XSS.

For an attacker, this is the *good news* signal — Cloudflare
is in path but isn't actively defending; the work continues
much as it would on a raw origin.

### Active WAF (Cloudflare with WAF on)

```
operator@cathedral:~$ waf https://app.acme-supplies.example
> probing https://app.acme-supplies.example for WAF fingerprints

  baseline GET    status 200    matches: Cloudflare
  probe GET       status 403  [BLOCKED]    matches: Cloudflare

  · WAF: Cloudflare  (reacted to probe)

1 WAF fingerprint(s) matched.
```

Same Cloudflare presence on baseline, but the probe returned a
403 — the WAF rule-set caught the obvious payload. The body of
the 403 response carries Cloudflare's "Attention Required!"
block page (matched by the body regex). For the engagement
this is the *engaged-WAF* signal: subsequent enumeration needs
to account for the WAF's reaction posture.

### No WAF detected

```
operator@cathedral:~$ waf https://lab.acme-supplies.example
> probing https://lab.acme-supplies.example for WAF fingerprints

  baseline GET    status 200    matches: (none)
  probe GET       status 200    matches: (none)

no WAF detected (or fingerprint not in our table).
```

No fingerprint match on either request, no block on the probe.
This is a raw origin — the most permissive starting posture.
Note the qualifier: "no WAF detected" is honest about the
table's coverage. An exotic regional WAF or a custom in-house
filter wouldn't appear in Cathedral's fingerprint set; absence
of detection is suggestive, not conclusive. For high-stakes
work, cross-check with `wafw00f` against the same target.

### Aggressive Imperva deployment

```
operator@cathedral:~$ waf https://target.example.com
> probing https://target.example.com for WAF fingerprints

  baseline GET    status 200    matches: Imperva / Incapsula
  probe GET       status 403  [BLOCKED]    matches: Imperva / Incapsula

  · WAF: Imperva / Incapsula  (reacted to probe)

1 WAF fingerprint(s) matched.
```

Imperva is fingerprinted by its `X-Iinfo` header on baseline
plus the canonical "Request unsuccessful. Incapsula incident
ID" body string on the probe-blocked response. Imperva
deployments are typically aggressive — the 403 fires on a
wider class of patterns than Cloudflare's defaults, and
follow-on requests from the same IP may be rate-limited or
challenged for several minutes. For engagement work against an
Imperva-protected target, rotate source IPs through an
authorised proxy and spread requests over time.

### Multiple matches (rare but possible)

```
operator@cathedral:~$ waf https://protected.example.com
> probing https://protected.example.com for WAF fingerprints

  baseline GET    status 200    matches: AWS WAF / CloudFront, ModSecurity
  probe GET       status 403  [BLOCKED]    matches: AWS WAF / CloudFront, ModSecurity

  · WAF: AWS WAF / CloudFront  (reacted to probe)
  · WAF: ModSecurity  (reacted to probe)

2 WAF fingerprint(s) matched.
```

Sites with layered defences sometimes match more than one
fingerprint. The pattern here is AWS CloudFront with WAF in
front of an origin that runs ModSecurity locally — both fire
on the probe. The two layers can flag for different reasons:
CloudFront WAF matches a managed rule against the URL pattern;
ModSecurity matches its own rule set on the request as it
reaches the origin. The combined response carries both sets
of identifying headers and the ModSecurity block-page body.

This is uncommon but informative — defence-in-depth on a
target means engagement-shape decisions need to account for
both layers, not just the outer one.

## Output protocol

```
{"event":"start",       "target":"…"}
{"event":"tls_warning", "message":"x509: …"}                                 # optional
{"event":"baseline",    "status":N,"hits":["WAF name", …]}
{"event":"probe",       "url":"…","status":N,"blocked":true|false,"hits":[…]}
{"event":"match",       "waf":"…","on_probe":true|false,"on_baseline":true|false}  *per WAF
{"event":"result",      "detected":true,"count":N}    # OR
{"event":"result",      "detected":false,"message":"…"}
{"event":"done"}
{"event":"error",       "message":"…"}
```

Extract just the names of detected WAFs:

```
$ waf https://target.example.com -j |
    jq -r 'select(.event=="match") | .waf'
Cloudflare
```

Compute "blocked or not" across a portfolio:

```
$ for h in $(cat hosts.txt); do
    blocked=$(waf "https://$h" -j |
      jq -r 'select(.event=="probe") | .blocked')
    waf=$(waf "https://$h" -j |
      jq -r 'select(.event=="match") | .waf' | paste -sd,)
    printf '%-40s blocked:%-5s  waf:%s\n' "$h" "$blocked" "${waf:-none}"
  done
acme-supplies.example                blocked:true   waf:Cloudflare
api.acme-supplies.example            blocked:true   waf:Cloudflare
shop.acme-supplies.example           blocked:false  waf:Cloudflare
blog.acme-supplies.example           blocked:false  waf:Cloudflare
docs.acme-supplies.example           blocked:false  waf:none
legacy-portal.acme-supplies.example  blocked:false  waf:none
```

The output above is the canonical "audit your own portfolio"
result: the customer-facing app and API have the WAF firing;
the marketing blog and docs do not (they're behind the same
Cloudflare but the WAF feature is disabled on those zones);
the legacy portal is on a different host with no Cloudflare at
all. Each of those rows is a separately-actionable finding.

## Limitations

- **Fourteen fingerprints only.** The long tail of WAF
  products (Citrix NetScaler, Radware, regional / cloud-
  specific products) isn't covered. Absence of match isn't
  conclusive — fall back to `wafw00f` for thorough coverage.
- **One payload, one injection point.** The probe is a single
  XSS+SQLi pattern in the URL query string. WAFs that block
  POST-body payloads but pass query-string ones (or vice
  versa) will produce false negatives. Multi-vector probes
  are out of scope.
- **Monitor-mode WAFs are invisible.** A WAF configured to
  log-only rather than block returns 200 on the probe; from
  the client side it looks the same as no WAF. The target's
  logs would show otherwise.
- **No bypass attempts.** Cathedral fingerprints; it doesn't
  evade. WAFs configured to drop the connection (TCP RST
  instead of a 403 response) appear as a network error rather
  than a WAF detection.
- **TLS auto-fallback.** Self-signed and expired certs are
  silently tolerated with one `tls_warning`. For cert-posture
  audits use `ssl` (planned).
- **Single GET per phase.** No rate limiting, no spaced-probe
  mode. Two requests fire as fast as the network allows.
- **404 isn't a block.** A 404 on the probe is interpreted as
  "the route doesn't exist", not "blocked". Some WAFs return
  404 to obscure their presence — those won't be detected as
  blocking even when they are.

## Authorized use

`waf` is **deliberately-flagged probing**. The probe payload is
the canonical attack pattern that every WAF rule-set is tuned
to catch — by design, the second request fires every IDS / SIEM
rule the target has for "suspicious URL query parameter". The
intent is fingerprinting, not exploitation, but the wire
pattern is indistinguishable from an early-stage attack.

Three notes worth attaching:

**Expect to be logged.** The probe payload `<script>alert(1)
</script> UNION SELECT * FROM users WHERE 1=1` will appear in
the target's WAF logs, SIEM alerts, and access logs with full
request detail (including your IP, User-Agent, and timestamp).
This is the *point* of the probe — but it does mean every
`waf` run leaves a forensic trace. For sensitive testing,
route through an authorised proxy.

**Rate limits may follow.** Many WAFs respond to the
`alert(1)`-style probe with a short-term rate limit on the
source IP, in addition to the 403 on the specific request.
Subsequent commands ([`recon`](recon.md),
[`dirscan`](dirscan.md), [`http`](http.md)) from the same IP
within the next minute or two may see degraded performance or
outright blocks. If `waf` succeeded and the next command times
out, the rate limit is the likely cause — wait, or rotate
source IP.

**Don't probe targets you're not authorised to test.** The
probe payload, in isolation, is harmless — it's a string
served back as a query parameter, never interpreted or
executed. But the *act of submitting* it constitutes attempted
SQL injection and attempted XSS under most jurisdictions'
computer-misuse statutes. The legal posture matches that of
[`dirscan`](dirscan.md): authorise first or don't run it.

## Further reading

- [OWASP WAF documentation](https://owasp.org/www-community/Web_Application_Firewall) — what WAFs are and how they're typically configured
- [wafw00f project](https://github.com/EnableSecurity/wafw00f) — the canonical WAF fingerprinter; covers ~150 products to Cathedral's ~14
- [Cloudflare WAF documentation](https://developers.cloudflare.com/waf/) — the most-deployed WAF Cathedral fingerprints
- [ModSecurity Reference Manual](https://github.com/SpiderLabs/ModSecurity/wiki/Reference-Manual) — the open-source WAF rule engine many appliances embed
- [OWASP Core Rule Set](https://coreruleset.org/) — the default rule-set inside many WAFs (knowing what's blocked starts here)
- Related Cathedral commands: [`headers`](headers.md) (security-header audit; complementary view of the same target),
  [`tech`](tech.md) (full-stack fingerprinting; reports CDN/WAF presence as part of the picture),
  [`recon`](recon.md) (breadth-first HTTP probing; first reach against an unfamiliar target),
  [`http`](http.md) (single-endpoint deep inspection),
  [`dirscan`](dirscan.md) (path enumeration — heavily impacted by WAF presence; run `waf` first)
