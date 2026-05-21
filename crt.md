---
title: crt — Certificate Transparency log search for subdomain discovery
command: crt
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [ssl, dns, reverse-dns, subs, fav]
---

# `crt` — Certificate Transparency log search for subdomain discovery

`crt` queries the public Certificate Transparency log aggregator at
crt.sh for every TLS certificate ever issued for a domain, then
dedupes the result into one row per unique name. The output is a
list of every hostname the operator ever asked a public CA to
certify — including the forgotten staging environments, the dev
boxes that were briefly exposed, the internal `*.corp.example`
infrastructure that ended up in a multi-SAN cert by mistake. CT
log search is the single most productive *subdomain enumeration*
technique available: where DNS brute-force finds what the operator
publishes today, CT log search finds what they ever publicly
authenticated.

The CT ecosystem ([RFC 6962](https://www.rfc-editor.org/rfc/rfc6962))
exists for an unrelated reason — preventing rogue-CA mis-issuance
via mandatory public logging — but the side effect of *every
public cert ever issued is permanently logged in public,
searchable, tamper-evident systems* turns out to be a recon
primitive of remarkable depth. Names persist forever; the operator
cannot remove them; the operator cannot prevent them.

```
crt acme-supplies.example
crt github.com
crt small-org.example                # may return very few rows on small domains
```

## What it does

For one domain Cathedral:

1. Queries `https://crt.sh/?Identity=<domain>&exclude=expired&output=json`.
2. Validates the response is actually JSON (crt.sh is famously
   flaky — see *How it works* below).
3. Parses the array of CT log entries. Each entry corresponds to
   one cert in one log; a single cert is typically logged in
   multiple CT logs so it appears as several rows.
4. Walks each row's `name_value` field — newline-separated list
   of every SAN on that cert.
5. Applies a suffix filter to keep only names that are the target
   domain or true subdomains of it. crt.sh's `Identity=`
   parameter does substring matching, so `Identity=github.com`
   would in principle return rows for `notgithub.com` — the
   filter drops those.
6. Dedupes by name, keeping the earliest `not_before` per name
   plus the issuing CA.
7. Sorts alphabetically and emits one event per unique name.

| Element            | Default                                          |
|--------------------|--------------------------------------------------|
| Source             | `crt.sh` (Sectigo's CT log aggregator)           |
| Query parameter    | `Identity=<domain>&exclude=expired`              |
| Timeout            | 60 s (crt.sh routinely takes 30–45 s)            |
| Retries            | 1 (with 2-second backoff)                        |
| Suffix filter      | strict — apex or `.<domain>` only                |

## What it answers

**Defender:** *"What hostnames have we ever certified — and is any
of that infrastructure still reachable?"* The output is the
*historical* map of your own organisation's public infrastructure.
Common findings on an internal audit:

- A `staging.<product>.example` that was deployed briefly two
  years ago, has been gone from DNS for 18 months, but the host
  still has a public IP and responds to TCP/443 on a forgotten
  EC2 instance.
- A `*.internal.example` wildcard cert that was provisioned for
  internal use but happened to be issued by a public CA, leaking
  the entire internal namespace structure.
- A short-lived `oauth-test.example` cert from a half-finished
  proof-of-concept that ended up on a public-facing route.

Cross-referencing the `crt` list against current DNS (with
[`dns`](dns.md)), against live HTTP (with [`recon`](recon.md)),
and against the favicon hash (with [`fav`](fav.md)) catches the
asset-inventory gaps no internal CMDB has heard of.

**Recon (authorized testing only):** *"What subdomains does this
target have?"* CT log search is the depth tool. A single `crt`
against a mature organisation routinely returns hundreds of
unique names — every microservice frontend, every staging
environment, every API region, every short-lived experiment.
Each name is the seed for further recon: DNS resolution (does it
still exist?), HTTP probing (does it still respond?), banner-
grabbing (what's on it?).

**Investigation:** *"What does this domain's certificate history
look like?"* The `first_seen` timestamp on each name traces the
infrastructure timeline:

- A cluster of new names dated to a single week → a deployment
  event or platform launch.
- A gap of years between issuance dates → infrastructure that
  was effectively dormant.
- A sudden new wildcard issuance → a CA-tier upgrade or vendor
  migration.

**Identification:** *"Who issues this organisation's
certificates?"* The issuer column reveals the CA stack — Let's
Encrypt R3/R10/R11/E5/E6 (Let's Encrypt's ECDSA / RSA
intermediates), Sectigo, DigiCert, GlobalSign, Amazon's own
RSA/ECDSA CAs. Mature orgs typically mix a primary public CA
(DigiCert / Sectigo for EV certs, Let's Encrypt for everything
automated) and Amazon's CA for things hosted on AWS managed
services.

## How it works

### Certificate Transparency in 60 seconds

[CT](https://certificate.transparency.dev/) is a mandatory
public-logging system for TLS certificates, introduced in 2013
by Google to combat rogue-CA mis-issuance. The mechanics:

- Every public CA issuing a TLS cert must submit it to at least
  two *CT logs* (operated by Google, Cloudflare, DigiCert, Let's
  Encrypt, Sectigo, etc.) before browsers will accept it.
- CT logs are *append-only, tamper-evident* Merkle trees —
  entries cannot be retroactively removed or edited.
- Every cert in the log carries a Signed Certificate Timestamp
  (SCT) that the issuing CA embeds in the cert (or staples
  during TLS handshake). Browsers verify the SCT against the
  log on connection.

The unintended-but-now-obvious side effect: **every public TLS
cert ever issued is permanently, publicly, searchably logged**.
The operator cannot remove a name from the logs. The operator
cannot prevent a name from being logged. Even if a cert was
issued in error and revoked seconds later, the issuance event
is in the logs forever.

For subdomain enumeration, CT logs are *strictly better* than
DNS brute-force. DNS brute-force finds what the operator
publishes *now*; CT logs find what the operator ever asked a
public CA to certify, which is a strictly larger set.

### crt.sh: the canonical CT aggregator

The CT log network has hundreds of logs across many operators.
Querying each one individually is impractical; the community
relies on a small number of aggregators that ingest from every
log and provide unified search. The canonical free aggregator
is **crt.sh**, operated by Sectigo:

- **Web UI**: `https://crt.sh/?q=<query>`
- **JSON API**: `?output=json`
- **Direct Postgres**: `psql -h crt.sh -p 5432 -U guest certwatch`
  for bulk operations (the database is publicly readable)

Cathedral uses the JSON API. The URL Cathedral constructs:

```go
u := "https://crt.sh/?Identity=" + url.QueryEscape(domain) +
    "&exclude=expired&output=json"
```

Three parameters in play:

- **`Identity=<domain>`** — the modern canonical search
  parameter. Substring-matches against the certificate
  identifier table (covering CN and all SANs). Returns rows for
  any cert whose identifier *contains* the domain. The older
  `?q=%.<domain>` wildcard form is no longer reliably served by
  crt.sh as of mid-2026 — `Identity=` is what the live HTML form
  submits and what the API serves reliably.
- **`exclude=expired`** — drops certs past their `not_after`
  date from the result set. Cuts response sizes meaningfully
  for high-volume domains and focuses on *currently-relevant*
  history. To audit expired certs specifically, query crt.sh
  directly without this filter.
- **`output=json`** — return JSON instead of HTML. The JSON
  schema is documented [here](https://crt.sh/?a=1) (informally;
  the source of truth is crt.sh's `certwatch` Postgres schema).

### Substring matching and the suffix filter

`Identity=` is substring-matching, which means a query for
`github.com` could in principle return rows for `notgithub.com`,
`github.community`, or `evil-github.com`. To keep the result
domain-bounded:

```go
lowerDomain := strings.ToLower(domain)
suffix := "." + lowerDomain
for _, e := range entries {
    names := strings.Split(e.NameValue, "\n")
    for _, n := range names {
        n = strings.TrimSpace(strings.ToLower(n))
        if n == "" { continue }
        base := strings.TrimPrefix(n, "*.")
        if base != lowerDomain && !strings.HasSuffix(base, suffix) {
            continue
        }
        // … record this name …
    }
}
```

The filter keeps:

- The apex (`github.com` exactly)
- The apex wildcard (`*.github.com`)
- Any true subdomain (`api.github.com`, `staging.api.github.com`)
- Any wildcard at any subdomain level (`*.api.github.com`)

The filter drops:

- Substring false positives (`notgithub.com`, `mygithub.example`)
- Unrelated names that happened to share a substring

### Crt.sh's reliability story

crt.sh is operationally famous for being flaky. The service
runs on relatively modest infrastructure and faces continuous
load from automated tools (cert monitoring, security research,
recon platforms). Common failure modes:

- **Apache 404** with HTML body — the older `?q=%.<domain>`
  wildcard route. Currently returns 404 even with correct URL
  encoding.
- **nginx 502 Bad Gateway** — upstream timeout or restart.
  Usually transient; second attempt typically succeeds.
- **Varnish "Backend fetch failed"** — fronting cache
  unhappy. Same as above.
- **Cloudflare challenge page** — bot detection on the front
  edge. Plain-text body, possibly starting with `B` for "Bad
  Gateway" / "Backend".
- **Empty body with HTTP 200** — the worst case; superficially
  successful, semantically broken.
- **HTML error page returned with status 200** instead of 5xx.
  Naïve JSON parsers blow up with cryptic errors like
  `invalid character '<' looking for beginning of value`.

Cathedral handles all these via a sniff + retry:

```go
trimmed := strings.TrimLeft(string(body), " \t\r\n")
if trimmed == "" {
    return nil, fmt.Errorf("crt.sh returned an empty body
        (service may be overloaded)")
}
if trimmed[0] != '[' && trimmed[0] != '{' {
    preview := trimmed
    if len(preview) > 80 { preview = preview[:80] + "…" }
    return nil, fmt.Errorf("crt.sh returned non-JSON
        (service may be overloaded): %q", preview)
}
```

The first non-whitespace byte tells Cathedral whether the
response is JSON (starts with `[` or `{`) or upstream
flakiness. On detection, the error message includes the first
80 bytes of the offending response so the operator can see
what crt.sh actually returned. Transient failures retry once
with a 2-second backoff.

### Why "exclude=expired"

A mature organisation accumulates hundreds-to-thousands of
certs over the years. Including all of them in every query
produces:

- Slower queries (more rows to process server-side).
- Larger responses (more bytes over the wire).
- More duplication in the deduped output (the same
  `staging.example.com` certified twenty times over five years
  produces twenty rows but one deduped name; the dedup cost
  scales with row count).

`exclude=expired` drops anything past its `not_after` date.
The result is the *currently-meaningful* history — names that
are or recently were certified. For full historical audit
(*"did we ever certify this name?"*), query crt.sh directly
without the parameter.

The trade-off: a forgotten subdomain whose cert expired six
months ago and was never renewed won't appear in the default
result. If you specifically want the historical haystack, drop
`exclude=expired` in a custom query.

## What Cathedral doesn't do

A few deliberate omissions:

- **No live cert inspection.** `crt` reports CT log history;
  it doesn't connect to any of the discovered names. For
  live TLS posture on a specific name, use [`ssl`](ssl.md).
- **Single aggregator (crt.sh only).** Other CT search
  services exist — [Censys](https://search.censys.io/) (the
  most polished, account-gated), [certspotter](https://sslmate.com/certspotter/)
  (SSLMate, also account-gated), [CertStream](https://certstream.calidog.io/)
  (Calidog, real-time WebSocket feed). Cathedral uses crt.sh
  because it's the only one accessible without an account.
  For redundancy on crt.sh outages, the others are worth
  knowing about.
- **No real-time monitoring.** crt.sh is a *historical* index;
  Cathedral queries it on demand. For "alert me when a new
  cert is issued for my domain", subscribe to a CertStream
  feed or use a dedicated cert-monitoring SaaS.
- **No CAA record auditing.** Whether the *right* CAs are
  authorised to issue for your domain (via CAA records) is a
  separate question — covered by [`dns`](dns.md) with
  `--types=CAA` (planned).
- **No cert-detail expansion.** Each row carries the cert ID
  but not the full certificate. To see the chain, the SAN
  list, or the signature algorithm, follow up with
  [`ssl`](ssl.md) against the discovered name.
- **No alternative-domain enumeration.** `crt` only walks
  forward (target → CT log → names). Backward enumeration
  (CT log → certs sharing infrastructure → other domains)
  isn't supported; that's [`fav`](fav.md)'s job in a
  different direction.
- **Expired certs hidden by default.** See `exclude=expired`
  rationale above.

## Worked example

A typical commercial enumeration, a wildcard-cert finding, a
small-org sparse result, and the upstream-flake case.

### Typical commercial enumeration

```
operator@cathedral:~$ crt acme-supplies.example
> querying crt.sh for acme-supplies.example

  2024-08-13 *.acme-supplies.example
  2024-08-13 acme-supplies.example
  2024-11-02 *.api.acme-supplies.example
  2025-01-18 *.staging.acme-supplies.example
  2025-04-22 admin-portal.acme-supplies.example
  2025-04-22 *.admin-portal.acme-supplies.example
  2025-06-14 docs.acme-supplies.example
  2025-07-30 status.acme-supplies.example
  2025-09-08 shop.acme-supplies.example
  2025-09-08 checkout.acme-supplies.example
  2025-10-19 metrics-internal.acme-supplies.example
  2026-01-05 oauth-test-q4.acme-supplies.example
  2026-02-14 *.legacy.acme-supplies.example
  2026-03-11 blog.acme-supplies.example
  2026-04-15 mail.acme-supplies.example
  2026-04-15 *.mail.acme-supplies.example
  2026-04-15 *.acme-supplies.example
  2026-05-08 release-2026.acme-supplies.example

18 unique names across 47 log entries.
```

Reading the result top-to-bottom is a tour through the
organisation's recent history:

- The earliest two entries (`*.acme-supplies.example` and the
  apex, both 2024-08-13) are the *original* wildcard cert that
  predates the modern infrastructure.
- The 2024-11 `*.api.acme-supplies.example` is when the API
  layer was carved off into its own subdomain space.
- The 2025-04 `admin-portal.acme-supplies.example` plus its
  wildcard sibling suggests a new product surface.
- The two findings worth flagging:
  - `metrics-internal.acme-supplies.example` (2025-10) — the
    `-internal` suffix is suggestive; a public cert was issued
    for what was apparently meant to be internal-only
    infrastructure. Either it's still reachable from the
    public internet (in which case the name is a finding), or
    the cert was issued by mistake and the actual host is
    internal-only (in which case the cert issuance was the
    finding).
  - `oauth-test-q4.acme-supplies.example` (2026-01) —
    `oauth-test-*` is the kind of name that gets stood up for
    a feature push and forgotten about. Q4 was two quarters
    ago; if the host is still up, it's a stale-deployment
    candidate.
- The 2026-04-15 cluster (three certs the same day) is a
  renewal event — the apex `*.acme-supplies.example` got
  re-issued alongside the mail-server certs.

Each of those 18 names is a starting point for further work.
The classic follow-on: pipe through [`dns`](dns.md) to find
what currently resolves, then [`recon`](recon.md) on each
live target.

### A wildcard cert reveals internal infrastructure

```
operator@cathedral:~$ crt corp-tools.example
> querying crt.sh for corp-tools.example

  2024-03-01 corp-tools.example
  2024-03-01 *.corp-tools.example
  2025-09-14 *.dev.corp-tools.example
  2025-09-14 *.staging.corp-tools.example
  2025-09-14 *.prod.corp-tools.example
  2025-09-14 *.internal.corp-tools.example
  2026-02-08 audit-portal.corp-tools.example
  2026-02-08 jenkins.internal.corp-tools.example

8 unique names across 21 log entries.
```

The 2025-09-14 batch is the headline: four wildcard certs
explicitly named for `dev`, `staging`, `prod`, and `internal`
tiers. The *cert names themselves* reveal the organisation
operates a four-tier infrastructure with that namespace
structure, even though none of the wildcard names individually
identify a specific host. The 2026-02-08 entry for
`jenkins.internal.corp-tools.example` confirms the `internal.`
tier is actively used and names a specific service running
there. The presence of Jenkins on an internet-reachable
hostname (even if firewalled at the IP level) is itself worth
investigating — Jenkins exposed to the internet has been a
recurring CVE source.

This is the canonical *cert-as-architecture-leak* pattern.
Every multi-tier organisation that uses wildcard certs leaks
their tier structure to anyone who queries CT logs.

### A small-org sparse result

```
operator@cathedral:~$ crt small-blog.example
> querying crt.sh for small-blog.example

  2026-02-18 small-blog.example
  2026-02-18 *.small-blog.example

2 unique names across 4 log entries.
```

A small WordPress blog with one Let's Encrypt wildcard.
Minimal CT footprint, minimal recon surface from this angle.
For small operators with a single cert, `crt` essentially
reports "this exists" — fine, but not the deep enumeration
the tool excels at on larger targets.

### crt.sh upstream flakiness

```
operator@cathedral:~$ crt acme-supplies.example
> querying crt.sh for acme-supplies.example

error: crt.sh returned non-JSON (service may be overloaded): "<html>\n<head><title>502 Bad Gateway</title></head>\n<body>\n<center><h1>502 Bad…"
```

crt.sh's nginx returned 502. Cathedral's retry already
attempted a second pass with a 2-second backoff; both came
back with the same error. The body preview confirms it's the
upstream proxy, not a parsing issue. The fix is to wait a few
minutes and try again — outages are usually short.

For repeated bad luck, the alternatives (Censys, certspotter,
or a direct query against `psql -h crt.sh -p 5432 -U guest
certwatch`) provide redundancy.

### A different finding: short-lived cert that shouldn't have been public

```
operator@cathedral:~$ crt finance-team.example
> querying crt.sh for finance-team.example

  2024-06-12 finance-team.example
  2024-06-12 *.finance-team.example
  2025-08-04 oauth-callback.finance-team.example
  2025-09-15 internal-q3-audit.finance-team.example
  2025-09-15 SECRET-DOCS-FINAL.finance-team.example
  2025-11-20 reports.finance-team.example
  2026-01-30 portal.finance-team.example
  2026-04-22 mail.finance-team.example

8 unique names across 19 log entries.
```

The 2025-09-15 entry `SECRET-DOCS-FINAL.finance-team.example`
is the kind of name nobody intends to expose. It's a public
cert issued for a hostname that someone clearly considered
private — and now the name is in CT logs forever. Even if the
host is taken down today and the cert is revoked tomorrow,
the *name* persists in every CT log archive globally.

This is the most common pattern in real-world CT enumeration:
people typing internal-sounding names into public-CA
cert-request forms because they don't realise the name itself
will be made public. crt sweeps catch these on the
defender side; on the recon side they're frequently the most
interesting findings in an engagement.

## Output protocol

```
{"event":"start", "domain":"…","source":"crt.sh"}
{"event":"name",  "name":"…","first_seen":"YYYY-MM-DDTHH:MM:SS","issuer":"…"}  *per unique name
{"event":"done",  "total":N,"rows":N}
{"event":"error", "message":"…"}
```

Extract just the names for pipeline use:

```
$ crt acme-supplies.example -j |
    jq -r 'select(.event=="name") | .name'
*.acme-supplies.example
acme-supplies.example
*.api.acme-supplies.example
…
```

Find which CT-discovered names *currently* resolve in DNS:

```
$ crt acme-supplies.example -j |
    jq -r 'select(.event=="name" and (.name | startswith("*.") | not)) | .name' |
    while read n; do
      if host "$n" >/dev/null 2>&1; then echo "LIVE  $n"; else echo "DEAD  $n"; fi
    done | sort
LIVE  acme-supplies.example
LIVE  api.acme-supplies.example
LIVE  blog.acme-supplies.example
DEAD  metrics-internal.acme-supplies.example
DEAD  oauth-test-q4.acme-supplies.example
LIVE  status.acme-supplies.example
…
```

The DEAD entries are the *interesting* ones — names that were
once publicly certified but no longer resolve. They might be
genuinely retired, or the cert was issued by mistake, or the
DNS was changed but the host kept running on the old IP.
Pivot via direct-IP probing or [`fav`](fav.md) hash search.

Find names with timestamps inside a window (e.g., the last 30
days — recent issuance often coincides with new deployments):

```
$ crt acme-supplies.example -j |
    jq -r --arg cutoff "$(date -d '30 days ago' +%Y-%m-%d)" \
        'select(.event=="name" and .first_seen >= $cutoff) | .name'
release-2026.acme-supplies.example
mail.acme-supplies.example
*.mail.acme-supplies.example
*.acme-supplies.example
```

Map the CA stack used by the organisation:

```
$ crt acme-supplies.example -j |
    jq -r 'select(.event=="name") | .issuer' |
    sort | uniq -c | sort -rn
     12 C=US, O=Let's Encrypt, CN=R10
      4 C=US, O=Let's Encrypt, CN=E5
      2 C=GB, O=Sectigo Limited, CN=Sectigo Public Server Authentication CA DV R36
```

## Limitations

- **crt.sh only.** No fallback to Censys / certspotter /
  CertStream. Those services require accounts; Cathedral aims
  for the no-credentials baseline.
- **Expired certs hidden by default.** `exclude=expired` is
  always on. For full historical audit, query crt.sh directly.
- **Substring matching with suffix filter.** Filter keeps only
  true subdomains; the cost is potentially missing certs
  issued for names that match the domain text but aren't DNS
  subdomains (rare but possible).
- **crt.sh's known flakiness.** Cathedral retries once and
  surfaces clear errors on failure. Persistent outages mean
  the tool simply doesn't work — wait and retry, or use an
  alternative.
- **No live verification.** A name in CT logs may have been
  taken down years ago. Cross-check with DNS / HTTP probing
  for current relevance.
- **No cert chain detail.** Each row carries the issuer name
  and the first-seen timestamp, not the full cert. For chain
  details follow up with [`ssl`](ssl.md).
- **CT only covers public CAs.** Private CAs (corporate internal
  CAs, AWS Private CA, smallstep step-ca, internal Hashicorp
  Vault) don't submit to CT logs by default. Names certified
  by private CAs only are not in this output.
- **One domain per invocation.** Iterate in the shell.
- **60-second timeout, one retry.** For genuinely large
  organisations on a healthy crt.sh, the query can occasionally
  exceed this. Cap on the database side, not the network.

## Authorized use

`crt` is **passive recon against a public dataset**. Every
query goes to crt.sh's public service; the target's own
infrastructure never sees the activity. CT log data is
*deliberately published* by design — that's the entire
purpose of the system. Reading CT logs is no more remarkable
than reading a published phone book.

Three notes worth attaching:

**crt.sh sees your queries.** Sectigo's infrastructure logs
request IPs and query strings. A pattern of queries (`crt
target-1`; `crt target-2`; …) traces an enumeration session
in crt.sh's access logs. For sensitive recon route through a
VPN or use the direct Postgres connection from a different
network.

**Volume matters.** Single queries are unremarkable. Bulk
sweeps of dozens of domains in seconds may trip crt.sh's
rate limits or be visible as automated tooling. The Postgres
direct interface (`psql -h crt.sh -p 5432 -U guest certwatch`)
is the right tool for bulk work — it bypasses the HTTP layer
and gives full SQL access to the cert database.

**The data is genuinely public.** CT logs are authoritative-
published data by design. Reading them is no more remarkable
than reading the same target's forward DNS or public webpages.
The *findings* derived from CT logs — names the operator
arguably didn't realise would be public — are sensitive even
though the underlying data isn't.

## Further reading

- [RFC 6962 — Certificate Transparency](https://www.rfc-editor.org/rfc/rfc6962) — the foundational spec
- [RFC 9162 — Certificate Transparency Version 2](https://www.rfc-editor.org/rfc/rfc9162) — the modernised spec
- [certificate.transparency.dev](https://certificate.transparency.dev/) — overview, log directory, ecosystem documentation
- [crt.sh](https://crt.sh/) — Sectigo's CT log aggregator
- [crt.sh advanced search syntax](https://groups.google.com/g/crtsh) — Google group for crt.sh users
- [Censys certificate search](https://search.censys.io/certificates) — account-gated alternative aggregator
- [SSLMate certspotter](https://sslmate.com/certspotter/) — account-gated; offers CT log monitoring + alerting
- [CertStream — real-time CT log feed](https://certstream.calidog.io/) — Calidog's WebSocket feed of new issuances
- [Bug Bounty Hunter — CT log subdomain enumeration walkthrough](https://github.com/six2dez/reconftw) — practical guide
- Related Cathedral commands: [`ssl`](ssl.md) (live TLS inspection of discovered names),
  [`dns`](dns.md) (does this name currently resolve?),
  [`reverse-dns`](reverse-dns.md) (PTR sweep for the IPs behind discovered names),
  [`subs`](subs.md) *(planned — subdomain enumeration via complementary techniques: dictionary, wordlist, DNS-zone-walking)*,
  [`fav`](fav.md) (favicon-hash pivoting — complementary infrastructure-discovery technique)
