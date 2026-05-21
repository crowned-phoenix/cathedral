---
title: mx-rep — MX-host reputation across DNS blocklists
command: mx-rep
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [dns, spf, dmarc, dnsbl, asn, whois]
---

# `mx-rep` — MX-host reputation across DNS blocklists

`mx-rep` resolves a domain's MX records, expands each MX hostname
to its IPv4 addresses, and checks every address against five
widely-used DNS-based blocklists in parallel (Spamhaus ZEN,
SpamCop, Barracuda BRBL, SORBS, UCEPROTECT-L1). The output is a
per-IP verdict — clean across all five, or listed on N of five
with the response code that identifies the listing reason.

For a self-hosted mail server the question is *"do other mail
systems see us as reputable?"* — RBL listings on your own MX IPs
correlate strongly with mail being rejected at the SMTP edge of
recipient organisations. For investigation against an unfamiliar
domain the question is *"what's the operational history of this
mail infrastructure?"* — listed MX IPs typically indicate either
a compromised server or shared-IP space with bad neighbours.

```
mx-rep gmail.com
mx-rep acme-supplies.example
mx-rep your-self-hosted-org.example
```

## What it does

For a single domain, Cathedral:

1. Issues an MX lookup. Sorts results by preference (lower
   first, per MX semantics) and reports each host with its
   preference value.
2. For each MX host, resolves both A and AAAA records.
3. For each *IPv4* address (IPv6 is noted but skipped — see
   below), queries the five DNS blocklist zones in parallel:
   `<reversed-octets>.<rbl-zone>`. A returned A record means
   listed; NXDOMAIN means clean.
4. Reports the per-IP outcome — `clean across N RBLs` or
   `[LISTED] <RBL> (response-IP)` for each hit.
5. Emits a summary with totals: hosts checked, IPs probed,
   clean count, listed count.

| RBL                  | Zone                       | Notes                                                              |
|----------------------|----------------------------|--------------------------------------------------------------------|
| Spamhaus ZEN         | `zen.spamhaus.org`         | composite of SBL + XBL + PBL — the canonical first reach           |
| SpamCop              | `bl.spamcop.net`           | user-reported spam aggregator; fast-cycling                        |
| Barracuda BRBL       | `b.barracudacentral.org`   | commercial; widely consulted by enterprise mail filters            |
| SORBS                | `dnsbl.sorbs.net`          | comprehensive multi-category list; slower-moving                    |
| UCEPROTECT-L1        | `dnsbl-1.uceprotect.net`   | conservative "directly-observed spam source" list (not L2/L3)      |

The five-list mix is chosen for *coverage with sanity*. UCEPROTECT
specifically uses Level 1 only — the broader L2 (network-block
escalation) and L3 (AS-wide escalation) lists include "guilty by
neighbour" entries that produce many false positives. The
conservative choice produces useful signal without the noise.

## What it answers

**Defender:** *"Is my mail server's IP clean from the
perspective of other mail systems?"* For self-hosted MTAs this
is the single most operationally-relevant reputation check.
Listed IPs experience higher rejection rates and longer
SMTP-acceptance delays from major recipient infrastructure
(Gmail, Microsoft 365, large corporate filters). Periodic
`mx-rep` against your own domain catches:

- A compromised mail server relaying spam, getting its IP
  listed within hours.
- A shared-hosting IP that picked up neighbour contamination.
- An ISP allocation change that placed the IP into a previously-
  listed range.

**Recon (authorized testing only):** *"What's this domain's mail
infrastructure history?"* Listed MX IPs suggest a target with
either mail-handling issues (compromise, misconfig) or operational
constraints (small-budget self-hosted setup on shared IP space).
Combined with [`spf`](spf.md) and [`dmarc`](dmarc.md), `mx-rep`
completes the picture of how mail authentication and reputation
interact for the target.

**Investigation:** *"Is the mail server behind this domain
trustworthy?"* When triaging a suspicious mail (claimed-from a
particular domain, looking for signal on whether the infrastructure
itself is suspicious), the MX reputation is one input. A clean
record across five major RBLs doesn't prove the mail is legitimate
— but a listed MX adds direct evidence of operational problems.

**Identification:** *"Who provides this domain's mail?"* The MX
hostnames usually identify the provider in their domain suffix —
`*.googlemail.com` (Google Workspace), `*.protection.outlook.com`
(Microsoft 365), `*.mailgun.org` (Mailgun), `*.fastmail.com`
(Fastmail). Combined with the IP-level RBL check, this gives both
the *vendor* and the *operational status* in one sweep.

## How it works

### DNS-based blocklists

A DNSBL is a DNS zone where the *presence* of an A record at a
specific name is the answer to "is this IP listed?". The query
format is:

```
<reversed-octets>.<blocklist-zone>
```

For IP `192.0.2.5` checked against Spamhaus ZEN
(`zen.spamhaus.org`):

```
5.2.0.192.zen.spamhaus.org   IN   A   ?
```

- **NXDOMAIN** (no record) → not listed.
- **A 127.x.x.x** → listed. The exact `127.x.x.x` response often
  encodes the listing reason. For Spamhaus ZEN:
  - `127.0.0.2` — SBL (manually-curated spam source)
  - `127.0.0.3` — SBL CSS (snowshoe spam)
  - `127.0.0.4`–`127.0.0.7` — XBL (exploited / compromised host)
  - `127.0.0.10`–`127.0.0.11` — PBL (dynamic / shouldn't-send-mail
    range)

Other RBLs use their own response-code conventions documented in
their respective FAQs. Cathedral reports the raw response value
without decoding — operators who care can look up the specific
meaning, but the *fact of listing* is usually the actionable
signal.

The protocol predates almost everything around it (RFC 5782,
formalised 2010 from much-earlier practice) and remains the
single most-deployed reputation mechanism in mail. Almost every
production MTA queries at least Spamhaus.

### Parallel RBL queries per IP

```go
for _, rbl := range rbls {
    wg.Add(1)
    go func(name, zone string) {
        defer wg.Done()
        cctx, cancel := context.WithTimeout(ctx, 4*time.Second)
        defer cancel()
        ips, err := r.LookupHost(cctx, rev+"."+zone)
        if err != nil || len(ips) == 0 { return }
        mu.Lock()
        out = append(out, rblHit{name, zone, strings.Join(ips, ",")})
        mu.Unlock()
    }(rbl.Name, rbl.Zone)
}
wg.Wait()
```

Each IP fans out into five concurrent DNS queries with a 4-second
per-RBL timeout. The whole check for one IP completes in roughly
the *slowest* RBL's response time (~50–500 ms on a warm cache,
up to 4 seconds on a cold one). Parallelisation matters: serial
would multiply by 5; parallel keeps the wall-clock at single-query
latency.

The IPs are queried in IP-order (whatever the resolver returned),
not sorted — this is the order Cathedral emits the per-IP results.

### Why MX-host IPs matter

MX records point at *receiving* mail servers. So why check MX IPs
for spam-source listings, when spam *flows out* from somewhere
else?

Three reasons:

1. **Most self-hosted MTAs use the same IP for inbound and
   outbound.** A single Postfix or Exim instance handles both
   directions on the same machine. If that machine gets
   compromised and starts relaying spam, the listing applies to
   the IP — which is also the MX IP visible to the public.
2. **Shared-IP contamination.** Small organisations on shared
   hosting (Mail-in-a-Box-style, cPanel mail) share an IP with
   neighbours; if a neighbour gets compromised, the shared IP
   gets listed and the legitimate organisation sees their mail
   rejected.
3. **Provider transitions can leave stale listings.** A
   reallocation moves an IP block from a previous operator
   (possibly a bulk-mail outfit) to a new tenant. The new
   tenant inherits the listing history for some time.

For organisations using major SaaS mail (Google Workspace,
Microsoft 365, Fastmail), the MX IPs are essentially never
listed — those providers manage reputation aggressively and at
massive scale. Listings on SaaS MX IPs would be remarkable;
Cathedral exists partly to surface that remarkability.

### IPv6 is intentionally skipped

```go
if ip.To4() == nil {
    emit(event{"event": "rbl_skip", "ip": ipStr,
        "reason": "IPv6 — most RBLs are IPv4-only"})
    continue
}
```

IPv6 RBLs do exist — Spamhaus operates `zen.spamhaus.org` for
v6 with the standard nibble-reversed query format — but
coverage across the five lists Cathedral queries is uneven, and
the cost of false-zero responses (no listing because *no v6
coverage*, not because *clean*) is higher than the signal value.
Cathedral surfaces v6 addresses as informational and explicitly
notes the skip; for v6-specific reputation use a dedicated tool
or query Spamhaus's v6 zone directly via [`dns`](dns.md).

### What's in Spamhaus ZEN

Worth a closer look since ZEN is the single most-consulted list
and its composite structure is the source of most listings.
ZEN is the union of three Spamhaus lists:

- **SBL** (Spamhaus Block List) — manually-curated spam sources.
  Listings are deliberate and reviewed; presence is a strong
  signal of either active spam operation or repeated abuse.
- **XBL** (Exploits Block List) — automated detection of
  compromised hosts (open proxies, infected machines, exploit
  staging). Listings cycle as machines get cleaned up.
- **PBL** (Policy Block List) — IP ranges *that shouldn't be
  sending mail directly*: dynamic-allocation residential pools,
  AWS EC2 default ranges, etc. Not a quality judgment about the
  IP — a statement about the *role*. A mail server in a PBL
  range is misconfigured; legitimate mail should originate from
  IPs explicitly assigned to mail use.

ZEN's response code in the `127.0.0.x` family identifies which
sub-list the listing came from. Cathedral surfaces the raw
value; operators can look it up.

## What Cathedral doesn't do

A few deliberate omissions:

- **Only five RBLs.** Many more exist — Mailspike, PSBL,
  Composite Blocklist (CBL, now retired/merged into XBL),
  Invaluement, Mailshell, Surriel, and dozens of regional
  lists. Cathedral picks five widely-deployed lists with
  reasonable false-positive rates. For comprehensive checks
  (compliance audits, deliverability deep-dives), MXToolbox
  queries ~100 RBLs in parallel.
- **No response-code decoding.** Cathedral reports the raw
  `127.0.0.x` response; the operator looks up the per-RBL
  meaning. Decoding would require maintaining a table per RBL
  that drifts.
- **No delist-status queries.** Some RBLs publish delisting
  pages; Cathedral doesn't fetch them. For remediation
  workflow, visit each RBL's site directly.
- **No sender-IP enumeration.** `mx-rep` checks MX (incoming)
  IPs. For *outbound* mail reputation (SPF-authorised
  senders), expand the SPF record with [`spf`](spf.md), extract
  each `ip4:` mechanism, and run `dnsbl` (planned) against
  each.
- **No historical RBL data.** Cathedral reports current
  status. Historical listing data (was this IP listed last
  year?) lives in specialised reputation services.
- **No IPv6 coverage.** v6 IPs are noted but skipped. See
  rationale above.
- **One domain at a time.** No portfolio mode; iterate in
  the shell.
- **No automatic retry on resolver failure.** A flaky resolver
  produces transient false-negatives. For high-stakes audits,
  rerun.

## Worked example

A major SaaS provider, a self-hosted setup, a listed MX, and
the no-MX edge case.

### Major SaaS (Google Workspace)

```
operator@cathedral:~$ mx-rep acme-supplies.example
> resolving MX for acme-supplies.example and querying 5 blocklists

[ MX   1 ] aspmx.l.google.com
  → 142.250.27.27                              
     clean across 5 RBLs
  → 2607:f8b0:4023:c0b::1b                     (IPv6)
     IPv6 — most RBLs are IPv4-only

[ MX   5 ] alt1.aspmx.l.google.com
  → 142.251.110.27                             
     clean across 5 RBLs
  → 2607:f8b0:4023:c0b::1a                     (IPv6)
     IPv6 — most RBLs are IPv4-only

[ MX   5 ] alt2.aspmx.l.google.com
  → 142.250.157.27                             
     clean across 5 RBLs
  → 2607:f8b0:4023:c0b::1b                     (IPv6)
     IPv6 — most RBLs are IPv4-only

[ MX  10 ] alt3.aspmx.l.google.com
  → 172.253.115.27                             
     clean across 5 RBLs

[ MX  10 ] alt4.aspmx.l.google.com
  → 172.253.62.27                              
     clean across 5 RBLs

5 MX hosts, 5 IPs   (5 clean · 0 listed)
```

Google Workspace's canonical five-MX layout — one primary at
preference 1, two at 5, two at 10. Each MX expands to one v4
plus one v6 (the v6s skipped). All five v4 IPs return clean
across all five RBLs, exactly as expected for major SaaS
infrastructure. The total 5-of-5-clean is the *operational
posture* you'd want on your own domain.

### Self-hosted (Fastmail)

```
operator@cathedral:~$ mx-rep self-hosted.acme-supplies.example
> resolving MX for self-hosted.acme-supplies.example and querying 5 blocklists

[ MX  10 ] in1-smtp.messagingengine.com
  → 64.147.123.24                              
     clean across 5 RBLs

[ MX  20 ] in2-smtp.messagingengine.com
  → 64.147.123.25                              
     clean across 5 RBLs

2 MX hosts, 2 IPs   (2 clean · 0 listed)
```

A Fastmail-hosted domain. The MX hosts are Fastmail's
infrastructure (`*.messagingengine.com`); the IPs are in
Fastmail's allocation; both clean. The two-MX setup with
primary/secondary preference (10/20) is Fastmail's standard
shape; smaller than Google's five-MX layout but operationally
equivalent.

### A listed MX (the finding case)

```
operator@cathedral:~$ mx-rep small-business.example
> resolving MX for small-business.example and querying 5 blocklists

[ MX  10 ] mail.small-business.example
  → 198.51.100.42                              
     [LISTED] Spamhaus ZEN  (127.0.0.10)
     [LISTED] UCEPROTECTL1  (127.0.0.2)
     2/5 listings

1 MX hosts, 1 IPs   (0 clean · 1 listed)
```

A self-hosted setup on a single MX IP with two listings:

- **Spamhaus ZEN response `127.0.0.10`** — the IP is on the
  PBL (Policy Block List), meaning Spamhaus considers this
  range "shouldn't be sending mail directly". This is
  typical of IPs in residential / dynamic allocation pools
  that have been repurposed for mail hosting. Receivers
  applying Spamhaus PBL will reject inbound mail from this
  IP outright — but inbound to the MX shouldn't be affected
  (the listing applies to *senders*, and the MX is a
  *receiver*). However, if this same IP is also the
  *outbound* relay for `small-business.example`'s users
  (typical for small self-hosted setups), their outbound
  mail is getting rejected by every Spamhaus-PBL-respecting
  recipient. Major Gmail/Microsoft/Outlook all respect PBL.

- **UCEPROTECT-L1 response `127.0.0.2`** — directly observed
  spam emission. Less time-decayed than Spamhaus XBL but
  more localised in coverage.

This is the *finding* case that justifies `mx-rep` existing:
the IP is operationally problematic in a way that's
invisible from the MX record itself. The remediation here is
either (a) move outbound mail to a different IP (a relay
service, a different VPS), (b) work with the ISP to migrate
the allocation, or (c) submit delisting requests at each RBL
and address the root cause.

### Mixed: clean inbound, listed neighbour-IP

```
operator@cathedral:~$ mx-rep multi-mx.example
> resolving MX for multi-mx.example and querying 5 blocklists

[ MX  10 ] mx1.multi-mx.example
  → 203.0.113.10                               
     clean across 5 RBLs

[ MX  10 ] mx2.multi-mx.example
  → 203.0.113.11                               
     [LISTED] SORBS  (127.0.0.10)
     1/5 listings

[ MX  20 ] mx3.multi-mx.example
  → 203.0.113.12                               
     clean across 5 RBLs

3 MX hosts, 3 IPs   (2 clean · 1 listed)
```

Three MX hosts on adjacent IPs in the same /29 — but only
`.11` is listed. SORBS's `127.0.0.10` response indicates the
specific sub-zone that matched (different SORBS sub-zones
encode different categories — escalations, dynamic
allocation, etc.; the operator looks up the exact meaning).
The single listing is moderate signal: SORBS is generally
slower-moving than Spamhaus, so a SORBS listing without a
ZEN listing suggests historical residue rather than current
problem. Worth investigating — possibly an old listing that
should be appealed for removal.

### No MX records

```
operator@cathedral:~$ mx-rep null-mx-domain.example
> resolving MX for null-mx-domain.example and querying 5 blocklists

  ! no MX records for null-mx-domain.example
```

The domain doesn't accept mail. This is either:

- A *null-MX* domain (RFC 7505) publishing the canonical
  refuse-mail signal (`0 .` MX record — `mx-rep` doesn't
  surface this distinction explicitly; [`dns`](dns.md) shows
  the null MX annotation).
- A domain with no MX records at all, in which case
  receivers fall back to the A/AAAA record per RFC 5321 §5.1
  — there's an *implicit* mail destination on the web server.
- A truly mail-less domain (asset-only host, redirect-only).

For each case the operational answer is the same: nothing to
audit on the receiving side. Cathedral reports the absence
and stops.

## Output protocol

```
{"event":"start",    "domain":"…","rbls":5}
{"event":"mx",       "host":"…","pref":N}                          *per MX
{"event":"ip",       "host":"…","ip":"…","v6":true|false}          *per IP
{"event":"rbl_skip", "ip":"…","reason":"IPv6 — …"}                 # IPv6 only
{"event":"listed",   "ip":"…","rbl":"…","zone":"…","response":"127.0.0.x"}  *per listing
{"event":"ip_done",  "ip":"…","listed":N,"checked":5}              *per IP
{"event":"ip_error", "host":"…","error":"…"}                       # optional
{"event":"no_mx",    "domain":"…"}                                 # optional
{"event":"summary",  "hosts":N,"ips":N,"listed_ips":N,"clean_ips":N}
{"event":"done"}
{"event":"error",    "message":"…"}
```

Extract just the listings across a portfolio:

```
$ for d in $(cat domains.txt); do
    mx-rep "$d" -j |
      jq -r --arg d "$d" \
        'select(.event=="listed") |
         "\($d)\t\(.ip)\t\(.rbl)\t\(.response)"'
  done
small-business.example       198.51.100.42  Spamhaus ZEN    127.0.0.10
small-business.example       198.51.100.42  UCEPROTECTL1    127.0.0.2
multi-mx.example             203.0.113.11   SORBS           127.0.0.10
```

Sort domains by listing count (worst first):

```
$ for d in $(cat domains.txt); do
    listed=$(mx-rep "$d" -j |
      jq -r 'select(.event=="summary") | .listed_ips')
    printf '%-40s %s\n' "$d" "${listed:-0}"
  done | sort -k2 -rn | head
small-business.example                3
multi-mx.example                      1
acme-supplies.example                 0
self-hosted.acme-supplies.example     0
```

Identify domains using major SaaS mail (clean-MX heuristic):

```
$ for d in $(cat domains.txt); do
    mx-rep "$d" -j |
      jq -r --arg d "$d" \
        'select(.event=="mx") | "\($d)\t\(.host)"'
  done | awk '
    { host=$NF; sub(/^.*\./, "", host); domains[$1]=host }
    END { for (d in domains) print d, domains[d] }
  ' | sort -k2
acme-supplies.example                com         # *.googlemail.com
self-hosted.acme-supplies.example    com         # *.messagingengine.com (Fastmail)
shop.acme-supplies.example           com         # *.protection.outlook.com (Microsoft 365)
small-business.example               example     # self-hosted
```

## Limitations

- **Five RBLs only.** Coverage is good for the common case;
  high-stakes audits should consult MXToolbox's ~100-RBL
  parallel check.
- **No response-code decoding.** Raw `127.0.0.x` values are
  emitted; operators look up per-RBL meaning.
- **No delisting integration.** Cathedral reports listings,
  not removal paths.
- **No outbound IP coverage.** MX = inbound. For
  SPF-authorised outbound senders, expand the SPF record and
  check those IPs separately.
- **No historical data.** Current status only.
- **No IPv6.** v6 IPs noted and skipped.
- **One domain per invocation.** Iterate in the shell.
- **Public-resolver caching.** RBL responses are cached by
  intermediate resolvers; a recently-listed IP may show as
  clean if the cache hasn't expired. Cathedral can't see
  cache metadata.
- **RBL service quotas.** Spamhaus enforces rate limits on
  public DNS resolvers for high-volume queriers. Bulk audits
  may trip these; if results look inconsistent, your resolver
  is being throttled.
- **30-second overall timeout.** Domains with many MX hosts
  across slow resolvers may time out.

## Authorized use

`mx-rep` is **passive recon against public datasets**. Every
query is a DNS lookup against a published RBL zone; the
target's mail infrastructure never sees the activity. Risk
profile is the same as [`dns`](dns.md) — unremarkable.

Two notes worth attaching:

**Resolver visibility.** RBL queries are unencrypted DNS. A
network operator between you and the recursive resolver, or
the resolver itself, sees which IPs you're checking. For
sensitive auditing, route through a privacy-respecting
resolver.

**Bulk-query rate limits.** Spamhaus and other major RBLs
rate-limit per-recursive-resolver query rates to discourage
abuse. A portfolio sweep of dozens of domains may produce
hundreds of RBL queries within minutes; if your shared
resolver hits the limit, your results degrade silently. For
genuine bulk work, Spamhaus offers a paid Data Query Service
(DQS) with per-customer keys; otherwise space queries with
a small `sleep`.

## Further reading

- [RFC 5782 — DNS Blacklists and Whitelists](https://www.rfc-editor.org/rfc/rfc5782) — the DNSBL protocol spec
- [Spamhaus DNSBL usage](https://www.spamhaus.org/zen/) — ZEN composite documentation, response codes, listing categories
- [Spamhaus return codes](https://www.spamhaus.org/dnsbl-usage/) — the `127.0.0.x` decode table
- [SpamCop FAQ](https://www.spamcop.net/fom-serve/cache/291.html) — user-reporting workflow and listing decay
- [Barracuda Reputation Block List](https://www.barracudacentral.org/rbl) — listing checker + removal request form
- [MXToolbox blacklist check](https://mxtoolbox.com/blacklists.aspx) — ~100-RBL parallel check; comprehensive complement to Cathedral's five
- [RFC 7505 — A Null MX Resource Record](https://www.rfc-editor.org/rfc/rfc7505) — for the no-MX edge case
- Related Cathedral commands: [`spf`](spf.md) (sender authorisation — the outbound side of the same mail flow),
  [`dmarc`](dmarc.md) (alignment policy — what receivers should do with auth failures),
  [`dns`](dns.md) (raw MX queries; surfaces null-MX with explicit annotation),
  [`dnsbl`](dnsbl.md) *(planned — single-IP reputation check against the same five lists)*,
  [`asn`](asn.md) (BGP attribution for the listed IPs — often the listing reason is "shares an AS with a known-bad neighbour"),
  [`whois`](whois.md) (registry attribution for the IP's allocation history)
