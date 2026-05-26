---
title: dnsbl — IP reputation across DNS blocklists + a whitelist
command: dnsbl
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [mx-rep, dns, reverse-dns, asn, whois, geoip]
---

# `dnsbl` — IP reputation across DNS blocklists + a whitelist

`dnsbl` checks a single IPv4 (or a hostname Cathedral resolves to
IPv4) against ten widely-used DNS-based reputation lists in
parallel. Nine are blocklists — listing on any of them means
"sender / scanner / spammer / known bad neighbour"; one is
DNSWL, an industry-curated allowlist where listing is a *positive*
signal. The output is one row per list with `[ ✓ ]` clean / `[ ✗ ]`
listed / `[ · ]` whitelisted, plus a summary verdict.

The cousin entry [`mx-rep`](mx-rep.md) does the same RBL technique
but starts from a domain, walks its MX records, and runs the
checks against each MX IP. Use `mx-rep` for "is this domain's
mail infrastructure reputable?"; use `dnsbl` for "is this single
IP listed?" — investigating an unfamiliar SMTP client, your own
egress NAT, a hosting provider's IP block, a host you found in
firewall logs.

```
dnsbl 8.8.8.8
dnsbl 185.220.101.4
dnsbl mail.example.com
dnsbl <your-egress-ip>
```

## What it does

For a single IP or hostname, Cathedral:

1. If the argument is already an IPv4 literal, use it directly.
   Otherwise resolve it as `ip4` via the system resolver. IPv6 is
   rejected — most RBLs don't publish AAAA-shaped zones, and
   mixing the two would only confuse output without adding signal.
2. Reverse the four octets. `1.2.3.4` becomes the DNS label
   prefix `4.3.2.1`. (RBLs are zoned this way so the longest-match
   property of DNS lookup works in the operator's favour: each
   "/8 of bad IPs" can be one delegation.)
3. Concurrently issue an A-record lookup for `4.3.2.1.<rbl-zone>`
   against each of the ten lists. 5-second per-list timeout,
   25-second overall budget.
4. Classify per-list:
   - `NXDOMAIN` → not listed (clean for blocklists; "no
     reputation signal" for the allowlist).
   - Any returned A record → listed. The A record is
     conventionally a 127.0.0.x address whose low byte encodes
     the category of the listing.
   - Network / timeout error → reported separately as `error`,
     not silently treated as clean.
5. Aggregate: count `listed_block`, `on_allow_list`, `errored`,
   `checked`. Emit a single-line verdict — `clean`, `clean
   (whitelisted)`, `listed on N RBLs`, or `heavily listed`
   (≥3 blocklists).

## What it answers

- Is this IP on a public spam/abuse blocklist?
- Is it on DNSWL — i.e., a curated trusted-sender list — which
  partially absolves it of mid-tier blocklist hits?
- How many independent lists agree, and how aggressive are they?
- Is the listing recent enough to matter, or could it be stale
  shared-IP-space residue?

## The ten lists Cathedral checks

| List              | Zone                       | Kind  | Notes                                                       |
|-------------------|----------------------------|-------|-------------------------------------------------------------|
| Spamhaus ZEN      | `zen.spamhaus.org`         | block | Aggregates SBL + XBL + PBL. **Public-resolver rate-limited.** |
| SpamCop           | `bl.spamcop.net`           | block | User-reported spam sources. Fast TTLs, recent-event-biased.  |
| Barracuda         | `b.barracudacentral.org`   | block | Barracuda's reputation list. Free registration encouraged.   |
| SORBS             | `dnsbl.sorbs.net`          | block | Aggregated SORBS zones (DUHL + SOCKS + Web + SPAM).          |
| UCEPROTECT-L1     | `dnsbl-1.uceprotect.net`   | block | Single-IP spam observations. Strict but specific.            |
| UCEPROTECT-L2     | `dnsbl-2.uceprotect.net`   | block | ASN-level escalation. Flags ASes with many L1-listed IPs.    |
| UCEPROTECT-L3     | `dnsbl-3.uceprotect.net`   | block | Very aggressive. **High false-positive rate** — treat with caution. |
| PSBL              | `psbl.surriel.com`         | block | Passive spam blocklist. Lower coverage, low FP rate.         |
| Mailspike Z       | `z.mailspike.net`          | block | Mailspike's combined reputation zone.                        |
| DNSWL             | `list.dnswl.org`           | allow | Industry-curated allowlist. **Listing here is positive.**    |

The mix is deliberate: Spamhaus ZEN is the canonical heavyweight
(if you're only checking one list, check this one); SpamCop and
Barracuda overlap with ZEN but catch different time windows;
SORBS adds open-proxy / dynamic-IP coverage; UCEPROTECT L1/L2/L3
together let you see the listing escalate from "one IP got
caught" to "whole AS is listed"; PSBL and Mailspike are
narrower-coverage validators; DNSWL exists to give Cathedral
something to *anchor* against — an IP listed by UCEPROTECT-L3 but
also on DNSWL is probably the L3 list being aggressive, not the
operator having a real reputation problem.

## How it works

### The reverse-IP-as-DNS-name trick

DNSBL is defined by [RFC 5782](https://datatracker.ietf.org/doc/html/rfc5782).
The protocol is older than the RFC — MAPS RBL ran on this
mechanism from 1997 — but the RFC formalises it: to ask "is IPv4
`A.B.C.D` on list `example.org`?", you issue an A-record DNS query
for `D.C.B.A.example.org`.

Why reversed? Because DNS reads least-specific labels right-to-left
(`mail.example.com` = `com.example.mail` semantically), and IPv4
groups its most-specific octet left-to-left. Reversing aligns the
two: `4.3.2.1.zen.spamhaus.org` lets Spamhaus delegate `1.zen…` to
"all IPv4 starting with `1.*`", further refine `2.1.zen…` for
"`1.2.*`", and so on. Standard DNS hierarchy infrastructure does
the heavy lifting; the RBL operator runs a single authoritative
nameserver and adds/removes A records to publish their list.

```go
// Cathedral's reverse step:
func reverseIPv4(v4 net.IP) string {
    return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}
// Lookup name: reverseIPv4(ip) + "." + rbl.Zone
ips, err := resolver.LookupHost(ctx, rev+"."+r.Zone)
```

### Response codes — the 127.0.0.x convention

A returned A record is conventionally in the `127.0.0.0/8`
loopback range, with the low octets encoding the listing category.
This isn't a routable address; it's a value-carrying response. Each
RBL operator publishes their own code table.

Spamhaus ZEN's codes (paraphrased from their documentation):

| Response       | Meaning                                                              |
|----------------|----------------------------------------------------------------------|
| `127.0.0.2`    | SBL — direct spam source                                             |
| `127.0.0.3`    | SBL — spammer-supporting service (Spamhaus's CSS sub-list)           |
| `127.0.0.4`    | XBL — exploited host (botnets, open relays, proxies)                 |
| `127.0.0.9`    | XBL — CBL (Composite Blocking List, exploited host source)           |
| `127.0.0.10`   | PBL — IP range that shouldn't be sending mail directly (ISP-declared) |
| `127.0.0.11`   | PBL — Spamhaus-declared end-user IP range                            |

DNSWL's codes signal the trust tier:

| Response       | Meaning                                                              |
|----------------|----------------------------------------------------------------------|
| `127.0.x.0`    | Untrusted — listed but not validated                                 |
| `127.0.x.1`    | Low trust                                                            |
| `127.0.x.2`    | Medium trust                                                         |
| `127.0.x.3`    | High trust (banks, ESPs, major mail providers)                        |
| `127.0.x.10`   | Legitimate financial / banking sender                                |

Cathedral surfaces the raw response string in the `response` field
of the JSON event so the operator can look up specific codes
against the RBL's documentation when the verdict needs deeper
investigation. The default text rendering treats any listing as
just `LISTED (response)` rather than translating every category —
the RBL-to-meaning maps drift over time, and Cathedral being
authoritative about them would be misleading.

### Concurrency and timeouts

Ten lookups in parallel with a 5-second per-list timeout, all
sharing a 25-second overall budget. The system DNS resolver
handles connection-pooling and TTL respect.

```go
ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
defer cancel()

for i, r := range rbls {
    go func(i int, r rbl) {
        cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
        defer cancel()
        ips, err := resolver.LookupHost(cctx, rev+"."+r.Zone)
        // …
    }(i, r)
}
```

In practice most lookups resolve in under 200ms — RBL operators
run high-performance authoritative servers because their service
model depends on mail servers querying them at SMTP-DATA time.
The 5-second cap exists for the long tail and as a global
liveness fence rather than a typical-case bound.

### NXDOMAIN vs error

The single most-important detail in the response classification:
**`NXDOMAIN` is the clean signal**. The RBL only publishes A
records for IPs it has listed; everything else returns
"no such domain." Cathedral surfaces this with
`*net.DNSError.IsNotFound`:

```go
if dnsErr, ok := err.(*net.DNSError); ok {
    return dnsErr.IsNotFound  // → "not listed", not "error"
}
```

A timeout, network failure, or SERVFAIL is *not* the same as
NXDOMAIN — those go into the `errored` bucket separately. The
distinction matters when you're auditing your own egress IP:
"clean across 9 lists" is meaningful only if the 9 actually
answered, not if 3 timed out.

## What Cathedral doesn't do

- **IPv6.** Most RBLs don't publish reverse-IPv6 zones. The few
  that do (Spamhaus, DNSWL) use the nibble-reverse format from
  ip6.arpa — different code path entirely. v1 refuses IPv6 input
  with a clear "not supported" error rather than half-implementing
  it.
- **URI / domain blocklists.** Lists like URIBL and SURBL operate
  on domain names rather than IPs (you query
  `bad-domain.com.uribl.com`, no reversal). Cathedral could ship
  these as a sibling category but they answer a different
  question — "is this URL/domain mentioned in a spam message?"
  rather than "is this IP a known abuser?".
- **Custom RBL zones.** No `--add-zone foo.example.org` flag. The
  ten lists are hardcoded based on coverage + free-availability +
  reasonable-policy criteria. If you need a private RBL or
  internal reputation feed, query it with `dig` directly.
- **TTL-honest caching.** Cathedral re-queries every invocation.
  RBL operators publish short TTLs (often 60-300 seconds) for
  exactly this reason — a listing should clear fast once delisted —
  so re-querying is the right behaviour for forensic accuracy.
  Don't loop `dnsbl <ip>` in a tight script; you'll burn through
  the public-resolver rate limits described below.
- **Rate-limit awareness.** Spamhaus (and others) actively
  rate-limit queries that come from public-recursive resolvers
  (Google `8.8.8.8`, Cloudflare `1.1.1.1`, etc.) because those
  resolvers serve too many clients to be considered "your own
  resolver." If your `/etc/resolv.conf` points at one of these and
  you query Spamhaus enough times, you'll start getting
  artificially "clean" (NXDOMAIN-shaped) responses or query
  failures — the lookup *succeeds*, but the answer is a lie. Use
  a local resolver (Unbound, systemd-resolved, your router) for
  trustworthy RBL data. Cathedral can't detect this from
  client-side observation; it's a known boundary of the
  technique.

## Worked example

End-to-end runs covering the four interesting states.

### Clean across the board (Google DNS)

```
operator@cathedral:~$ dnsbl 8.8.8.8
> querying 10 reputation lists for 8.8.8.8

  [ ✓ ] Spamhaus ZEN     clean
  [ ✓ ] SpamCop          clean
  [ ✓ ] Barracuda        clean
  [ ✓ ] SORBS            clean
  [ ✓ ] UCEPROTECT-L1    clean
  [ ✓ ] UCEPROTECT-L2    clean
  [ ✓ ] UCEPROTECT-L3    clean
  [ ✓ ] PSBL             clean
  [ ✓ ] Mailspike Z      clean
  [ · ] DNSWL            not whitelisted

clean   (0 listed · 0 whitelisted · 0 errors · 10 checked)
```

`8.8.8.8` is Google's anycast DNS — clean across every blocklist
and *also* not on DNSWL. The DNSWL "not whitelisted" line carries
the `[ · ]` (informational) badge rather than a check or cross: an
IP doesn't have to be on DNSWL to be reputable, it just doesn't
get the extra "vouched-for" signal.

### Hostname resolution then check

```
operator@cathedral:~$ dnsbl mail.acme-supplies.example
  mail.acme-supplies.example → 198.51.100.23
> querying 10 reputation lists for 198.51.100.23

  [ ✓ ] Spamhaus ZEN     clean
  [ ✗ ] SpamCop          LISTED  (127.0.0.2)
  [ ✓ ] Barracuda        clean
  [ ✓ ] SORBS            clean
  [ ✗ ] UCEPROTECT-L1    LISTED  (127.0.0.2)
  [ ✓ ] UCEPROTECT-L2    clean
  [ ✗ ] UCEPROTECT-L3    LISTED  (127.0.0.2)
  [ ✓ ] PSBL             clean
  [ ✓ ] Mailspike Z      clean
  [ · ] DNSWL            not whitelisted

listed on 3 RBLs   (3 listed · 0 whitelisted · 0 errors · 10 checked)
```

A fictional company's mail server. Three blocklists agree — but
note which three: SpamCop (recent user reports), UCEPROTECT-L1
(direct-IP observation), and UCEPROTECT-L3 (the very-aggressive
escalation). L3 listing without an L2 listing means the IP got
caught in a wide-net heuristic rather than the AS having a
sustained reputation problem.

Spamhaus ZEN's silence here is telling — ZEN is the
heavyweight, and absent listing there usually means the
SpamCop/UCEPROTECT hits are either narrow-window blips or
shared-IP-block residue. Investigation question: is this address
on a hosting provider's IP block that recently changed tenants?
([`whois`](whois.md) + [`asn`](asn.md) answer that.)

### Heavily listed (clear bad actor)

```
operator@cathedral:~$ dnsbl 185.234.218.71
> querying 10 reputation lists for 185.234.218.71

  [ ✗ ] Spamhaus ZEN     LISTED  (127.0.0.4)
  [ ✗ ] SpamCop          LISTED  (127.0.0.2)
  [ ✗ ] Barracuda        LISTED  (127.0.0.2)
  [ ✗ ] SORBS            LISTED  (127.0.0.6)
  [ ✗ ] UCEPROTECT-L1    LISTED  (127.0.0.2)
  [ ✗ ] UCEPROTECT-L2    LISTED  (127.0.0.2)
  [ ✗ ] UCEPROTECT-L3    LISTED  (127.0.0.2)
  [ ✗ ] PSBL             LISTED  (127.0.0.2)
  [ ✗ ] Mailspike Z      LISTED  (127.0.0.2)
  [ · ] DNSWL            not whitelisted

heavily listed   (9 listed · 0 whitelisted · 0 errors · 10 checked)
```

9-of-9 blocklists agree — and Spamhaus ZEN returned `127.0.0.4`
(XBL, exploited host: botnet / open relay / proxy). UCEPROTECT
escalated from L1 through L3 (single IP → ASN level → aggressive
heuristic) which means the rest of the AS is also implicated. The
`heavily listed` verdict triggers at the ≥3-blocklist threshold,
so this is well past the threshold.

For a forensic context, the differing response codes are useful:
SORBS's `127.0.0.6` means "spam source" specifically, ZEN's
`127.0.0.4` is "exploited host," and the others' `127.0.0.2` is
each list's plain "listed for spam." All consistent with a
botnet-conscripted machine.

### Whitelisted but mid-tier listed (informational)

```
operator@cathedral:~$ dnsbl 209.85.220.41
> querying 10 reputation lists for 209.85.220.41

  [ ✓ ] Spamhaus ZEN     clean
  [ ✓ ] SpamCop          clean
  [ ✓ ] Barracuda        clean
  [ ✓ ] SORBS            clean
  [ ✓ ] UCEPROTECT-L1    clean
  [ ✗ ] UCEPROTECT-L2    LISTED  (127.0.0.2)
  [ ✗ ] UCEPROTECT-L3    LISTED  (127.0.0.2)
  [ ✓ ] PSBL             clean
  [ ✓ ] Mailspike Z      clean
  [ · ] DNSWL            whitelisted (127.0.10.3)

listed on 2 RBLs   (2 listed · 1 whitelisted · 0 errors · 10 checked)
```

A Google outbound mail relay. UCEPROTECT L2/L3 listing alongside
a DNSWL trust-tier-3 ("high trust") whitelist entry is the
canonical false-positive shape: UCEPROTECT's ASN-level heuristics
flag Google's mail AS because the AS contains *some* end-user
addresses that send spam, but Google's actual mail-sending IPs
are individually well-reputed (DNSWL trust 3 is "banks, ESPs,
major mail providers" tier). Real mail systems weight DNSWL very
heavily here and ignore the UCEPROTECT signal.

The DNSWL response `127.0.10.3` decodes as: octet 2 = mail-sending
category (10), octet 3 = trust tier 3 (high).

### Resolution failure

```
operator@cathedral:~$ dnsbl mail.does-not-exist.example
error: could not resolve to IPv4: mail.does-not-exist.example
```

`dnsbl` resolves the hostname before checking blocklists; a
hostname that doesn't resolve gets the early-exit error rather
than producing nine NXDOMAINs against a target that wouldn't have
mattered anyway.

### IPv6 input refused

```
operator@cathedral:~$ dnsbl 2001:db8::1
error: IPv6 not supported by most RBLs
```

Most RBLs don't publish reverse-IPv6 zones, so v1 refuses cleanly
rather than half-implementing the lookup. If you need IPv6
reputation, query Spamhaus's IPv6 zone manually with `dig` for
now.

### Partial errors

```
operator@cathedral:~$ dnsbl 192.0.2.10
> querying 10 reputation lists for 192.0.2.10

  [ ✓ ] Spamhaus ZEN     clean
  [ ! ] SpamCop          error: lookup 10.2.0.192.bl.spamcop.net: i/o timeout
  [ ✓ ] Barracuda        clean
  [ ✓ ] SORBS            clean
  [ ✓ ] UCEPROTECT-L1    clean
  [ ✓ ] UCEPROTECT-L2    clean
  [ ✓ ] UCEPROTECT-L3    clean
  [ ! ] PSBL             error: lookup 10.2.0.192.psbl.surriel.com: i/o timeout
  [ ✓ ] Mailspike Z      clean
  [ · ] DNSWL            not whitelisted

clean   (0 listed · 0 whitelisted · 2 errors · 10 checked)
```

Two lists timed out (`[ ! ]` badge); the rest returned clean. The
verdict line reports `clean` but flags the `2 errors` count — a
clean verdict with errors is *less confident* than a clean verdict
with all 10 lists answering. For a one-off check that's usually
fine; for an audit you'd re-run.

## Output protocol

Line-oriented JSON, one event per line. Event types:

| Event       | Fields                                                                                                       |
|-------------|--------------------------------------------------------------------------------------------------------------|
| `resolved`  | `target` (hostname), `ip` — emitted only when the input was a hostname that resolved                          |
| `start`     | `target`, `ip`, `rbls` (count)                                                                                |
| `result`    | `name`, `zone`, `kind` (`block`/`allow`), `listed`, `verdict` (`good`/`bad`/`warn`/`info`), `response`, `error`, `note`, `took_ms` |
| `summary`   | `listed_block`, `on_allow_list`, `errored`, `checked`, `verdict` (`clean` / `listed on N RBLs` / `heavily listed` / `clean (whitelisted)`) |
| `done`      | sentinel                                                                                                      |
| `error`     | `message` — fatal pre-flight error                                                                            |

Stream-friendly with `jq`:

```
# Get just the listed-on entries
dnsbl 198.51.100.23 | jq -r 'select(.event=="result" and .verdict=="bad") | "\(.name): \(.response)"'

# Boolean exit: is the IP clean across all blocklists?
dnsbl 8.8.8.8 | jq -e 'select(.event=="summary" and .listed_block==0)' >/dev/null \
  && echo "clean"

# Find lists that errored — useful for resolver-health checks
dnsbl 192.0.2.10 | jq -r 'select(.event=="result" and .error != "") | .name'

# Per-list latency table for tuning the per-RBL timeout
dnsbl 8.8.8.8 | jq -r 'select(.event=="result") | "\(.took_ms)ms\t\(.name)"'
```

## Limitations

- **Spamhaus public-resolver poisoning.** Spamhaus blocks
  queries that come via Google / Cloudflare / Quad9 / other
  public recursors. Your `/etc/resolv.conf` matters more than
  you'd think; check `resolvectl status` or `cat /etc/resolv.conf`
  before relying on a clean verdict from ZEN. The canonical
  test: `dig @1.1.1.1 4.3.2.1.zen.spamhaus.org` — if Cloudflare's
  resolver returns the same answer your local one does, you're
  fine; if they diverge, the public resolver is the one being
  lied to (or rate-limited into NXDOMAIN-shaped silence).
- **The ten-list set is hardcoded.** No `--lists` flag, no
  config file, no add-your-own. The lists were chosen for
  free-availability + reasonable-policy + meaningful-coverage
  criteria; if you need a different mix, the source is short
  enough to fork.
- **No per-RBL ignore.** `UCEPROTECT-L3` produces a lot of
  noise; you may want a `--skip=uceprotect-l3` flag. Planned.
- **No TXT-record reason fetching.** Most RBLs publish a TXT
  record alongside the A record explaining *why* the IP is
  listed (a forum URL, a date, an originating-mail header). v1
  shows only the A-record code; v2 would issue a parallel TXT
  query when the A query returns a hit.
- **No domain blocklists (URIBL / SURBL).** Different question,
  different protocol shape — domain.URIBL.zone rather than
  reversed-IP.zone. Worth a sibling command but not this one.
- **Sequential summary, not streaming.** The summary event fires
  after all ten lookups complete (or time out), not
  incrementally — fine for human eyes, but a programmatic
  consumer that wants early-out on the first listing should
  read the per-result events and compute the verdict itself.

## Authorized use

DNS reputation lookups are passive third-party DNS queries. The
authorization considerations are:

- **Querying public RBLs about any IP is fine.** The lists are
  published exactly so anyone can check; there's no "are you
  authorized to look up this IP?" implied. Mail servers issue
  millions of these queries per day at SMTP-DATA time.
- **Querying RBLs *via your local resolver*** routes those
  lookups through your resolver's cache, which is yours to
  manage. The same query against a public resolver is shared
  with that operator's logging.
- **The list publishers' terms** matter for high-volume
  programmatic use. Spamhaus's free tier explicitly prohibits
  scaling beyond ~300k queries/day from one source and
  prohibits use via public resolvers as described above; if
  you find yourself looping `dnsbl` in a script over thousands
  of IPs, you've crossed into a use case where you should be
  using Spamhaus's licensed DQS service, not the public DNS
  interface.
- **An IP being listed isn't a finding by itself.** Old IP-block
  assignments, shared hosting platforms, and dynamic IP pools
  routinely show stale listings that don't reflect the current
  tenant's behaviour. Cross-reference with [`whois`](whois.md)
  for allocation history and [`asn`](asn.md) for the AS context
  before treating an RBL hit as actionable.

## Further reading

- [RFC 5782 — DNS Blacklists and Whitelists](https://datatracker.ietf.org/doc/html/rfc5782)
  — the protocol specification. Covers the reverse-IP shape,
  IPv6 nibble form, response-code conventions, and the
  liveness-test convention (every RBL must list `127.0.0.2`
  and not list `127.0.0.1` so clients can probe).
- [Spamhaus DNSBL return codes](https://www.spamhaus.org/zen/return-codes/)
  — the authoritative code table for ZEN. Re-check whenever a
  forensic investigation hinges on a specific code; Spamhaus
  publishes updates as new categories get added.
- [DNSWL trust-level documentation](https://www.dnswl.org/?page_id=15)
  — what each octet of a DNSWL response means. The trust-level
  scale is `none → low → medium → high → financial`; categories
  cover ESPs, organisational mail, banks, etc.
- [SORBS zones](http://www.sorbs.net/general/using.shtml) —
  SORBS aggregates multiple sub-zones (DUHL, SOCKS, web, spam);
  the `dnsbl.sorbs.net` shortcut Cathedral uses covers all of
  them as one query.
- [UCEPROTECT policy](http://www.uceprotect.net/en/index.php?m=6&s=11)
  — important reading on L3 false positives. UCEPROTECT
  explicitly markets L3 as "very aggressive, will list good
  neighbourhoods"; their own documentation recommends most mail
  systems ignore L3 and use L1 + L2 only.
- [`mx-rep`](mx-rep.md) — the related entry that walks a
  domain's MX records and runs five RBL checks per IP. Same
  technique, different question.
- [`asn`](asn.md) — when an RBL listing surfaces, the AS
  context tells you whether the listing implicates the whole
  network or just one address.
- [`whois`](whois.md) — IP allocation history; helpful when
  you need to know whether a stale listing predates the
  current tenant.
- [`reverse-dns`](reverse-dns.md) — the PTR record for the IP
  is often a useful corroboration: `static.dynamicpool.isp.example`
  + a UCEPROTECT-L1 listing makes the verdict obvious.
