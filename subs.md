---
title: subs — live subdomain enumeration from CT logs + wordlist
command: subs
category: dns-identity
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-06-23
related: [crt, dns, reverse-dns, dirscan]
---

# `subs` — live subdomain enumeration from CT logs + wordlist

`subs` maps the live subdomains of a domain. It gathers candidate
names from two sources — historical names from Certificate
Transparency logs and a curated brute-force wordlist — resolves
every candidate in parallel, and reports only the ones that actually
answer DNS, tagged by which source found them.

```
subs example.com
```

One argument: the apex domain. The output is the set of subdomains
that resolve *right now* — not every name that has ever existed, but
the ones standing up live infrastructure today.

## What it does

For one domain, `subs` runs two phases:

1. **Gather candidates.**
   - **crt.sh history** — every name that has ever appeared in a TLS
     certificate for the domain (Certificate Transparency is an
     append-only public log; certificates are issued for real hosts,
     so the names are real leads). This phase is passive — it reads
     a public log, it does not touch the target.
   - **Wordlist** — a curated 139-label list of common subdomain
     conventions (`admin`, `dev`, `staging`, `api`, `mail`, `vpn`,
     `grafana`, `git`, `ci`, …), each prepended to the domain.
2. **Resolve and filter.** Every candidate is resolved via DNS in
   parallel; only those returning at least one IP are emitted. Each
   live result is tagged `crt`, `wl`, or `crt+wl` by where it came
   from, with its resolved address(es).

The result is a deduplicated, live, source-attributed subdomain map
— the attack surface as it exists today, not as it once was.

## What it answers

- *"What's actually running under this domain?"* — the live host
  inventory: `api.`, `staging.`, `vpn.`, `grafana.`, `git.`, and the
  rest.
- *"What did they forget to take down?"* — CT logs remember names
  long after the marketing site does. A `legacy-`, `old-`, or
  `staging-` host that still resolves is exactly the kind of
  under-maintained surface an assessment cares about.
- *"crt vs wordlist — which found it?"* — the source tag tells you
  whether a host was publicly certificate-logged (`crt`) or only
  surfaced by guessing a common name (`wl`). A `wl`-only hit is a
  host with no public certificate footprint.

## How it works

### Phase 1 — Certificate Transparency (passive)

`subs` queries crt.sh for `%.<domain>` and pulls every
`name_value` field, splitting multi-name SANs, lowercasing, and
deduplicating. Wildcard entries (`*.example.com`) are reduced to
their parent label rather than kept literally:

```go
q := "%25." + domain                       // %.<domain>
u := "https://crt.sh/?q=" + url.QueryEscape(q) + "&output=json"
// … for each entry, split name_value on "\n", lowercase, dedupe …
```

crt.sh is a free public service that occasionally returns errors or
times out. `subs` treats that as non-fatal — it emits a `warn` and
proceeds with the wordlist phase, because the brute-force half is
where most of the value is. (For a dedicated, full CT dump *with
first-seen dates*, use the standalone [`crt`](crt.md) command.)

### Phase 2 — wordlist + parallel resolution

The candidate set is the union of the CT names and
`<word>.<domain>` for every wordlist label, with the bare apex
dropped (we report on *sub*domains). The wordlist is deliberately
small — 139 high-signal labels covering admin panels, dev/staging
stages, mail/DNS infra, API conventions, CI/CD, and SaaS tooling —
so the resolve phase finishes in seconds without flooding DNS.

Resolution runs 32 candidates at a time, each with a 3-second
timeout, under a 50-second overall budget, using the system
resolver:

```go
ips, err := resolver.LookupHost(cctx, name)
if err != nil || len(ips) == 0 {
    return // silent — only live names are emitted
}
emit(event{"event":"found", "name":name, "ips":ips, "source":source})
```

Only resolving names produce a `found` event; the (typically large)
majority that don't resolve are counted but not printed. The
`source` field is computed per hit: a wordlist name that *also*
appeared in CT history is tagged `both`.

## Worked example

> Illustrative output — fabricated against a documentation domain.
> Real results depend on the live CT log and DNS.

```
operator@cathedral:~$ subs acme-corp.example
> enumerating subs of acme-corp.example via crt.sh history + wordlist brute
  crt.sh: 23 historical names
  resolve phase: 147 candidates

  [crt+wl] www.acme-corp.example                    203.0.113.10
  [crt   ] grafana.acme-corp.example                203.0.113.42
  [wl    ] api.acme-corp.example                     203.0.113.20  (+1)
  [wl    ] staging.acme-corp.example                 198.51.100.7
  [crt   ] legacy-vpn.acme-corp.example              198.51.100.33
  [wl    ] git.acme-corp.example                     203.0.113.51

enumeration complete — 12 resolved / 135 unresolved
```

Reading this: `grafana.` and `legacy-vpn.` came from certificates
(`crt`) — real, logged, and the `legacy-` one is the classic
forgotten host. `api.`, `staging.`, and `git.` were found only by
the wordlist (`wl`) — live hosts with no public certificate
footprint, which a CT-only tool would have missed entirely. `www.`
showed up in both. The `(+1)` on `api.` means it resolved to more
than one address (round-robin / multi-A).

## Output protocol

Line-oriented JSON.

```
{"event":"start",   "domain":"…","sources":["crt.sh history","wordlist brute"],"wordlist_size":139}
{"event":"phase",   "name":"crt.sh","found":N}
{"event":"phase",   "name":"resolve","candidates":N}
{"event":"found",   "name":"…","ips":["…"],"source":"crt.sh|wordlist|both"}*
{"event":"warn",    "source":"crt.sh","error":"…"}     # non-fatal CT failure
{"event":"summary", "candidates":N,"resolved":N,"unresolved":N,"crt_only":N}
{"event":"done"}
{"event":"error",   "message":"…"}                     # fatal (bad input)
```

Pipe-friendly — a clean list of live subdomains and their IPs:

```
$ subs example.com | jq -r 'select(.event=="found") | "\(.name)\t\(.ips|join(","))"'

# Only the wordlist-only hits (live but not certificate-logged)
$ subs example.com | jq -r 'select(.event=="found" and .source=="wordlist") | .name'
```

## Limitations

- **Live names only.** A subdomain that exists in CT history but no
  longer resolves is dropped. `subs` answers "what's up now," not
  "what has ever existed" — for the full historical list, use
  [`crt`](crt.md).
- **The wordlist is small by design.** 139 labels catch the common
  conventions, not the long tail. A site with an unusually-named
  host (`whisper-prod-eu3.`) won't be found by brute force — only
  by CT, if it was ever certificate-logged. This is a deliberate
  speed/coverage trade, not an exhaustive enumerator.
- **Wildcard DNS inflates results.** A domain with a `*` record
  resolves *every* candidate, so a `subs` run against it reports the
  whole wordlist as "live." The output is still true (they do
  resolve) but no longer discriminating.
- **No recursive brute-force.** `subs` enumerates `<word>.<domain>`,
  not `<word>.<found-sub>.<domain>`. Deeper labels come only from
  CT history.
- **crt.sh is flaky.** The CT phase can return a 502 or time out;
  when it does, you get the wordlist results plus a `warn`, not a
  failure.
- **System-resolver dependent.** Resolution uses the host's
  configured resolver, so split-horizon DNS, a captive resolver, or
  aggressive caching can shape what's visible.

## Authorized use

`subs` is **standard reconnaissance** and **low-risk**. The CT
phase reads a public, append-only log and touches nothing belonging
to the target. The resolve phase issues ordinary DNS lookups
through your configured resolver — the same queries any browser
makes — not direct probes against the target's servers.

That said, enumerating a domain's subdomains is mapping its attack
surface, and that's a pre-engagement activity:

- **Map domains you own or are authorized to assess.** Your own
  infrastructure, or a target explicitly in the scope of an
  authorized engagement.
- **Subdomain enumeration is the first step of a great many
  intrusions.** Doing it against third-party domains you have no
  authorization for is reconnaissance-for-intrusion in posture,
  even though each individual query is innocuous. Stay in scope.
- **Live results name real systems.** A `subs` map is a list of
  someone's running infrastructure; treat the output accordingly.

## Further reading

- [crt.sh](https://crt.sh/) — the Certificate Transparency search the CT phase queries.
- [Certificate Transparency](https://certificate.transparency.dev/) — why every issued certificate becomes a public, permanent subdomain lead.
- Related Cathedral commands: [`crt`](crt.md) (full CT-log dump with first-seen dates), [`dns`](dns.md) (records for a single name), [`reverse-dns`](reverse-dns.md) (PTR sweep across a subnet), [`dirscan`](dirscan.md) (the same brute-force idea, one layer up, against a web server's paths).
