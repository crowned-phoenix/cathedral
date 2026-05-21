---
title: dmarc — DMARC policy evaluator with grade A→F
command: dmarc
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [spf, mx-rep, dns, whois]
---

# `dmarc` — DMARC policy evaluator with grade A→F

`dmarc` reads the `v=DMARC1` TXT record at `_dmarc.<domain>`,
parses every published tag (`p` / `sp` / `pct` / `rua` / `ruf`
/ `adkim` / `aspf` / `fo` / `ri` / `rf`), and grades the policy
on its enforcement strength. Where [`spf`](spf.md) covers the
*authorisation* layer (which IPs may send), `dmarc` covers the
*alignment* layer (whether the visible `From:` matches the
authenticated identifiers) — and crucially, whether the domain
is publishing a policy strong enough that receivers will
actually act on failures.

DMARC is what makes SPF and DKIM useful against the most common
phishing pattern: spoofing the visible `From:` header. SPF and
DKIM on their own only authenticate envelope-level identifiers
that users never see. DMARC binds those identifiers to the
`From:` header the recipient reads — and tells receivers what
to do when they don't match. A site running `p=none` is
*publishing* DMARC but not *enforcing* it; a site running
`p=reject` with `pct=100` is rejecting unaligned mail outright.

```
dmarc gmail.com
dmarc acme-supplies.example
dmarc _dmarc.acme-supplies.example      # equivalent — the prefix is auto-added
```

## What it does

For a single domain, Cathedral:

1. Queries TXT records at `_dmarc.<domain>`.
2. Picks the entry starting with `v=DMARC1` (warns if more
   than one).
3. Tokenises the semicolon-separated `key=value` tags.
4. Renders each tag with its human-readable label.
5. Reports whether aggregate (`rua`) and forensic (`ruf`)
   report destinations are configured.
6. Grades the policy A–F based on enforcement strength.

| Outcome                                       | Grade |
|-----------------------------------------------|-------|
| No `v=DMARC1` record at `_dmarc.<domain>`     | `F`   |
| `p=reject` with `pct=100`                     | `A`   |
| `p=reject` with `pct<100` (gradual rollout)   | `B`   |
| `p=quarantine`                                | `B`   |
| `p=none` with aggregate-report URI            | `C`   |
| `p=none` without `rua`                        | `D`   |

The summary lines that accompany the grade — `p=reject at 100%
— strict enforcement`, `p=none — monitoring only, no
enforcement`, `subdomain policy differs (sp=reject)` — make the
policy intent legible without needing to parse the tag soup
manually.

## What it answers

**Defender:** *"Is our DMARC actually enforcing?"* The most
common DMARC misstep isn't *absence* — it's stalling at
`p=none` for years. Every domain that publishes DMARC publishes
it eventually; very few make it past the monitoring phase to
quarantine or reject. `dmarc` against your own domains
distinguishes "we published a DMARC record" from "we're
actually protected": the difference between C-grade monitoring
and A-grade enforcement is the difference between knowing about
phishing and stopping it.

**Recon (authorized testing only):** *"Is this domain
spoofable?"* A site with no DMARC, with `p=none`, or with a
`sp=` policy weaker than `p` is *trivially* spoofable from any
sending infrastructure — the visible `From:` header can be
freely set and the mail will land in inboxes. The grade
correlates strongly with the *practical risk* of pretending to
be the domain in a phishing context.

**Investigation:** *"How does this domain handle alignment?"*
The `adkim` and `aspf` tags control whether the From-header
domain must match the DKIM signing domain / SPF MAIL-FROM
exactly (`s`) or only at the organisational level (`r`). Most
deployments use relaxed; strict is the harder bar that breaks
many vendor integrations. Knowing which is in use shapes any
analysis of why specific mail flows succeed or fail
authentication.

**Identification:** *"Who handles this domain's DMARC
analytics?"* The `rua=` and `ruf=` URIs frequently reveal the
DMARC-analytics vendor. Common patterns: `dmarc.postmarkapp.com`,
`dmarc.cloudflare.net`, `dmarcian.com`, `valimail.com`,
`uriports.com`. Each is a vendor relationship visible from one
TXT query.

## How it works

### The DMARC record

DMARC records live on a fixed subdomain — `_dmarc.<domain>` —
and start with the literal string `v=DMARC1`:

```
_dmarc.acme-supplies.example.   IN   TXT   "v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@acme-supplies.example; ruf=mailto:dmarc-forensic@acme-supplies.example"
```

The record is semicolon-separated `key=value` pairs. Only `v`
and `p` are required; the rest carry sensible defaults.
Cathedral parses every tag and surfaces it under its
human-readable label:

```go
var tagLabels = map[string]string{
    "v":     "version",
    "p":     "policy",
    "sp":    "subdomain policy",
    "pct":   "percent",
    "rua":   "aggregate reports",
    "ruf":   "forensic reports",
    "adkim": "DKIM alignment",
    "aspf":  "SPF alignment",
    "fo":    "failure options",
    "ri":    "report interval",
    "rf":    "report format",
}
```

Unknown tags are emitted with a `(custom)` label rather than
silently dropped — receivers ignore tags they don't recognise,
so publishing `custom=value` is allowed, though uncommon.

### The policy ladder: none → quarantine → reject

The `p=` tag is the policy instruction to receiving mail
servers. Three values:

- **`p=none`** — "monitor only". Receivers don't act on
  alignment failures, but they *should* report them via the
  aggregate-report channel. This is the entry-level policy for
  any DMARC deployment; the operator collects reports for 30+
  days before tightening.
- **`p=quarantine`** — "treat unaligned mail as suspicious".
  Receivers typically route to the spam folder rather than the
  inbox. Lower-stakes enforcement; legitimate-but-misconfigured
  mail still reaches the user, just slower.
- **`p=reject`** — "refuse unaligned mail outright". Receivers
  bounce the message at SMTP time. This is the goal state — at
  `p=reject` your domain is fully protected against `From:`
  spoofing.

The `pct=` tag (default 100) is the rollout percentage. A
deployment can run `p=quarantine; pct=10` to apply quarantine
to 10% of failing mail (sampled by the receiver) while
leaving the other 90% with the previous behaviour. This
enables gradual migration: `p=quarantine` at 10%, then 25%,
then 50%, then 100%, then move to `p=reject` and repeat.

Cathedral's grading reflects the ladder:

```go
case policy == "reject" && pct == "100":
    return "A", notes
case policy == "reject":
    return "B", notes  // p=reject but pct<100 — partial enforcement
case policy == "quarantine":
    return "B", notes
case policy == "none" && rua != "":
    return "C", notes  // monitoring with visibility
case policy == "none":
    return "D", notes  // monitoring without visibility (flying blind)
```

The C-versus-D distinction is the load-bearing one: a domain
that publishes `p=none` without `rua=` is publishing the
policy syntactically but receiving none of the operational
value (no reports, no view into spoofing attempts). Going
past `p=none` into enforcement is impossible without report
data to validate the rollout; without `rua=`, the deployment
is essentially performative.

### Alignment: `adkim` and `aspf`

DMARC's job is to check that the visible `From:` header
domain *aligns* with the domain that SPF or DKIM
authenticated. Two flavours of alignment:

- **Relaxed (`r`, the default)** — same *organisational*
  domain is enough. `mail.acme-supplies.example` aligns
  with `acme-supplies.example`. This handles the common
  case where mail is sent from a subdomain (the bounce
  envelope) but the `From:` header uses the main domain.
- **Strict (`s`)** — the domains must be identical.
  `mail.acme-supplies.example` does *not* align with
  `acme-supplies.example`. Strict alignment is more
  precise but breaks many real-world setups where vendors
  send from delegated subdomains.

Most real DMARC deployments use the relaxed defaults. The
`adkim=s` / `aspf=s` upgrade comes after the rest of the
mail authentication stack is fully audited — vendor
relationships catalogued, every legitimate sender's exact
DKIM-signing domain known.

### Aggregate vs forensic reports

Two reporting channels:

- **`rua=mailto:…`** (aggregate reports) — receivers send a
  daily XML summary of every alignment outcome to this
  address. Gmail, Outlook, Yahoo, AOL, and most major
  ISPs send these. Aggregate reports list every sending IP,
  message count, SPF/DKIM/DMARC results, and the receiver's
  enforcement decision. They are the *only* visibility into
  what's actually happening to your domain's mail.
- **`ruf=mailto:…`** (forensic reports) — per-failure
  samples of the actual failing messages (with PII redacted
  to varying degrees). Far less commonly supported (only
  some receivers send them, citing privacy concerns) but
  occasionally useful for debugging specific failures.

A DMARC record without `rua=` is the *flying blind* case
Cathedral grades as D — the policy is syntactically present
but operationally invisible. Adding `rua=` is the first thing
a real DMARC deployment does after `p=none`.

The values are typically `mailto:` URIs:

```
rua=mailto:dmarc@example.com
rua=mailto:rua@dmarc-reports.acme-vendor.com
rua=mailto:dmarc@example.com,mailto:rua@vendor.com    # multiple destinations allowed
```

External `rua` destinations (a destination outside the policy
domain) require a confirmation TXT record at the destination
domain — `example.com._report._dmarc.dmarc-vendor.com` must
exist and say `v=DMARC1`. Cathedral doesn't verify this;
mxtoolbox does.

### Subdomain policy: `sp=`

The `sp=` tag specifies a *separate* policy for subdomains.
A common pattern is:

```
v=DMARC1; p=quarantine; sp=reject; rua=mailto:dmarc@example.com
```

— the main domain is at `quarantine` (still rolling out), but
all subdomains are at `reject`. The asymmetry is deliberate:
the main domain has lots of legitimate-but-misconfigured
sending sources (vendor integrations, transactional services,
internal apps), so the operator is being cautious about
turning on enforcement. Subdomains are typically simpler — the
operator knows exactly what should send from them, so `reject`
is safe.

Cathedral notes the `sp=` value when it differs from `p`:

```go
if subPolicy != "" && subPolicy != policy {
    notes = append(notes, "subdomain policy differs (sp="+subPolicy+")")
}
```

The note surfaces the asymmetry; the grade is still computed
from `p` (the main-domain policy).

### `fo=`, `ri=`, `rf=`

Three less-common tags:

- **`fo=`** (failure options) — when forensic reports should
  fire. Values: `0` (only when *all* authentication fails — the
  default), `1` (when any check fails), `d` (only on DKIM
  failure), `s` (only on SPF failure). Combinations are allowed
  with colon separator: `fo=d:s`.
- **`ri=`** (report interval, seconds) — requested cadence
  for aggregate reports. Default is 86400 (daily). Most
  receivers honour the request loosely; daily is the standard.
- **`rf=`** (report format) — almost always `afrf` (the only
  defined value). Tag survives from a future-proofing intent
  that never materialised.

These are surfaced if present but rarely affect grading.

## What Cathedral doesn't do

A few deliberate omissions:

- **No alignment evaluation against an actual message.** `dmarc`
  reads the policy; it doesn't take an inbound mail header and
  compute pass/fail. For that, a real receiving server or a
  specialised tool like Authentication-Results parsers is the
  right reach.
- **No DKIM key inspection.** DKIM is one of the two
  underlying authentication mechanisms, but its keys live at
  `<selector>._domainkey.<domain>` TXT records — selector-
  specific, and Cathedral doesn't enumerate selectors. Use
  [`dns`](dns.md) directly: `dns selector1._domainkey.example.com
  --types=TXT`.
- **No external-destination verification.** `rua=mailto:…` to
  an address outside the policy domain requires a confirmation
  record at the destination; Cathedral doesn't check this.
- **No `rua` mailbox inspection.** Reports go to a mailbox that
  Cathedral can't read. Aggregate-report analysis is a separate
  workflow (Postmark DMARC Digests, dmarcian, EasyDMARC, etc.).
- **One domain at a time.** No portfolio mode; iterate in the
  shell.
- **No subdomain enumeration.** `dmarc <domain>` queries the
  policy at `_dmarc.<domain>` only. Subdomain-level policies
  (when `sp=` differs from `p=`) inherit from the parent unless
  the subdomain has its own `_dmarc.<sub>.<domain>` record.
  Cathedral doesn't walk this.
- **No tag-value validation beyond known keys.** Cathedral
  surfaces `p=foo` as a tag without complaining; the grading
  classifies unknown policies as F. For strict tag-value
  validation use mxtoolbox or dmarcian.

## Worked example

A strict modern setup, a migration in progress, monitoring
only, and the missing-record case.

### Strict modern setup (A)

```
operator@cathedral:~$ dmarc acme-supplies.example
> querying _dmarc.acme-supplies.example

  v=DMARC1; p=reject; sp=reject; pct=100; adkim=s; aspf=s; rua=mailto:dmarc@acme-supplies.example; ruf=mailto:dmarc-forensic@acme-supplies.example; fo=1

[ tags ]
  v      version                v=DMARC1
  p      policy                 reject
  sp     subdomain policy       reject
  pct    percent                100
  adkim  DKIM alignment         s
  aspf   SPF alignment          s
  rua    aggregate reports      mailto:dmarc@acme-supplies.example
  ruf    forensic reports       mailto:dmarc-forensic@acme-supplies.example
  fo     failure options        1

[ reports ]
  aggregate : mailto:dmarc@acme-supplies.example
  forensic  : mailto:dmarc-forensic@acme-supplies.example

  · p=reject at 100% — strict enforcement

grade   : A
```

The full hardened shape: `p=reject` at 100% rollout, strict
alignment on both DKIM and SPF (`adkim=s; aspf=s`), `sp=reject`
matching the parent, aggregate and forensic reports both
configured, `fo=1` requesting forensic reports on any auth
failure. Mail that doesn't perfectly align with this domain
gets rejected at SMTP time. Spoofing attempts that flow through
any DMARC-respecting receiver (Gmail, Outlook, Yahoo, and most
ISPs) bounce.

This is the *correct* end state for a DMARC deployment. Many
years of work for most organisations to reach.

### Migration in progress (B)

```
operator@cathedral:~$ dmarc shop.acme-supplies.example
> querying _dmarc.shop.acme-supplies.example

  v=DMARC1; p=quarantine; sp=reject; pct=50; rua=mailto:rua@dmarc-reports.acme-supplies.example; ruf=mailto:ruf@dmarc-reports.acme-supplies.example; fo=d:s

[ tags ]
  v      version                v=DMARC1
  p      policy                 quarantine
  sp     subdomain policy       reject
  pct    percent                50
  adkim  DKIM alignment         r
  aspf   SPF alignment          r
  rua    aggregate reports      mailto:rua@dmarc-reports.acme-supplies.example
  ruf    forensic reports       mailto:ruf@dmarc-reports.acme-supplies.example
  fo     failure options        d:s

[ reports ]
  aggregate : mailto:rua@dmarc-reports.acme-supplies.example
  forensic  : mailto:ruf@dmarc-reports.acme-supplies.example

  · p=quarantine — failing mail goes to spam
  · subdomain policy differs (sp=reject)

grade   : B
```

A real migration captured in mid-flight. The main domain is at
`p=quarantine` with `pct=50` (half of unaligned mail goes to
spam; the other half is delivered as before — gradual
rollout). Subdomains are already at `p=reject` (the operator
audited subdomain senders first, found them simpler, and
locked them down). Alignment is relaxed (`adkim=r; aspf=r`)
because the production vendor stack still includes services
that sign from delegated subdomains. Aggregate reports are
collected via a vendor-hosted DMARC-analytics platform; the
`fo=d:s` tag means forensic reports fire on either DKIM-only
or SPF-only failures (both checks failing is the default).

The grade is B because the *strongest* enforcement on the main
domain is quarantine (not reject), and the rollout isn't yet
at 100%. The path forward: bump `pct` toward 100, then move
`p=` to `reject`.

### Monitoring only (C)

```
operator@cathedral:~$ dmarc blog.acme-supplies.example
> querying _dmarc.blog.acme-supplies.example

  v=DMARC1; p=none; rua=mailto:dmarc-reports@dmarc.cloudflare.net

[ tags ]
  v      version                v=DMARC1
  p      policy                 none
  pct    percent                100
  adkim  DKIM alignment         r
  aspf   SPF alignment          r
  rua    aggregate reports      mailto:dmarc-reports@dmarc.cloudflare.net

[ reports ]
  aggregate : mailto:dmarc-reports@dmarc.cloudflare.net
  forensic  : (none)

  · p=none — monitoring only, no enforcement

grade   : C
```

The "we published DMARC but haven't enforced it" case. The
domain is collecting aggregate reports (delegated to
Cloudflare's DMARC analytics platform, which reveals the
vendor stack), so visibility is in place — but `p=none` means
receivers don't act on alignment failures. Spoofed mail from
this domain still gets delivered. The C grade reflects "you
have a deployment, but it doesn't protect you yet".

The path forward: review the aggregate reports for a few
weeks, identify legitimate senders, fix their SPF/DKIM, then
move to `p=quarantine; pct=10` and increment from there.
Many organisations spend years stuck at this step.

### Flying blind (D)

```
operator@cathedral:~$ dmarc unloved.example
> querying _dmarc.unloved.example

  v=DMARC1; p=none

[ tags ]
  v      version                v=DMARC1
  p      policy                 none
  pct    percent                100
  adkim  DKIM alignment         r
  aspf   SPF alignment          r

[ reports ]
  aggregate : (none)
  forensic  : (none)

  · p=none — monitoring only, no enforcement
  · no aggregate report URI (rua) — flying blind

grade   : D
```

`p=none` with no `rua=` is the *worst* of both worlds: no
enforcement, *and* no visibility. The domain is in a state
that publishes DMARC syntactically (which may satisfy a
compliance checkbox somewhere) but provides none of the
operational protection or observation. This is typically a
copy-paste deployment where someone added a DMARC record
without understanding why; the fix is "add `rua=mailto:…`
and start collecting reports", which is a 5-minute change
that unlocks the rest of the migration.

### No record (F)

```
operator@cathedral:~$ dmarc legacy-portal.example
> querying _dmarc.legacy-portal.example
  ! no DMARC record at _dmarc.legacy-portal.example

grade   : F  (no record)
```

No DMARC published at all. Receivers fall back to inferring
policy from the SPF, which is significantly weaker (SPF
authenticates the envelope sender, not the visible `From:`).
For a domain that sends mail, this is a finding: every
`@legacy-portal.example` mail address is trivially spoofable
because no receiver has a published instruction to align
the `From:` header.

For a domain that *shouldn't* send mail (a redirect-only
host, an asset-only subdomain), the canonical hardening is to
publish:

```
_dmarc.legacy-portal.example.  IN  TXT  "v=DMARC1; p=reject; rua=mailto:dmarc@parent-domain.example"
```

— `p=reject` plus reports going to the parent organisation's
DMARC inbox. Any mail attempted from this domain gets
rejected and logged for awareness.

## Output protocol

```
{"event":"start",     "domain":"…"}
{"event":"record",    "domain":"_dmarc.…","text":"v=DMARC1; …"}
{"event":"tag",       "key":"…","label":"…","value":"…"}         *per tag
{"event":"reports",   "has_aggregate":bool,"has_forensic":bool,
                      "aggregate_uri":"…","forensic_uri":"…"}
{"event":"no_record", "domain":"_dmarc.…","error":"…"}            # optional
{"event":"warn",      "message":"…"}                              # optional
{"event":"summary",   "found":bool,"grade":"A|B|C|D|F","notes":[…]}
{"event":"done"}
{"event":"error",     "message":"…"}
```

Extract the grade across a list of domains:

```
$ for d in $(cat domains.txt); do
    grade=$(dmarc "$d" -j | jq -r 'select(.event=="summary") | .grade')
    printf '%-40s %s\n' "$d" "$grade"
  done | sort -k2
acme-supplies.example                A
api.acme-supplies.example            A
shop.acme-supplies.example           B
docs.acme-supplies.example           C
blog.acme-supplies.example           C
unloved.example                      D
legacy-portal.example                F
```

Find domains stuck at `p=none` for too long (the canonical
deployment-paralysis pattern):

```
$ for d in $(cat domains.txt); do
    dmarc "$d" -j |
      jq -r --arg d "$d" \
        'select(.event=="tag" and .key=="p" and .value=="none") |
         "\($d)\tp=none"'
  done
```

Map the DMARC-analytics vendors used across a portfolio:

```
$ for d in $(cat domains.txt); do
    dmarc "$d" -j |
      jq -r 'select(.event=="tag" and .key=="rua") | .value'
  done | sort -u | awk -F'@' '{print $2}' | sort | uniq -c | sort -rn
     12 acme-supplies.example
      4 dmarc.cloudflare.net
      3 rep.dmarcian.com
      2 reports.postmarkapp.com
      1 valimail.com
```

Find domains with subdomain policy stronger than parent
(the *sp asymmetry* often hints at incomplete rollout):

```
$ for d in $(cat domains.txt); do
    p=$(dmarc "$d" -j | jq -r 'select(.event=="tag" and .key=="p") | .value')
    sp=$(dmarc "$d" -j | jq -r 'select(.event=="tag" and .key=="sp") | .value')
    if [ -n "$sp" ] && [ "$p" != "$sp" ]; then
      printf '%-40s p=%s  sp=%s\n' "$d" "$p" "$sp"
    fi
  done
shop.acme-supplies.example           p=quarantine  sp=reject
internal.acme-supplies.example       p=none        sp=reject
```

## Limitations

- **No actual alignment evaluation.** Cathedral parses the
  policy; it doesn't take a mail header and decide
  pass/fail. For that, a real receiving server or specialised
  parser is needed.
- **No DKIM key inspection.** DKIM keys are on per-selector
  subdomains Cathedral doesn't enumerate. Use [`dns`](dns.md)
  directly with `--types=TXT` against
  `<selector>._domainkey.<domain>`.
- **No external-rua verification.** Aggregate-report
  destinations outside the policy domain require a
  confirmation record Cathedral doesn't check.
- **No report-data integration.** Cathedral reports the policy
  configuration; it doesn't read or process the aggregate
  reports that arrive at the `rua` address. DMARC analytics
  is a separate workflow (Postmark Digests, dmarcian,
  EasyDMARC, internal Splunk).
- **Single domain.** No subdomain walking; if you query
  `dmarc parent.example` and want to know what the policy at
  `_dmarc.api.parent.example` says, query that explicitly.
- **First v=DMARC1 record only.** Multiple records is invalid
  per RFC; Cathedral warns and proceeds with the first.
- **10-second timeout.** Slow resolvers may time out; rerun
  with the system resolver pointing somewhere faster.
- **No tag-value validation beyond known policies.** A typo
  like `p=quarintine` falls into the unknown bucket and
  grades F; mxtoolbox flags this more clearly.

## Authorized use

`dmarc` is **passive recon against a public dataset**. One
DNS TXT query per invocation; the queried domain's
infrastructure never sees the request. Risk profile is the
same as [`spf`](spf.md) or [`dns`](dns.md) — DNS lookups are
unremarkable and the targets of the query never observe the
activity.

The output may surface DMARC-analytics-vendor relationships
(`rua=mailto:…@dmarcian.com` reveals dmarcian is the
analytics partner) which are arguably less public than the
policy itself. For published security reports, double-check
that the `rua`/`ruf` URIs aren't operationally sensitive
before publishing.

## Further reading

- [RFC 7489 — Domain-based Message Authentication, Reporting, and Conformance (DMARC)](https://www.rfc-editor.org/rfc/rfc7489) — the authoritative spec
- [RFC 8617 — Authenticated Received Chain (ARC) Protocol](https://www.rfc-editor.org/rfc/rfc8617) — preserves DMARC results across forwarding hops (relevant for mailing lists)
- [M3AAWG — Email Authentication Recommended Best Practices](https://www.m3aawg.org/published-documents) — operator-side recommendations
- [DMARC.org — Overview](https://dmarc.org/overview/) — gentler introduction with deployment guidance
- [dmarcian.com](https://dmarcian.com/) — analytics platform; canonical reference for `rua` data interpretation
- [Postmark DMARC Digests](https://dmarc.postmarkapp.com/) — free aggregate-report parser
- [MXToolbox DMARC lookup](https://mxtoolbox.com/dmarc.aspx) — point-and-click equivalent
- Related Cathedral commands: [`spf`](spf.md) (the authorisation layer DMARC alignment binds against),
  [`mx-rep`](mx-rep.md) *(planned — MX-host reputation on the receiving side)*,
  [`dns`](dns.md) (raw TXT queries; useful for inspecting DKIM selectors directly),
  [`whois`](whois.md) (registry attribution for the domain publishing DMARC)
