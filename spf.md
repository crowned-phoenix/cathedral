---
title: spf — Sender Policy Framework evaluator with grade A→F
command: spf
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [dmarc, mx-rep, dns, whois]
---

# `spf` — Sender Policy Framework evaluator with grade A→F

`spf` reads the `v=spf1` TXT record at a domain, walks every
`include:` and `redirect=` chain, counts DNS lookups against the
RFC 7208 limit of 10, and grades the policy A through F based on
the `all`-qualifier on the main path. Each mechanism is rendered
with its qualifier so the *policy intent* (`+a`, `-all`,
`~include:_spf.google.com`) is visible at a glance, and the
include chains are indented so multi-vendor mail setups read as
the trees they actually are.

Where [`dns`](dns.md) returns the SPF record verbatim as one of
six TXT entries, `spf` is the *evaluator* — it traverses the
chain the way a receiving mail server would, surfaces what would
actually happen on inbound mail, and flags the two failure modes
that matter most: a permissive default and a chain that exceeds
the lookup limit.

```
spf gmail.com
spf acme-supplies.example                # the typical use
spf _spf.google.com                      # inspect an include target directly
```

## What it does

For a single domain, Cathedral:

1. Queries `<domain>` for TXT records and finds the entries
   starting with `v=spf1`.
2. Tokenises the record into mechanisms (`ip4:…`, `a`, `mx`,
   `include:…`, `redirect=…`, `all`, …) and modifiers, each
   carrying an optional qualifier (`+`, `-`, `~`, `?`).
3. For every `include:` or `redirect=` mechanism, recursively
   evaluates the referenced domain.
4. Counts DNS lookups against the RFC 7208 §4.6.4 limit of 10
   per evaluation.
5. Tracks the `all` qualifier on the main path (root →
   redirect → redirect…) — the `all` from inside an `include:`
   subtree never wins.
6. Emits a summary with lookup count, the effective `all`
   qualifier, and a coarse letter grade.

| Outcome                            | Grade |
|------------------------------------|-------|
| No `v=spf1` record at root         | `F`   |
| `+all` (accepts everything)        | `F`   |
| Over the 10-lookup limit           | `D`   |
| `?all` or no `all` (implicit `?all`)| `C`   |
| `~all` (softfail — recommended-min)| `B`   |
| `-all` (fail — strict)             | `A`   |

The grade is a single-character verdict on the *deliverability
+ security* trade-off: A means "spoofed mail from this domain
will be rejected"; F means "spoofed mail from this domain will
be delivered to the inbox alongside real mail"; the in-between
grades are the spectrum between.

## What it answers

**Defender:** *"Is our SPF actually doing what we think it's
doing?"* The most common SPF mistakes aren't *absence* (most
mail-sending domains have *some* `v=spf1` record) — they're
configurations that quietly fail to protect:

- `~all` instead of `-all` (softfail isn't enforcement; mail
  still gets delivered, just to the spam folder).
- Lookup chains that exceed the 10-lookup limit (the whole
  policy stops working; receivers treat the SPF as PermError).
- Missing `all` directive entirely (implicit `?all` neutral
  — every IP is "neutral", which receivers usually treat as
  permissive).
- Multiple `v=spf1` records (invalid per RFC; receivers must
  fail the policy).

`spf` surfaces each of these in 20 ms of DNS time.

**Recon (authorized testing only):** *"Who handles mail for
this organisation?"* The `include:` chain catalogues the email
vendor stack:

- `_spf.google.com` → Google Workspace
- `spf.protection.outlook.com` → Microsoft 365
- `mailgun.org` / `mg.mailgun.com` → Mailgun
- `sendgrid.net` → SendGrid
- `_spf.mandrillapp.com` → Mailchimp Transactional
- `amazonses.com` → AWS SES
- `spf.messagingengine.com` → Fastmail
- `_spf.salesforce.com` → Salesforce
- `_spf.intuit.com` → QuickBooks / Intuit

Each include is a vendor relationship rendered visible. For a
target's email-infrastructure map, `spf` is the fast first
reach.

**Investigation:** *"Is this domain authorised to send mail
as that one?"* When inspecting a suspicious mail header (an
SPF `Received-SPF: pass` from a domain you don't recognise),
`spf <domain>` tells you whether the sending IP appears in the
authorised list. Combined with [`dns`](dns.md) for DMARC
policy and [`mx-rep`](mx-rep.md) for receiving-side reputation,
the trio answers most authentication-investigation questions.

**Identification:** *"What's the email-vendor stack on this
domain?"* Same as the recon answer — but for defensive
inventory rather than offensive footprinting. `spf` on your
own domains catches the surprise: a `sendgrid.net` include
added during a marketing campaign that nobody removed; an
`amazonses.com` include left over from a discontinued service.

## How it works

### The SPF record

SPF is a TXT record at the domain root, starting with the
literal string `v=spf1`:

```
acme-supplies.example.   IN   TXT   "v=spf1 include:_spf.google.com include:sendgrid.net ip4:198.51.100.0/24 -all"
```

The record is a space-separated list of *terms*. Each term is
either a **mechanism** (rules describing which senders are
authorised) or a **modifier** (configuration directives like
`redirect=` and `exp=`).

Mechanisms carry an optional qualifier prefix that changes the
verdict applied when the mechanism matches:

| Qualifier | Verdict     | Meaning                                                    |
|-----------|-------------|------------------------------------------------------------|
| `+` (default) | **pass**    | "this sender is authorised"                            |
| `-`         | **fail**    | "this sender is forbidden; receivers should reject"      |
| `~`         | **softfail**| "probably not authorised; receivers should treat with suspicion" |
| `?`         | **neutral** | "no opinion; treat as if SPF weren't published"          |

The conventional shape of an SPF record is a positive list of
authorised senders (default `+` qualifier) followed by `-all`
or `~all` at the end as the catch-all default. The qualifier
on the trailing `all` is what determines the verdict for
*unauthorised* senders — which is the entire point of
publishing SPF.

### Mechanisms and the lookup limit

Nine mechanism types are defined in RFC 7208:

- **`ip4:<cidr>`** / **`ip6:<cidr>`** — literal IP / CIDR.
  No DNS lookup.
- **`a`** / **`a:<host>`** — match against the A/AAAA records
  of `<host>` (or the policy domain, by default). One lookup.
- **`mx`** / **`mx:<host>`** — match against the A/AAAA
  records of the host's MX records. One lookup (which itself
  expands to per-MX queries — RFC bounds those separately).
- **`ptr`** / **`ptr:<host>`** — match against PTR records.
  Deprecated; one lookup. The PTR mechanism is **strongly
  discouraged** in RFC 7208 §5.5 because PTR lookups are slow,
  unreliable, and the overall lookup amplification is poorly
  bounded — receivers may decline to evaluate `ptr` and
  treat policies that include it as PermError. If your SPF
  contains `ptr`, replacing it is a real upgrade.
- **`include:<domain>`** — evaluate the SPF record at
  `<domain>` as a subroutine; a pass match short-circuits the
  current record as a pass. One lookup, plus everything the
  included record costs.
- **`exists:<host>`** — true if `<host>` resolves to any
  address. One lookup. Used for macro-driven matches in
  advanced setups.
- **`all`** — matches any sender; the qualifier becomes the
  default verdict. No lookup.

Plus two modifiers:

- **`redirect=<domain>`** — replaces the current evaluation
  with the SPF at `<domain>`. One lookup, plus the cost of
  the redirected record. Unlike `include`, this is a *delegation*
  — the redirected record's `all` becomes the effective one.
- **`exp=<host>`** — explanation host for fail responses. One
  lookup *but only if evaluation needs to construct an
  explanation*; in practice Cathedral treats this as a
  no-lookup term (the explanation isn't fetched).

RFC 7208 §4.6.4 caps the **total DNS lookups during a single
SPF evaluation at 10**. The limit exists because SPF without
a cap could be a denial-of-service amplifier (each include
expands into another include, recursively). Receivers must
treat over-limit policies as PermError — and PermError means
the SPF effectively doesn't apply, which means receivers fall
back to whatever the rest of their authentication stack says
(usually DMARC).

Cathedral counts the same six mechanisms the RFC counts:

```go
var lookupMechs = map[string]bool{
    "include":  true,
    "a":        true,
    "mx":       true,
    "ptr":      true,
    "exists":   true,
    "redirect": true,
}
```

When the count exceeds 10, `over_limit: true` is flagged on
the summary event and the grade is forced to D regardless of
the `all` qualifier — a policy that can't be evaluated isn't a
policy at all.

### `include:` vs `redirect=`: subtle but important

These look similar — both reference another domain — but their
semantics differ in ways that matter:

- **`include:<domain>`** — evaluate the other SPF as a
  subroutine. If the included record returns a pass, this
  evaluation returns a pass. If it returns a fail, the current
  evaluation *continues* — the include is not authoritative
  over the policy's outcome.
- **`redirect=<domain>`** — replace the current evaluation
  entirely. The redirected record's `all` is what determines
  the final verdict; the original domain's local rules are
  abandoned.

The practical effect on grading: an `all` qualifier *inside an
include subtree* doesn't determine the policy's behaviour for
the parent domain. Cathedral tracks this via the `mainPath`
flag in the walker:

```go
case "all":
    if mainPath && qual != "" && out.AllQual == "" {
        out.AllQual = qual
    }
```

The `mainPath` is the root → redirect → redirect chain; once
the walker descends into an `include:`, `mainPath` is false
and any `all` it encounters is just informational, not
load-bearing.

### Grading

The five-bucket grade is intentionally coarse:

```go
func grade(r *spfResult) string {
    if r.Records == 0    { return "F" }
    if r.OverLimit       { return "D" }
    switch r.AllQual {
    case "-":  return "A"
    case "~":  return "B"
    case "?":  return "C"
    case "+":  return "F"
    default:   return "C"  // no all → implicit ?all
    }
}
```

The grade reflects how a receiving mail server treats mail
that *doesn't* match any of the listed authorised mechanisms —
which is essentially every spoofing attempt:

- **A** (`-all`) — reject. Spoofing attempts bounce.
- **B** (`~all`) — softfail. Spoofing attempts go to spam.
- **C** (`?all` or no `all`) — neutral. Spoofing attempts
  arrive with no negative signal; downstream DMARC may still
  reject.
- **D** (over-limit) — PermError. The policy can't be
  evaluated. Receivers treat as no SPF.
- **F** (`+all` or missing) — pass everything. The policy
  actively *authorises* spoofing. Almost always a
  misconfiguration.

The grade is a quick triage signal. For a complete deliverability
assessment, pair `spf` with `dmarc` (planned) and inspect actual
DKIM signatures via received-message headers.

### Multiple records and depth limits

Two extra checks the walker performs:

- **Multiple `v=spf1` records at the same domain** —
  invalid per RFC 7208 §3.2. Cathedral emits a `warn` event
  and proceeds with the first record found. Receivers that
  encounter multiple records must fail the policy.
- **Recursion depth** — Cathedral bounds `include:` /
  `redirect=` depth at 8. The DNS-lookup limit caps total
  cost anyway, but the depth bound is a safety against
  pathological constructions that include very few but
  deeply.

## What Cathedral doesn't do

A few deliberate omissions:

- **No IP evaluation.** `spf` parses and walks; it doesn't
  evaluate against a specific sending IP to decide
  pass/softfail/fail/etc. For "would this IP be authorised
  to send as this domain?", use a dedicated SPF evaluator
  or paste the IP into `mxtoolbox.com`.
- **No macro expansion.** SPF macros (`%{i}`, `%{d}`,
  `%{ir}`, etc.) are noted but not expanded. Macros are rare
  in practice — most policies are static.
- **No `exp=` explanation fetching.** The `exp=` modifier
  points to a TXT record containing a human-readable
  explanation for `fail` outcomes. Cathedral surfaces the
  presence of `exp=` but doesn't dereference it.
- **No void-lookup counting.** RFC 7208 §4.6.4 adds a
  second limit: a maximum of 2 "void lookups" (queries that
  return empty or NXDOMAIN). Cathedral doesn't track this.
- **No DKIM / DMARC integration.** SPF is one of three
  email-authentication layers. For DMARC alignment use the
  planned `dmarc` command; for DKIM key inspection,
  [`dns`](dns.md) against `<selector>._domainkey.<domain>`.
- **No history.** Cathedral reports the live record; for
  before/after analysis save the JSON output and diff
  manually.
- **20-second timeout for the whole walk.** Deep include
  chains across slow resolvers may time out; rerun against
  a faster resolver via the system's DNS configuration.

## Worked example

A strict modern setup, a typical commercial mix, an
over-the-limit case, and the missing-record finding.

### A strict modern setup (A)

```
operator@cathedral:~$ spf acme-supplies.example
> resolving SPF for acme-supplies.example

  [ root ] acme-supplies.example
    v=spf1 include:_spf.google.com include:sendgrid.net ip4:198.51.100.0/24 -all
    · +include _spf.google.com
    · +include sendgrid.net
    · +ip4 198.51.100.0/24
    · -all

    [ depth 1 ] _spf.google.com
      v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all
      · +include _netblocks.google.com
      · +include _netblocks2.google.com
      · +include _netblocks3.google.com
      · ~all

      [ depth 2 ] _netblocks.google.com
        v=spf1 ip4:35.190.247.0/24 ip4:64.233.160.0/19 ip4:66.102.0.0/20 ip4:66.249.80.0/20 ~all
        · +ip4 35.190.247.0/24
        · +ip4 64.233.160.0/19
        · +ip4 66.102.0.0/20
        · +ip4 66.249.80.0/20
        · ~all

      [ depth 2 ] _netblocks2.google.com
        v=spf1 ip6:2001:4860:4000::/36 ip6:2404:6800:4000::/36 ip6:2607:f8b0:4000::/36 ~all
        · +ip6 2001:4860:4000::/36
        · +ip6 2404:6800:4000::/36
        · +ip6 2607:f8b0:4000::/36
        · ~all

      [ depth 2 ] _netblocks3.google.com
        v=spf1 ip4:172.217.0.0/19 ip4:108.177.8.0/21 ~all
        · +ip4 172.217.0.0/19
        · +ip4 108.177.8.0/21
        · ~all

    [ depth 1 ] sendgrid.net
      v=spf1 ip4:167.89.0.0/17 ip4:168.245.0.0/17 ~all
      · +ip4 167.89.0.0/17
      · +ip4 168.245.0.0/17
      · ~all

lookups : 6 / 10
default : fail (-all)  strict
grade   : A
```

The mail-infrastructure stack reads as: **Google Workspace**
(`_spf.google.com` with its three netblock includes) and
**SendGrid** (`sendgrid.net`) for transactional email, plus a
**self-hosted IP range** (`198.51.100.0/24`) that's probably a
small mail relay the team operates directly. The trailing
`-all` is the part that matters — any IP not on the authorised
list will be rejected by receiving servers. Total lookup count
is 6 (one for each include, one each for the three
sub-includes inside `_spf.google.com`), comfortably under the
limit of 10.

This is the *correct* shape for SPF in 2026 — explicit
vendor includes, sufficient headroom under the lookup limit,
strict `-all`. Most large organisations have a record close
to this.

### A typical commercial setup (B)

```
operator@cathedral:~$ spf shop.acme-supplies.example
> resolving SPF for shop.acme-supplies.example

  [ root ] shop.acme-supplies.example
    v=spf1 include:spf.protection.outlook.com include:mailgun.org include:_spf.mandrillapp.com ~all
    · +include spf.protection.outlook.com
    · +include mailgun.org
    · +include _spf.mandrillapp.com
    · ~all

    [ depth 1 ] spf.protection.outlook.com
      v=spf1 ip4:40.92.0.0/15 ip4:40.107.0.0/16 ip4:52.100.0.0/14 ip4:104.47.0.0/17 -all
      · +ip4 40.92.0.0/15
      · +ip4 40.107.0.0/16
      · +ip4 52.100.0.0/14
      · +ip4 104.47.0.0/17
      · -all

    [ depth 1 ] mailgun.org
      v=spf1 include:spf-1.mailgun.org include:spf-2.mailgun.org ~all
      · +include spf-1.mailgun.org
      · +include spf-2.mailgun.org
      · ~all

      [ depth 2 ] spf-1.mailgun.org
        v=spf1 ip4:69.72.32.0/19 ~all
        · +ip4 69.72.32.0/19
        · ~all

      [ depth 2 ] spf-2.mailgun.org
        v=spf1 ip4:159.135.224.0/20 ~all
        · +ip4 159.135.224.0/20
        · ~all

    [ depth 1 ] _spf.mandrillapp.com
      v=spf1 ip4:198.2.128.0/18 ip4:205.201.128.0/20 ~all
      · +ip4 198.2.128.0/18
      · +ip4 205.201.128.0/20
      · ~all

lookups : 6 / 10
default : softfail (~all)  recommended-minimum
grade   : B
```

Three vendors — **Microsoft 365** (`spf.protection.outlook.com`),
**Mailgun**, **Mailchimp Transactional** (Mandrill) — plus
`~all`. The grade is B because softfail is the
recommended-minimum but isn't strict; spoofed mail from
unauthorised IPs gets delivered to spam rather than rejected
outright. Many organisations live on `~all` for years —
the upgrade to `-all` is risk-adjacent (if your SPF is
missing a vendor your real mail starts getting rejected),
so teams stay on softfail.

The verdict the receiving server reaches when an `all`
matches an include's nested `all` is *just* the include's
verdict — note that `mailgun.org`'s `~all` does *not*
short-circuit the outer policy. Only the outermost (root)
`all` determines the final outcome for unauthorised IPs.

### Over the 10-lookup limit (D)

```
operator@cathedral:~$ spf overpacked.example
> resolving SPF for overpacked.example

  [ root ] overpacked.example
    v=spf1 include:_spf.google.com include:sendgrid.net include:mailgun.org include:_spf.salesforce.com include:_spf.intuit.com include:amazonses.com include:_spf.mandrillapp.com -all
    · +include _spf.google.com
    · +include sendgrid.net
    · +include mailgun.org
    · +include _spf.salesforce.com
    · +include _spf.intuit.com
    · +include amazonses.com
    ! DNS lookup limit exceeded (>10)
    · +include _spf.mandrillapp.com
    · -all

lookups : 13 / 10  EXCEEDED
default : fail (-all)  strict
grade   : D
```

Seven vendor includes, each of which themselves include
sub-records, totals over the 10-lookup limit. The policy
*looks* right (`-all` is strict; the vendors are real), but
receiving servers will treat it as PermError because the
walker can't complete. PermError → SPF doesn't apply →
receivers fall back to DMARC (if published) or to no
authentication signal at all.

Common fix patterns: flatten one or more includes into
literal `ip4:` / `ip6:` blocks (tools like Mailhardener and
EasyDMARC have flattener services), drop unused vendor
includes, or split mail into subdomains so each has its own
sub-10-lookup SPF.

### A missing-record finding (F)

```
operator@cathedral:~$ spf old-blog.example
> resolving SPF for old-blog.example
  ! old-blog.example: no SPF record at old-blog.example

lookups : 0 / 10
default : (no all)  effectively neutral
grade   : F
```

No `v=spf1` record found at all. Receivers treat the domain as
having no SPF — every mail server is "neutral" on whether
arbitrary IPs may send as `old-blog.example`. For a domain
that actively sends mail, this is a finding (the SPF was
never set up or was removed by accident). For a domain that
*shouldn't* send mail (an unused redirect domain, an asset-
only host), publishing `v=spf1 -all` is the canonical
hardening — no IP is authorised to send as this domain.

### An accept-everything misconfiguration (F)

```
operator@cathedral:~$ spf misconfig.example
> resolving SPF for misconfig.example

  [ root ] misconfig.example
    v=spf1 +all
    · +all

lookups : 0 / 10
default : pass (+all)  accepts everything!
grade   : F
```

`+all` means every sender on the internet is *positively
authorised* to send as `misconfig.example`. This is almost
always a mistake — someone typed `+all` when they meant
`-all`, or imported a placeholder config without changing the
default. The grade F reflects the severity: this is worse
than having no SPF, because it actively counteracts
spoofing-detection heuristics that would otherwise flag the
mail as suspicious.

## Output protocol

```
{"event":"start",        "domain":"…"}
{"event":"record",       "domain":"…","text":"v=spf1 …","depth":N}            # per record
{"event":"mech",         "domain":"…","depth":N,"qualifier":"+|-|~|?",
                         "mech":"…","value":"…","raw":"…"}                    # per term
{"event":"lookup_error", "domain":"…","error":"…"}                            # optional
{"event":"no_record",    "domain":"…"}                                        # optional
{"event":"warn",         "domain":"…","message":"…"}                          # optional
{"event":"summary",      "lookups":N,"over_limit":bool,"all":"+|-|~|?|",
                         "records":N,"errors":["…"],"grade":"A|B|C|D|F"}
{"event":"done"}
{"event":"error",        "message":"…"}
```

Extract the grade across a list of domains:

```
$ for d in $(cat domains.txt); do
    grade=$(spf "$d" -j | jq -r 'select(.event=="summary") | .grade')
    printf '%-40s %s\n' "$d" "$grade"
  done | sort -k2
acme-supplies.example                A
api.acme-supplies.example            A
status.acme-supplies.example         A
shop.acme-supplies.example           B
docs.acme-supplies.example           B
overpacked.example                   D
old-blog.example                     F
misconfig.example                    F
```

Map all `include:` targets to identify the vendor stack
across a portfolio:

```
$ for d in $(cat domains.txt); do
    spf "$d" -j |
      jq -r --arg d "$d" 'select(.event=="mech" and .mech=="include") |
                          "\($d)\t\(.value)"'
  done | sort -u | awk '
    { vendors[$2]++ }
    END { for (v in vendors) printf "%-40s %d\n", v, vendors[v] }
  ' | sort -k2 -rn
_spf.google.com                          18
spf.protection.outlook.com                7
sendgrid.net                              5
amazonses.com                             3
mailgun.org                               3
_spf.salesforce.com                       2
```

Find SPF records approaching the lookup limit (8+ lookups,
warning territory):

```
$ for d in $(cat domains.txt); do
    spf "$d" -j |
      jq -r --arg d "$d" \
        'select(.event=="summary" and .lookups >= 8) |
         "\($d)\t\(.lookups)/10"'
  done
overpacked.example                   13/10
api.acme-supplies.example            9/10
internal.acme-supplies.example       8/10
```

## Limitations

- **No IP evaluation.** Cathedral parses and walks; it doesn't
  decide pass/fail against a specific sending IP.
- **No macro expansion.** SPF macros (`%{i}`, `%{d}`, etc.)
  are surfaced but not expanded.
- **No void-lookup counting.** The RFC's second limit (max 2
  void lookups) isn't tracked.
- **No DKIM / DMARC integration.** SPF is one layer; the full
  authentication picture requires the other two. `dmarc`
  (planned) covers alignment.
- **First v=spf1 record only.** Multiple v=spf1 records is
  invalid; Cathedral warns and proceeds with the first.
- **20-second overall timeout.** Deep includes across slow
  resolvers may time out.
- **Default system resolver.** No way to specify a custom
  resolver via `--server`; use the system DNS configuration.
- **No historical evaluation.** Cathedral reports the live
  record; for before/after diffs save JSON output and diff.
- **No `exp=` dereferencing.** The explanation modifier is
  parsed but not fetched.

## Authorized use

`spf` is **passive recon against a public dataset**. SPF
records are deliberately-published DNS metadata — every TXT
query goes to the configured resolver, never to the target's
own infrastructure. Risk profile is the same as
[`dns`](dns.md) or [`whois`](whois.md): one or two unremarkable
DNS lookups per evaluation, no detection footprint.

One note: the resolver path (your machine's recursive resolver,
or a chain of them) sees what you ask about. For sensitive
portfolio auditing, route through a privacy-respecting resolver
or use Cathedral's [`dns`](dns.md) command with `--server=…`
to manually traverse the chain through a chosen path.

## Further reading

- [RFC 7208 — Sender Policy Framework version 1](https://www.rfc-editor.org/rfc/rfc7208) — the authoritative spec; especially §4.6 on evaluation limits
- [RFC 7208 §5.5 — `ptr` mechanism (discouraged)](https://www.rfc-editor.org/rfc/rfc7208#section-5.5) — why `ptr` is deprecated
- [M3AAWG — Best Practices: SPF and DKIM](https://www.m3aawg.org/published-documents) — operator-side recommendations
- [Mailhardener SPF tools](https://www.mailhardener.com/tools/spf-validator) — flatten and evaluate
- [EasyDMARC SPF flattener](https://easydmarc.com/tools/spf-flattening-tool) — vendor-include flattening to reduce lookup count
- [MXToolbox SPF lookup](https://mxtoolbox.com/SuperTool.aspx?action=spf) — point-and-click equivalent
- Related Cathedral commands: [`dmarc`](dmarc.md) *(planned — the alignment policy on top of SPF)*,
  [`mx-rep`](mx-rep.md) (MX-host reputation — the receiving side of the same mail flow),
  [`dns`](dns.md) (raw TXT queries including SPF; useful for inspecting include targets directly),
  [`whois`](whois.md) (registry attribution — who owns this domain to publish SPF for it)
