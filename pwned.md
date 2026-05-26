---
title: pwned — Have I Been Pwned password lookup via k-anonymity
command: pwned
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [hash, entropy, argon2, bcrypt, encrypt-decrypt]
---

# `pwned` — Have I Been Pwned password lookup via k-anonymity

`pwned` asks one specific question: *does this exact password
appear in the Have I Been Pwned breach corpus?* — the aggregated
collection of ~750 million distinct passwords seen in publicly
exposed data dumps over the past decade. If yes, the password is
unsafe regardless of any other property it has: a cracker's
dictionary already contains it, and credential-stuffing botnets
will try it against any account where the email matches.

The query happens via HIBP's [k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords):
Cathedral SHA-1s the password locally, sends only the first 5 hex
characters of the hash to `api.pwnedpasswords.com/range/<prefix>`,
and gets back a list of ~500–1000 hash suffixes that share the
prefix. Cathedral scans the response locally for an exact match
against the remaining 35 characters. **The full hash never leaves
the machine, and the password itself is never sent anywhere.** That
property is what makes routinely checking passwords against the
corpus an OK thing to do; without it, the API would be a credential-
harvesting honeypot.

```
pwned "hunter2"
pwned "correct horse battery staple"
pwned "Tx7!Qm2#vR9pK4nL"
```

## What it does

For one password:
1. Compute `SHA-1(password)` locally → 40 hex chars, uppercase.
2. Split into `prefix = first 5` and `suffix = remaining 35`.
3. Issue `GET https://api.pwnedpasswords.com/range/<prefix>`.
   Send `Add-Padding: true` to mitigate response-size traffic
   analysis (without it, an observer could correlate response
   size against known prefixes; with it, all responses round
   up to a multiple of an opaque padding unit).
4. Read the response line-by-line. Each line is
   `<35-char-suffix>:<count>`. The count is how many times that
   exact hash appeared across HIBP's collected breaches.
5. Match the local `suffix` against the returned list. If
   found, the count is the breach severity signal. If not
   found, the password isn't in the corpus.
6. Emit a verdict: not breached, or breached + a severity tier
   derived from the count.

| `count`             | Severity   | What it means                                          |
|---------------------|------------|--------------------------------------------------------|
| `0`                 | (n/a)      | Not in HIBP — no record of this password being leaked  |
| `1`                 | low        | Single appearance (often a one-off compromise)         |
| `2–9`               | moderate   | A handful of breaches — likely a personal pattern      |
| `10–999`            | high       | Widely-leaked password — in cracker dictionaries       |
| `≥1000`             | critical   | Among the top-leaked passwords on the internet         |

A `count ≥ 1000` password is unsafe in the strongest sense: every
credential-stuffing tool tries it first against every email it
acquires. `count = 1` is still a no-go for fresh use — it appeared
in a breach somewhere — but the urgency of rotation differs from
"123456" (count: ~37 million).

## What it answers

- Is this password in the public breach corpus?
- How many breaches has it appeared in? (Severity proxy.)
- Can I safely use this password somewhere new? (No, if found.)
- Has my own commonly-typed password leaked? (Routine self-audit.)

## How it works

### k-anonymity, briefly

The naive "is my password breached?" lookup would require sending
either the password (catastrophic) or its full hash (still
catastrophic — a hash is just another representation of the
password for offline-cracking purposes). HIBP's k-anonymity API
solves this with a prefix-bucketing scheme that owes its design to
Cloudflare research published in 2018.

```
sha1(password)  =  C7A89DAB1F5E847B2C6D3A8F4B5E9C2D7A1F8B6E
                   ─────                                           ← prefix sent
                        ──────────────────────────────────────     ← suffix kept local
                          
Request:        GET /range/C7A89
Response:       DAB1F5E847B2C6D3A8F4B5E9C2D7A1F8B6E:42
                AD9X3F2E1C6B8D5A7F4E2C3D8A1F5B9C2D7:1024
                AE5C1B8D2F4E9A6C7D3B5E2F4A8C1D6E7F9:7
                … (~500–1000 more)

Match locally:  scan response for `DAB1F5E847B2C6D3A8F4B5E9C2D7A1F8B6E`
                → found with count=42 → "breached, 42 appearances"
```

What the server learns from a single query: the operator queried
*something* whose SHA-1 starts with `C7A89`. There are ~250–1000
distinct passwords in HIBP that share any given 5-hex-char
prefix (HIBP's full corpus is ~750M passwords; with 16⁵ = 1.05M
possible prefixes, that averages out to ~750 passwords per
bucket, with significant variance because real password hashes
aren't uniformly distributed).

What the server doesn't learn: which of those ~750 passwords the
operator was asking about. The matching happens entirely on the
client. From the server's perspective, every query for a given
prefix is indistinguishable.

### The `Add-Padding: true` header

Cloudflare added this header in 2020 as a response-size traffic-
analysis mitigation. The base k-anonymity scheme leaks one piece
of information beyond the prefix: the *size* of the response
correlates with the number of suffixes in that bucket. An observer
between client and server (a corporate proxy, an ISP TLS-fingerprint
analyser) could see "this client queried HIBP and got back N bytes"
and cross-reference N against the known per-prefix response sizes
to narrow down which prefix was queried.

With `Add-Padding: true`, Cloudflare pads every response up to the
next multiple of an opaque chunk size and adds a varying number of
fake suffix entries that don't match anything real. The padded
response size no longer leaks the prefix.

Cathedral always sends `Add-Padding: true`. The cost is a slightly
larger response (typically 800-2000 bytes more); the privacy gain
is meaningful for operators behind anything that does TLS metadata
analysis.

### Why SHA-1, not SHA-256

HIBP launched the API in 2018 when SHA-1 was already known to be
collision-broken (SHAttered, 2017). The design choice is deliberate:

- The API isn't using SHA-1 as a *security* primitive — there's
  no signature being verified, no integrity-of-payload claim.
  It's using SHA-1 as a *hashing-to-uniformly-distribute-into-
  buckets* primitive. The 160-bit space is large enough that
  random preimage probability is negligible at the corpus's
  ~750M-password scale.
- Collision resistance doesn't matter for this use case. Even
  if an attacker could construct two distinct passwords with the
  same SHA-1, they'd both bucket together; the operator would
  get the same answer ("breached / not breached") regardless of
  which one they queried.
- SHA-1 produces 40-hex-char output. 5 chars → 16⁵ = 1.05M
  buckets; SHA-256 would produce 64-hex-char output and need a
  larger prefix for similar bucket count, which would shrink the
  k-anonymity set per query and *worsen* the privacy property.

The Go implementation:

```go
sum := sha1.Sum([]byte(password))
full := strings.ToUpper(hexBytes(sum[:]))
prefix := full[:5]
suffix := full[5:]
```

HIBP returns uppercase hex; Cathedral uppercases the local hash
before comparison to avoid case mismatches. `strings.EqualFold`
in the comparison loop is belt-and-braces.

### The argv-passing trade-off

The password is the only argument. Two real consequences:

- **Shell history.** Bash / zsh / fish all log argv by default.
  After `pwned "hunter2"`, the password sits in `~/.bash_history`
  (or equivalent) until you clean it up. On a shared host this
  is a real leak: anyone who later reads the history file knows
  what password you checked.
- **`ps` visibility.** During the few hundred milliseconds the
  process runs, the full argv (including the password) is
  visible in `/proc/<pid>/cmdline` and via `ps auxf` to any user
  who can see your processes. On a multi-user system that's not
  zero.

Both can be mitigated:

```
# Skip history for this one command (bash: HISTCONTROL=ignorespace)
$ pwned "hunter2"          # ← note the leading space
                              this line won't enter history

# Clear the last entry retroactively
$ history -d $((HISTCMD-1))

# Or pipe through a one-off temp script and delete it
$ cat > /tmp/p.sh <<'EOF'
read -s p; pwned "$p"
EOF
$ bash /tmp/p.sh; shred -u /tmp/p.sh
```

Long-term mitigation is a `-` argument that reads the password
from stdin without it touching argv. Planned, see
[Limitations](#limitations).

## What Cathedral doesn't do

- **Email lookups.** HIBP's separate "is this email in a breach?"
  API has been paid since 2019 ($3.95/month). Cathedral's `pwned`
  is password-only. The email-side equivalent for OSINT use lives
  in `identify` indirectly (which checks profile URLs but not
  paid breach data).
- **List the actual breaches.** HIBP's free password API returns
  only the count, not the breach names. To see which breaches
  exposed a *given email* (different question), you'd need the
  paid Breaches API or a third-party aggregator.
- **Multi-password batch mode.** One password per invocation.
  For batch use (auditing a CSV of users' suspected passwords),
  drive `pwned` from a shell loop with the same rate-limit-
  awareness as for any HIBP client.
- **Local corpus.** Cathedral doesn't bundle the HIBP password
  list locally. The full corpus is ~37 GB of SHA-1 hashes
  (downloadable from HIBP for offline use); shipping it inside
  Cathedral would balloon the binary. The k-anonymity API call
  is cheap enough (~100 ms) that local-corpus is a
  performance optimisation that doesn't justify the size cost.
- **Strength analysis.** "Not in HIBP" doesn't mean the password
  is strong — it means it hasn't *yet* been seen in a public
  breach. A password could be brand-new-and-weak (e.g. the user
  invented it last week) and still pass this check. Pair with
  [`entropy`](entropy.md) for the strength upper bound;
  [`pwned`](pwned.md) and `entropy` together cover the two
  failure modes (leaked vs. weak) that get past `argon2`
  hashing-for-storage.

## Worked example

### Famously-leaked password

```
operator@cathedral:~$ pwned "hunter2"
> querying Have I Been Pwned (k-anonymity API)
  sending only: F3BBB    (full SHA-1 stays local)

  bucket F3BBB → 873 hash suffixes returned

[ ✗ ] BREACHED — appears 27452 time(s) in known leaks
       severity: critical — appears in known breaches — DO NOT USE
```

27,452 appearances in the corpus — the canonical "joke password
that everyone knows" plus its long tail of actual reuse. Anything
above ~1000 is in the cracker-dictionary tier; this is firmly there.

The `bucket F3BBB → 873 hash suffixes` line confirms that 873 distinct
SHA-1s share that prefix, so the API operator can only deduce that
you queried *one of 873 possible passwords* — that's the k-anonymity
set size for this particular bucket.

### Common-but-not-top-tier password

```
operator@cathedral:~$ pwned "Hunter22!"
> querying Have I Been Pwned (k-anonymity API)
  sending only: A1F2E    (full SHA-1 stays local)

  bucket A1F2E → 612 hash suffixes returned

[ ✗ ] BREACHED — appears 142 time(s) in known leaks
       severity: high — appears in known breaches — DO NOT USE
```

142 appearances — significantly less than `hunter2` but still in
the "widely-leaked" tier. The capitalisation + number + symbol
satisfies a typical complexity policy but the *pattern* (real
word + small number suffix + punctuation) is exactly what
credential-stuffing dictionaries enumerate.

### Single-appearance password

```
operator@cathedral:~$ pwned "Mar7h1nb0w&Loop-tw3lve"
> querying Have I Been Pwned (k-anonymity API)
  sending only: 8C4D2    (full SHA-1 stays local)

  bucket 8C4D2 → 745 hash suffixes returned

[ ✗ ] BREACHED — appears 1 time(s) in known leaks
       severity: low — appears in known breaches — DO NOT USE
```

A single appearance is the lowest non-zero severity but still a
no-go for new use. Most one-off appearances trace to a specific
breach where someone used the password and it got dumped; the
specific breach is hidden by the free API's design.

### Not breached

```
operator@cathedral:~$ pwned "correct horse battery staple"
> querying Have I Been Pwned (k-anonymity API)
  sending only: B8B7D    (full SHA-1 stays local)

  bucket B8B7D → 798 hash suffixes returned

[ ✓ ] not found in the HIBP corpus
```

The famous XKCD-inspired diceware example *was* known-breached
for years after the comic went viral (people copied the example
verbatim). HIBP's current dataset may or may not still contain
it — the corpus updates as new breaches surface, and historical
listings can fall out as old breach DBs get pruned for legal
reasons. The point of the example: "not in corpus" is a
*current* answer, not a permanent guarantee.

### Strong random password

```
operator@cathedral:~$ pwned "Tx7!Qm2#vR9pK4nL"
> querying Have I Been Pwned (k-anonymity API)
  sending only: 2A5E1    (full SHA-1 stays local)

  bucket 2A5E1 → 681 hash suffixes returned

[ ✓ ] not found in the HIBP corpus
```

A 16-character password manager output (no real-word pattern, no
substitution structure to enumerate) — not in HIBP, which is the
expected outcome for genuinely random output.

This is the use case that makes a routine HIBP check
worthwhile: any password manager output should pass; if a
supposedly-random password fails the check, the generator is
broken (using a flawed entropy source, leaking through a recent
public dataset, or simply not as random as advertised).

### Verifying the privacy property

You can confirm Cathedral's claim that only the prefix leaves the
machine by watching `tcpdump` during a query:

```
$ sudo tcpdump -i any -A 'host api.pwnedpasswords.com' &
$ pwned "hunter2"
…
GET /range/F3BBB HTTP/1.1
Host: api.pwnedpasswords.com
User-Agent: cathedral-pwned/0.1
Add-Padding: true
…
```

The URL path shows `F3BBB` — the same five chars Cathedral's
`sent_only` line reported. The remaining 35 chars of the hash, and
the password itself, never appear in the request.

## Output protocol

Line-oriented JSON. Event types:

| Event   | Fields                                                                 |
|---------|------------------------------------------------------------------------|
| `start` | `sha1` (partial, first 8 chars + `…`), `prefix`, `sent_only`, `note`   |
| `bucket`| `prefix`, `hashes_in` — anonymity-set size for this prefix             |
| `result`| `breached` (bool), `count`, `severity` (when breached), `verdict`       |
| `done`  | sentinel                                                               |
| `error` | `message` — fatal HTTP / network failure                                |

Pipe-friendly with `jq`:

```
# Boolean exit: is the password breached?
pwned "hunter2" | jq -e 'select(.event=="result" and .breached)' >/dev/null \
  && echo "leaked"

# Just the count for logging
pwned "hunter2" | jq -r 'select(.event=="result") | .count'

# Bucket size — useful for understanding the anonymity-set per query
pwned "hunter2" | jq -r 'select(.event=="bucket") | "prefix \(.prefix) → \(.hashes_in)"'

# Audit a list of suspected weak passwords (input one-per-line)
while read -r pw; do
  result=$(pwned "$pw" | jq -r 'select(.event=="result") | "\(.count)"')
  printf "%-40s  count=%s\n" "$pw" "$result"
done < weak-passwords.txt
```

For batch use, keep in mind HIBP's rate-limit guidance (their docs
say the range API is "fast enough" without specifying a number;
in practice ~1-2 requests/second is comfortable, hundreds/second
will start getting throttled).

## Limitations

- **Argv-only password input.** No stdin form (`pwned -`),
  no env-var form (`PWNED_PASSWORD=… pwned -e`), no file-as-secret
  form (`pwned -f /tmp/p`). Planned: `-` for stdin, which is the
  cleanest of the three for keeping the password out of history
  and ps.
- **No batch mode.** Each invocation is one password + one HTTP
  call. For auditing many passwords in a loop, the shell wrapper
  above works but a built-in batch mode would amortise the
  per-call latency.
- **No timeout flag.** The HTTP client uses a hardcoded 10s
  timeout. For network-flaky environments this might be too
  short or too long.
- **No offline mode.** Cathedral doesn't carry the HIBP
  password corpus locally. For air-gapped use or guaranteed-
  privacy environments (where even k-anonymity is too much), use
  the [downloaded corpus](https://haveibeenpwned.com/Passwords)
  with a local SHA-1 hasher (`hash` works) and grep.
- **Outdated readings can persist.** HIBP refreshes the corpus
  periodically but doesn't typically remove individual entries
  even when the source breach is taken down. A password that
  appeared once in a 2014 leak is still "breached: count 1" in
  2026, even if the breach DB itself is no longer accessible
  anywhere.
- **No "is this password similar to a leaked one?"** Exact-match
  only. `password1` and `password2` are independent queries; the
  fact that an attacker would try both means little to the API.
- **Severity tiers are rough heuristics.** The boundaries (1,
  10, 1000) are Cathedral's interpretation, not HIBP-canonical.
  Treat them as a rough proxy; the actual count is the real
  signal.

## Authorized use

`pwned` is a privacy-preserving query against your *own*
passwords. The authorization considerations are:

- **Checking your own current password** — fine, this is the
  whole intended use. The k-anonymity property is what makes it
  ethical to do routinely.
- **Checking a password you found in someone else's breach
  dump** — fine in principle (the password isn't yours to be
  cautious about) but the workflow gets into compliance
  territory if you're doing it commercially without explicit
  customer consent. For incident-response work where you're
  authenticating breach claims, this is exactly what HIBP
  exists for; for marketing-as-security-service, less clear.
- **Checking a password someone *gave* you** — usually a "they
  just emailed me their account password and I need to tell them
  it's bad" scenario. Fine, but the act of typing their password
  into your shell makes it land in your shell history; that's
  worse from a chain-of-custody perspective than just citing
  HIBP's site directly to them.
- **Mass-checking dumped credentials** — if you're processing
  a leaked credential list against HIBP, you're probably also
  hitting the rate-limit guidance; consider using the downloadable
  corpus for this rather than hammering the API.
- **Argv leakage** — see the [argv trade-off
  section](#the-argv-passing-trade-off) above. On shared hosts,
  the leading-space-skips-history trick is worth knowing.

## Further reading

- [HIBP Passwords API documentation](https://haveibeenpwned.com/API/v3#PwnedPasswords)
  — the canonical reference for the `/range/<prefix>` endpoint,
  the `Add-Padding` header, and the response format.
- [Troy Hunt — Pwned Passwords V2](https://www.troyhunt.com/ive-just-launched-pwned-passwords-version-2/)
  — Troy Hunt's launch post for the k-anonymity API in 2018.
  Explains the design rationale from the operator side.
- [Cloudflare — Validating Leaked Passwords with k-Anonymity](https://blog.cloudflare.com/validating-leaked-passwords-with-k-anonymity/)
  — the Cloudflare engineering blog post that designed the
  k-anonymity range query. The math + threat model section is
  the best technical reference for *why* the design works.
- [Cloudflare — Adding Padding to the Pwned Passwords API](https://blog.cloudflare.com/here-comes-the-padding/)
  — the 2020 follow-up that added `Add-Padding`. The traffic-
  analysis attack it mitigates is worked through in detail.
- [SHAttered — first SHA-1 collision (2017)](https://shattered.io/)
  — why SHA-1's collision-broken status doesn't matter for this
  use case (the answer: HIBP uses SHA-1 as a bucketing function,
  not a security primitive).
- [`hash`](hash.md) — Cathedral's general-purpose digest tool;
  the SHA-1 line in its output is exactly what `pwned` computes
  internally before sending the prefix.
- [`entropy`](entropy.md) — the complementary check: is this
  password *strong enough* (independent of whether it's leaked).
  `entropy` + `pwned` together cover the two main "is this
  password OK?" failure modes.
- [`argon2`](argon2.md) — what you should be running on the
  password *after* the `entropy` + `pwned` checks pass, before
  storing it.
- [`encrypt` / `decrypt`](encrypt-decrypt.md) — uses Argon2id
  too, with the same passphrase-strength caveat: a 50-bit-entropy
  passphrase + Argon2id-at-defaults is still well below the
  threshold where an attacker stops bothering to brute-force.
