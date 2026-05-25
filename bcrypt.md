---
title: bcrypt — legacy password hashing with cost-factor verify
command: bcrypt
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-25
related: [argon2, crypt, hash, entropy, pwned]
---

# `bcrypt` — legacy password hashing with cost-factor verify

`bcrypt` generates and verifies bcrypt password hashes — the
1999-vintage Blowfish-based KDF that powered every Rails / Django /
Laravel / Spring Security app from the mid-2000s through the
mid-2020s. Two subcommands: `hash` to generate a salted hash for
storage, `verify` to check a password against an existing one.
Cost factor defaults to **12** (the OWASP 2024 recommendation, up
from the library default of 10); the cost is embedded in the
stored hash so verify doesn't need an out-of-band parameter table.

bcrypt is **superseded by [`argon2`](argon2.md)** for any new
password-storage code — it's not memory-hard, so a GPU with 24 GB
of RAM can run *millions* of bcrypt attempts in parallel where it
would run only a few hundred Argon2id attempts at OWASP defaults.
But bcrypt remains everywhere in production: every legacy
authentication codebase you'll touch in 2025 will be storing
bcrypt hashes. The `bcrypt` tool is for verifying those, debugging
PHP-vs-Go-vs-Node hash compatibility, and migrating users
gradually to Argon2id on next-login (verify with bcrypt, re-hash
with argon2 on success, update the stored hash).

```
bcrypt hash "hunter2"                         # OWASP default cost (12)
bcrypt hash "hunter2" -c 14                   # higher cost
bcrypt verify "hunter2" '$2a$12$z9w…'         # check against stored hash
```

## What it does

For `hash <password> [-c COST]`:
1. Generate 16 bytes of salt via the OS RNG (handled inside
   `golang.org/x/crypto/bcrypt`).
2. Run bcrypt with the chosen cost factor → 24-byte derived key.
3. Concatenate `$2a$<cost>$<salt-bcrypt64><hash-bcrypt64>` into a
   60-character stored string.
4. Emit the string + elapsed wall-clock time.

For `verify <password> <stored-hash>`:
1. Parse the stored hash — extract variant prefix (`$2a$` / `$2b$`
   / `$2y$`), cost factor, salt, expected hash.
2. Re-derive a candidate hash using the same parameters + supplied
   password.
3. Constant-time compare via `bcrypt.CompareHashAndPassword` (the
   library function does the constant-time check internally).
4. Emit match / no-match + elapsed time.

| Flag (hash only) | Meaning                              | Default |
|------------------|--------------------------------------|---------|
| `-c COST`        | cost factor (`bcrypt.MinCost`=4 to `bcrypt.MaxCost`=31) | `12`    |

Verify takes no parameters — the cost is encoded in the stored
hash and is automatically read on parse.

## What it answers

**Defender (legacy maintenance):** *"I have a Rails / Django /
Laravel / WordPress app from 2014. What should I do with the
bcrypt hashes already in the database?"* Two operationally
distinct paths:

- **Bump the cost in place**: if you can't introduce a new hash
  algorithm right now, raise the work factor on next login.
  Verify with the stored hash; if successful and the cost factor
  is below your current minimum, transparently re-hash at the
  higher cost and update the stored value. Cathedral's `verify`
  reports the cost factor on the start event, so you know
  whether to upgrade.
- **Migrate to Argon2id**: the right long-term answer. Verify
  with `bcrypt`; on success re-hash with [`argon2`](argon2.md)
  and replace the stored value. Within 12–18 months most active
  users have logged in and migrated. The Cathedral pair
  (`bcrypt verify` + `argon2 hash`) is exactly the toolkit for
  this migration.

**Defender (incident triage):** *"How crackable is this leaked
bcrypt hash dump?"* Read the cost factor from the `$2a$<cost>$`
prefix and translate to attempts/sec on commodity GPU hardware:

| Cost | Approx attempts/sec on a modern GPU |
|---|---|
| 10 | ~25,000 |
| 11 | ~12,500 |
| 12 | ~6,000 |
| 13 | ~3,000 |
| 14 | ~1,500 |
| 15 | ~750 |

Each +1 in cost roughly halves the rate (because the underlying
work is `2^cost` rounds). For a typical 2017-era app at cost 10
with a top-1M-passwords wordlist, the dump is fully recoverable
in hours. For a modern app at cost 12+ with anything beyond the
top-100k, dictionary attacks tail off and only specific targets
get cracked.

**Authorized testing:** *"Should I bother trying to crack this
bcrypt hash from the engagement?"* If cost ≤ 11 and you have GPU
budget, **yes** — bcrypt isn't memory-hard, so hashcat mode 3200
is well-optimised and dictionaries up to a few million entries
will finish in human time. If cost ≥ 13, you're in days-to-weeks
territory for serious dictionaries. If the engagement is
short-deadline, focus on the lower-cost or non-bcrypt hashes in
the dump first.

**Identification:** *"What library produced this hash?"* The
variant prefix is a fingerprint:

- `$2a$` — most libraries (Go, Python `bcrypt`, Node `bcryptjs`).
- `$2b$` — newer reference implementations after the 2014
  255-byte-wraparound bug fix. Functionally identical to `$2a$`
  for any practical password length.
- `$2y$` — PHP's `password_hash()` since 5.5. Same algorithm,
  PHP-specific cosmetic prefix.
- `$2x$` — broken (legacy `crypt_blowfish` bug), should never
  appear in modern data.

Cathedral's verify accepts all of `$2a$` / `$2b$` / `$2y$` (the
library handles them as compatible) and refuses `$2x$` and
non-bcrypt strings cleanly.

## How it works

### Brief history

bcrypt was published in 1999 by Niels Provos and David Mazières as
part of their USENIX paper "A Future-Adaptable Password Scheme".
Built on the Blowfish cipher, it was the first widely-deployed
password hash with an *adjustable work factor* — a single integer
that scales how slow the algorithm runs, designed so administrators
could keep pace with Moore's-Law-faster hardware by bumping the
factor over time.

For 25+ years, bcrypt was the right answer for password storage.
The Password Hashing Competition concluded in 2015 with Argon2 as
the new recommendation, but bcrypt remained ubiquitous in
production because:

1. Every major web framework had a battle-tested bcrypt library.
2. Migrations require user-by-user re-hashing on login — slow
   organic change.
3. bcrypt at cost 12+ is still genuinely strong against
   dictionary attacks; only the GPU-scale brute-force resistance
   is meaningfully worse than Argon2.

Cathedral exposes both — `bcrypt` for legacy and migration,
`argon2` for new code.

### The cost factor

Single integer 4–31. Number of internal rounds is `2^cost`:

| Cost | Rounds (`2^cost`) | Typical wall-clock |
|------|-------------------|--------------------|
| 4    | 16                | ~0.3 ms            |
| 8    | 256               | ~6 ms              |
| 10   | 1,024             | ~70 ms             |
| 12   | 4,096             | ~280 ms            |
| 14   | 16,384            | ~1.1 s             |
| 16   | 65,536            | ~4.4 s             |

**Each +1 doubles the time.** This is the famous "raise the cost
to keep pace with hardware" property — pick a cost factor that
takes ~250-500 ms today, and in 5 years bump it by 1 or 2.

Cathedral defaults to **cost 12** rather than the library default
of 10 — the library default has been the same since 2014 and is
no longer aligned with OWASP's 2024 cheatsheet. Override via
`-c` if you have a deployment constraint (low-power mobile,
massive bulk-hashing job).

### The output format

60 fixed characters. Example:

```
$2a$12$LQv3c1yqBWVHxkd0LHAkCO.YgN6XF.lGdgqV8.bvVgU7Mqp0LLPzC
```

Layout:

| Field | Width | Meaning |
|-------|-------|---------|
| `$2a$` | 4 | variant prefix (or `$2b$` / `$2y$`) |
| `12$` | 3 | cost factor + separator |
| `LQv3c1yqBWVHxkd0LHAkC` | 22 | 16-byte salt, *bcrypt's modified base64* |
| `O.YgN6XF.lGdgqV8.bvVgU7Mqp0LLPzC` | 31 | 24-byte hash, same encoding |

**bcrypt uses a non-standard base64 alphabet** — `./` then `A-Z`
then `a-z` then `0-9`, instead of standard base64's
`A-Z` + `a-z` + `0-9` + `+/`. This is a 1999 OpenBSD-isms
decision; every bcrypt implementation in every language agrees,
but you can't decode bcrypt hashes with `base64 -d` directly.

The 60-char total fits any `CHAR(60)` column. The format predates
the [PHC string spec](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md) (which
Argon2 uses) by ~16 years; bcrypt is conventionally called "the
PHC string before PHC was a thing."

### The 72-byte password limit

**The most important bcrypt gotcha.** bcrypt operates on 72 bytes
of password input — anything longer is silently truncated by most
older implementations, leading to the famous Dropbox NUL-byte
collision bug. (Two passwords differing only after byte 72 hash
to the same value.)

The Go library Cathedral uses **returns
`bcrypt.ErrPasswordTooLong`** for passwords over 72 bytes rather
than silently truncating. Cathedral surfaces that as a normal
error — fail loud rather than produce a hash that silently
ignores the tail of the input.

Common workarounds in real production code:

- **Pre-hash with SHA-256 before bcrypt**: `bcrypt(sha256(password))`
  collapses any length to 32 bytes. Works fine in pure-binary
  contexts; introduced the Dropbox bug because hex-encoded
  SHA-256 contains NUL bytes if you're not careful.
- **Reject long passwords at the API boundary**: simplest. UX
  cost is minor (passwords longer than 72 ASCII characters are
  rare in the wild).
- **Switch to Argon2** for new code: no length limit.

Cathedral hashes whatever is passed; if your input is over 72
bytes, the library returns an error and Cathedral surfaces it.

### Not memory-hard

bcrypt uses ~4 KiB of working memory per attempt, regardless of
the cost factor. Compare to Argon2id at OWASP defaults
(19,456 KiB per attempt). A modern GPU with 24 GiB of memory:

- bcrypt cost 12: ~6,000 attempts/sec
- Argon2id at OWASP defaults: ~500 attempts/sec, often less

The 12× difference understates the practical asymmetry, because
the bcrypt rate scales with GPU clock and core count while the
Argon2 rate is memory-bandwidth-bottlenecked and barely improves
with newer GPUs. The gap widens over time.

This is the single reason Argon2 supersedes bcrypt for new
deployments. bcrypt's "slow by design" is *time*-slow; Argon2's
is *time + memory*-slow, and memory cost is what defeats
GPU/ASIC parallelism.

### The verify path

```go
// 1. Cost is encoded in the stored hash; surface it for visibility
cost, _ := bcrypt.Cost([]byte(stored))

// 2. Library handles everything: extracts salt, re-derives, compares
err := bcrypt.CompareHashAndPassword([]byte(stored), []byte(password))

// 3. Distinguish match / mismatch / parse-error
if err == nil { /* match */ }
else if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) { /* mismatch */ }
else { /* malformed hash, surface error */ }
```

Constant-time comparison is handled inside
`CompareHashAndPassword` — there's no `==` on derived bytes
exposed at our level. The library uses
`crypto/subtle.ConstantTimeCompare` internally.

The verify takes exactly as long as the original hash (same cost
factor, same algorithm). No information leaks from elapsed time
about whether the password was correct.

### Migration to argon2id

The canonical bcrypt → argon2 migration pattern:

```
On each successful login:
  1. argon2 verify "$password" "$stored_hash"     ← already Argon2?
     → if yes, done
  2. bcrypt verify "$password" "$stored_hash"     ← otherwise check bcrypt
     → if no match, login fails
  3. argon2 hash "$password"                       ← rehash with modern KDF
  4. UPDATE users SET password = $new_hash WHERE id = $user_id
```

The user notices nothing — login takes the bcrypt cost (~280 ms
at cost 12) plus the Argon2 cost (~50 ms at OWASP defaults).
Within 12–18 months most active users have logged in and been
migrated; stragglers can be forced into a password reset.

Cathedral's `bcrypt verify` + `argon2 hash` are exactly the two
primitives this migration needs. The discriminator at step 1 is
just the variant prefix — if the stored string starts with
`$argon2id$`, route to `argon2`; if `$2a$`/`$2b$`/`$2y$`, route
to `bcrypt`.

## What Cathedral doesn't do

A few deliberate omissions:

- **No bulk-hashing mode.** Each invocation hashes one password.
  Importing a large user dump benefits from a dedicated batch
  wrapper; the per-invocation Go process startup is non-trivial
  overhead for millions of hashes.
- **No `--stdin` input.** The password is a positional argument,
  which means it shows up in `/proc/<pid>/cmdline` and shell
  history. For sensitive production use, integrate at the
  application layer rather than via the CLI.
- **No `$2x$` support.** That variant indicates a known bug in
  ancient `crypt_blowfish` versions; modern data shouldn't
  contain it and Cathedral refuses to verify against it.
- **No custom salt.** Always 16 random bytes from the OS RNG.
  Operator-supplied salts are a footgun (low entropy, reuse,
  predictable values).
- **No cost-rotation helper.** The 4-step migration pattern
  above is application-layer logic; Cathedral provides the two
  primitives but not a wrapper that auto-detects "this hash's
  cost is below current policy → re-hash on next verify."

## Worked example

A hash + verify cycle, cost scaling, and the most common error
cases.

### Hash with default cost

```
operator@cathedral:~$ bcrypt hash "hunter2"
> hashing with bcrypt cost=12
  hash : $2a$12$LQv3c1yqBWVHxkd0LHAkCO.YgN6XF.lGdgqV8.bvVgU7Mqp0LLPzC
  cost : 12
  time : 286 ms
```

286 ms on Cathedral's host hardware at the default cost factor
12. The 60-character stored hash drops directly into a `CHAR(60)`
password column.

Running the same command again produces a *different* string —
identical cost, identical algorithm, different random salt → different
output. That's the salt's job: identical passwords across users
must not produce identical stored hashes.

### Hash with higher cost (sensitivity profile)

```
operator@cathedral:~$ bcrypt hash "hunter2" -c 14
> hashing with bcrypt cost=14
  hash : $2a$14$K4cD8sR0wM2pVx5y6QnPzC.fGdhqV8tHa7sZ1F2nUe9bMqp0LLAvO
  cost : 14
  time : 1124 ms
```

1.1 seconds at cost 14 — that's 4× the time of cost 12, because
each +1 in cost doubles. Suitable for high-value accounts
(finance, healthcare admin); too slow for general user-facing
login (users notice anything over ~500 ms).

The cost factor is visible in the `$2a$14$` prefix of the stored
hash — `verify` reads this back automatically.

### Verify (correct password)

```
operator@cathedral:~$ bcrypt verify "hunter2" '$2a$12$LQv3c1yqBWVHxkd0LHAkCO.YgN6XF.lGdgqV8.bvVgU7Mqp0LLPzC'
> verifying — stored cost=12   $2a$12$LQv3c1yqBWVHxkd0LH…
[ ✓ ] match — password is correct (281 ms)
```

Same ~280 ms as the original hash took. The verify runs the
identical algorithm with the salt + cost encoded in the stored
hash, then compares — symmetric cost is by design.

The constant-time compare means a wrong password takes exactly
the same wall-clock; elapsed-time observation leaks nothing
about correctness.

### Verify (wrong password)

```
operator@cathedral:~$ bcrypt verify "wrong" '$2a$12$LQv3c1yqBWVHxkd0LHAkCO.YgN6XF.lGdgqV8.bvVgU7Mqp0LLPzC'
> verifying — stored cost=12   $2a$12$LQv3c1yqBWVHxkd0LH…
[ ✗ ] no match — password does not match stored hash    (283 ms)
```

282 ms — identical to the match case, within measurement noise.
The visible `[ ✗ ]` is the only signal, and that's the only
signal you'd return to an authentication caller in production too.

### The 72-byte limit

```
operator@cathedral:~$ bcrypt hash "$(python3 -c 'print("A"*100)')"
> hashing with bcrypt cost=12
error: bcrypt: password length exceeds 72 bytes
```

100 bytes of `A` exceeds the bcrypt input limit. The Go library
fails loud (returns `bcrypt.ErrPasswordTooLong`); Cathedral
surfaces the error rather than silently producing a hash that
ignores everything past byte 72.

If your real application needs to hash longer passwords without
imposing a length limit on users, the canonical patterns are:

1. Pre-hash with SHA-256 (`bcrypt(sha256(password))`) — collapses
   any length to 32 bytes; be careful about NUL bytes if you
   hex-encode the SHA-256 output.
2. Reject at the API boundary with a clear "passwords longer
   than 72 characters not supported" message.
3. Migrate to [`argon2`](argon2.md) which has no length limit.

### Malformed hash

```
operator@cathedral:~$ bcrypt verify "hunter2" 'not-a-real-hash'
error: stored hash is not a valid bcrypt string: crypto/bcrypt: hashedSecret too short to be a bcrypted password
```

Cathedral refuses to compute anything if it can't parse the
stored string — there's nothing useful to do. The error message
comes from the library and identifies what's wrong with the
input.

### Cost-scaling calibration

```
operator@cathedral:~$ for c in 10 11 12 13 14; do
    ms=$(bcrypt hash "calibration" -c $c -j |
        jq -r 'select(.event=="hashed") | .elapsed_ms')
    printf 'cost=%-2d  →  %s ms\n' "$c" "$ms"
  done
cost=10  →   71 ms
cost=11  →  142 ms
cost=12  →  284 ms
cost=13  →  567 ms
cost=14  →  1133 ms
```

Each +1 doubles the wall-clock — the expected `2^cost` scaling.
Use this loop to calibrate the cost on your production hardware:
target ~250–500 ms for general web login, ~500 ms–1 s for
sensitive accounts, drop to ~70 ms (cost 10) only for
memory-constrained mobile / embedded targets where the higher
cost is prohibitive.

## Output protocol

```
{"event":"start",         "mode":"hash|verify","cost":N,"hash_cost":N,"hash_short":"…"}
{"event":"hashed",        "hash":"$2a$…","cost":N,"elapsed_ms":N}
{"event":"verify_result", "match":bool,"elapsed_ms":N,"reason":"…"}
{"event":"done"}
{"event":"error",         "message":"…"}
```

`cost` on the start event reflects the requested cost for `hash`;
`hash_cost` reflects the cost embedded in the stored hash for
`verify`. `hash_short` on `verify` start is the first 24
characters of the stored hash plus an ellipsis — enough to
identify which hash is being checked without scrolling the full
60 chars.

Pipe to extract the hash for scripting:

```
$ bcrypt hash "$NEW_PASSWORD" -j |
    jq -r 'select(.event=="hashed") | .hash'
$2a$12$…
```

Detect bcrypt hashes whose cost is below current policy
(migration trigger):

```
$ cat user_hashes.txt | while read hash; do
    cost=$(bcrypt verify "any-password" "$hash" -j 2>/dev/null |
        jq -r 'select(.event=="start") | .hash_cost')
    if [ -n "$cost" ] && [ "$cost" -lt 12 ]; then
      echo "needs-rehash  cost=$cost  $hash"
    fi
  done
```

Note that `bcrypt verify` against a wrong password still reports
the cost on the start event before doing the comparison — making
this pattern work without actually knowing user passwords.

bcrypt → argon2 migration (Bash sketch):

```
# On successful login that used bcrypt
$ new_hash=$(argon2 hash "$password" -j |
    jq -r 'select(.event=="hashed") | .hash')
$ psql -c "UPDATE users SET password_hash = '$new_hash' WHERE id = $user_id"
```

## Limitations

- **72-byte password input limit.** Surfaced as an error rather
  than silent truncation; applications that need to support
  longer passwords must pre-hash or migrate to Argon2.
- **Not memory-hard.** Cracking-resistance scales with cost
  factor only, not memory. GPU/ASIC cracking is well-tuned for
  bcrypt; modern attackers can run thousands of attempts per
  second per GPU at cost 10.
- **`$2x$` variant rejected.** Indicates a known bug in ancient
  `crypt_blowfish`; modern data shouldn't contain it.
- **One password per invocation.** No batch mode. Process
  startup overhead matters for bulk import; integrate at the
  application layer for that.
- **Password as positional argument.** Visible in
  `/proc/<pid>/cmdline` and shell history. Same caveat as
  [`argon2`](argon2.md).
- **No PHC string output.** bcrypt's format predates and differs
  from the PHC spec; the algorithm-identifier convention is
  `$2a$<cost>$<encoded>` rather than `$bcrypt$<…>$<…>`. Every
  language library agrees on the bcrypt-specific format, but
  it's not interoperable with generic PHC parsers.

## Authorized use

`bcrypt` is **a local cryptographic computation tool**. No
network activity, no external dependencies — same posture as
[`argon2`](argon2.md), `md5sum`, or `openssl passwd`. Authorised
to run anywhere; the underlying cryptographic primitive isn't
subject to any meaningful regulatory constraint.

One note worth attaching: **password handling caveats are the
same as argon2**. The first positional argument is visible in
process listings on multi-user systems and gets captured by
shell history. For sensitive use, either prefix with a space
(if your shell respects `HISTCONTROL=ignorespace`) or integrate
bcrypt at the application layer where the password never leaves
the process memory of the auth service.

## Further reading

- ["A Future-Adaptable Password Scheme" — Provos & Mazières, USENIX 1999](https://www.usenix.org/legacy/event/usenix99/provos/provos_html/index.html)
  — the original bcrypt paper
- [OWASP Password Storage Cheat Sheet — bcrypt section](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#bcrypt)
  — current parameter recommendations
- [`golang.org/x/crypto/bcrypt`](https://pkg.go.dev/golang.org/x/crypto/bcrypt)
  — the pure-Go bcrypt package Cathedral uses
- [Dropbox engineering — "How we made our password hashing safer"](https://dropbox.tech/security/how-dropbox-securely-stores-your-passwords)
  — describes the SHA-256 pre-hashing + the NUL-byte bug that
  made bcrypt's 72-byte truncation infamous
- [hashcat — bcrypt mode 3200](https://hashcat.net/wiki/doku.php?id=example_hashes)
  — bcrypt cracking benchmark reference
- Related Cathedral commands: [`argon2`](argon2.md) (the modern
  successor — verify with `bcrypt`, re-hash with `argon2` is the
  canonical migration),
  [`crypt`](crypt.md) *(planned — Unix `$1$` / `$5$` / `$6$`
  shadow-file hashes; even older than bcrypt and still found in
  `/etc/shadow` everywhere)*,
  [`hash`](hash.md) *(planned — fast generic digests; useful for
  pre-hashing to bypass the 72-byte bcrypt limit)*,
  [`entropy`](entropy.md) *(planned — password-strength check
  before hashing)*,
  [`pwned`](pwned.md) *(planned — Have I Been Pwned k-anonymity
  lookup)*
