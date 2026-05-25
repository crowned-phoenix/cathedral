---
title: argon2 — modern password hashing with Argon2id + PHC verify
command: argon2
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-25
related: [hash, bcrypt, crypt, entropy, pwned]
---

# `argon2` — modern password hashing with Argon2id + PHC verify

`argon2` is Cathedral's password-hashing primitive. Two subcommands —
`hash` to generate a salted Argon2id hash for storage, `verify` to
check a password against an existing one. Defaults follow the
[OWASP 2024 cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
(19 MiB memory, 2 iterations, 1 thread, 16-byte salt, 32-byte
output); stored hashes use the standard [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
so they self-describe their parameters and verify without any
out-of-band schema. Constant-time comparison on the verify path.

Argon2id is the 2024 best-practice replacement for bcrypt in any
new password-storage code. Where bcrypt costs an attacker ~4 KiB of
RAM per cracking attempt (cheap on a modern GPU), Argon2id at OWASP
defaults costs them ~19 MiB — a factor of nearly 5000× more memory,
which collapses GPU/ASIC parallelism advantages.

```
argon2 hash "hunter2"                         # OWASP defaults
argon2 hash "hunter2" -t 3 -m 65536           # higher cost
argon2 hash "hunter2" -t 1 -m 7168 -p 4       # lower memory, more threads
argon2 verify "hunter2" '$argon2id$v=19$m=19456,t=2,p=1$…$…'
```

## What it does

For `hash <password> [flags]`:
1. Generate 16 random bytes of salt from `crypto/rand`.
2. Run Argon2id with the chosen cost parameters → 32-byte derived
   key.
3. Encode parameters + salt + key into a single PHC string.
4. Emit the PHC string + elapsed wall-clock time.

For `verify <password> <stored-hash>`:
1. Parse the stored PHC string — extract variant, version, memory,
   time, parallelism, salt, expected key.
2. Re-derive a candidate key using the same parameters + supplied
   password.
3. Constant-time compare (`crypto/subtle`) the candidate against
   the stored key.
4. Emit match / no-match + elapsed time.

| Flag (hash only) | Meaning                              | Default       |
|------------------|--------------------------------------|---------------|
| `-t TIME`        | iterations / time cost               | `2`           |
| `-m MEMORY-KB`   | memory cost in KiB                   | `19456` (19 MiB) |
| `-p PAR`         | parallelism (lanes)                  | `1`           |

Verify takes no parameters — they're encoded in the stored hash and
must match exactly for the verify to succeed.

## What it answers

**Defender:** *"What should I store for user passwords in 2025+?"*
The right answer is "an Argon2id hash with OWASP-recommended
parameters." `argon2 hash` produces exactly that — a single string
you store in the password column of your users table.
`argon2 verify` checks login attempts. No salt-management table, no
parameter-rotation schema, no custom encoding — the PHC string is
the entire interface.

**Defender (incident triage):** *"Was this leaked hash strong?"* If
a breach dump contains `$argon2id$v=19$m=19456,t=2,p=1$…` strings,
the attacker faces ~19 MiB of RAM per cracking attempt — at OWASP
defaults that's roughly 100–1000 hashes per second on a high-end
GPU (versus 100k+/sec for unsalted SHA-1 or 10k+/sec for bcrypt
cost 10). For unique strong passwords, the dump is effectively
unrecoverable; for common passwords, dictionary attacks still work
but at much higher cost.

**Authorized testing:** *"Should I bother trying to crack this
Argon2id hash from the engagement?"* Look at the parameters in the
PHC string. If `m` is in the OWASP range (19000+) and the password
isn't in the top-1k common-passwords list, your hashcat/john run is
unlikely to finish in human time on whatever hardware you have. The
PHC parameters tell you the cost before you start. Cathedral
exposes the same parameters via `verify` if you want to time-test
on your own hardware.

**Identification:** *"What variant and cost parameters did this
application use?"* The PHC string self-describes — `$argon2id$
v=19$m=...,t=...,p=...$...$...` tells you variant, version, and
all three cost parameters at a glance. No reverse-engineering of
the auth library needed.

## How it works

### The Argon2 family (id vs. i vs. d)

Argon2 won the Password Hashing Competition in 2015. Three
variants:

- **Argon2d** — fastest; data-*dependent* memory access pattern.
  Fastest because GPU memory access can be optimised; but the
  data-dependent pattern is theoretically vulnerable to
  side-channel attacks (cache-timing). Used in cryptocurrencies
  and other settings where side-channel attacks are
  out-of-scope.
- **Argon2i** — data-*independent* memory access; resistant to
  side-channel attacks but slightly slower per iteration. Designed
  for password hashing.
- **Argon2id** — hybrid: first half-iteration data-independent,
  remainder data-dependent. The best of both — side-channel
  resistance for the part that matters, raw cracking-resistance
  for the rest. **The recommended variant for new password
  storage.**

Cathedral implements Argon2id only. The Go stdlib's
`golang.org/x/crypto/argon2` package exposes `IDKey()` for exactly
this purpose; the call is one line and produces a 32-byte derived
key from `(password, salt, time, memory, threads, keyLen)`.

### Why memory-hard matters

The fundamental defensive idea: make each password-cracking attempt
expensive in *memory*, not just CPU time. Memory-hardness collapses
the attacker's parallelism advantage because:

- A modern GPU has ~10,000 compute cores but only ~10–24 GiB of
  shared memory. At 19 MiB per Argon2id attempt, the GPU can run
  at most ~500–1200 parallel attempts.
- Compare to bcrypt at ~4 KiB per attempt: same GPU can run
  ~2.5–6 *million* parallel attempts.
- ASICs are similarly bottlenecked — die area for SRAM is
  expensive; a custom Argon2id chip can't pack many lanes into
  one die.

The result: even with state-of-the-art hardware, brute-forcing
Argon2id at OWASP parameters takes orders of magnitude more
hardware-hours than the equivalent bcrypt or PBKDF2 attack.
Memory-hardness is the single most important hashing property
introduced this decade.

### The cost parameters

Three knobs:

- **`m` (memory, KiB)** — how much working memory the algorithm
  must allocate per attempt. Directly multiplies the attacker's
  hardware cost. OWASP 2024 recommends **19 MiB minimum** for
  general password storage; raise to 47 MiB for "interactive
  login" sensitivity (financial, healthcare).
- **`t` (time, iterations)** — how many passes the algorithm makes
  over the memory block. Multiplies wall-clock per attempt
  linearly. Default `t=2` is fine paired with the standard
  memory; raise to `t=3` if you can't increase `m` further (e.g.,
  on memory-constrained mobile or embedded targets).
- **`p` (parallelism, lanes)** — how many independent threads the
  algorithm can use within a single hash. Doesn't change the
  attacker's cost meaningfully (their parallelism still scales
  with hardware) but lets you use more CPU cores per hash to
  reduce wall-clock latency. Default `p=1` is fine on a server;
  raise to match available cores if you genuinely need to.

The right way to pick parameters: **target a wall-clock latency**.
For interactive web login, ~500 ms per hash is the upper bound
users tolerate. Measure on production hardware, raise `m` as much
as that latency budget allows, then add `t` if you have headroom.
Cathedral's `hash` subcommand reports `elapsed_ms`, which is the
calibration signal.

### The PHC string format

Output looks like:

```
$argon2id$v=19$m=19456,t=2,p=1$rIZdPhfP/c8C5+u8nL4cDw$1ufW31wA…6sX0eEZc
```

Six `$`-separated fields after a leading empty segment:

1. *(empty)* — leading `$`.
2. `argon2id` — variant identifier.
3. `v=19` — Argon2 version (1.3). Cathedral refuses to verify
   against other versions; `golang.org/x/crypto/argon2.Version`
   is `19` and that's the only version most modern deployments
   produce.
4. `m=…,t=…,p=…` — cost parameters as a comma-separated list.
   Order is conventional (m, t, p) but the parser handles any
   order.
5. `<salt-b64>` — 16-byte random salt, base64-encoded *without*
   padding (`RawStdEncoding` in Go terms). Length: 22 chars.
6. `<hash-b64>` — 32-byte derived key, same encoding. Length: 43
   chars.

Total length: ~96 characters. Fits in a `VARCHAR(255)` or any
text column. The format is portable across languages — every
mainstream Argon2 library reads and writes the same string.

### The verify path

```go
// 1. Parse PHC string → params + salt + expected-key bytes
params, salt, key, err := decodePHC(stored)

// 2. Re-derive using supplied password with exact same params
cand := argon2.IDKey([]byte(password), salt,
    params.time, params.memory, params.threads, uint32(len(key)))

// 3. Constant-time compare (resists timing side-channels)
match := subtle.ConstantTimeCompare(key, cand) == 1
```

Three details that matter:

- **Re-using the stored parameters** is what makes verify work
  without an out-of-band parameter table. Even if you bump your
  default parameters later, old hashes still verify because their
  parameters are in the PHC string.
- **Re-using the stored salt** is what makes the verify
  deterministic. A new random salt would produce a different
  key for the same password.
- **`subtle.ConstantTimeCompare`** — not the regular `==`. The
  timing of a naive byte-by-byte comparison leaks information
  about which byte first differs, which over many attempts could
  reveal the stored hash. Cathedral uses the stdlib's
  constant-time primitive that takes the same number of cycles
  regardless of where the bytes first disagree.

### Parameter rotation (a use case for `verify`)

A typical lifecycle: you deploy with OWASP 2024 defaults
(`m=19456, t=2`). Two years later hardware has improved and you
want to raise to `m=47104, t=3`. Strategy:

1. On every successful login, after `argon2 verify` succeeds,
   check if the stored hash's parameters meet your *current*
   minimum.
2. If not, transparently re-hash the password with the new
   parameters and update the stored hash.
3. Within ~12 months, most active users have logged in and
   migrated. Stragglers can be forced into a password reset.

This is enabled by the PHC self-description: you read the old
parameters from the stored string, compare to your current
policy, decide whether to upgrade. No database migration.

## What Cathedral doesn't do

A few deliberate omissions:

- **Only Argon2id.** Not 2d, not 2i — both have specialised use
  cases (cryptocurrency mining, side-channel-only environments)
  that aren't relevant for password storage. Adding them would
  expand the command surface for no general operational gain.
- **No parameter auto-tuning.** Some libraries (libsodium's
  `crypto_pwhash`) probe the hardware and pick parameters that
  target a latency budget. Cathedral takes explicit parameters
  because the right values depend on your deployment context
  (server vs. mobile vs. embedded), not just the local
  hardware. Use `hash` repeatedly with different `-m` and read
  `elapsed_ms` to calibrate.
- **No bulk-hashing mode.** One password per invocation. For
  importing a large user dump (millions of passwords), pipeline
  via `xargs` or write a small wrapper that holds the binary
  open via stdin (not currently supported — would need a
  separate "server" mode).
- **No password-strength checking.** `hash` will happily hash
  `password123`. For strength evaluation before hashing, use
  the planned [`pwned`](pwned.md) (Have I Been Pwned k-anonymity
  lookup) or [`entropy`](entropy.md) (Shannon entropy + common-
  password dictionary).
- **No custom salt.** Always 16 random bytes from
  `crypto/rand`. Letting the operator supply their own salt is
  a footgun (low-entropy salts, reused salts, predictable
  salts) — the random one is always correct.
- **No salt-pepper split.** A "pepper" (application-wide secret
  added to every hash before storage) provides additional
  defence against database leaks. Cathedral doesn't help build
  that — it's an application-layer pattern you implement
  around the hashing primitive, not in it. If you need it, hash
  `password + pepper` with `argon2 hash`.

## Worked example

A hash + verify cycle, parameter tuning, and the failure case.

### Hash with defaults

```
operator@cathedral:~$ argon2 hash "hunter2"
> hashing with argon2id   t=2   m=19456 KiB   p=1
  hash : $argon2id$v=19$m=19456,t=2,p=1$rIZdPhfP/c8C5+u8nL4cDw$1ufW31wAyXkLqHe4mYJoVhFt9PIzC6sX0eEZcQfGn8M
  time : 47 ms
```

47 ms on Cathedral's host hardware. The hash string is
ready to drop into a `password` column.

The salt (`rIZdPhfP/c8C5+u8nL4cDw`) and derived key
(`1ufW31wA…GfGn8M`) are both random per-invocation — running the
exact same command again produces a *different* string with the
same parameters but a new salt + new key. That's the whole point
of salting: identical passwords don't produce identical stored
hashes, so an attacker can't recognise repeats across users.

### Hash with higher cost (financial / healthcare)

```
operator@cathedral:~$ argon2 hash "hunter2" -t 3 -m 47104
> hashing with argon2id   t=3   m=47104 KiB   p=1
  hash : $argon2id$v=19$m=47104,t=3,p=1$tFq8VgM4wXJq6cP1pBKQfA$5cN3hzG4eJpQaP9LqM2vT8fY1xN6sR0kE4dY7xA3bMU
  time : 168 ms
```

168 ms — still well under the 500 ms interactive-login budget on
this hardware, with 2.5× more memory and a 3rd iteration. This is
the OWASP "interactive sensitivity" recommendation; the cost-to-
crack on a GPU goes up by approximately the same multiplier.

### Hash trading memory for parallelism

```
operator@cathedral:~$ argon2 hash "hunter2" -t 1 -m 7168 -p 4
> hashing with argon2id   t=1   m=7168 KiB   p=4
  hash : $argon2id$v=19$m=7168,t=1,p=4$cKv6jPwQz8sLnRqYxH9bMA$pZ4tFw7eD2nGqHmYxV5jBkP8sQ3cR1xL6nM9aE8tDoU
  time : 18 ms
```

Suitable for memory-constrained targets (mobile, embedded). The
attacker's cost is lower because the memory parameter is smaller —
the `-p 4` doesn't help defensively, only reduces your wall-clock.
Use this profile only when 19 MiB allocations are genuinely off
the table.

### Verify (correct password)

```
operator@cathedral:~$ argon2 verify "hunter2" '$argon2id$v=19$m=19456,t=2,p=1$rIZdPhfP/c8C5+u8nL4cDw$1ufW31wAyXkLqHe4mYJoVhFt9PIzC6sX0eEZcQfGn8M'
> verifying — stored t=2  m=19456 KiB  p=1   $argon2id$v=19$m=19456,t=2,…
[ ✓ ] match — password is correct (45 ms)
```

The verify reports the same `~45 ms` as the hash took to generate
— that's expected, since verify runs the exact same algorithm with
the exact same parameters, just comparing the result rather than
encoding it. Symmetric cost is by design.

The constant-time compare means the elapsed time doesn't depend on
*which* byte first differs in a wrong password — it's always the
full algorithm runtime. An attacker observing timing learns
nothing about how close their guess was.

### Verify (wrong password)

```
operator@cathedral:~$ argon2 verify "wrong" '$argon2id$v=19$m=19456,t=2,p=1$rIZdPhfP/c8C5+u8nL4cDw$1ufW31wAyXkLqHe4mYJoVhFt9PIzC6sX0eEZcQfGn8M'
> verifying — stored t=2  m=19456 KiB  p=1   $argon2id$v=19$m=19456,t=2,…
[ ✗ ] no match — password does not match stored hash    (44 ms)
```

Same ~45 ms — the wall-clock leaks nothing about correctness. The
visible `[ ✗ ]` is the only signal, and that's the only signal
you'd return to a real authentication caller as well.

### Verify (malformed hash)

```
operator@cathedral:~$ argon2 verify "hunter2" 'not-a-real-hash'
error: invalid argon2 hash: not an argon2id PHC string
```

Cathedral refuses to attempt verification against a string it
can't parse — there's nothing useful to compute. The error message
identifies which parse step failed (`not an argon2id PHC string`,
`bad version`, `unknown parameter "q"`, etc.) so PHC-string
debugging is straightforward.

### Verify (wrong Argon2 version)

If someone produced a hash with an older version (`v=0x10` =
Argon2 1.0) — virtually no modern deployment does, but it
happens with old hash dumps:

```
operator@cathedral:~$ argon2 verify "hunter2" '$argon2id$v=16$m=19456,t=2,p=1$…$…'
error: invalid argon2 hash: unsupported argon2 version 16 (this build expects 19)
```

Cathedral pins to Argon2 v1.3 (the current standard). Older v1.0
hashes are rare enough that re-hashing on next login is the right
migration path.

## Output protocol

```
{"event":"start",         "mode":"hash|verify","time":N,"memory":N,"par":N,"hash_short":"…"}
{"event":"hashed",        "hash":"$argon2id$…","time":N,"memory":N,"par":N,"elapsed_ms":N}
{"event":"verify_result", "match":bool,"elapsed_ms":N,"reason":"…"}
{"event":"done"}
{"event":"error",         "message":"…"}
```

`hash_short` on the start event is the first 28 characters of the
stored hash with a trailing ellipsis — for console display only,
so the user knows which hash is being verified without scrolling
past the full PHC string.

Pipe to extract just the generated hash for scripting:

```
$ argon2 hash "$NEW_PASSWORD" -j |
    jq -r 'select(.event=="hashed") | .hash'
$argon2id$v=19$m=19456,t=2,p=1$…$…
```

Time-test parameter changes on the local hardware:

```
$ for m in 19456 32768 47104 65536; do
    elapsed=$(argon2 hash "calibration-test" -m "$m" -j |
        jq -r 'select(.event=="hashed") | .elapsed_ms')
    printf 'm=%-6d  →  %s ms\n' "$m" "$elapsed"
  done
m=19456  →  47 ms
m=32768  →  82 ms
m=47104  →  168 ms
m=65536  →  241 ms
```

Verify a batch of password-hash pairs from a CSV:

```
$ while IFS=, read -r password hash; do
    result=$(argon2 verify "$password" "$hash" -j |
        jq -r 'select(.event=="verify_result") | .match')
    echo "$password → $result"
  done < pairs.csv
```

## Limitations

- **Argon2id only.** No 2d or 2i. The relevant standards (OWASP,
  NIST SP 800-63B, IETF RFC 9106) all recommend id for password
  storage anyway.
- **Argon2 v1.3 only.** Older v1.0 hashes (`v=16`) are explicitly
  rejected. Rare in modern deployments but worth knowing if you're
  migrating old data.
- **Salt and output sizes are fixed.** 16-byte salt, 32-byte key.
  Both are at the upper end of what spec recommends and at the
  lower end of what tooling supports — perfectly compatible with
  every Argon2 implementation in the wild.
- **No bulk mode.** Each invocation forks a process. For very
  large password-import jobs (hundreds of thousands), the
  per-invocation overhead matters; a dedicated batch wrapper or
  application-level integration would be a better fit.
- **Single-password verify.** No way to verify against multiple
  candidates in one call. For cracking-style operations, hashcat
  / john are the right tools.
- **No memory-pressure protection.** A `-m 1000000` request
  (1 GB) won't be refused — it'll just allocate 1 GB. Don't ask
  for memory you don't have.
- **Constant-time compare protects the verify path only.** The
  hash subcommand's elapsed-time output is informational and
  varies normally with input. Don't expose `elapsed_ms` to
  untrusted callers as part of an auth API response.

## Authorized use

`argon2` is **a local cryptographic computation tool**. No
network activity, no external dependencies, no per-target probing
— same posture as `md5sum` or `openssl`. Fine to run anywhere on
anything you have authorisation to authenticate against.

One note worth attaching: **be careful where the password string
ends up**. The first positional argument shows up in
`/proc/<pid>/cmdline` (visible to other local users on
multi-user systems), gets logged into shell history, and may be
captured by terminal scrollback. For sensitive use:

- Use shell features to avoid history capture (a leading space if
  your shell is configured with `HISTCONTROL=ignorespace`, or
  `set +o history` temporarily).
- Or wrap in a script that reads the password from stdin (not
  currently a Cathedral feature; would require a `--stdin` flag).
- For one-off generation of seeded test hashes, the visibility
  doesn't matter; for actual user-password handling, integrate
  Argon2 at the application layer rather than via the CLI.

## Further reading

- [RFC 9106 — The Memory-Hard Argon2 Password Hash and Proof-of-Work Function](https://www.rfc-editor.org/rfc/rfc9106)
  — the IETF-standardised Argon2 spec, including parameter
  recommendations and security analysis
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
  — the operator-facing parameter recommendations Cathedral's
  defaults follow
- [PHC string format spec](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
  — the canonical format for self-describing password hashes
- [Argon2 reference implementation](https://github.com/P-H-C/phc-winner-argon2)
  — Password Hashing Competition winner, the C reference Cathedral's
  Go implementation matches
- [`golang.org/x/crypto/argon2`](https://pkg.go.dev/golang.org/x/crypto/argon2)
  — the pure-Go Argon2 package Cathedral uses
- [Password Hashing Competition](https://www.password-hashing.net/)
  — the 2013–2015 competition that selected Argon2
- Related Cathedral commands: [`bcrypt`](bcrypt.md) *(planned —
  the older standard Argon2id supersedes; useful for verifying
  legacy stored hashes during migration)*,
  [`crypt`](crypt.md) *(planned — Unix `$1$` md5-crypt / `$5$`
  sha256-crypt / `$6$` sha512-crypt for `/etc/shadow`-style
  hashes)*,
  [`hash`](hash.md) *(planned — fast generic digests across
  MD5/SHA1/SHA2/SHA3 families)*,
  [`entropy`](entropy.md) *(planned — Shannon entropy + common-
  password check before hashing)*,
  [`pwned`](pwned.md) *(planned — Have I Been Pwned k-anonymity
  lookup for password-strength validation)*
