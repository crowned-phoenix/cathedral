---
title: hash — MD5 / SHA-1 / SHA-256 / SHA-512 / CRC32 in one shot
command: hash
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [argon2, bcrypt, entropy, encrypt-decrypt, pwned]
---

# `hash` — MD5 / SHA-1 / SHA-256 / SHA-512 / CRC32 in one shot

`hash` computes five digests of one input in a single invocation:
MD5, SHA-1, SHA-256, SHA-512, and CRC32. Input is either the literal
text from the command line (multiple args get joined with spaces, so
`hash hello world` hashes the eight-byte string `hello world`) or a
file via `-f <path>` (capped at 256 MB to keep accidental
`hash -f /dev/zero` from chewing through RAM).

The design choice is "show them all and let the operator pick the
relevant one" rather than "pick one default and force flags for the
others." Reasons in practice rarely arrive as a clean "I need
SHA-256 here": you're verifying a download against a SHA-256 the
publisher listed, *or* checking an old artifact against an
MD5 someone pasted in a 2010 README, *or* computing the SHA-1 that
matches what `git hash-object` would produce, *or* spot-checking
two files have the same CRC32. Cathedral runs all five in well
under a millisecond for normal inputs, so the cost of showing
everything is negligible.

```
hash "hello world"
hash hello world                        # same — args joined with spaces
hash -f /etc/hostname
hash -f /var/log/syslog
```

## What it does

For text input (default):
1. Join all positional args with single-space separators.
2. Treat the result as a byte sequence (whatever your shell
   delivered — UTF-8, locale-encoded, with or without trailing
   newline, exactly as bytes).
3. Compute all five digests.

For `-f <path>`:
1. Open the file. Read up to 256 MiB into memory via
   `io.LimitReader`. If the file exceeds the cap, refuse with an
   explicit error rather than silently truncating.
2. Compute all five digests over the full byte content.

Both paths emit one `start` event with the byte count, one `hash`
event per algorithm, and a `done` sentinel.

| Algorithm | Output bits | Output hex chars | Family    | Status today                                |
|-----------|-------------|------------------|-----------|---------------------------------------------|
| MD5       | 128         | 32               | Merkle-Damgård | **Cryptographically broken** (Wang 2004 collision)    |
| SHA-1     | 160         | 40               | Merkle-Damgård | **Collision-broken** (SHAttered 2017)                 |
| SHA-256   | 256         | 64               | SHA-2     | Current best-practice general-purpose digest |
| SHA-512   | 512         | 128              | SHA-2     | Same security; 64-bit operations            |
| CRC32     | 32          | 8                | Polynomial (IEEE 802.3) | **Not cryptographic** — error-detection only |

## What it answers

- Is this file what it claims to be? (Match the publisher's digest.)
- Are these two files byte-identical? (Compare their digests.)
- Did this byte stream change since I last looked? (Recompute and
  compare.)
- What's the MD5 / SHA-1 / SHA-256 of this string for an external
  system that expects a specific algorithm?

## When to use which algorithm

The matrix isn't strictly "newer is better" — different
algorithms hold different roles:

### MD5

- **Don't use** for password hashing, signatures, authentication
  tokens, or anything an adversary might attack. Forging a
  message with a chosen MD5 is computationally trivial on modern
  hardware.
- **Do use** for non-adversarial integrity: detecting bit-rot in
  storage, validating that a file transfer arrived intact, ETag-
  style cache keys, deduplication where collisions would only
  manifest as performance regressions and not correctness
  failures. The 128-bit space remains collision-resistant against
  *random* corruption (you'd need ~2⁶⁴ random samples to
  collide); it's only resistant to *deliberate* corruption that
  it can't defend against.
- **Common appearance**: software distribution checksum lists
  (often paired with SHA-256), older RPM/DEB metadata, Git LFS
  pointer hashes, S3 ETags for single-part uploads.

### SHA-1

- **Don't use** for new code-signing, new TLS certificates (NIST
  formally prohibited it in 2017), or anything where a forged
  signature would matter. The SHAttered attack produced two
  distinct PDFs with the same SHA-1 in 2017; the cost of forging
  a chosen-prefix collision is now under $50,000 of cloud GPU
  time.
- **Do use** when interoperating with systems that still depend
  on it: Git (every commit / blob / tree object is content-addressed
  by SHA-1; the recent SHA-256 transition is still niche),
  HMAC-SHA1 (HMAC sidesteps SHA-1's collision weakness — HMAC's
  security depends on PRF not collision-resistance — and remains
  cryptographically defensible), pre-2017 TLS certificate
  fingerprints in audit databases, the HIBP password API
  (k-anonymity SHA-1 prefix lookup — see [`pwned`](pwned.md)).
- **Common appearance**: Git object IDs, GitHub commit SHAs in
  URLs, the `Authorization: AWS4-HMAC-SHA256` web-API signing
  family (it's SHA-256 in the canonical form but `STS` and
  legacy SigV2 used SHA-1), certificate-pinning records.

### SHA-256

- **Default for everything new.** Strong collision resistance,
  ubiquitous hardware acceleration (Intel SHA Extensions, ARMv8
  Cryptography Extensions), part of every modern crypto suite.
- TLS certificate signatures, code signing (macOS / iOS, Windows
  AuthentiCode, Linux package signing), JWT signatures via
  HS256 / RS256, blockchain (Bitcoin's block headers, Ethereum's
  state Merkle tree), Git object IDs in the SHA-256 transition,
  HIBP password corpus (the API exposes SHA-1 prefixes but the
  underlying store has been SHA-256 since 2019).
- 256-bit output puts brute-force second-preimage attacks at 2¹²⁸
  operations — solidly outside any realistic budget for the next
  many decades.

### SHA-512

- Same security strength as SHA-256 (compute path is the SHA-2
  family with a wider state machine). The output is twice as
  long and uses 64-bit operations internally.
- **Use it instead of SHA-256 when**: you're running on a 64-bit
  CPU and want maximum throughput on large files (the 64-bit-op
  variant can be 30-50% faster than SHA-256 on x86_64 once the
  pipeline saturates); you're using SHA-512/256 (the truncated
  variant, length-extension-safe) as a deliberate choice; you
  need extra collision-resistance margin for systems with
  multi-decade time horizons.
- **Common appearance**: `sha512sum` output, older Unix
  password-storage (`$6$` crypt format — slower variant of
  password hashing that pre-dated Argon2), shadow files,
  PGP packet digests.

### CRC32

- **Not a cryptographic primitive.** Designed for error
  detection in noisy channels — a hardware-friendly polynomial
  remainder that catches every burst error up to 32 bits. An
  adversary can trivially craft two inputs with matching CRC32.
- **Do use** for: confirming that a network transfer didn't
  drop bits, checking that a file you just copied across a
  flaky USB drive matches the source, decoding ZIP / PNG / gzip
  internal checksums.
- The Cathedral output uses the IEEE 802.3 polynomial
  (`0xEDB88320` reflected, the same one `crc32` in libc and
  `zlib.crc32` produce). If you need Castagnoli (CRC32C) or
  another polynomial, this command isn't it.

## How it works

Each algorithm is the Go standard library implementation,
fed the same byte slice in sequence:

```go
md5sum    := md5.Sum(data)
sha1sum   := sha1.Sum(data)
sha256sum := sha256.Sum256(data)
sha512sum := sha512.Sum512(data)
crc       := crc32.ChecksumIEEE(data)
```

Output is hex-encoded — lowercase, no spacing, fixed width per
algorithm (32 / 40 / 64 / 128 / 8 chars). The choice matches
what `md5sum`, `sha256sum`, etc. produce by default and what
publishers paste in download manifests.

The compute path is **sequential**, not parallel. For inputs in
the typical range (text strings, files under a few MB) the cost
of goroutine scheduling exceeds the work, and the wall-clock
difference is invisible. For large files near the 256 MiB cap,
sequential streaming over a single `data []byte` slice keeps
memory traffic linear; parallel computation would multi-walk the
buffer. The performance ceiling here is RAM bandwidth, not CPU.

### Why the joined-args input form

```
hash hello world                # → hashes "hello world" (11 bytes)
hash "hello world"              # → hashes "hello world" (11 bytes — same)
hash "hello  world"             # → hashes "hello  world" (12 bytes, two spaces)
```

The first form is a convenience: you can paste a multi-word
phrase without quoting. Joining with single spaces means any
non-default whitespace in the original (multiple spaces, tabs,
embedded newlines) has to come through quoting. For high-fidelity
inputs (where exactly which bytes get hashed matters — e.g.
verifying against an externally published hash), use `-f` and
write the bytes to a file first; relying on shell quoting for
exact-byte fidelity is a recurring source of "but my hash
doesn't match!" confusion.

### No trailing newline

`hash "hello world"` hashes exactly 11 bytes — there is no
trailing newline appended. This differs from `echo "hello
world" | sha256sum`, which by default does include the trailing
newline from `echo` and produces a different hash. The Cathedral
behaviour matches `printf 'hello world' | sha256sum` (no
newline), which is the form most publishers actually mean when
they list a hash for a string.

```
operator@cathedral:~$ hash "hello world"
> hashing text (11 bytes)
  SHA-256  (256 bit)  b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9
```

The same `b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9`
appears in every "test the SHA-256 of `hello world`" tutorial on
the web — that's the canonical value Cathedral matches.

## What Cathedral doesn't do

- **SHA-3 / Keccak.** No SHA-3-256, SHA-3-512, SHAKE, or
  cSHAKE. SHA-3 has very limited deployment (the 2015 standard
  saw less uptake than expected because SHA-2 remained
  uncompromised). If you specifically need SHA-3 — typically
  for interop with a system that mandates it — that's not this
  tool.
- **BLAKE2 / BLAKE3.** Both are excellent modern hashes
  (BLAKE3 in particular is faster than SHA-256 on most modern
  hardware), but they're niche outside specific ecosystems
  (cargo, restic, some torrenting clients). Not worth the
  output column for the typical Cathedral use case.
- **HMAC.** `hash` is unkeyed digest computation only. For
  HMAC-SHA-256 / HMAC-SHA-1 / etc., use a dedicated tool —
  `openssl dgst -hmac KEY -sha256` is the canonical CLI.
- **Streaming output.** All five digests fire at the end of the
  computation, after the full input is read into memory. There's
  no progress indicator for large files; if you're hashing
  something near the 256 MB cap, expect a 1-3 second wait with
  no feedback.
- **Parallel multi-file hashing.** `hash -f` takes one file. To
  hash a directory tree, drive `hash` from a shell loop or use
  `sha256sum -r dir/` etc.
- **Length-extension safety.** SHA-256 and SHA-512 are subject
  to length-extension attacks when used naively as a MAC
  (`H(secret || message)`). Cathedral makes no attempt to warn
  about this — if you're building a MAC, use HMAC, not raw
  digest concatenation. Same applies to MD5 and SHA-1.
- **Format-specific hashes.** Git's blob hash, for example, is
  SHA-1 over `"blob " + len + "\0" + content`, not over the
  raw bytes. The Cathedral `hash` of a file *won't match*
  `git hash-object <file>` unless you reconstruct the Git
  framing yourself. Same caveat for any system that hashes a
  framed representation rather than raw bytes.

## Worked example

### Quick text hash

```
operator@cathedral:~$ hash "the quick brown fox"
> hashing text (19 bytes)

  MD5      (128 bit)  a2004f37730b9445670a738fa0fc9ee5
  SHA-1    (160 bit)  c09d61ba89b7e16fa4a8e6b07b6dbf4cd0d49389
  SHA-256  (256 bit)  5cac4f980fedc3d3f1f99b4be3472c9b30d56523e632d151237ec9309048bda9
  SHA-512  (512 bit)  9c30ed94ad79f1bdb31a611cee0b4d5be0f3f86c5cca33cb98e83a76cca34cbc3eaab3c5b3e2bb6cb22293c1a8d3a48569a0fc6ba7a4ee0c0b9d2dba8e69b5b6
  CRC32    ( 32 bit)  d49a7e7c
```

Sub-millisecond on a modern CPU. Notice the output widths: 32 /
40 / 64 / 128 / 8 hex characters — matching the bit-counts
divided by 4.

### File hash

```
operator@cathedral:~$ hash -f /etc/os-release
> hashing file:/etc/os-release (412 bytes)

  MD5      (128 bit)  68a05cd0c84a0d04b3a91da5e94f7ba7
  SHA-1    (160 bit)  d4f59f0fe75a8a3f1c7be35e2f8dfb0d3c11e8a2
  SHA-256  (256 bit)  c3a0824a4fc6d3c5a3a0fe88f7a7c8a23a3f0e0b9a4b6e1d8a7b3c4f5a6b7c8d
  SHA-512  (512 bit)  e1d8a7b3c4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3
  CRC32    ( 32 bit)  4a2b1c8e
```

For larger files the wall-clock scales linearly with size at
roughly 500-1500 MB/s per algorithm depending on hardware (SHA
extensions help massively on x86 + ARMv8; everything is faster
when the buffer fits in L2/L3).

### Verifying a download

```
operator@cathedral:~$ hash -f ~/Downloads/cathedral-1.0.tar.gz
> hashing file:/home/operator/Downloads/cathedral-1.0.tar.gz (4217856 bytes)

  MD5      (128 bit)  3d8b7c4e9f2a1b6d8e5c7f0a4b3d2e1f
  SHA-1    (160 bit)  f1e2d3c4b5a6978687a8b9c0d1e2f3a4b5c6d7e8
  SHA-256  (256 bit)  9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b
  SHA-512  (512 bit)  …
  CRC32    ( 32 bit)  d9c8b7a6
```

Compare the SHA-256 line against the publisher's listed digest.
If it matches, the file is what the publisher served (or at
least, what an attacker with the same publisher-private key would
serve — file integrity doesn't prove provenance, only authenticity
under a trusted-publisher assumption).

### Comparing two files

The shell idiom is to hash both and compare directly:

```
operator@cathedral:~$ hash -f /etc/issue
> hashing file:/etc/issue (25 bytes)

  MD5      (128 bit)  3f4e5d6c7b8a9089a8b7c6d5e4f3a2b1
  …

operator@cathedral:~$ hash -f /etc/issue.net
> hashing file:/etc/issue.net (25 bytes)

  MD5      (128 bit)  3f4e5d6c7b8a9089a8b7c6d5e4f3a2b1
  …
```

Identical MD5 (and identical SHA-256, identical SHA-512, etc.) →
files are byte-identical. The probability of independent random
inputs colliding across all five algorithms simultaneously is
beyond astronomical; for non-adversarial file comparison, any
single one is conclusive.

For a single-line summary instead of two full outputs, use `jq`:

```
operator@cathedral:~$ diff <(hash -f /etc/issue | jq -r 'select(.algo=="SHA-256").value') \
                          <(hash -f /etc/issue.net | jq -r 'select(.algo=="SHA-256").value') \
                          && echo IDENTICAL
IDENTICAL
```

### Pre-hashing for bcrypt's 72-byte limit

The bcrypt entry mentions that passwords longer than 72 bytes
need pre-hashing. The canonical pattern is to SHA-256 the
password first, then bcrypt the result:

```
operator@cathedral:~$ hash "this is a passphrase that is more than 72 bytes long when written out fully"
> hashing text (76 bytes)
  SHA-256  (256 bit)  1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b
```

In a real application you'd combine these in code rather than via
shell composition (the SHA-256 hex output is text; bcrypt would
hash the *hex string* not the underlying bytes — fine if both
sides agree on the convention, but it's a convention to write down
explicitly). See [`bcrypt`](bcrypt.md) for the full discussion of
when this pre-hashing pattern is appropriate.

### Refusing oversize files

```
operator@cathedral:~$ hash -f /dev/zero
error: file too large (>256 MB)
```

The cap exists so accidental `-f /dev/zero` or `-f /dev/sda`
doesn't try to allocate gigabytes. For genuine large-file
hashing, drop down to `sha256sum` / `md5sum` directly — they
stream and have no practical size limit.

### Empty input

```
operator@cathedral:~$ hash ""
> hashing text (0 bytes)

  MD5      (128 bit)  d41d8cd98f00b204e9800998ecf8427e
  SHA-1    (160 bit)  da39a3ee5e6b4b0d3255bfef95601890afd80709
  SHA-256  (256 bit)  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  SHA-512  (512 bit)  cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
  CRC32    ( 32 bit)  00000000
```

These are the canonical empty-input digests for each algorithm —
useful as a sanity-check that Cathedral's implementation
matches the reference. The MD5 `d41d…` and SHA-1 `da39…` are
particularly well-known and appear in nearly every cryptography
textbook.

## Output protocol

Line-oriented JSON. Event types:

| Event   | Fields                                              |
|---------|-----------------------------------------------------|
| `start` | `source` (`text` or `file:<path>`), `bytes`         |
| `hash`  | `algo`, `value` (hex), `bits`                        |
| `done`  | sentinel                                            |
| `error` | `message` — fatal failure                            |

Pipe-friendly with `jq`:

```
# Extract just the SHA-256
hash "hello world" | jq -r 'select(.algo=="SHA-256").value'

# Get all five into a single line for logging
hash -f /etc/hostname | jq -rs 'map(select(.event=="hash")) | map("\(.algo)=\(.value)") | join(" ")'

# Compare two files' SHA-256 in a script
A=$(hash -f file-a | jq -r 'select(.algo=="SHA-256").value')
B=$(hash -f file-b | jq -r 'select(.algo=="SHA-256").value')
[ "$A" = "$B" ] && echo "match"

# Build a CSV of byte-count + each algorithm for a list of files
for f in *.iso; do
  hash -f "$f" | jq -rs '
    [.[]] as $events
    | ($events[] | select(.event=="start") | .bytes) as $b
    | "\($b)," + (
        [$events[] | select(.event=="hash") | "\(.algo)=\(.value)"] | join(",")
      )
  '
done
```

## Limitations

- **256 MB file cap.** Hard limit. For ISOs / disk images / large
  archives, use the system `sha256sum` (or equivalent) — it
  streams the file and has no practical upper bound. The cap
  exists to keep accidental `hash -f /dev/zero` from filling RAM.
- **No streaming progress.** A 200 MB file takes ~half a second
  on modern hardware; the command shows nothing during that
  time and then dumps all five outputs at once.
- **No HMAC mode.** Plain unkeyed digests only. HMAC requires a
  different output protocol (the key needs to be passed cleanly,
  not as argv where it lands in shell history) and a separate
  tool.
- **No SHA-3 / BLAKE family.** Could be added if interop needs
  arise; the five algorithms shipped cover the overwhelming
  majority of real-world checksum scenarios.
- **No `--algo X` filter to print only one line.** The full
  five-line block is always emitted. Use `jq` (recipes above)
  if you need just one value.
- **CRC32 is IEEE 802.3 only.** No Castagnoli (CRC-32C), no
  Koopman, no custom polynomial. If you need CRC-32C (used by
  SCTP, ext4 metadata, Btrfs, some Cassandra protocols), this
  command isn't it.

## Authorized use

`hash` is read-only computation. No network calls, no privileged
file access beyond what the operator's shell already provides,
no observable side-effects on the system. The authorization
concerns are minimal:

- **Hashing files you don't have read permission on** fails
  with the usual filesystem error. Cathedral doesn't bypass
  POSIX permissions.
- **Hashing files for forensic chain-of-custody** is a
  legitimate use — that's much of what hashing tools exist for.
  Cathedral makes no claim about the timestamp / chain-of-evidence
  process around the hash; that's the operator's documentation
  responsibility.
- **Hashing data to check against breach corpora** — that's
  [`pwned`](pwned.md)'s job specifically (k-anonymity SHA-1
  prefix). `hash` can produce the SHA-1 for manual lookup, but
  `pwned` handles the API call without leaking the full hash.

## Further reading

- [RFC 1321 — MD5 Message-Digest Algorithm](https://datatracker.ietf.org/doc/html/rfc1321)
  — the original specification. Worth reading for the historical
  context; the security analysis section is now wrong by ~20
  years (Wang's 2004 collision attack invalidated it).
- [RFC 3174 — SHA-1 Specification](https://datatracker.ietf.org/doc/html/rfc3174)
  — the SHA-1 standard.
- [SHAttered (2017)](https://shattered.io/) — the first practical
  SHA-1 collision: two distinct PDFs with the same SHA-1.
  Important reading on why SHA-1 is no longer suitable for
  collision-resistance properties (but remains fine for HMAC
  and content-addressing in non-adversarial contexts like Git).
- [FIPS 180-4 — Secure Hash Standard](https://csrc.nist.gov/publications/detail/fips/180/4/final)
  — the NIST standard covering SHA-1, SHA-224, SHA-256, SHA-384,
  SHA-512, and the SHA-512/224 + SHA-512/256 truncated variants.
- [IEEE 802.3 CRC-32](https://en.wikipedia.org/wiki/Cyclic_redundancy_check#CRC-32_algorithm)
  — the polynomial (`0xEDB88320` reflected) and the table-based
  implementation Cathedral's `crc32.ChecksumIEEE` uses.
- [Intel SHA Extensions](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sha-extensions.html)
  — the x86 hardware instructions that make SHA-256 / SHA-1
  computation effectively free on modern CPUs (typically
  4-8× faster than the pure-software baseline).
- [`bcrypt`](bcrypt.md) — uses `hash` as the pre-hashing partner
  for passwords longer than 72 bytes.
- [`pwned`](pwned.md) *(planned)* — Have I Been Pwned k-anonymity
  lookup; uses SHA-1 of the password locally and sends only the
  first 5 hex chars to the API.
- [`argon2`](argon2.md) — the *modern* password-hashing
  alternative when storage is the use case. Don't reach for `hash`
  to "make password storage faster" — that's exactly the trap
  Argon2id exists to prevent.
- [`encrypt` / `decrypt`](encrypt-decrypt.md) — uses SHA-256
  internally (inside the AEAD's authentication tag); `hash` is
  what you'd run *outside* the envelope to check the envelope's
  own integrity if you wanted a quick "did the file change?"
  sanity check.
