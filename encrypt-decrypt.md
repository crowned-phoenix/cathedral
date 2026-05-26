---
title: encrypt / decrypt — passphrase-based authenticated encryption
command: [encrypt, decrypt]
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [argon2, bcrypt, hash, entropy, jwt]
---

# `encrypt` / `decrypt` — passphrase-based authenticated encryption

`encrypt` takes a passphrase, a cipher choice, and some data, and
returns a self-describing base64 envelope. `decrypt` takes the
passphrase and the envelope and returns the original bytes. The
envelope carries every parameter the decryptor needs — algorithm,
KDF, KDF cost, salt, nonce, ciphertext, authentication tag — so the
only out-of-band secret is the passphrase itself.

The two commands are deliberately one-shot: no key files, no key
management, no key servers, no recipients. The use cases are local
("encrypt this `.env` before I rsync it to a thumb drive"), pasted
("here's the staging password — paste this envelope into our shared
Bitwarden note"), and pipeline-friendly (`encrypt … @secrets.txt`
in a backup script). When you need a real cryptosystem with
identities, signatures, and forward secrecy, this isn't it — but
when you just want one passphrase to seal one piece of data with
modern primitives, this is the shortest path that's still
defensible.

```
encrypt aes-gcm "open sesame" "the password is hunter2"
encrypt aes-gcm "open sesame" @/tmp/secrets.env
encrypt chacha20 "stage-key" "small message"
decrypt "open sesame" '$cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$…'
decrypt "open sesame" @/tmp/secrets.env.enc
```

## What it does

For `encrypt <algo> <passphrase> <data-or-@file>`:
1. Read the data — literal string or `@/path` file (capped at 64 MiB).
2. Generate 16 random bytes of salt from `crypto/rand`.
3. Derive a 256-bit key with Argon2id at the OWASP-2024 defaults
   (memory=19 MiB, time=2, threads=1).
4. Construct the requested AEAD (AES-256-GCM or ChaCha20-Poly1305).
5. Generate a fresh random nonce of the AEAD's expected size.
6. Seal (encrypt + authenticate) the plaintext.
7. Format every parameter and the ciphertext into one
   `$cthd1$…` envelope string.
8. Emit the envelope + elapsed wall-clock time.

For `decrypt <passphrase> <envelope-or-@file>`:
1. Parse the envelope — extract algorithm, KDF parameters, salt,
   nonce, ciphertext.
2. Re-derive the key with the *envelope's* Argon2id parameters and
   the supplied passphrase.
3. Build the same AEAD.
4. Open (authenticate + decrypt) the ciphertext.
5. On auth failure (wrong passphrase or tampered envelope) emit a
   clear `[ ✗ ] failed` row and exit non-zero.
6. On success emit the plaintext (or a hex preview for binary data
   that isn't printable text).

| Algorithm  | Cipher                | Key  | Nonce | Tag  | Notes                                  |
|------------|-----------------------|------|-------|------|----------------------------------------|
| `aes-gcm`  | AES-256-GCM           | 32 B | 12 B  | 16 B | NIST-blessed; hardware-accelerated on CPUs with AES-NI |
| `chacha20` | ChaCha20-Poly1305     | 32 B | 12 B  | 16 B | Faster on CPUs without AES-NI (older Intel, most ARM)  |

## What it answers

- Can I move this secret across an untrusted channel?
- Can I store this in shared notes / wiki / Slack pin without
  exposing the content?
- If someone tampered with this envelope, will decryption fail
  loudly?
- Did the person on the other end use the right passphrase?

## How it works

### Key derivation — Argon2id, parameters embedded

Argon2id (the hybrid variant — combines Argon2d's GPU resistance
with Argon2i's side-channel resistance) is the OWASP-recommended
password-based KDF as of 2024. It's memory-hard by design: each
derivation allocates ~19 MiB of working memory at the default
settings, so an attacker brute-forcing the passphrase pays that
memory cost per attempt. On commodity GPUs, that collapses the
parallelism advantage that makes plain hash-iteration KDFs (PBKDF2,
bcrypt) cheap to attack.

```go
salt := make([]byte, 16)
rand.Read(salt)

key := argon2.IDKey(
    []byte(passphrase),
    salt,
    /* time   */ 2,
    /* memory */ 19 * 1024, // 19 MiB
    /* threads*/ 1,
    /* keyLen */ 32,
)
```

The salt and parameters are stored in the envelope alongside the
ciphertext, so `decrypt` can re-derive the same key without any
out-of-band knowledge — exactly the property a PHC-style string
provides for password storage. (Cathedral's [`argon2`](argon2.md)
entry covers the cost-tuning trade-offs in detail; same defaults
apply here.)

### AEAD — sealing + authentication in one step

An AEAD (Authenticated Encryption with Associated Data) cipher
encrypts and authenticates in a single pass. AES-GCM and
ChaCha20-Poly1305 are the two modern choices; both produce a
ciphertext that's the same length as the plaintext plus a fixed
16-byte authentication tag.

```go
aead, _ := cipher.NewGCM(aes256Block)  // or chacha20poly1305.New(key)

nonce := make([]byte, aead.NonceSize())  // 12 B for both
rand.Read(nonce)

ciphertext := aead.Seal(nil, nonce, plaintext, nil)
// ciphertext = encrypted bytes || 16-byte authentication tag
```

On decrypt:

```go
plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
// err != nil  ⇒  authentication failed
//                (wrong key, tampered ciphertext, tampered nonce, …)
```

That single `err != nil` is the whole correctness signal Cathedral
needs: any mutation of any byte in the envelope — including the
salt, nonce, ciphertext, or tag — flips the result to failure.
The decryptor cannot be tricked into returning garbage that "looks
decrypted" but isn't.

### Nonce handling — random, not counter

Both AEADs Cathedral exposes have 12-byte nonces. For the
counter-based use case (a long-lived session encrypting many
messages with one key), you'd allocate a counter and increment per
message; reuse of a nonce with the same key is catastrophic for GCM
and merely bad for ChaCha20.

Cathedral's `encrypt` doesn't have that use case. Each invocation
is one passphrase + one nonce + one ciphertext. So we use random
nonces from `crypto/rand`: the 2⁹⁶ space is large enough that the
birthday-bound collision probability is negligible until you've
encrypted ~2⁴⁸ messages with the same key — and since every
`encrypt` invocation derives a *new* key from a *new* salt, there's
not even a shared-key scenario to worry about.

### Choosing between aes-gcm and chacha20

| Property                        | AES-GCM        | ChaCha20-Poly1305 |
|---------------------------------|----------------|-------------------|
| Hardware acceleration           | Yes (AES-NI)   | No (designed for software speed) |
| Performance on CPUs *with* AES-NI | Faster       | Slightly slower |
| Performance on CPUs *without* AES-NI | Much slower | Faster |
| Side-channel resistance (constant-time) | Implementation-dependent (Go's stdlib is constant-time) | Constant-time by design |
| Output size                     | plaintext + 16 B tag | plaintext + 16 B tag |
| Standardisation                 | NIST SP 800-38D | RFC 8439 |

For most operators on modern x86_64 hardware, AES-GCM wins on speed
by 2–4×. For old hardware, embedded targets, or anything ARM-based
without AES extensions, ChaCha20-Poly1305 wins both speed *and*
side-channel safety. Cathedral's default-ish recommendation is
AES-GCM — it's the modern interop choice — but the alternative
exists for a real reason.

## The envelope format

The envelope is a single ASCII string that starts with `$cthd1$`
and consists of seven `$`-separated fields:

```
$cthd1$<algo>$argon2id$m=<mem>,t=<time>,p=<par>$<salt>$<nonce>$<ct+tag>
```

- **`cthd1`** — version identifier. Future-proofing for envelope
  format revisions; `decrypt` refuses to parse unknown versions.
- **`<algo>`** — `aes-gcm` or `chacha20`.
- **`argon2id`** — the KDF identifier. The format reserves a slot
  for swap-in alternatives (Argon2d, Argon2i, or future KDFs);
  v1 only accepts `argon2id`.
- **`m=…,t=…,p=…`** — Argon2id cost parameters in PHC convention
  (memory in KiB, time iterations, parallelism degree). At the
  defaults this is `m=19456,t=2,p=1`.
- **`<salt>`** — 16 random bytes, raw-standard-base64.
- **`<nonce>`** — 12 random bytes, raw-standard-base64.
- **`<ct+tag>`** — ciphertext concatenated with the 16-byte AEAD
  tag, raw-standard-base64.

Raw-standard-base64 means no padding (`=` characters dropped) and
no URL-safe alphabet — the standard `+/` set. The format choice is
deliberate: pasteable into web forms, shell scripts, and clipboards
without quoting drama, while still surviving any system that
preserves ASCII bytes.

A real envelope looks like this (one line in practice; broken here
to fit the page):

```
$cthd1$aes-gcm$argon2id$m=19456,t=2,p=1
  $7tL2vJ8AqV3pXnQ1KfRmZw
  $9rH3PqK2YxN8sJfBmZc4
  $bL6vTzKj9YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjN
```

The conceptual ancestor is the [PHC string format](https://github.com/P-H-C/phc-string-format)
used for password storage — same `$`-delimited, version-prefixed,
self-describing shape. Cathedral's envelope extends the idea past
"a password hash" into "a sealed payload."

## What Cathedral doesn't do

- **Key management.** There are no key files, key servers, or
  hardware-token integrations. The passphrase is the key material;
  losing it loses the data, full stop. If you need rotation,
  expiry, escrow, or multi-recipient unlock, you're shopping for
  age, OpenSSL CMS, GPG, or a real KMS.
- **Asymmetric / public-key encryption.** Symmetric only. There's
  no "encrypt to a recipient by their public key"; you and your
  counterparty must already share the passphrase out-of-band.
- **Signing.** AEAD authenticates *that the data wasn't tampered
  with* under the key — anyone with the key can produce a valid
  envelope, so this isn't a non-repudiable signature. If you need
  to prove *who* produced a message, you want Ed25519 or
  equivalent.
- **Forward secrecy.** Each envelope is self-contained; if you
  reuse the same passphrase for ten envelopes and an attacker
  later compromises that passphrase, all ten decrypt. There's no
  ratchet, no ephemeral keys, no per-message session.
- **Streaming.** `encrypt` reads the entire plaintext into memory
  (capped at 64 MiB) and emits one ciphertext blob. For real
  archive-style streaming you want age, or AES-GCM with a chunking
  layer like Tink's streaming AEAD.
- **Plaintext metadata protection.** The envelope's algorithm
  field, KDF parameters, and the very *fact* that something is a
  Cathedral envelope are all visible in plaintext. An adversary
  seeing a `$cthd1$…` string knows the cipher and KDF cost
  before they even try to crack it.
- **Side-channel hardening for the passphrase.** The passphrase
  is passed as an argv string. On a multi-user machine, anyone
  with `ps` access can read it during the lifetime of the
  `encrypt` process. For sensitive operational use, edit
  Cathedral's shell history afterwards or feed the passphrase via
  a different channel (file input is a planned alternative).

## Worked example

End-to-end encrypt + decrypt cycle, plus the failure modes.

### Encrypt a short string

```
operator@cathedral:~$ encrypt aes-gcm "open sesame" "the password is hunter2"
> encrypting literal with aes-gcm   (23 B)
  envelope :
    $cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$7tL2vJ8AqV3pXnQ1KfRmZw$9rH3PqK2YxN8sJfBmZc4$bL6vTzKj9YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjN
  23 B → 39 B   (54 ms)
```

54 ms wall-clock on Cathedral's host hardware. Most of that is the
Argon2id key derivation (the actual AES-GCM seal of 23 plaintext
bytes is microseconds); per-message KDF cost is the whole point of
the design — an attacker brute-forcing the passphrase pays the
same 54 ms ×19 MiB of memory per guess.

The 23 B plaintext expanded to 39 B of base64-encoded ciphertext
(16-byte AEAD tag included), wrapped in a 156-character envelope
string overall.

### Encrypt a file with ChaCha20

```
operator@cathedral:~$ encrypt chacha20 "stage-key" @/etc/staging.env
> encrypting file:/etc/staging.env with chacha20   (482 B)
  envelope :
    $cthd1$chacha20$argon2id$m=19456,t=2,p=1$KfRmZw7tL2vJ8AqV3pXnQ1$xN8sJfBmZc49rH3PqK2Y$YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjNbL6vTzKj9Y…
  482 B → 498 B   (51 ms)
```

ChaCha20-Poly1305 produces the same 16-byte tag overhead as AES-GCM
(498 = 482 + 16). The wall-clock is dominated by the same Argon2id
derivation — the cipher choice barely registers at this size.

The `@/etc/staging.env` form reads from the named file; same
behaviour as `cat /etc/staging.env | encrypt …` would have, but
without the shell intermediate and without the 64 MiB limit being
imposed on a pipe buffer.

### Decrypt — correct passphrase

```
operator@cathedral:~$ decrypt "open sesame" '$cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$7tL2vJ8AqV3pXnQ1KfRmZw$9rH3PqK2YxN8sJfBmZc4$bL6vTzKj9YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjN'
> decrypting aes-gcm envelope   (39 B ciphertext, argon2id m=19456 t=2 p=1)
[ ✓ ] decrypted — 23 B   (53 ms)

  the password is hunter2
```

Round-trip works; the 53 ms is symmetric with the encrypt side
(same Argon2id derivation pays the same cost). The plaintext is
printable, so Cathedral renders it directly.

### Decrypt — wrong passphrase

```
operator@cathedral:~$ decrypt "wrong" '$cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$7tL2vJ8AqV3pXnQ1KfRmZw$9rH3PqK2YxN8sJfBmZc4$bL6vTzKj9YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjN'
> decrypting aes-gcm envelope   (39 B ciphertext, argon2id m=19456 t=2 p=1)
[ ✗ ] failed — authentication failed — wrong passphrase or tampered ciphertext    (52 ms)
```

The same ~52 ms cost as the success case — Argon2id runs to
completion regardless of correctness, and the AEAD authentication
check is constant-time. Elapsed-time observation reveals nothing
about whether the passphrase was *close* or *far*.

### Decrypt — tampered envelope

```
operator@cathedral:~$ decrypt "open sesame" '$cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$7tL2vJ8AqV3pXnQ1KfRmZw$9rH3PqK2YxN8sJfBmZc4$bL6vTzKj9YnQpX2WqMxK4dN5rT8hF3LjPqR7VsWzKjA'
> decrypting aes-gcm envelope   (39 B ciphertext, argon2id m=19456 t=2 p=1)
[ ✗ ] failed — authentication failed — wrong passphrase or tampered ciphertext    (53 ms)
```

Same envelope, last base64 character flipped from `N` to `A` — one
byte of ciphertext or tag has changed. AEAD fails closed. The
error message can't distinguish between "wrong key" and "tampered
ciphertext" without leaking information that helps the attacker, so
both surface as the same opaque "authentication failed."

### Encrypt a binary file

```
operator@cathedral:~$ encrypt aes-gcm "open sesame" @/usr/bin/true
> encrypting file:/usr/bin/true with aes-gcm   (35672 B)
  envelope :
    $cthd1$aes-gcm$argon2id$m=19456,t=2,p=1$KfRmZw7tL2vJ8AqV3pXnQ1$xN8sJfBmZc49rH3PqK2Y$… [several KB of base64] …
  35672 B → 35688 B   (54 ms)
```

The 35 KB binary expands to ~47 KB of base64 in the final
envelope — the ciphertext itself is plaintext-sized + 16-byte tag,
but base64 encoding adds ~33% overhead on top.

For files larger than a few KB, redirect the envelope to disk:

```
operator@cathedral:~$ encrypt aes-gcm "open sesame" @/usr/bin/true > /tmp/true.enc
```

### Decrypt — binary output

```
operator@cathedral:~$ decrypt "open sesame" @/tmp/true.enc
> decrypting aes-gcm envelope   (35688 B ciphertext, argon2id m=19456 t=2 p=1)
[ ✓ ] decrypted — 35672 B   (53 ms)

  (binary plaintext — first 64 B as hex below; pipe to file via shell to recover):
  7f454c4602010100000000000000000000020003e80020019b0001000000400000000000000040000000…
```

Cathedral detects that the plaintext is binary (presence of NUL
bytes or non-UTF-8 sequences in the first few KB) and shows a hex
preview of the first 64 bytes rather than dumping a binary stream
to the terminal. To actually recover the file, redirect through a
small driver:

```
operator@cathedral:~$ decrypt --raw "open sesame" @/tmp/true.enc > /tmp/true
```

*(The `--raw` flag emits the plaintext to stdout without the JSON
envelope wrapping; planned, see [Limitations](#limitations).)*

### Wrong algorithm in envelope

```
operator@cathedral:~$ decrypt "open sesame" '$cthd1$rot13$argon2id$m=19456,t=2,p=1$KfRmZw$xN8sJfBmZc4$YnQpX2W'
error: unknown algorithm "rot13" (use aes-gcm or chacha20)
```

The version prefix passed but the algorithm field listed
something Cathedral doesn't know how to construct. Cathedral
refuses early rather than trying to "guess what the operator
meant."

### Malformed envelope

```
operator@cathedral:~$ decrypt "open sesame" 'not-an-envelope'
error: invalid envelope: expected 8 fields, got 1
```

Anything that doesn't `$`-split into the expected 8 pieces (empty
prefix + 7 fields) is rejected immediately. Helpful when an
envelope gets line-wrapped or partial-pasted and you need to know
*why* it's broken.

## Output protocol

`encrypt` and `decrypt` are line-oriented JSON streams. Each line
is one event. Shared shape:

| Event              | Fields                                                                                  |
|--------------------|-----------------------------------------------------------------------------------------|
| `start` (encrypt)  | `mode: "encrypt"`, `algo`, `source` (`literal` or `file:<path>`), `bytes`               |
| `start` (decrypt)  | `mode: "decrypt"`, `algo`, `kdf`, `kdf_time`, `kdf_memory`, `kdf_threads`, `ciphertext_bytes` |
| `encrypted`        | `envelope`, `plaintext_bytes`, `ciphertext_bytes`, `elapsed_ms`                         |
| `decrypted`        | `bytes`, `is_text`, `elapsed_ms`, `plaintext` (if textish) or `hex_preview` (if binary) |
| `decrypt_failed`   | `reason`, `elapsed_ms`                                                                  |
| `done`             | end-of-stream sentinel                                                                  |
| `error`            | `message` — fatal pre-flight or parse failure                                           |

Pipe-friendly with `jq`:

```
# Round-trip just the envelope through a shell variable
ENV=$(encrypt aes-gcm "open sesame" "secret" | jq -r 'select(.event=="encrypted").envelope')

# Decrypt and extract just the plaintext
decrypt "open sesame" "$ENV" | jq -r 'select(.event=="decrypted").plaintext'

# Detect authentication failures programmatically
decrypt "wrong" "$ENV" | jq -e 'select(.event=="decrypt_failed")' >/dev/null \
  && echo "auth failed"
```

## Limitations

- **Passphrase via argv only.** No prompt, no environment variable
  source, no file source. On a shared host, anyone with `ps` can
  read the passphrase during the few hundred milliseconds the
  process runs. Planned: `-p` flag for interactive prompt, `-e
  ENVVAR` for env-var lookup, `-f PATH` for file-as-passphrase.
- **64 MiB input cap.** Files larger than that are rejected at
  read time. Cathedral isn't a backup tool; if you're encrypting
  archive-shaped data the right tool is age or restic.
- **No `--raw` output flag yet.** Binary plaintext currently shows
  a hex preview but doesn't write the full bytes to stdout. To
  recover binary files via the current CLI, redirect the JSON to
  a file and decode the `plaintext` field with `jq -r` + `base64
  -d` — workable but ugly. Tracked.
- **KDF parameters are fixed at encrypt time.** No flag to bump
  Argon2id cost above the defaults for high-value payloads. The
  envelope format supports it (the `m=,t=,p=` slot is read
  verbatim on decrypt), but `encrypt` has no flag yet to set
  non-default values. Planned: `--kdf-mem=N`, `--kdf-time=N`,
  `--kdf-threads=N`.
- **No envelope-format versioning beyond v1.** When `cthd2`
  arrives, `decrypt` will need a v1/v2 dispatcher. Today there's
  only one branch.

## Authorized use

Symmetric encryption of your own data is one of the lowest-risk
things Cathedral does. The relevant boundary is the passphrase:

- **Encrypting your own data with your own passphrase** — fine,
  this is the whole intended use.
- **Encrypting third-party data without consent** — irrelevant
  to Cathedral; it's just an encryption tool. The legal and
  ethical questions live elsewhere.
- **Decrypting someone else's envelope without their passphrase**
  — Cathedral can't help you. Argon2id at OWASP defaults plus a
  decent passphrase puts brute-force attacks in the
  "thousands-of-CPU-years" range; that's the design.
- **Adversarial sniffing of `ps` output for the argv passphrase**
  — real on shared hosts, see the passphrase-via-argv limitation
  above. Edit your shell history after use; don't run `encrypt`
  on hosts where you don't trust the operator above you.

## Further reading

- [Argon2 RFC 9106](https://datatracker.ietf.org/doc/html/rfc9106)
  — the canonical specification for Argon2id, including the
  parameter-tuning guidance Cathedral follows.
- [OWASP Password Storage Cheat Sheet — Argon2id](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html#argon2id)
  — source of Cathedral's default `m=19 MiB, t=2, p=1`. Worth
  re-checking annually; the defaults shift as hardware does.
- [ChaCha20-Poly1305 RFC 8439](https://datatracker.ietf.org/doc/html/rfc8439)
  — the AEAD specification. Notably the explicit
  constant-time-by-construction property that makes it the
  preferred choice on hardware without AES acceleration.
- [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
  — AES-GCM specification. The nonce-reuse warnings here are
  important reading if you ever need to drive GCM with a counter
  rather than randomness.
- [PHC string format](https://github.com/P-H-C/phc-string-format/blob/master/phc-sf-spec.md)
  — the lineage of the `$cthd1$…` envelope shape.
- [age](https://age-encryption.org/) — what to reach for when you
  outgrow `encrypt`/`decrypt`: identities (key pairs), recipients,
  streamable. Cathedral aims at the strictly smaller "one
  passphrase, one envelope" niche.
- [`argon2`](argon2.md) — Cathedral's password-hashing command;
  same Argon2id primitive used here as a KDF, but in
  password-storage rather than key-derivation framing.
- [`entropy`](entropy.md) — checks the passphrase you're about to
  use against the strength bands Cathedral cares about. A 60-bit
  passphrase paired with Argon2id at default cost is roughly the
  floor for "an attacker won't brute-force this on any
  realistic budget"; below that, increase the passphrase entropy
  before relying on this command.
