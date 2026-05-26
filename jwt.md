---
title: jwt — decode + verify JSON Web Tokens with alg-safety classification
command: jwt
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-26
related: [hash, argon2, bcrypt, encrypt-decrypt, headers]
---

# `jwt` — decode + verify JSON Web Tokens with alg-safety classification

`jwt` has two subcommands: `decode` splits a token's three
base64url segments and pretty-prints header + payload + signature
metadata without checking anything; `verify` does the same and then
runs the signature against a supplied secret (for HMAC) or PEM
public key (for RSA / ECDSA / EdDSA).

The alg field of the header is classified into four safety tiers
(`good` / `warn` / `unknown` / `danger`) so the rendering can
flag obviously-bad choices at decode time:

- **`danger`** — `alg: none`. The `none` header is the canonical
  JWT anti-pattern: it tells the *verifier* to skip signature
  checking entirely. Some library bugs over the years (the
  classic 2015 jwtcrack writeup, plus many CVE-shaped sequels)
  have made `none` an attacker's first-try header substitution.
  Cathedral refuses to verify a `none`-algorithm token *even
  when a key is supplied* — the security signal has to be
  unambiguous.
- **`warn`** — HS256 / HS384 / HS512. HMAC is fine when used
  correctly, but the symmetric-shared-secret model means any
  party that can *verify* can also *forge*. Used incorrectly
  (the secret leaks via a misconfigured CI variable, or both
  client and server share the same secret), HMAC tokens become
  forgeable across trust boundaries.
- **`good`** — RS256/384/512, PS256/384/512, ES256/384/512,
  EdDSA. Asymmetric signing means the verifier only needs the
  public key; the signing key stays on the issuer.
- **`unknown`** — anything outside the supported list. Cathedral
  reports the value verbatim and treats it as unverifiable.

```
jwt decode $TOKEN
jwt verify $TOKEN -k "your-256-bit-secret"
jwt verify $TOKEN -k @/path/to/pubkey.pem
```

## What it does

For `decode <token>`:

1. Split on `.` into exactly three segments. Reject if not 3.
2. Base64url-decode each (handling the no-padding convention).
3. JSON-decode header + payload. Signature stays as raw bytes.
4. Classify `alg` into the safety tier.
5. Separate RFC 7519 standard claims (`iss`, `sub`, `aud`,
   `exp`, `nbf`, `iat`, `jti`) from custom claims.
6. If `iat` / `nbf` / `exp` are present, compute ISO timestamps
   + relative-time strings ("3h 12m from now" / "5d 2h ago")
   and produce a verdict (`active` / `expired` / `not_yet_valid`).
7. Emit the lot as structured events.

For `verify <token> -k <secret|@key.pem>`:

1. Run the full decode pipeline above.
2. If `alg == "none"`: emit `match: false`, exit non-zero. The
   key is not consulted.
3. Otherwise dispatch on `alg`:
   - HS256/384/512 → HMAC-SHA256/384/512 with `key` as raw bytes.
   - RS256/384/512 → RSA-PKCS1v15-verify with PEM-parsed public
     key + matching SHA family.
   - PS256/384/512 → RSA-PSS-verify with PEM-parsed public key +
     matching SHA family + salt length = hash length.
   - ES256/384/512 → ECDSA-verify with PEM-parsed public key,
     splitting the signature into `r || s` (JWS-style, fixed-width
     per curve).
   - EdDSA → Ed25519.Verify with PEM-parsed public key.
4. Emit `verify_result` with `match: true|false` + reason on
   failure.

| Algorithm    | Class    | Key format for `-k`                | Notes                                  |
|--------------|----------|-------------------------------------|----------------------------------------|
| `none`       | danger   | (none)                              | Refused outright; security signal      |
| HS256/384/512| warn     | Raw secret string                   | Symmetric — secret must not leak       |
| RS256/384/512| good     | PEM public key (PKIX/PKCS1/cert)    | RSA-PKCS1v15 + SHA-2 family            |
| PS256/384/512| good     | PEM public key                      | RSA-PSS, salt length = hash length     |
| ES256/384/512| good     | PEM public key                      | ECDSA on P-256/P-384/P-521 with r∥s sig|
| EdDSA        | good     | PEM public key (Ed25519)            | RFC 8037; fast + deterministic         |

## What it answers

- What's actually inside this token? (Decode — no key needed.)
- Did this signature actually come from someone with the key?
  (Verify with HMAC secret or asymmetric public key.)
- Is this token currently active, expired, or not yet valid?
- Is this token using `alg: none` — i.e. the verifier is being
  asked not to verify?

## How it works

### JWT structure

A JWT is three base64url-encoded segments joined by dots:

```
eyJhbGciOiJIUzI1NiJ9 . eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkphbmUifQ . SflKxw...kpXVCJ9
└────── header ─────┘ └──────────────── payload ──────────────────────┘ └── signature ──┘
```

Each segment decodes to:

- **Header** — JSON `{"alg":"HS256","typ":"JWT"}` describing
  the signing algorithm and (optionally) the token type and a
  key identifier (`kid` is the most common header extension).
- **Payload** — JSON containing claims. RFC 7519 defines seven
  *standard* claim names (`iss`, `sub`, `aud`, `exp`, `nbf`,
  `iat`, `jti`); anything else is application-specific.
- **Signature** — bytes whose interpretation depends on `alg`.
  For HMAC algorithms it's the raw MAC; for RSA-PKCS1v15 it's
  the signature in standard RSA encoding; for ECDSA it's
  `r || s` (concatenated big-endian, fixed-width per curve);
  for EdDSA it's the 64-byte Ed25519 signature.

### Base64url, no padding

The `base64url` variant uses `-` and `_` instead of `+` and `/`
so the result is URL-safe without escaping. JWTs additionally
strip the trailing `=` padding characters. Cathedral re-adds the
padding on decode:

```go
func b64urlDecode(s string) ([]byte, error) {
    if pad := len(s) % 4; pad != 0 {
        s += strings.Repeat("=", 4-pad)
    }
    return base64.URLEncoding.DecodeString(s)
}
```

### The signing-input convention

For every algorithm except `none`, the *signed bytes* are the
ASCII string `header_b64 + "." + payload_b64` — the first two
segments of the token, joined by a literal dot, with their
base64url encoding intact (not the decoded JSON). This is what
the signer signed; this is what Cathedral hashes / verifies
against. The signature segment is *not* included in the signed
bytes (it's the output, not the input).

```go
signingInput := []byte(parts[0] + "." + parts[1])
// HMAC: hmac(secret, signingInput) == claimed-signature?
// RSA-PKCS1v15: verify(pubkey, sha2(signingInput), claimed-sig)
// ECDSA: verify(pubkey, sha2(signingInput), r, s)
// EdDSA: ed25519.Verify(pubkey, signingInput, claimed-sig)
```

### `alg: none` — refused even with a key

```go
if parsed.alg == "none" {
    emitDecoded(parsed, false, "")
    emit(event{
        "event":  "verify_result",
        "match":  false,
        "reason": "algorithm `none` is never trusted, regardless of key",
    })
    os.Exit(1)
}
```

This is structural, not heuristic. Even if the operator supplies
a `-k secret`, `jwt verify` *will not* return `match: true` on a
`none`-algorithm token. The reasoning is the canonical
verifier-side defence: many real-world JWT bugs over the years
allowed `{"alg":"none"}` tokens to validate because the library's
`verify(token, key)` API would fall through to "no signature to
check" before consulting the supplied key. Cathedral's `verify`
is allowed to be paranoid here because there's no legitimate
use case for asking a verification tool to accept the
unverifiable.

### HMAC verification

The straightforward case. The secret is whatever bytes the
operator passes via `-k`:

```go
mac := hmac.New(sha256.New, secret)  // or sha512.New384, sha512.New
mac.Write(signingInput)
return hmac.Equal(mac.Sum(nil), claimedSignature)
```

`hmac.Equal` is the standard library's constant-time compare —
elapsed-time observation of the verify path doesn't leak
information about how close the candidate is to correct.

### RSA-PKCS1v15 vs RSA-PSS

Two RSA padding schemes share the JWT family. Both use the same
RSA public key; they differ in how the signature is constructed:

- **PKCS1v15** (algorithms `RS256`/`RS384`/`RS512`) — the
  older, deterministic encoding. Given the same key + same
  message + same hash, the signature is always the same bytes.
- **PSS** (algorithms `PS256`/`PS384`/`PS512`) — the modern,
  randomised encoding. Each signature uses a fresh random salt
  (Cathedral expects salt length = hash output length, the
  JWS-standard value). Different signatures of the same
  message are different bytes; verification is unaffected.

```go
// RSA-PKCS1v15
hashed := sha256(signingInput)
err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, hashed, claimedSig)

// RSA-PSS
opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash}
err := rsa.VerifyPSS(pub, crypto.SHA256, hashed, claimedSig, opts)
```

The PSS-vs-PKCS1v15 choice rarely matters in practice for
verification — if the issuer uses one, the verifier uses the
same. Both are cryptographically sound; PSS has marginally
better theoretical security properties but PKCS1v15 has the
longer track record.

### ECDSA — `r || s`, not DER

ECDSA signatures consist of two integers `r` and `s`. The
*standard* X.509 / OpenSSL encoding wraps them in DER as a
SEQUENCE of two INTEGERs. **JWS does not do that.** JWS encodes
ECDSA signatures as `r || s` — concatenated fixed-width
big-endian, padded with leading zeros to the curve's byte
length:

| Algorithm | Curve | Coordinate bytes | Signature bytes |
|-----------|-------|------------------|-----------------|
| ES256     | P-256 | 32               | 64              |
| ES384     | P-384 | 48               | 96              |
| ES512     | P-521 | 66 (rounded up)  | 132             |

```go
curveBits := pub.Curve.Params().BitSize
sigSize := (curveBits + 7) / 8   // ⌈bits/8⌉ — handles P-521's 521 bits
if len(sig) != sigSize*2 {
    return false, fmt.Errorf("invalid ECDSA signature length…")
}
r := new(big.Int).SetBytes(sig[:sigSize])
s := new(big.Int).SetBytes(sig[sigSize:])
return ecdsa.Verify(pub, sha2(signingInput), r, s)
```

This is the most common JWT-library bug across languages — code
that uses `crypto/x509` to verify ECDSA signatures assumes DER
encoding, and JWS tokens fail verification because they're not
DER. Cathedral does the right thing by splitting the
fixed-width concatenated form.

### EdDSA — Ed25519

The newest and arguably cleanest signature in the JWT family.
[RFC 8037](https://datatracker.ietf.org/doc/html/rfc8037)
specifies the JOSE algorithm identifier `EdDSA` and binds it to
Ed25519. The signature is exactly 64 bytes; verification is
deterministic, fast, and side-channel-resistant by design.

```go
return ed25519.Verify(pub, signingInput, claimedSig)
```

If you have a choice when designing a new JWT-based system,
EdDSA is what Cathedral recommends — fastest verification path,
smallest public keys (32 bytes), no parameter choices to get
wrong.

### PEM auto-detection

Cathedral accepts three PEM forms for asymmetric verification,
auto-detected by the BEGIN marker:

```
-----BEGIN PUBLIC KEY-----            ← PKIX (most common)
…
-----END PUBLIC KEY-----

-----BEGIN RSA PUBLIC KEY-----        ← PKCS1 (RSA-specific, legacy)
…
-----END RSA PUBLIC KEY-----

-----BEGIN CERTIFICATE-----            ← cert; key extracted via cert.PublicKey
…
-----END CERTIFICATE-----
```

The third form is useful when the only thing you have is the
TLS certificate of an OAuth provider — Cathedral parses the
certificate, extracts the public key embedded in it, and
verifies the JWT against that. No need to extract the public
key into a separate file first.

### Standard claims, timing, verdict

RFC 7519 defines seven standard claim names. Cathedral
separates them from custom claims and treats `iat`/`nbf`/`exp`
specially because they have time semantics:

- **`iat`** (issued at) — when the token was issued. Always
  in the past for a valid token.
- **`nbf`** (not before) — earliest time the token is valid.
  Tokens are *not yet valid* before this.
- **`exp`** (expires at) — latest time the token is valid.
  Tokens are *expired* at or after this.

```go
now := time.Now().Unix()
verdict := "active"
if exp, ok := claims["exp"]; ok && now >= exp {
    verdict = "expired"
} else if nbf, ok := claims["nbf"]; ok && now < nbf {
    verdict = "not_yet_valid"
}
```

The verdict appears in the rendered output as a colour-coded
badge: green `[ ✓ ] ACTIVE`, red `[ ✗ ] EXPIRED`, amber `[ ! ]
NOT YET VALID`. Tokens with no time claims at all skip the
timing block — but they're also strongly suspect (a token that
can't expire is a perpetual credential, almost never the
intended design).

## What Cathedral doesn't do

- **No signing.** `jwt` decodes and verifies; it doesn't
  produce new tokens. For signing, every JWT library in every
  language has a sign function — pick the library you'd use
  for verification in your application code, drive it from
  there.
- **No JWE.** [JSON Web Encryption](https://datatracker.ietf.org/doc/html/rfc7516)
  is a separate spec (RFC 7516) for *encrypted* JWTs — the
  payload is opaque ciphertext, not base64'd JSON. Cathedral
  doesn't handle JWE; trying to `jwt decode` a JWE produces
  the "3 segments, got 5" error because JWE has five segments
  (header.encryptedKey.iv.ciphertext.tag).
- **No JWK Set fetching.** Many real-world JWT issuers
  publish their public keys at a `/.well-known/jwks.json`
  endpoint with rotation support. Cathedral expects you to
  paste/save a single PEM key — there's no `-k @url://…` form.
  Workflow: fetch the JWKS JSON externally, extract the
  relevant key by `kid`, save as PEM.
- **No `kid`-based key selection.** The header's `kid` field
  identifies which key signed the token. Cathedral surfaces
  the `kid` value in the header display so the operator can
  cross-reference it manually, but doesn't auto-select a
  key from a multi-key keyring.
- **No claim-content verification beyond timing.** Cathedral
  checks `exp` / `nbf` but doesn't validate `iss`
  (issuer-allowlist), `aud` (audience-must-match), or `jti`
  (replay-protection). Real production verifiers should do
  all of these; Cathedral is an inspection tool, not a
  policy-enforcement gateway.
- **No nested JWT (`cty: JWT`) unwrapping.** Encrypted
  containers with a signed JWT inside are uncommon outside
  enterprise SSO and not handled.
- **No clock-skew tolerance.** Cathedral compares against
  *exact* `time.Now()`. Real verifiers typically allow ±60s of
  skew to cope with clock drift between issuer and verifier;
  Cathedral reports the literal verdict, which can be more
  honest for forensic use but stricter than what production
  systems would accept.

## Worked example

### Decode an HS256 token

```
operator@cathedral:~$ jwt decode eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL2F1dGguZXhhbXBsZS5jb20iLCJzdWIiOiJ1c2VyXzg4OTEiLCJhdWQiOiJjYXRoZWRyYWwiLCJleHAiOjE3ODc0NTY3ODksImlhdCI6MTc4NzQ1MzE4OSwianRpIjoiYzQ4N2MwMmEifQ.WzVdRrU9KxCgVnZmDPnpPN2VYy2HoNXuB-Iqz8sBLUM
> decoding JWT

[ header ]
  alg : HS256     (warn)
  typ : JWT

[ payload — standard claims ]
  iss  issuer       https://auth.example.com
  sub  subject      user_8891
  aud  audience     cathedral
  jti  token id     c487c02a

[ timing ]
  iat  2026-05-21T08:33:09Z     (5d 14h ago)
  exp  2026-05-21T09:33:09Z     (5d 13h ago)
  [ ✗ ] EXPIRED    now is past `exp`

[ signature ]
  32 bytes   WzVdRrU9KxCgVnZmDPnpPN2VYy2HoNXuB-Iqz8sBLUM
```

Decode shows everything except signature validity. The `alg :
HS256 (warn)` tag is the symmetric-secret warning; the `[ ✗ ]
EXPIRED` verdict tells you immediately that this token wouldn't
authenticate anywhere right now even if the signature were
valid. The `5d 13h ago` makes the expiry concrete without
requiring you to mentally convert epoch seconds.

### Verify with the correct HMAC secret

```
operator@cathedral:~$ jwt verify eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyXzg4OTEiLCJpYXQiOjE3ODc0NTMxODl9.K8nF2hQp3vR7m9DxLcS8WaY1B5gN0iE6tZjA4yU2oP -k "your-256-bit-secret"
> verifying JWT

[ header ]
  alg : HS256     (warn)
  typ : JWT

[ payload — standard claims ]
  sub  subject      user_8891

[ timing ]
  iat  2026-05-21T08:33:09Z     (5d 14h ago)
  [ ✓ ] ACTIVE

[ signature ]
  32 bytes   K8nF2hQp3vR7m9DxLcS8WaY1B5gN0iE6tZjA4yU2oP
  ✓ verified with HS256
```

The `✓ verified with HS256` line is the affirmative signal.
Note that ACTIVE here is just "no exp claim, so not expired";
a permanent HMAC token like this should raise a different
flag for "no expiry set" — but Cathedral surfaces the structure,
not the policy.

### Verify with the wrong secret

```
operator@cathedral:~$ jwt verify eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyXzg4OTEifQ.K8nF2hQp3vR7m9DxLcS8WaY1B5gN0iE6tZjA4yU2oP -k "wrong-secret"
> verifying JWT

[ header ]
  alg : HS256     (warn)

[ payload — standard claims ]
  sub  subject      user_8891

[ signature ]
  32 bytes   K8nF2hQp3vR7m9DxLcS8WaY1B5gN0iE6tZjA4yU2oP
  ✗ signature does not match
```

The signature-mismatch path. No information about which byte
position differs; HMAC is constant-time and there's nothing
useful to surface beyond "no match."

### Verify with an RSA public key (PEM)

```
operator@cathedral:~$ jwt verify eyJhbGciOiJSUzI1NiIsImtpZCI6IjJjMmExNGUifQ.eyJpc3MiOiJodHRwczovL3Rva2VuLmF1dGgwLmNvbS8iLCJzdWIiOiJhdXRoMHwxMjM0NTYiLCJhdWQiOiJodHRwczovL2FwaS5leGFtcGxlLmNvbSIsImV4cCI6MTc4ODA1MDAwMCwiaWF0IjoxNzg3OTk2MDAwfQ.sigBlobHere -k @/etc/auth0/pubkey.pem
> verifying JWT

[ header ]
  alg : RS256     (good)
  kid : 2c2a14e

[ payload — standard claims ]
  iss  issuer       https://token.auth0.com/
  sub  subject      auth0|123456
  aud  audience     https://api.example.com

[ timing ]
  iat  2026-05-27T15:00:00Z     (1d 6h from now)
  exp  2026-05-28T06:00:00Z     (21h from now)
  [ ! ] NOT YET VALID    now is before `nbf`
```

The `kid: 2c2a14e` header field gives you the key identifier
the issuer is using — useful for cross-referencing against a
multi-key keyring when picking which PEM to pass via `-k`.

(In this fabricated example the `iat` is in the future, which
real tokens never are — it's shown to illustrate the timing
display.)

### Verify with an ECDSA public key

```
operator@cathedral:~$ jwt verify eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.Ec5oZ_K6V8dQfH3R1pL2nW7sA4yU2oPzM9NxJqB6vRtKx7gF1cD2hM0iE6tZjA4yU2oP3sNbX1ZwT5fHrL6uIqAg -k @/tmp/ec256-pub.pem
> verifying JWT

[ header ]
  alg : ES256     (good)

[ payload — standard claims ]
  sub  subject      test

[ signature ]
  64 bytes   Ec5oZ_K6V8dQfH3R1pL2nW7sA4yU2oPzM9NxJqB6vRtKx7gF1cD2hM0i…
  ✓ verified with ES256
```

ECDSA ES256 signatures are exactly 64 bytes (32-byte `r` ||
32-byte `s` on P-256). If you see `Ec5oZ…` decoded to 71 or 72
bytes, the issuer encoded the signature as DER — Cathedral will
reject with "invalid ECDSA signature length" because JWS requires
the `r||s` form. That's the most common cross-library
incompatibility.

### `alg: none` is refused even with a key

```
operator@cathedral:~$ jwt verify eyJhbGciOiJub25lIn0.eyJzdWIiOiJyb290IiwiYWRtaW4iOnRydWV9. -k "doesnt-matter"
> verifying JWT

[ header ]
  alg : none     (danger)

[ payload — standard claims ]
  sub  subject      root

[ payload — custom claims ]
  admin            true

[ signature ]
  0 bytes
  ✗ algorithm `none` is never trusted, regardless of key
```

The classic attacker-substitution form: real header swapped to
`{"alg":"none"}`, signature blanked, payload changed to set
`admin: true`. Cathedral renders the header in red, refuses the
verify (exit code 1 from the tool), and shows the `(danger)`
classification on the alg row. There is no way to convince
`jwt verify` to accept this token.

### Malformed token

```
operator@cathedral:~$ jwt decode "not.a.real.jwt.token"
error: token must have 3 dot-separated segments, got 5
```

Anything that doesn't `.`-split into exactly 3 segments is
rejected before any decoding happens. Five segments is the JWE
shape (which Cathedral doesn't support); two segments is the
JWS-without-signature shape used in some signing tools but not
a complete JWT.

### Verify against an embedded certificate

```
operator@cathedral:~$ openssl s_client -connect token.auth0.com:443 -showcerts < /dev/null \
                       2>/dev/null | openssl x509 > /tmp/auth0-cert.pem
operator@cathedral:~$ jwt verify $TOKEN -k @/tmp/auth0-cert.pem
> verifying JWT

[ header ]
  alg : RS256     (good)
  kid : 2c2a14e

[ payload — standard claims ]
  …

[ signature ]
  256 bytes   sigBlobHere…
  ✓ verified with RS256
```

When the only thing you have is the issuer's TLS certificate,
Cathedral's PEM-auto-detection means you can pass the cert
directly. The public key gets extracted from `cert.PublicKey`
internally; no need to manually `openssl pkey -in cert.pem
-pubout` first.

## Output protocol

Line-oriented JSON. Event types:

| Event           | Fields                                                                       |
|-----------------|------------------------------------------------------------------------------|
| `start`         | `mode` (`decode` or `verify`)                                                |
| `header`        | `alg`, `typ`, `safety` (`good`/`warn`/`danger`/`unknown`), `raw` (full header map) |
| `payload`       | `all` (full claims map), `std` (standard-only), `custom` (non-standard-only)  |
| `timing`        | `info` map — `iat_iso`/`nbf_iso`/`exp_iso`, `iat_relative`/…, `verdict`, `reason` |
| `signature`     | `bytes`, `preview` (first 40 chars), `verified` (bool), `verified_with` (alg, on success) |
| `verify_result` | `match` (bool), `algo` (on success), `reason` (on failure)                   |
| `done`          | sentinel                                                                      |
| `error`         | `message` — malformed token, parse error                                     |

Pipe-friendly with `jq`:

```
# Just the issuer + subject
jwt decode "$TOKEN" | jq -r '
  select(.event=="payload") |
  "iss: \(.all.iss // "—")   sub: \(.all.sub // "—")"
'

# Boolean exit: is the token currently active?
jwt decode "$TOKEN" | jq -e '
  select(.event=="timing" and .info.verdict=="active")
' >/dev/null && echo "active"

# Detect alg=none across a batch of tokens (stdin input)
while read -r t; do
  jwt decode "$t" 2>/dev/null \
    | jq -r 'select(.event=="header" and .alg=="none") | "ALG-NONE: " + (.raw|tostring)'
done < tokens.txt

# Pull all custom claim names from a token
jwt decode "$TOKEN" | jq -r 'select(.event=="payload") | .custom | keys[]'
```

## Limitations

- **No signing path.** `jwt sign` doesn't exist; this is a
  consumer-only tool. Pair with the JWT library in your
  application's language for the producer side.
- **No JWE / encrypted JWTs.** Five-segment tokens get the
  3-segments-expected error early. JWE handling would
  require key-management infrastructure that doesn't fit the
  one-shot CLI shape.
- **No JWKS auto-fetch.** Manual key extraction from
  `/.well-known/jwks.json` is on the operator's side. Could
  add `-k jwks:https://… ?kid=…` as a future option.
- **No clock-skew tolerance.** Strict `now >= exp` /
  `now < nbf` comparisons. Real verifiers typically allow
  ±60-300 seconds. Could add `--skew=SEC`.
- **No `iss` / `aud` policy checks.** Cathedral surfaces both
  fields but doesn't enforce them. A real verifier should
  reject tokens whose `aud` doesn't match its expected audience.
- **PEM-only for asymmetric keys.** No raw `BEGIN OPENSSH` /
  `BEGIN PKCS8 PRIVATE KEY` for *signing* (which Cathedral
  doesn't do anyway) and no JWK JSON for public-key input.
- **No payload reformatting beyond the standard claims.**
  Nested objects in custom claims render via `jsonEncode`
  rather than pretty-printed multi-line — the panel is
  console-wide, not a JSON editor.

## Authorized use

Token decoding is read-only inspection of bytes the operator
already possesses. The authorization considerations are:

- **Decoding your own tokens** — fine, this is the whole
  intended use. Forensic inspection during integration work
  ("what's the structure of the token our IdP issues?"), debug
  workflows ("is this token actually expired or is the clock
  off?"), audit ("are any of our internal services accepting
  `alg: none`?").
- **Decoding tokens someone else captured** — the JWT itself
  is just text. The legal questions are about the act of
  acquiring the token (network capture, log scraping,
  filesystem access on a machine you don't own), not the
  decode. Cathedral neither helps nor hinders those acquisition
  questions; they're orthogonal.
- **HMAC secrets via argv** — `-k "your-secret"` puts the
  secret in shell history and `/proc/<pid>/cmdline` for the
  process lifetime. On shared hosts this is a real leak; the
  leading-space-skips-history bash trick applies same as it
  does for the `pwned` command.
- **No automatic policy enforcement.** Cathedral renders the
  alg-safety classification and the timing verdict honestly
  but doesn't reject the token's *content* for policy
  reasons — that's the application's job. An `alg: HS256`
  token with a leaked secret will verify just as cleanly as
  one with a strong secret; Cathedral's `warn` classification
  signals "use HMAC carefully," not "this token is fine."

## Further reading

- [RFC 7519 — JSON Web Token (JWT)](https://datatracker.ietf.org/doc/html/rfc7519)
  — the canonical JWT specification. Standard-claim semantics,
  the dotted-segment shape, the security-considerations section
  worth re-reading.
- [RFC 7515 — JSON Web Signature (JWS)](https://datatracker.ietf.org/doc/html/rfc7515)
  — the underlying signing format. Defines the ECDSA-as-`r||s`
  rule that catches half of all JWT-library cross-language bugs.
- [RFC 7518 — JSON Web Algorithms (JWA)](https://datatracker.ietf.org/doc/html/rfc7518)
  — the algorithm-identifier registry. `RS256` / `ES256` /
  `HS256` etc. all defined here with their parameter mappings.
- [RFC 8037 — CFRG ECDH and EdDSA in JWS / JWE](https://datatracker.ietf.org/doc/html/rfc8037)
  — adds `EdDSA` (Ed25519) to the JWT family. The newest
  signature algorithm in the spec and the one Cathedral would
  recommend for new JWT-based systems.
- [OWASP JWT Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
  — the operational-security cheat sheet. The `alg: none`
  warning, key-rotation guidance, and the "don't store the
  secret in the JWT itself" reminders. Java-titled but the
  guidance is language-agnostic.
- [jwt.io](https://jwt.io/) — the canonical online JWT
  inspector. Useful for cross-checking Cathedral's output
  against a separate implementation; type the same token into
  both and the header / payload / signature decoding should
  match exactly.
- [`hash`](hash.md) — Cathedral's general-purpose digest tool;
  HMAC-SHA256 inside `jwt verify` is the same SHA-256 primitive
  `hash` exposes.
- [`encrypt` / `decrypt`](encrypt-decrypt.md) — the related
  symmetric-encryption command. JWE (which Cathedral doesn't
  decode) is conceptually similar but with a much more
  elaborate key-management story.
- [`headers`](headers.md) — when a JWT appears in an
  `Authorization: Bearer` header on the wire, `headers` will
  show you the *header containing* the JWT; `jwt decode`
  unpacks the token itself.
