---
title: ssh-audit — SSH server algorithm posture grader
command: ssh-audit
category: reachability
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-17
related: [banner, scan, discover, ssl]
---

# `ssh-audit` — SSH server algorithm posture grader

`ssh-audit` connects to an SSH server, exchanges banners and the
opening `KEXINIT` packet, then classifies every algorithm the
server advertises against the Mozilla SSH guide and OpenSSH
release notes. The output is a per-algorithm verdict (good /
warn / bad / unknown) plus an overall letter grade A → F. No
authentication is attempted; the audit is purely pre-auth
transport-layer.

```
ssh-audit github.com
ssh-audit my-server.example:2222
ssh-audit 10.0.0.5
```

## What it does

One TCP connection to port 22 (or whatever port you specify),
followed by exactly two SSH transport-layer rounds:

1. **Banner exchange.** The server announces its SSH version
   (`SSH-2.0-OpenSSH_9.7p1 Ubuntu-3`); Cathedral announces
   itself (`SSH-2.0-cathedral-audit_0.1`). Pre-banner notice
   text — some servers send legal notices before the SSH-2.0
   line — is tolerated up to 32 lines.
2. **`KEXINIT` exchange.** Cathedral sends a minimal `KEXINIT`
   advertising one placeholder algorithm per category; the
   server responds with its real `KEXINIT` carrying the full
   list of algorithms it supports for: key exchange, host-key
   signature, ciphers (client→server and server→client), MACs
   (both directions), and compression.

Cathedral parses the server's `KEXINIT`, classifies every
algorithm, and emits the report. The connection closes
immediately after — no authentication packet is ever sent.

The default port is 22; `ssh-audit host:2222` overrides.

## What it answers

**Defender:** *"Is my SSH server hardened?"* The primary use
case. Run `ssh-audit my-server.example` and compare the
verdict to your expectation. A grade below B is a finding;
specific `bad`-flagged algorithms (any `ssh-rsa`, any `-sha1`,
any CBC cipher, any MD5 MAC) name what to remove from
`/etc/ssh/sshd_config`.

**Recon (authorized testing only):** *"What SSH configuration
does this target run?"* Before any auth attempt, the
algorithm posture tells you the rough age and maintenance
state of the server. An OpenSSH 5.x server (grade F) often
co-occurs with other neglected services on the same host —
patch cadence is correlated.

**Operational:** *"Why is my SSH client refusing this
server?"* Modern OpenSSH clients (9.x) refuse to connect to
servers that don't offer any non-bad algorithms. The audit
shows exactly which negotiation slot is empty.

**Learning:** This is the protocol-level lens on SSH. The
algorithm list is the surface a real attacker would read
first — `ssh-audit` makes it legible without requiring you
to construct your own `KEXINIT`.

## How it works

### The two-round protocol

SSH's transport layer is defined in RFC 4253. The opening
exchange is intentionally cleartext: both sides need to agree
on the algorithms *before* they have a session key to encrypt
with. `ssh-audit` exploits that to read the server's
preferences without progressing to authentication:

1. The client and server each send a single line of ASCII
   ending `\r\n`: their identification banner.
2. The client sends a binary `KEXINIT` packet listing
   algorithms in preference order.
3. The server replies with its own `KEXINIT` listing
   algorithms in *its* preference order.
4. Key exchange begins.

Cathedral does steps 1–3 and stops. Step 4 would require an
actual cryptographic exchange (which Cathedral's audit doesn't
need) and could leave traces in some servers' connection
counters.

### The minimal `KEXINIT` trick

To get the server's full algorithm list, Cathedral has to send
its own `KEXINIT` first. The contents of *Cathedral's* list
don't matter for the audit; the server still replies with its
own full list regardless of what the client offered. So
Cathedral sends a minimal placeholder:

```go
dummy       := "diffie-hellman-group14-sha256"
dummyHK     := "ssh-ed25519"
dummyCipher := "aes128-ctr"
dummyMAC    := "hmac-sha2-256"
dummyComp   := "none"
for _, s := range []string{dummy, dummyHK, dummyCipher, dummyCipher,
                            dummyMAC, dummyMAC, dummyComp, dummyComp, "", ""} {
    buf = appendNameList(buf, s)
}
```

One algorithm per category — enough to be a syntactically valid
`KEXINIT` and convince the server we're a real client. The
server's reply carries everything Cathedral actually needs.

### Algorithm classification

Each advertised algorithm is looked up in a curated table sourced
from the Mozilla SSH guide, OpenSSH release notes, and NIST CNSA
recommendations:

| Verdict | Meaning                                                          |
|---------|------------------------------------------------------------------|
| `good`  | Current best practice. AEAD ciphers, ETM MACs, Curve25519 KEX, post-quantum hybrids. |
| `warn`  | Works correctly but suboptimal — NIST curves (no patent issues, but constants-of-unclear-origin), CTR ciphers (not AEAD), non-ETM MACs (vulnerable to padding attacks if paired with CBC). |
| `bad`   | Known broken or deprecated — SHA-1 in any role, CBC ciphers without ETM, RC4 variants, MD5 MACs, ssh-rsa as a host-key algorithm (uses SHA-1 for signature). |
| `unknown` | Algorithm not in the curated table. Could be a new addition or a vendor-specific name; the verdict stays neutral. |

Representative entries from the table:

```go
"kex|curve25519-sha256":                "good",
"kex|sntrup761x25519-sha512@openssh.com":"good",  // post-quantum hybrid
"kex|mlkem768x25519-sha256":            "good",   // post-quantum hybrid
"kex|ecdh-sha2-nistp256":               "warn",   // NIST curves
"kex|diffie-hellman-group14-sha1":      "bad",    // SHA-1

"hostkey|ssh-ed25519":                  "good",
"hostkey|rsa-sha2-512":                 "good",
"hostkey|ssh-rsa":                      "bad",    // signs with SHA-1
"hostkey|ssh-dss":                      "bad",    // DSA, 1024-bit

"cipher|chacha20-poly1305@openssh.com": "good",   // AEAD
"cipher|aes256-gcm@openssh.com":        "good",   // AEAD
"cipher|aes128-ctr":                    "warn",   // not AEAD, but secure
"cipher|aes128-cbc":                    "bad",    // Lucky13-class

"mac|hmac-sha2-256-etm@openssh.com":    "good",   // encrypt-then-MAC
"mac|hmac-sha2-256":                    "warn",   // mac-then-encrypt
"mac|hmac-sha1":                        "bad",
```

### Why NIST curves are `warn`, not `good`

This is the cookbook detail people argue about. NIST curves
(P-256, P-384, P-521) are mathematically fine — there's no
public break. The reservation is about how their constants
were chosen. The post-Snowden NSA disclosures cast doubt on
the seed values for some NIST-standardised primitives, and
the cryptography community has gradually drifted toward
curves whose constants are *explicitly* derived from public
constants (Curve25519's parameters are documented; nothing
about its constants is "trust me"). The Mozilla SSH guide
follows that drift.

`ssh-audit` records NIST curves as `warn` rather than `good`
or `bad`. They work; they're not weak; they're just not the
*current* best-practice answer.

### The grading rubric

The overall letter grade is computed from the algorithm tally
and a few category-level checks:

| Grade | Condition                                                           |
|-------|---------------------------------------------------------------------|
| **A** | Zero `bad`, zero `warn` algorithms. Mozilla "modern" config. Rare. |
| **B** | Zero `bad`, some `warn` algorithms. Typical hardened modern config. |
| **C** | Some `bad` algorithms BUT all four categories (KEX, host-key, cipher, MAC) have at least one `good` option. A client can negotiate down to a safe combination. |
| **D** | Some `bad` algorithms, KEX and host-key have good options, but cipher OR MAC does not. Negotiation can land in a bad state. |
| **F** | Missing a good KEX OR good host-key algorithm. No safe negotiation path exists. |

The C-vs-D distinction is the design choice worth surfacing:
an SSH server is *only* as secure as the algorithm the client
negotiates. A server that offers both `ssh-ed25519` and
`ssh-rsa` is fine if the client prefers `ssh-ed25519`. But a
server offering no AEAD cipher *forces* every connecting
client into a non-AEAD mode. The grading captures whether the
server retains a safe negotiation path.

The grade is accompanied by `notes` — short reasons the grade
isn't higher: *"no AEAD cipher offered (chacha20/aes-gcm)"*,
*"no ETM MAC offered (encrypt-then-MAC)"*.

## Worked example

Two contrasting servers. Both fabricated to illustrate the
shape; both reflect realistic algorithm sets you'd find in the
wild.

### A modern, hardened server — grade B

```
> connecting to vault.example.com:22
  banner : SSH-2.0-OpenSSH_9.7p1 Debian-2
  server : OpenSSH_9.7p1 Debian-2

[ Key Exchange  (7) ]
  [ ✓ ] sntrup761x25519-sha512@openssh.com
  [ ✓ ] mlkem768x25519-sha256
  [ ✓ ] curve25519-sha256
  [ ✓ ] curve25519-sha256@libssh.org
  [ ✓ ] diffie-hellman-group-exchange-sha256
  [ ! ] ecdh-sha2-nistp256
  [ ! ] ecdh-sha2-nistp384

[ Host Key  (3) ]
  [ ✓ ] ssh-ed25519
  [ ✓ ] rsa-sha2-512
  [ ✓ ] rsa-sha2-256

[ Ciphers (server→client)  (4) ]
  [ ✓ ] chacha20-poly1305@openssh.com
  [ ✓ ] aes256-gcm@openssh.com
  [ ✓ ] aes128-gcm@openssh.com
  [ ! ] aes256-ctr

[ MACs (server→client)  (4) ]
  [ ✓ ] hmac-sha2-256-etm@openssh.com
  [ ✓ ] hmac-sha2-512-etm@openssh.com
  [ ✓ ] umac-128-etm@openssh.com
  [ ! ] hmac-sha2-256

[ Compression (server→client)  (1) ]
  [ ✓ ] none

grade: B   (15 good · 3 warn · 0 bad)
```

Reading this: a current OpenSSH with post-quantum hybrid KEX
enabled, Ed25519 + modern RSA host keys, AEAD ciphers, ETM
MACs. The three `warn` entries are NIST curves (kept for
compatibility) and one non-ETM MAC. No `bad` algorithms means
this server can never negotiate a weak session — the worst
realistic outcome is a NIST-curve KEX, which is suboptimal but
not broken. **Grade B is the realistic ceiling for most
production servers** because removing NIST curves entirely
breaks clients running on older platforms.

### A legacy server with mixed posture — grade C

```
> connecting to legacy.example.com:22
  banner : SSH-2.0-OpenSSH_7.4
  server : OpenSSH_7.4

[ Key Exchange  (8) ]
  [ ✓ ] curve25519-sha256@libssh.org
  [ ! ] ecdh-sha2-nistp256
  [ ! ] ecdh-sha2-nistp384
  [ ! ] ecdh-sha2-nistp521
  [ ✓ ] diffie-hellman-group-exchange-sha256
  [ ! ] diffie-hellman-group14-sha256
  [ ✗ ] diffie-hellman-group14-sha1
  [ ✗ ] diffie-hellman-group-exchange-sha1

[ Host Key  (4) ]
  [ ✓ ] ssh-ed25519
  [ ✓ ] rsa-sha2-512
  [ ✗ ] ssh-rsa
  [ ! ] ecdsa-sha2-nistp256

[ Ciphers (server→client)  (8) ]
  [ ✓ ] chacha20-poly1305@openssh.com
  [ ✓ ] aes256-gcm@openssh.com
  [ ! ] aes128-ctr
  [ ! ] aes192-ctr
  [ ! ] aes256-ctr
  [ ✗ ] aes128-cbc
  [ ✗ ] aes192-cbc
  [ ✗ ] aes256-cbc

[ MACs (server→client)  (7) ]
  [ ✓ ] hmac-sha2-256-etm@openssh.com
  [ ✓ ] umac-128-etm@openssh.com
  [ ! ] hmac-sha2-256
  [ ! ] umac-128@openssh.com
  [ ✗ ] hmac-sha1
  [ ✗ ] hmac-sha1-etm@openssh.com
  [ ✗ ] hmac-md5

grade: C   (8 good · 11 warn · 8 bad)
```

This is the cookbook teaching moment. A CentOS 7 / RHEL 7-era
OpenSSH 7.4 server with **defaults left on**. Every category
has a `good` algorithm available — so a modern client *can*
negotiate down to a safe combination — but the server is
*also* advertising:

- **SHA-1 KEX** (`diffie-hellman-group14-sha1`,
  `diffie-hellman-group-exchange-sha1`)
- **`ssh-rsa` host key** (signs with SHA-1)
- **CBC ciphers** (Lucky13 attack class)
- **HMAC-SHA1, HMAC-MD5 MACs**

A client that doesn't prefer modern algorithms — for example,
an embedded device with hard-coded preferences — would
negotiate one of the `bad` combinations and end up with a
session that's exploitable in 2026. The fix in
`/etc/ssh/sshd_config`:

```
KexAlgorithms       curve25519-sha256,curve25519-sha256@libssh.org,\
                    diffie-hellman-group-exchange-sha256
HostKeyAlgorithms   ssh-ed25519,rsa-sha2-512,rsa-sha2-256
Ciphers             chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,\
                    aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr
MACs                hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,\
                    umac-128-etm@openssh.com
```

Applied: grade jumps from C to B. The verdict shifts from
"can be safe if the client negotiates well" to "*is* safe no
matter what the client picks."

## Output protocol

```
{"event":"start",   "host":"…","port":"…"}
{"event":"banner",  "text":"SSH-2.0-…","server":"…"}
{"event":"section", "category":"kex|hostkey|cipher|mac|compress",
                    "label":"…","count":N}
{"event":"algo",    "category":"…","name":"…",
                    "verdict":"good|warn|bad|unknown"}*
{"event":"summary", "grade":"A|B|C|D|F","good":N,"warn":N,"bad":N,
                    "notes":[…]}
{"event":"done"}
```

`server` on the `banner` event strips the `SSH-2.0-` prefix —
e.g. `OpenSSH_9.7p1 Debian-2` rather than the full banner.

Extract just the bad algorithms across a target:

```
$ ssh-audit host:22 -j |
    jq -r 'select(.event=="algo" and .verdict=="bad") |
           "\(.category)\t\(.name)"'
```

Audit a list of servers and tally grades:

```
$ for h in $(cat ssh-targets.txt); do
    ssh-audit "$h" -j | jq -r --arg host "$h" '
      select(.event=="summary") | "\(.grade)\t\($host)"'
  done | sort
```

## Limitations

- **Pre-auth only.** `ssh-audit` does not test password / key
  authentication, host-key fingerprints, certificate chains,
  or session protocol behaviour. The audit covers only the
  algorithms the server *advertises*; what it actually accepts
  during a full session can differ if the server has
  `MaxSessions` / `MaxAuthTries` / certificate-only auth.
- **No host-key trust-on-first-use check.** Cathedral does not
  fingerprint or remember the host key the server presents.
  Use `ssh-keygen -F host` or `ssh-keyscan` for that.
- **Curated algorithm table can lag.** New algorithms (e.g.
  recent post-quantum additions) come back as `unknown` until
  the table is updated. Cathedral surfaces unknowns plainly
  rather than guessing — better than misclassifying.
- **Grading rubric is opinionated.** Mozilla-aligned. CNSA
  (US government) profile is stricter; PCI-DSS is looser. The
  letter grade is a default; the per-algorithm verdicts are
  the more durable data for specific compliance contexts.
- **Single connection.** A server that ratchets algorithm
  offerings based on client capabilities (rare but
  possible with `Match` blocks) might present a different
  list to a real OpenSSH client than to Cathedral's minimal
  one. `ssh-audit` sees what the server tells *it*.
- **Connect timeout is 8s, overall deadline 15s.** Slow links
  (satellite, deep-VPN tunnels) may need a more patient
  client; not configurable in v1.

## Authorized use

`ssh-audit` opens one TCP connection to the SSH port, sends
~50 bytes of banner + ~200 bytes of `KEXINIT`, reads the
server's response, and closes. No authentication is attempted.
No password is sent. The traffic is the same shape any SSH
client makes in its first 30 milliseconds of contact, then
disconnects.

The client banner identifies as `cathedral-audit_0.1` — that
string appears in the server's SSH logs alongside source IP
and timestamp, so the audit is honestly attributable. There
is no covert mode.

For a server you administer, this is unremarkable — the same
shape as `ssh -G` running against the same host. For a server
you do not administer, the audit traffic itself is harmless
(one pre-auth handshake, no auth attempt) but the *information
it reveals* — algorithm posture, software version — is
recon-grade. Use within the scope of an authorised engagement,
or against your own infrastructure.

## Further reading

- [Mozilla OpenSSH Security Guide](https://infosec.mozilla.org/guidelines/openssh) — the source of most algorithm verdicts
- [RFC 4253 §7 — SSH Transport Layer Protocol: Algorithm Negotiation](https://www.rfc-editor.org/rfc/rfc4253#section-7) — the `KEXINIT` exchange
- [OpenSSH release notes](https://www.openssh.com/releasenotes.html) — what was added / deprecated when
- [`ssh-audit` upstream tool](https://github.com/jtesta/ssh-audit) — the Python project that inspired the algorithm verdicts; has deeper compliance profile support
- Related Cathedral commands: [`banner`](banner.md) (the raw single-port grab that surfaces just the SSH banner),
  [`scan`](scan.md) (find the SSH port in the first place),
  [`discover`](discover.md) (find every SSH host on a subnet),
  [`ssl`](ssl.md) (the equivalent algorithm audit for HTTPS)
