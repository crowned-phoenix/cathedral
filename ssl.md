---
title: ssl — TLS handshake and certificate-chain inspection
command: ssl
category: email-and-certificates
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-21
related: [crt, banner, headers, http, recon]
---

# `ssl` — TLS handshake and certificate-chain inspection

`ssl` opens a TLS connection to a host, negotiates the highest
protocol version the server offers, and reports the full
handshake outcome: protocol version, cipher suite, ALPN-negotiated
protocol, chain-verification status, and one card per certificate
in the server's chain with subject / issuer / SANs / validity
window / expiry countdown. The handshake is run *twice* — once
with system root verification and once with `InsecureSkipVerify`
— so the certificate details surface even when the chain itself
is broken.

Where [`banner`](banner.md) gives the wire-level view of any
single port and [`headers`](headers.md) audits HTTP response
hardening, `ssl` is the dedicated *TLS posture* tool: protocol
version freshness, expiry timeline, SAN coverage, signature
algorithm, and the specific reason any verification failure
fired. For everything from "are our certs about to expire" to
"why does the browser flag this site as insecure", `ssl` is the
shortest path to the answer.

```
ssl example.com                          # default port 443
ssl mail.example.com -p 993              # TLS-wrapped IMAP
ssl 1.2.3.4 -name api.example.com        # SNI override on an IP
ssl example.com -p 8443                  # admin panel on alt port
```

## What it does

For a single host (with optional port and SNI override), Cathedral:

1. **Verified dial** — opens a TLS connection with system-root
   verification. Records whether it succeeded; on failure, keeps
   the error message for later diagnosis.
2. **Insecure dial** — opens a second connection with
   `InsecureSkipVerify: true` so the certificate chain is
   reachable regardless of trust. This is what produces the
   chain detail.
3. Reports the negotiated TLS version, cipher suite, ALPN
   protocol, and session-resumption flag.
4. Surfaces every certificate in the chain returned by the
   server — leaf, intermediates, anything else the server
   sends. Each cert renders with subject / issuer / SANs /
   validity / days-until-expiry / signature algorithm / serial.
5. If verification failed, re-runs the verification with
   explicit roots and surfaces the *specific* x509 error
   (chain-of-trust missing, hostname mismatch, expired, etc.)
   in a dedicated `verify_reason` event.

| Flag             | Meaning                              | Default            |
|------------------|--------------------------------------|--------------------|
| `-p PORT`        | TCP port to connect to               | `443`              |
| `-name SNI`      | SNI hostname to send                 | same as host       |

The SNI override is the load-bearing flag for two common
cases: probing a specific IP that hosts many SNI-multiplexed
domains (`ssl 1.2.3.4 -name foo.example.com` gets the cert for
`foo.example.com` even though the IP would default-respond
with whatever the catch-all is), and probing a host through a
DNS-bypass workflow (`ssl 198.51.100.42 -name production.example
.com` validates the cert the production hostname *would* receive
if it resolved to that IP — useful during failover testing or
when verifying a CDN edge).

## What it answers

**Defender:** *"Is our TLS posture clean and not about to break?"*
The most common operational failure on TLS infrastructure is
silent certificate expiry — a renewal job that fails without
alerting, a Let's Encrypt automation that stops working after a
config change. The `expires in: <N> days` line surfaces the
near-expiry case before browsers do:

- `< 0` days renders in error red (cert is *already expired*;
  the user is seeing the warning).
- `< 14` days renders in warn amber (renewal window is closing).
- otherwise renders info-neutral.

Periodic `ssl` against your own production endpoints catches the
two days before disaster, when the renewal job has already
failed and the cert is on day 28 of a 30-day Let's Encrypt
window.

**Recon (authorized testing only):** *"What's this target's TLS
posture?"* Three pieces of signal in one handshake:

- The TLS *version* (TLS 1.0/1.1 = legacy / deprecated; 1.2 =
  baseline; 1.3 = modern). Old protocols imply old software.
- The *cipher suite* (named curves, AEAD modes, forward
  secrecy). Mismatches between cipher choice and a claimed
  modern stack reveal misconfigurations.
- The *SANs* (subject alternative names). The leaf certificate
  often lists every hostname it covers — including subdomains
  not otherwise advertised. A wildcard cert for `*.example.com`
  with explicit additional SANs for `api-staging.example.com`,
  `legacy.example.com`, `vpn.example.com` is its own form of
  subdomain enumeration.

**Investigation:** *"Why is the browser rejecting this cert?"*
The verified-dial-then-insecure-dial pattern is the diagnostic
shortcut. Most cert problems aren't visible from "the connection
failed" — they're visible from "the chain was X, the validation
failed for reason Y". The `verify_reason` event names the exact
error (`x509: certificate signed by unknown authority`,
`x509: certificate is valid for foo.com, not bar.com`,
`x509: certificate has expired or is not yet valid`), which is
typically the entire root-cause analysis.

**Identification:** *"Who issued these certificates and on what
infrastructure are they?"* The issuer fields (`Let's Encrypt`,
`DigiCert`, `GlobalSign`, `Sectigo`, internal CAs) reveal both
the CA choice and the operational maturity. A Let's Encrypt cert
is automation-driven (typical of modern infrastructure); a
DigiCert EV cert is manually-procured (typical of regulated
industries); a self-signed cert is a development or internal-
only environment.

## How it works

### Two-phase handshake

The verification-then-insecure pattern is the central design
choice:

```go
// First: attempt verified handshake so we learn if the system trusts it.
verifiedErr := ""
{
    cfg := &tls.Config{ServerName: sni}
    conn, err := tls.DialWithDialer(dialer, "tcp", net.JoinHostPort(host, port), cfg)
    if err != nil {
        verifiedErr = err.Error()
    } else {
        conn.Close()
    }
}

// Second: insecure dial to always get cert details even if chain fails.
cfg := &tls.Config{ServerName: sni, InsecureSkipVerify: true}
conn, err := tls.DialWithDialer(dialer, "tcp", ...)
```

Why two dials? A *single* verified dial fails closed: on any
chain problem (expired cert, untrusted CA, name mismatch), the
connection errors out before you see *which* cert is broken or
*what* its details are. That's the wrong failure mode for a
diagnostic tool. The insecure dial guarantees Cathedral gets to
*read* the chain regardless; the verified dial separately
records whether the system trusts it.

The two pieces of state combine on the `conn` event:

- `verified: true` → handshake passed standard validation.
- `verified: false, verify_error: "x509: …"` → chain has a
  problem; the message names what it is.

When verified is false, Cathedral additionally re-runs the
x509 verification with explicit system roots and the leaf's
chain, then emits a `verify_reason` event with the precise
verification failure. This is occasionally more detailed than
the initial dial error — particularly for hostname-mismatch
cases where the initial error may be vague.

### TLS version reporting

```go
func versionName(v uint16) string {
    switch v {
    case tls.VersionTLS10:  return "TLS 1.0"
    case tls.VersionTLS11:  return "TLS 1.1"
    case tls.VersionTLS12:  return "TLS 1.2"
    case tls.VersionTLS13:  return "TLS 1.3"
    case tls.VersionSSL30:  return "SSL 3.0"
    }
    return fmt.Sprintf("0x%04x", v)
}
```

The version Cathedral reports is the *highest* version the
server accepted in the handshake. Modern Go (1.18+) defaults
to TLS 1.2 minimum and TLS 1.3 ceiling; the client offers
both and the server picks the highest it supports. So:

- **TLS 1.3** — the modern default. Almost every CDN, every
  major cloud provider, and most production stacks support it.
- **TLS 1.2** — fine, but the version-skew signal: a server
  that *only* offers 1.2 in 2026 is either explicitly
  configured to disable 1.3, or running software old enough
  that 1.3 isn't supported.
- **TLS 1.0 / 1.1 / SSL 3.0** — Cathedral cannot negotiate
  these from a default Go client. Servers offering only these
  protocols will fail the handshake entirely; the `conn`
  event won't fire. Investigate via a dedicated tool that
  forces the protocol (`openssl s_client -tls1`).

### Cipher suite reporting

```go
func cipherName(c uint16) string {
    for _, s := range tls.CipherSuites() {
        if s.ID == c { return s.Name }
    }
    for _, s := range tls.InsecureCipherSuites() {
        if s.ID == c { return s.Name + " (insecure)" }
    }
    return fmt.Sprintf("0x%04x", c)
}
```

Two tiers per Go's stdlib:

- **`tls.CipherSuites()`** — the modern accepted set: TLS 1.3
  AEAD suites (`TLS_AES_128_GCM_SHA256`,
  `TLS_AES_256_GCM_SHA384`, `TLS_CHACHA20_POLY1305_SHA256`)
  plus TLS 1.2 AEAD-with-ECDHE suites
  (`TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`, etc.).
- **`tls.InsecureCipherSuites()`** — historically broken or
  weakened suites (RC4, 3DES, CBC without ECDHE). Go's
  client *can* negotiate these but Cathedral marks them
  with a `(insecure)` suffix so the operator notices.

A server that negotiates an "insecure" suite from the Go
client is *severely* misconfigured — every modern client has
disabled these, and a server still offering them as an
acceptable choice has a hardening gap.

### ALPN — h2, http/1.1, or empty

ALPN (Application-Layer Protocol Negotiation, RFC 7301) is
the TLS extension where the client and server agree on which
application protocol to use over the TLS connection. The
common values:

- **`h2`** — HTTP/2. Modern default for HTTPS.
- **`http/1.1`** — HTTP/1.1. Still very common in older or
  HTTP/1-only configurations.
- **Empty** — no ALPN negotiated. The connection is TLS-only;
  what protocol runs on top is unspecified by the handshake.
  Typical for non-HTTP TLS endpoints — IMAP/POP3/SMTP TLS,
  RDP gateways, custom protocols.

Cathedral reports the ALPN if non-empty. The line is omitted
otherwise to keep the output clean for non-HTTP probes.

### Certificate chain emission

Every cert in `state.PeerCertificates` becomes a `cert` event,
indexed from 0 (the leaf the server presents) up through the
chain to whatever the server sends — usually one intermediate
on Let's Encrypt and similar, sometimes two on enterprise CAs:

```go
for i, cert := range state.PeerCertificates {
    sans := append([]string{}, cert.DNSNames...)
    for _, ip := range cert.IPAddresses {
        sans = append(sans, ip.String())
    }
    daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
    selfSigned := cert.Issuer.String() == cert.Subject.String()
    emit(event{
        "event": "cert", "idx": i,
        "subject_cn": cert.Subject.CommonName,
        "subject_org": strings.Join(cert.Subject.Organization, ", "),
        "issuer_cn": cert.Issuer.CommonName,
        "issuer_org": strings.Join(cert.Issuer.Organization, ", "),
        "sans": sans,
        "not_before": cert.NotBefore.Format(time.RFC3339),
        "not_after":  cert.NotAfter.Format(time.RFC3339),
        "days_left":  daysLeft,
        "is_ca":      cert.IsCA,
        "self_signed": selfSigned,
        "sig_algo":   cert.SignatureAlgorithm.String(),
        "serial":     cert.SerialNumber.String(),
    })
}
```

Servers are expected to send the leaf plus all intermediates
(but *not* the root — clients have the root in their trust
store). Some misconfigured servers send only the leaf, which
breaks chain validation; some send extra unrelated certs.
Cathedral surfaces whatever the server sends, in the order
sent.

The `is_ca` and `self_signed` flags are convenience badges on
the chain header line — `cert[0]` for a leaf is typically
just `cert[0]`; for a CA cert it's `cert[1] · CA`; for a
self-signed leaf it's `cert[0] · self-signed`.

### Why SAN coverage matters

Modern TLS validation uses the SAN list (Subject Alternative
Names), not the legacy Common Name field, for hostname
matching. The chrome/Firefox behaviour since 2017 is that *only*
SANs are consulted — a cert whose CN says `foo.example.com`
but whose SAN list doesn't include it will fail validation in
modern browsers regardless of the CN.

Cathedral lists the first 6 SANs and indicates additional
count: `sans: foo.example.com, bar.example.com, *.api.example.com
(+12)`. The full list is in the JSON event for programmatic
consumption.

The SAN list is itself a *fingerprint* of what infrastructure
the cert covers. A multi-SAN cert that names production +
staging + internal endpoints together reveals the operator
considered them one administrative group at issuance time —
an attribution signal that occasionally matters.

### What's not in the verification

Cathedral's verification is the standard system-trust check:
chain-of-trust to a root in the OS trust store, signature
validation, time-window (not-before / not-after), hostname
match against the SNI. Notably *not* included:

- **OCSP / CRL revocation.** A cert revoked yesterday will
  still verify if the chain is intact and the time window is
  valid. For revocation status, dedicated tools (`openssl ocsp`)
  are needed.
- **CT (Certificate Transparency) log presence.** Cathedral
  doesn't check whether the cert appears in CT logs (that's
  [`crt`](crt.md)'s job, from the other direction —
  *finding certs by CT log query*).
- **Pinning.** No support for HPKP / certificate pinning
  validation. HPKP is deprecated; modern alternatives are
  CT-based.
- **Browser-specific behaviour.** Cathedral uses Go's standard
  verification, which closely matches browser behaviour but
  isn't a *simulation* of any particular browser. Edge cases
  (Symantec distrust, custom root removals, browser-specific
  trust decisions) may differ.

## What Cathedral doesn't do

A few deliberate omissions:

- **No protocol-version forcing.** Cathedral negotiates the
  best TLS version both sides support — TLS 1.2 minimum, 1.3
  preferred. To test whether a server *accepts* TLS 1.0 / 1.1
  for compliance reasons, use `openssl s_client -tls1_1` or
  similar.
- **No cipher-suite enumeration.** Cathedral reports the
  *negotiated* suite, not the full list of suites the server
  *offers*. For complete suite enumeration use `nmap
  --script=ssl-enum-ciphers` or `testssl.sh`.
- **No STARTTLS support.** SMTP (25, 587), IMAP (143), POP3
  (110), FTP (21) all support upgrading a plaintext connection
  to TLS via STARTTLS. Cathedral does TLS-from-connection-start
  only; for STARTTLS-protected services point `ssl` at the
  implicit-TLS port (587, 993, 995, 990 — the ones that wrap
  TLS from the start).
- **No OCSP / CRL revocation checking.** Cert revocation
  status is out of scope. `openssl ocsp` is the dedicated tool.
- **No CT-log lookup.** Cathedral inspects the cert the server
  sends; for "what certs has this domain *ever* had", see
  [`crt`](crt.md).
- **No PEM dump.** The JSON event contains parsed cert fields
  but not the raw PEM bytes. For full certificate capture use
  `openssl s_client -showcerts` or `gnutls-cli`.
- **Single connection.** No session-resumption testing across
  multiple connections, no 0-RTT testing.
- **6-second connect timeout.** Slow servers may time out; no
  way to extend currently.

## Worked example

A modern TLS 1.3 site, a self-signed dev environment, an
expired cert, and an SNI-override scenario.

### A modern TLS 1.3 site

```
operator@cathedral:~$ ssl acme-supplies.example
> TLS handshake with acme-supplies.example:443 (sni=acme-supplies.example)

  protocol  : TLS 1.3
  cipher    : TLS_AES_256_GCM_SHA384
  alpn      : h2
  status    : [chain verified]

[ cert[0] ]
  subject   : acme-supplies.example
  issuer    : E5  (Let's Encrypt)
  valid     : 2026-04-15T08:32:11Z  →  2026-07-14T08:32:10Z
  expires in: 53 days
  sig algo  : ECDSA-SHA256
  serial    : 32849872934567823948239
  sans      : acme-supplies.example, *.acme-supplies.example

[ cert[1] · CA ]
  subject   : E5  (Let's Encrypt)
  issuer    : ISRG Root X2  (Internet Security Research Group)
  valid     : 2024-03-13T00:00:00Z  →  2027-03-12T23:59:59Z
  expires in: 295 days
  sig algo  : ECDSA-SHA384
  serial    : 7521094872398476234907

handshake complete.
```

The hardened modern shape: TLS 1.3, an AEAD cipher
(`TLS_AES_256_GCM_SHA384` — AES-GCM-256 with SHA-384 KDF), ALPN
negotiates HTTP/2, the chain validates against system roots.
Two certs sent: the leaf (a wildcard cert covering both the
apex and all immediate subdomains) and the Let's Encrypt
intermediate (E5, the ECDSA-signed intermediate that took over
from R3 around 2024). The intermediate's parent is `ISRG Root
X2` — Let's Encrypt's own ECDSA root, also present in modern
trust stores.

The 53-days-until-expiry signal is healthy for a Let's Encrypt
cert (90-day lifetime; renewal typically triggers around day
60). For a self-audit, anything below 14 days would render in
amber — a strong nudge to check the renewal automation.

### A self-signed dev environment

```
operator@cathedral:~$ ssl lab.acme-supplies.example
> TLS handshake with lab.acme-supplies.example:443 (sni=lab.acme-supplies.example)

  protocol  : TLS 1.2
  cipher    : TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  alpn      : http/1.1
  status    : [UNTRUSTED CHAIN]
  reason    : x509: certificate signed by unknown authority

[ cert[0] · self-signed ]
  subject   : lab.acme-supplies.example  (ACME Supplies — Internal)
  issuer    : lab.acme-supplies.example  (ACME Supplies — Internal)
  valid     : 2023-09-01T00:00:00Z  →  2033-08-30T00:00:00Z
  expires in: 2657 days
  sig algo  : SHA256-RSA
  serial    : 1
  sans      : lab.acme-supplies.example, *.lab.acme-supplies.example
  reason    : x509: certificate signed by unknown authority

handshake complete.
```

A self-signed cert on an internal lab environment. Three signals
at once:

- The `[ cert[0] · self-signed ]` tag fires because Subject
  matches Issuer — this cert wasn't signed by any external CA.
- The chain status is `[UNTRUSTED CHAIN]` with the reason
  `x509: certificate signed by unknown authority` — standard
  validation fails because the system trust store doesn't have
  this cert's "root".
- The cert is valid for 10 years (`expires in: 2657 days`) — a
  typical pattern for internal CAs that aren't subject to the
  90-day Let's Encrypt or 397-day public-CA lifetime caps.

Cathedral surfaces the chain anyway. The cert is *fine* in
context (an internal lab service intended to be trusted by an
internal CA), but the browser will complain when a user hits
the URL.

### An expired cert (finding case)

```
operator@cathedral:~$ ssl legacy-portal.acme-supplies.example
> TLS handshake with legacy-portal.acme-supplies.example:443 (sni=legacy-portal.acme-supplies.example)

  protocol  : TLS 1.2
  cipher    : TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  alpn      : http/1.1
  status    : [UNTRUSTED CHAIN]
  reason    : x509: certificate has expired or is not yet valid: current time 2026-05-21T12:18:33Z is after 2026-03-15T08:00:00Z

[ cert[0] ]
  subject   : legacy-portal.acme-supplies.example
  issuer    : R3  (Let's Encrypt)
  valid     : 2025-12-15T08:00:00Z  →  2026-03-15T08:00:00Z
  expires in: -67 days
  sig algo  : SHA256-RSA
  serial    : 4892375923847583928347
  sans      : legacy-portal.acme-supplies.example

[ cert[1] · CA ]
  subject   : R3  (Let's Encrypt)
  issuer    : ISRG Root X1  (Internet Security Research Group)
  valid     : 2020-09-04T00:00:00Z  →  2025-09-15T16:00:00Z
  expires in: -248 days
  sig algo  : SHA256-RSA
  serial    : 192473983476...

  reason    : x509: certificate has expired or is not yet valid

handshake complete.
```

The finding case — and revealingly, *two* expired certs in the
same chain. The leaf expired 67 days ago (a 90-day Let's
Encrypt cert from December, never renewed); the intermediate
R3 actually expired in September of the previous year (R3 was
retired by Let's Encrypt and replaced by R10/R11; this server's
cached intermediate is itself stale).

The `expires in: -67 days` line in red is the headline signal.
Browser users have been seeing TLS warnings on this site for
over two months. The renewal automation failed and no monitoring
caught it.

### SNI override on a shared IP

```
operator@cathedral:~$ ssl 198.51.100.42
> TLS handshake with 198.51.100.42:443 (sni=198.51.100.42)

  protocol  : TLS 1.3
  cipher    : TLS_AES_256_GCM_SHA384
  alpn      : h2
  status    : [UNTRUSTED CHAIN]
  reason    : x509: cannot validate certificate for 198.51.100.42 because it doesn't contain any IP SANs

[ cert[0] ]
  subject   : default.cdn-provider.example
  issuer    : E5  (Let's Encrypt)
  valid     : 2026-04-01T00:00:00Z  →  2026-06-30T00:00:00Z
  expires in: 40 days
  sig algo  : ECDSA-SHA256
  sans      : default.cdn-provider.example
...
```

Without `-name`, the IP-only probe receives the *default* cert
the multi-tenant CDN serves — a generic certificate for the CDN
operator's catch-all hostname. The hostname-mismatch verify
reason is informative ("can't validate for the IP because the
cert doesn't include IP SANs") but expected.

```
operator@cathedral:~$ ssl 198.51.100.42 -name acme-supplies.example
> TLS handshake with 198.51.100.42:443 (sni=acme-supplies.example)

  protocol  : TLS 1.3
  cipher    : TLS_AES_256_GCM_SHA384
  alpn      : h2
  status    : [chain verified]

[ cert[0] ]
  subject   : acme-supplies.example
  issuer    : E5  (Let's Encrypt)
  valid     : 2026-04-15T08:32:11Z  →  2026-07-14T08:32:10Z
  expires in: 53 days
  sig algo  : ECDSA-SHA256
  sans      : acme-supplies.example, *.acme-supplies.example
...
```

With `-name acme-supplies.example`, the CDN serves the *right*
cert for that hostname — chain verifies cleanly. This is the
canonical pattern for "is the CDN edge serving the right cert
for this hostname when reached via this specific IP" — useful
during failover testing, CDN migrations, or any context where
DNS resolution is bypassed.

### A TLS-wrapped IMAP service

```
operator@cathedral:~$ ssl mail.acme-supplies.example -p 993
> TLS handshake with mail.acme-supplies.example:993 (sni=mail.acme-supplies.example)

  protocol  : TLS 1.3
  cipher    : TLS_AES_256_GCM_SHA384
  status    : [chain verified]

[ cert[0] ]
  subject   : mail.acme-supplies.example
  issuer    : R10  (Let's Encrypt)
  valid     : 2026-04-20T08:00:00Z  →  2026-07-19T08:00:00Z
  expires in: 58 days
  sig algo  : SHA256-RSA
  sans      : mail.acme-supplies.example, smtp.acme-supplies.example, imap.acme-supplies.example, pop3.acme-supplies.example
...
```

Port 993 is IMAPS (IMAP-over-TLS). No ALPN field rendered —
IMAP doesn't use ALPN. The SAN list reveals the mail server
covers all the canonical mail-service hostnames in one
certificate (`mail`, `smtp`, `imap`, `pop3` — common for
self-hosted mail). The chain validates; everything healthy.

Cathedral *cannot* probe SMTP STARTTLS on port 25 / 587 the
same way — those protocols start in plaintext and *upgrade*
to TLS via the STARTTLS command. For STARTTLS-protected
services either point Cathedral at the implicit-TLS variant
(`-p 465` for SMTPS, `-p 993` for IMAPS, `-p 995` for POP3S),
or use `openssl s_client -starttls smtp`.

## Output protocol

```
{"event":"start", "host":"…","port":"…","sni":"…"}
{"event":"conn",  "version":"TLS 1.3","cipher":"…","alpn":"h2|http/1.1|",
                  "resumed":bool,"verified":bool,"verify_error":"…"}
{"event":"cert",  "idx":N,"subject_cn":"…","subject_org":"…",
                  "issuer_cn":"…","issuer_org":"…",
                  "sans":["…"],"not_before":"…","not_after":"…",
                  "days_left":N,"is_ca":bool,"self_signed":bool,
                  "sig_algo":"…","serial":"…"}                          *per cert
{"event":"verify_reason", "message":"…"}                                # if unverified
{"event":"done"}
{"event":"error", "message":"…"}
```

Extract just the days-until-expiry for the leaf cert across a
portfolio (the canonical certificate-monitoring use case):

```
$ for h in $(cat hosts.txt); do
    days=$(ssl "$h" -j |
      jq -r 'select(.event=="cert" and .idx==0) | .days_left')
    printf '%-40s %s days\n' "$h" "${days:-error}"
  done | sort -k2 -n
legacy-portal.acme-supplies.example      -67 days
old-staging.acme-supplies.example        12 days
status.acme-supplies.example             40 days
api.acme-supplies.example                53 days
acme-supplies.example                    53 days
docs.acme-supplies.example               58 days
```

Find hosts with chain-verification failures:

```
$ for h in $(cat hosts.txt); do
    ssl "$h" -j |
      jq -r --arg h "$h" \
        'select(.event=="conn" and .verified==false) |
         "\($h)\t\(.verify_error)"'
  done
legacy-portal.acme-supplies.example  x509: certificate has expired or is not yet valid
lab.acme-supplies.example            x509: certificate signed by unknown authority
internal-tool.example                x509: certificate is valid for tool.example, not internal-tool.example
```

Inventory SANs across the portfolio (subdomain discovery via
SAN coverage):

```
$ for h in $(cat hosts.txt); do
    ssl "$h" -j |
      jq -r 'select(.event=="cert" and .idx==0) | .sans[]'
  done | sort -u | grep -v '^\*\.'    # drop wildcards for clarity
acme-supplies.example
api.acme-supplies.example
docs.acme-supplies.example
internal-portal.acme-supplies.example
legacy-portal.acme-supplies.example
mail.acme-supplies.example
pop3.acme-supplies.example
smtp.acme-supplies.example
status.acme-supplies.example
```

## Limitations

- **No protocol forcing.** Cathedral uses Go's default
  negotiation (TLS 1.2 min, TLS 1.3 preferred). For testing
  specific protocol versions use `openssl s_client -tls1_1`
  (etc.) or `testssl.sh`.
- **No cipher enumeration.** Reports negotiated cipher only;
  doesn't list all offered. `nmap --script=ssl-enum-ciphers`
  is the right tool for that.
- **No STARTTLS.** Implicit-TLS ports only. For SMTP submission
  (587), IMAP (143), POP3 (110), FTP (21) STARTTLS handshakes,
  use `openssl s_client -starttls <proto>`.
- **No OCSP / CRL revocation checking.** A revoked-but-valid
  cert verifies green.
- **No CT-log lookup.** [`crt`](crt.md) is the complementary
  tool — find certs from the other direction.
- **No raw PEM output.** Parsed fields only; for full
  certificate capture use `openssl s_client -showcerts`.
- **6-second connect timeout.** Fixed; slow servers time out.
- **No session resumption testing.** Single dial; doesn't
  exercise the resumption path.
- **Limited browser-simulation accuracy.** Verification matches
  Go's stdlib, which closely tracks browser behaviour but isn't
  identical. Browser-specific trust decisions (Symantec distrust,
  custom intermediate handling) may differ.

## Authorized use

`ssl` is **passive recon**. One TLS connection per invocation
(actually two — verified and insecure — but to the same host).
Connection footprint is indistinguishable from a single
HTTPS visit. Risk profile is the same as [`http`](http.md) or
any other single-request tool.

The TLS handshake itself is unencrypted on the wire (the SNI
hostname is visible in cleartext until ESNI/ECH adoption
matures), so observers on the network path can see which
hostnames you're probing. For sensitive recon, route through
a VPN or use a host that's already exposed to that observer
context.

For *internal* infrastructure auditing — self-signed certs,
expired certs, weak protocols on internal services — the
output of `ssl` is operationally useful but contains
infrastructure-detail information (SAN coverage, internal
hostname patterns, internal-CA names) that's worth treating
as moderately sensitive before sharing externally.

## Further reading

- [RFC 8446 — The TLS Protocol Version 1.3](https://www.rfc-editor.org/rfc/rfc8446) — the modern TLS spec
- [RFC 5246 — TLS 1.2](https://www.rfc-editor.org/rfc/rfc5246) — the still-widely-deployed previous version
- [RFC 6066 §3 — Server Name Indication](https://www.rfc-editor.org/rfc/rfc6066#section-3) — the SNI extension `-name` controls
- [RFC 7301 — Application-Layer Protocol Negotiation Extension](https://www.rfc-editor.org/rfc/rfc7301) — ALPN spec
- [RFC 5280 — X.509 PKI Certificates](https://www.rfc-editor.org/rfc/rfc5280) — cert structure, SAN validation, chain semantics
- [BR — CA/Browser Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) — public-CA cert issuance rules (lifetime caps, key reqs, validation)
- [testssl.sh](https://testssl.sh/) — comprehensive TLS auditing tool; complements Cathedral's quick-look approach
- [Qualys SSL Labs](https://www.ssllabs.com/ssltest/) — point-and-click TLS scanner with letter grade
- [Let's Encrypt — Chain of Trust](https://letsencrypt.org/certificates/) — current and historical intermediate / root structure
- Related Cathedral commands: [`crt`](crt.md) *(planned — CT-log certificate discovery from the other direction)*,
  [`banner`](banner.md) (TCP / TLS banner grab; the layer below `ssl`),
  [`headers`](headers.md) (HTTP-response security headers; the layer above TLS),
  [`http`](http.md) (single-endpoint inspection over the TLS connection),
  [`recon`](recon.md) (breadth-first HTTP probing; uses the TLS chain Cathedral inspects)
