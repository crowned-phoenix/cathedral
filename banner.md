---
title: banner — single-port banner grab with probe, TLS, and hex dump
command: banner
category: reachability
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [scan, discover, ssh-audit, ssl, tech]
---

# `banner` — single-port banner grab with probe, TLS, and hex dump

`banner` connects to one TCP or UDP port, optionally sends a
probe payload, and captures whatever the server replies. For TLS
ports it inspects the handshake — protocol, cipher, ALPN, chain
verification — alongside the application-layer response. Text
replies render as text; binary replies render as `xxd`-style hex
dumps. It's the deep companion to [`scan`](scan.md): scan finds
what's open; `banner` figures out what's *actually running*.

```
banner 213.168.17.125:22                                  # SSH greeting
banner host:25 --probe="EHLO probe\r\n"                    # SMTP capability list
banner host:80 --probe="GET / HTTP/1.0\r\n\r\n"            # HTTP response
banner host:443 --tls --probe="HEAD / HTTP/1.0\r\n\r\n"    # HTTPS + TLS inspect
banner 1.1.1.1:53 --udp --probe-hex="0001 0100 0001 0000 …"
banner host:9200 --tls --max=65536                         # large banner cap
```

## What it does

One outbound connection to `host:port`, optionally a single
probe payload sent, then up to `--max` bytes (default 8 KB) read
back. The exchange is reported as a sequence of structured
events: connect, optional TLS handshake details, optional
probe-sent marker, the response payload as text or hex.

| Flag                | Meaning                                          | Default |
|---------------------|--------------------------------------------------|---------|
| `<host:port>`       | target (positional, required); IPv6 as `[::1]:80` | —       |
| `--probe="…"`       | text probe; supports `\r \n \t \\ \" \xHH` escapes | unset  |
| `--probe-hex=…`     | raw byte probe; spaces and colons in hex tolerated | unset  |
| `--tls`             | wrap the TCP socket in TLS before probing         | off     |
| `--udp`             | use UDP instead of TCP (probe usually required)   | off     |
| `--sni=NAME`        | SNI hostname for TLS                              | host    |
| `--timeout=MS`      | overall timeout (ms)                              | `5000`  |
| `--max=N`           | cap response read at N bytes                      | `8192`  |
| `-k`                | suppress the "TLS chain unverified" warning       | off     |

The flag set is deliberate. `banner` is the tool you reach for
when *one* port wants careful attention — not the tool for
sweeping a network. For sweeping, see [`scan`](scan.md) (many
ports on one host) or [`discover`](discover.md) (one port on
many hosts).

## What it answers

**Defender:** *"What's actually answering on my port 8443?"* Port
maps to expectation only loosely — port 22 *usually* means SSH,
port 25 *usually* means SMTP, but port 8443 could be anything.
`banner` opens the connection, exchanges one round, shows the
response, and tells you whether what's there matches what you
thought was there.

**Recon (authorized testing only):** *"What software and version
is this service running?"* Banners frequently leak software
names and versions — `SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13`
identifies both the SSH version and the underlying distribution.
That single line tells an auditor more about the host's
maintenance posture than a port scan does.

**Investigation:** *"What is this connection trying to do?"*
Sometimes log analysis surfaces a connection to an unfamiliar
port — `:6379`, `:11211`, `:27017`. A single `banner host:port`
reveals whether it's Redis, memcached, MongoDB, or something
masquerading as one of those.

**Learning:** This is the protocol-level lens of Cathedral.
Want to see what a server actually sends on first byte?
`banner host:25` is the protocol greeting from SMTP. Want to
inspect a TLS handshake? `banner host:443 --tls` shows protocol,
cipher, ALPN, peer common name, and chain verification.
Cathedral leaves nothing in opaque libraries when it doesn't
have to.

## How it works

### TCP: connect, optionally probe, read

The TCP path is simple but careful about timing. Connect with a
deadline; record the connect latency. If a probe was given, send
it. Then read whatever arrives, up to `--max` bytes, until the
connection closes, times out, or fills the cap.

```go
tcp, err := net.DialTimeout("tcp", addr, timeout)
// … connected event …
if len(args.probe) > 0 {
    tcp.Write(args.probe)
    // … probe_sent event …
}
data, _ := readAvailable(tcp, args.maxBytes)
```

The overall timeout governs probe + read together — a server
that hangs after answering some bytes won't trap the tool
forever. `readAvailable` returns whatever was accumulated when
the connection ends. EOF, timeout, and connection reset are all
*acceptable read endings*, not errors — banners often terminate
that way and Cathedral surfaces the captured bytes either way.

### TLS: handshake first, banner second

When `--tls` is set, Cathedral wraps the TCP socket in a TLS
client, completes the handshake, then proceeds to probe / read
inside the encrypted stream. The handshake itself is what makes
the tool useful for TLS investigation:

```go
cfg := &tls.Config{
    ServerName:         sni,
    InsecureSkipVerify: true,   // see "inspect mode" note below
}
tlsConn := tls.Client(tcp, cfg)
tlsConn.Handshake()
state := tlsConn.ConnectionState()
verified := verifyChain(state, host)
```

After the handshake, a `tls` event reports protocol version
(TLS 1.0 through 1.3), cipher suite name, negotiated ALPN
protocol (often empty for non-HTTP services, `h2` or `http/1.1`
for HTTPS), SNI used, peer certificate common name, and a
verification verdict.

**Inspect-mode rationale.** Cathedral sets `InsecureSkipVerify:
true` for the handshake itself — meaning the handshake completes
even when the cert chain is bad — *and then* runs full x509
verification separately and reports the result. The reasoning:
"can't connect to invalid-cert server" is the wrong behaviour
for an investigation tool. An internal service with a self-
signed cert is still worth inspecting; the right move is to
*complete* the handshake, *read* what the service says, and
*also* tell the operator that the cert chain didn't validate.
The `verified: true | false` field carries that finding.

### Probe escape sequences

The `--probe="…"` flag accepts a small, predictable escape set
so binary-ish probes stay typeable at the shell:

| Escape | Byte                                |
|--------|-------------------------------------|
| `\r`   | carriage return (0x0D)              |
| `\n`   | line feed (0x0A)                    |
| `\t`   | tab (0x09)                          |
| `\\`   | literal backslash                   |
| `\"`   | literal double-quote                |
| `\0`   | NUL                                 |
| `\xHH` | byte with hex value `HH`            |

Anything else passes through verbatim. The shell layer
typically demands its own quoting around the whole thing —
single-quote the probe to avoid double-escape sandwiches:

```
banner host:25 --probe='EHLO me\r\n'
```

For fully binary probes (DNS queries, MQTT CONNECT, RDP
negotiate, Modbus, …), `--probe-hex=` is the right tool. Spaces
and colons in the hex string are tolerated for readability:

```
banner 1.1.1.1:53 --udp \
  --probe-hex="00 01 01 00 00 01 00 00 00 00 00 00 \
               07 65 78 61 6d 70 6c 65 03 63 6f 6d 00 \
               00 01 00 01"
```

### UDP without a probe is a warning

UDP services do not speak first. A bare `banner host:53 --udp`
sends no datagrams; the read returns nothing within the
timeout. Cathedral emits an explicit warning event to make this
clear rather than silently returning empty:

```
{"event":"warn","message":"UDP without --probe — most services won't respond unsolicited"}
```

The proper UDP workflow is always probe-driven: construct or
borrow a protocol-correct query, send it via `--probe-hex=`,
read the answer.

### Text vs hex auto-classification

Captured bytes are classified before display:

```go
func isTextish(b []byte) bool {
    if !utf8.Valid(b) { return false }
    for _, c := range b {
        if c == '\r' || c == '\n' || c == '\t' { continue }
        if c < 0x20 || c == 0x7f { return false }
    }
    return true
}
```

Valid UTF-8 with only printable runes plus the usual whitespace
controls → render as text. Anything else → render as an
`xxd`-style hex dump (offset · 16 bytes · ASCII gutter) so binary
protocols stay legible without flooding the terminal with
mojibake. The decision is recorded in `is_text` on the
`received` event.

## Worked example

Three contrasting probes, each showing a different shape of the
tool.

### Bare TCP — SSH speaks first

```
$ banner scanme.nmap.org:22
> TCP connect to scanme.nmap.org:22   timeout 5000ms
  [::]:46406  →  [2600:3c01::f03c:91ff:fe18:bb2f]:22   1837ms

SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
```

No probe needed — SSH announces itself the moment the
connection completes. The version string identifies *both* the
SSH implementation (`OpenSSH_6.6.1p1`, from 2014) *and* the
distribution it ships with (`Ubuntu-2ubuntu2.13`, Ubuntu 14.04
LTS). The cookbook entry for [`scan`](scan.md) flagged the same
banner; here, you get the full untruncated line without scanning
anything else. For deeper SSH-specific analysis (key-exchange
algorithms, ciphers, MAC modes), reach for
[`ssh-audit`](ssh-audit.md).

### TCP with a probe — HTTP HEAD

```
$ banner scanme.nmap.org:80 --probe='HEAD / HTTP/1.0\r\n\r\n'
> TCP connect to scanme.nmap.org:80   timeout 5000ms
  [::]:49428  →  [2600:3c01::f03c:91ff:fe18:bb2f]:80   180ms
  → sent 19 probe bytes (text)

HTTP/1.1 200 OK
Date: Fri, 15 May 2026 19:52:38 GMT
Server: Apache/2.4.7 (Ubuntu)
Accept-Ranges: bytes
Vary: Accept-Encoding
Connection: close
Content-Type: text/html
```

`Apache/2.4.7 (Ubuntu)` — released in 2013, an unmistakable
"this host hasn't been package-updated in years" finding. The
HTTP response is the full header block; the `Content-Type` line
ends without a body because `HEAD` was the request method.

### TLS handshake + HTTPS response

```
$ banner github.com:443 --tls --probe='HEAD / HTTP/1.0\r\nHost: github.com\r\nConnection: close\r\n\r\n'
> TCP+TLS connect to github.com:443   timeout 5000ms
  192.168.1.176:53908  →  140.82.121.4:443   41ms

[ tls ]
  protocol : TLS 1.3
  cipher   : TLS_AES_128_GCM_SHA256
  sni      : github.com
  peer cn  : github.com
  status   : [chain verified]
  → sent 56 probe bytes (text)

HTTP/1.1 200 OK
Date: Fri, 15 May 2026 19:52:37 GMT
Content-Type: text/html; charset=utf-8
Strict-Transport-Security: max-age=31536000; includeSubdomains; preload
X-Frame-Options: deny
X-Content-Type-Options: nosniff
Content-Security-Policy: default-src 'none'; …
Server: github.com
… (4500+ bytes of headers and cookies, truncated)
```

The `[ tls ]` block is the value-add: one round-trip captures
protocol version, cipher suite, SNI, peer common name, and the
verification verdict. The combined output answers *what's
running on :443* (HTTPS), *with what TLS settings* (TLS 1.3,
AES-GCM-128, verified), *behind what cert* (peer CN
`github.com`), and *with what application headers*
(`Strict-Transport-Security`, full CSP, etc.). For dedicated TLS
analysis, see [`ssl`](ssl.md); for security-header grading, see
[`headers`](headers.md).

## Output protocol

```
{"event":"start",     "host":"…","port":N,"transport":"TCP|TCP+TLS|UDP",
                      "probe_bytes":N,"timeout_ms":N}
{"event":"connected", "local":"…","remote":"…","elapsed_ms":N}
{"event":"tls",       "protocol":"…","cipher":"…","alpn":"…",
                      "sni":"…","verified":bool,"peer_cn":"…"}?
{"event":"probe_sent","bytes":N,"source":"text|hex"}?
{"event":"warn",      "message":"…"}?
{"event":"received",  "bytes":N,"is_text":bool,"text":"…"|"hex":"…"}
{"event":"done"}
```

`received` carries either a `text` field (UTF-8 string, single
trailing newline stripped) or a `hex` field (multi-line
`xxd`-style dump). Inspect `is_text` to know which to read.

Pipe to capture just the text response:

```
$ banner host:25 --probe='EHLO probe\r\n' -j |
    jq -r 'select(.event=="received" and .is_text) | .text'
```

Capture binary payload as raw bytes:

```
$ banner 1.1.1.1:53 --udp --probe-hex='…' -j |
    jq -r 'select(.event=="received" and .is_text==false) | .hex'
```

## Limitations

- **Single host, single port.** `banner` deliberately does not
  sweep. For per-host port enumeration, run [`scan`](scan.md)
  first and pipe interesting ports through `banner`. For
  per-port host enumeration, [`discover`](discover.md) is the
  right tool.
- **Max read defaults to 8 KB.** Large banners (web pages, big
  HTTP responses, verbose service greetings) are truncated.
  Raise with `--max=N` — up to whatever you're willing to read
  from a probably-hostile-or-misbehaved peer.
- **5-second overall timeout.** Slow-responding services
  (legacy mainframes, satellite-link services, deliberate
  rate-limiters) may not finish within the default. Bump
  `--timeout=15000` for long-pole protocols.
- **One round-trip.** `banner` sends *one* probe, reads *one*
  response. Multi-step protocols (FTP login + LIST, SMTP EHLO +
  MAIL FROM + RCPT TO) need a real client or scripted
  composition — `banner` is not a session driver.
- **TLS inspect-mode accepts any chain.** That's the right
  trade for an investigation tool, but it does mean `banner`
  will happily connect to a phishing site's expired cert and
  return its response. The `verified: false` finding is the
  signal; treat it as one.
- **UDP without a probe gets nothing useful.** Cathedral warns
  but doesn't refuse — sometimes "this port has no
  unsolicited-talker semantic" is itself the finding.
- **Hex dump doesn't decode protocols.** Binary responses are
  shown as bytes; what they *mean* (DNS answer parse, MQTT
  CONNACK fields, TLS alert codes) is left to the operator.
  Cathedral's protocol-specific tools handle protocol-specific
  semantics — `ssh-audit` for SSH, `ssl` for TLS, planned `dns
  rev` / `mx-rep` for DNS-shaped data.

## Authorized use

`banner` opens *one* TCP connection (or sends *one* UDP
datagram) to *one* port on *one* host. The risk profile is the
same as `nc` or `openssl s_client` — a single probe, fully
attributable to the source IP, no sweep semantics.

For a target you own, this is unremarkable — the same shape of
traffic any legitimate client makes.

For a target you do not own, the calculus is the same as for any
single-host investigation: the probe is visible in the target's
logs, the source IP is yours, and the captured banner contents
may identify vulnerable software versions. Make sure the
authorisation under which you're operating covers what `banner`
reveals.

**The probe is what you send.** A bare connect is no different
from a normal client connecting and disconnecting. A custom
probe (`HEAD /`, `EHLO …`, hex payload) is *active*: the target
sees you talking to it. If the engagement model is "passive
only", don't pass `--probe`.

## Further reading

- [RFC 9293 — Transmission Control Protocol](https://www.rfc-editor.org/rfc/rfc9293) — the connect/EOF semantics the read loop relies on
- [RFC 8446 — TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446) — the handshake `--tls` inspects
- [`xxd` man page](https://man7.org/linux/man-pages/man1/xxd.1.html) — the hex-dump format Cathedral mirrors
- Related Cathedral commands: [`scan`](scan.md) (find open ports — banner investigates one),
  [`discover`](discover.md) (scan inverted: one port, many hosts),
  [`ssh-audit`](ssh-audit.md) (protocol-aware SSH inspection),
  [`ssl`](ssl.md) (dedicated TLS certificate-chain analysis),
  [`tech`](tech.md) (HTTP-aware technology fingerprinting)
