---
title: Cookbook roadmap
last-updated: 2026-05-26
---

# Cookbook roadmap

This is a meta-document about the *cookbook's* own direction — what entries
are coming, in roughly what order, and why some categories land later than
others. It is not a project roadmap (that lives at `ROADMAP.md` in the
repository root, with detailed scope per tool).

Cookbook entries describe **technique** — how a shipped tool works, what
question it answers, where it fits in a workflow. That focus shapes what
appears here: tools that exist today get a placeholder until their entry is
written; tools that haven't been built yet get a sketch of what their entry
will cover when they land.

For a *current* index of shipped cookbook entries, see [README.md](README.md).

---

## Shipped tools awaiting cookbook entries

These tools exist in Cathedral and run today; the cookbook entry just
hasn't been written yet. Roughly in landing order:

### `oui` — MAC vendor lookup
Curated ~115-entry table of common consumer / networking / IoT /
virtualization OUI prefixes. Also flags multicast and locally-administered
MACs. Cookbook will cover the OUI registry structure (IEEE-assigned 24-bit
prefixes, plus 28-bit MA-M and 36-bit MA-S blocks) and why a curated table
beats a full IEEE OUI database for the analyst use case (small, fast,
covers the vast majority of MACs you actually see).

### `subs` — subdomain enumeration via dictionary + DNS-zone walking
The third complementary surface to [`crt`](crt.md) (CT log search) and
[`fav`](fav.md) (favicon pivot). Where those two find subdomains via
*historical artifacts*, `subs` finds them via *active resolution* —
wordlist-driven DNS lookups plus DNS-zone-walking where the zone is loosely
configured. Cookbook will frame the three subdomain-discovery techniques
side-by-side: each catches different things, and engagements benefit from
running all three.

### `sysmon` — system HUD sidecar
Long-running sidecar that feeds the system HUD panels (CPU, memory, network
sparklines, load, uptime). Cookbook entry will be unusual in scope — the
*tool* is small, but it's Cathedral's canonical example of the long-running-
sidecar pattern (as opposed to the one-shot-command pattern that all other
shipped entries cover). Entry will cover both the sidecar's data sources
and the pattern itself, since the pattern shapes how future live-data
features get added.

### Crypto utility belt — *(category complete)*
All seven entries shipped:
[`argon2`](argon2.md), [`bcrypt`](bcrypt.md), and
[`entropy`](entropy.md) on 2026-05-25 — the password-handling triad;
[`encrypt` / `decrypt`](encrypt-decrypt.md), [`hash`](hash.md),
[`pwned`](pwned.md), and [`jwt`](jwt.md) on 2026-05-26 — the
authenticated-encryption pair, the multi-algo digest tool, the
HIBP k-anonymity lookup (closes the password-strength workflow
alongside `entropy`), and the JWT inspector / verifier.

Note on `jwt`: the original planned scope included signing
("decode, verify, and sign"). The shipped tool covers decode +
verify only — signing is a producer-side concern best handled
inside the application that needs to produce tokens, where the
key-management context lives. If a `jwt sign` subcommand ever
ships, it'll inherit the same five-algorithm-family dispatch
(HMAC / RSA-PKCS1v15 / RSA-PSS / ECDSA-r∥s / EdDSA) from the
verify path.

The shipped [`argon2`](argon2.md), [`bcrypt`](bcrypt.md), and
[`entropy`](entropy.md) entries establish the cookbook style for this
category — algorithm history, parameter-tuning guidance, format
walkthrough, defender vs. legacy-maintenance vs. authorized-testing
perspectives, constant-time-compare safety notes where relevant.
`entropy` adds a separate template for *estimator*-style tools (honest
about being an upper bound, pattern sniffer as the corrective lens).
The shipped [`encrypt` / `decrypt`](encrypt-decrypt.md) entry adds
another structural template: a *paired-command* doc covering both
the producer and the consumer of a shared on-the-wire format
(`$cthd1$…` envelope). Future paired tools (`jwt sign` / `jwt
verify`, eventual asymmetric-encryption commands) should mirror this
shape — single combined entry with the format spec section being the
backbone.

Note on naming: two cross-currents to be aware of.

1. The original `entropy` planned-entry was sketched as "Shannon
   entropy + byte-distribution analysis on file regions." The
   shipped version is a **password-strength estimator** instead — a
   fundamentally different tool that happens to share the name.
   The file-entropy idea remains a future candidate, most naturally
   as a `--scan` mode on the shipped [`hash`](hash.md) since the
   natural pairing is "compute digest + report entropy distribution"
   on the same file. Worth doing in `hash` rather than re-using the
   `entropy` name (the password-strength meaning is now load-bearing).

2. The originally planned `crypt` command (classic Unix crypt
   formats — `$1$` md5-crypt, `$5$` sha256-crypt, `$6$`
   sha512-crypt) hasn't shipped. The binary name `crypt` was
   instead taken by the AEAD implementation that backs
   [`encrypt` / `decrypt`](encrypt-decrypt.md). If the Unix-crypt
   tool eventually ships, it will need a different name — most
   likely `shadowhash` (descriptive of the `/etc/shadow` format
   it operates on) or absorbed as `hash --shadow-format` now that
   [`hash`](hash.md) has shipped.

### Filesystem — `ls`, `stat`, `tree`
Cathedral-styled replacements for the standard utilities, with the
phosphor aesthetic and richer output (full mode bits, xattrs, capability
flags, magic-byte sniffs on suspicious files). Will land as the
**Filesystem** category section.

---

## Planned tools (not yet built)

Sketch of each, ordered by which cookbook category they'll land in. Full
scope notes for each — what the parser surface looks like, which libraries
are chosen, what edge cases need handling — live in `ROADMAP.md` at the
repo root.

### Discovery expansion

**`discover icmp/arp` — host discovery subcommands.** The current
[`discover`](discover.md) is TCP-ping. ROADMAP adds:

- `discover icmp <targets>` — classic ping via `golang.org/x/net/icmp`
  with proper reply-type distinction (Echo Reply / Destination Unreachable
  / Time Exceeded as separate findings, not all-or-nothing), per-host RTT,
  TTL fingerprinting for OS-family hints (~64 Linux/BSD, ~128 Windows,
  ~255 network gear).
- `discover arp <cidr>` *(deferred — libpcap dependency)* — ARP scan on
  the local segment. Most reliable LAN reachability check; hosts that
  drop ICMP can't ignore ARP without falling off the network.

Cross-method findings: "alive on TCP but not on ICMP" ⇒ ICMP filtered at
the edge (recon note, not a vuln). When this lands, the existing
`discover.md` entry gets a *significant* update rather than splitting into
three entries.

**`sniff` v1** [shipped 2026-05-26, see [`sniff`](sniff.md)] —
basic passive packet capture: Ethernet → IPv4 / IPv6 / ARP → TCP /
UDP / ICMP / ICMPv6, with Cathedral's `proto=` / `host=` / `port=`
filter syntax. The libpcap concern in earlier roadmap drafts turned
out to be unnecessary — raw `AF_PACKET` sockets are reachable from
pure Go via `syscall.Socket` directly, so the static-binary property
holds. Trade-off: Linux-only (the syscall doesn't exist on macOS /
Windows). Cookbook entry covers the AF_PACKET shortcut, the
CAP_NET_RAW capability model, the Ethernet-to-layer-4 parser, and
TCP-flag decoding.

**`sniff` v2 — findings extractor (lower priority).** The richer
behaviour the original roadmap envisioned: DHCP-request device
inventory, ARP-spoof anomaly detection, DNS-query introspection,
TLS-SNI extraction (no decryption), plaintext-cred extraction in
HTTP/FTP/Telnet/SMTP/IMAP, mDNS/SSDP service discovery, port-scan
detection (defensive mirror). All deferred: the v1 shipped surface
covers the "show me packets matching a filter" use case, and the
richer extractors compete with `tshark` / `bettercap` on their
home turf without a clear Cathedral-specific win yet. Likely shape
when revisited: subcommands (`sniff dhcp`, `sniff arp`, `sniff
plaintext`) sharing v1's socket+parser pipeline, each emitting
its own finding-event type rather than packet-events.

### DNS & identity expansion

**`dns` — multi-subcommand verb.** The current `dns` is a single-domain
forward-records inspector. ROADMAP describes promoting it to a multi-
subcommand verb:

- `dns fwd <hostname>` — what the current `dns` is.
- `dns rev <ip|cidr|file>` — FCrDNS (forward-confirmed reverse) with
  hostname-pattern role tagging (`mail-`, `vpn-`, `jenkins-`, cloud-tell
  patterns).
- `dns axfr <domain>` — zone-transfer attempts against each NS (AXFR
  success is itself a high-severity finding).
- `dns enum <domain>` — common-record sweep (MX, NS, TXT, SOA, SPF,
  DMARC, DKIM selectors, CAA) with policy grading.
- `dns brute <domain> --wordlist <file>` — wordlist-driven subdomain
  bruteforce with `dirscan`-style rate guards.

When this lands, [`dns.md`](dns.md) and [`reverse-dns.md`](reverse-dns.md)
likely consolidate, with per-subcommand sections under one entry.

### Identification expansion

[`locate`](locate.md) shipped 2026-05-23 — address-to-satellite-view
geocoder with phosphor map render and auto-centred globe pin. The
cookbook entry covers the Photon geocoder, the Web Mercator slippy-
tile pipeline, the two-source split (Esri satellite via Flutter
ColorFilter, Carto Voyager street via Go-side gamma + Sobel edge
detection), the deep-zoom wide+close cross-fade architecture, and
the multi-panel orchestration that drives the GLOBE and VISUAL MAP
panels together. Build also produced the *bonus signals* deferral
(local time, sunrise/sunset, distance from netinfo-primary) and the
*Tor compose* deferral (`--via-tor` routing pending the Tor feature)
— both noted in the entry's *What Cathedral doesn't do* section.

Notable architectural firsts the entry documents:
- First Cathedral command driving two HUD panels simultaneously
  (GLOBE + VISUAL MAP).
- First command using **Go-side pixel-level image processing** for
  the visual output — gamma curve + Sobel edge detection — because
  Flutter's `ColorFilter.matrix` mishandles negative weights (see
  [[architecture_flutter_colorfilter_negatives]]). Future
  inversion-style visual effects should follow the same pattern.
- First command implementing **auto-centre on highlighted pins**
  via `_GlobeState`'s yaw tween — pattern reusable for any future
  "pin arrived, look here" UX.

If more geographic-intelligence tools follow (Mapillary street view,
Sentinel-2 recent imagery, Overpass overlays), `locate` and `geoip`
likely graduate together into a renamed *Geographic intelligence*
subcategory.

### Web app analysis expansion

**`webrecon` — passive web reconnaissance multi-tool.** Single verb
absorbing what would be separate small tools, sharing an HTTP client,
redirect-chain handling, JSON envelope, and authorized-testing banner:

- `webrecon cookies <url>` — deeper than the current [`cookies`](cookies.md)
  (which inspects only the final response's Set-Cookie set). Walks the
  full redirect chain, surfaces cookies set at every hop, severity-tags
  findings.
- `webrecon comments <url>` — HTML-comment extractor with per-comment
  classification (`secret-candidate` / `internal-host` / `path-leak` /
  `version-leak` / `todo` / `removed-code` / `trivial`). Uses
  `golang.org/x/net/html` tokenizer for proper HTML handling rather than
  regex.
- `webrecon forms <url>` *(post-v1)* — action URLs, hidden inputs, CSRF
  tokens, autocomplete-on-password fields.
- `webrecon links <url>` *(post-v1)* — internal/external link inventory;
  flag `mailto:`, `tel:`, `javascript:`, `data:`.

How this lands in the cookbook is partially open: the simplest path is
one entry per subcommand under the existing **Web app analysis**
category; the cleaner path is a single `webrecon.md` covering all
subcommands together. Decision deferred until the implementation shape
settles.

### File & data forensics expansion

**`meta` — multi-format expansion.** The current [`meta`](meta.md) covers
PDF and EXIF (JPEG/TIFF). The roadmap adds PNG `tEXt`/`iTXt`/`zTXt`
chunks, OOXML (`.docx`/`.xlsx`/`.pptx` via the ZIP container's
`docProps/core.xml`), ID3 (`.mp3` via `github.com/dhowden/tag`), and
optional MP4 atoms. Plus `--all` for verbose XMP/embedded-JS/font-list
output and `--hash` for digests alongside the metadata. The existing
cookbook entry will be updated rather than replaced — the grouped-layout
rendering pattern that landed 2026-05-22 already accommodates more
formats as parsers are added.

**`imgforensic` — image integrity inspector.** Pairs with `meta`. Where
`meta` reads metadata field *contents*, `imgforensic` answers questions
about the file's integrity: format triangulation (claimed extension vs
magic bytes vs what decoders accept), decoded-dimensions sanity, trailing-
data detection (bytes after JPEG `FFD9` / PNG `IEND` / GIF trailer —
canonical polyglot / appended-payload signal), polyglot magic-byte sniff
in the trailing region, hashes, and `--deep` chunk/marker walking. Cookbook
entry will be the finding-flavored deep dive — trailing-data detection is
the meat; the format checks are the plumbing.

**`browser` — browser-artifact forensics.** Multi-vendor (Firefox, Chrome,
Chromium, Brave, Edge) read-only inspection of SQLite-backed artifacts:
history, cookies, downloads, logins (URLs + usernames only — never
decrypted passwords), search queries, profile discovery. Cookbook entry
will cover per-OS profile-discovery paths, locked-DB handling (browsers
hold exclusive locks while running — copy-to-tmp or SQLite immutable read-
only mode), and the pure-Go SQLite choice (`modernc.org/sqlite` over
`mattn/go-sqlite3` for the no-CGO property).

### Email & certificates expansion

(Category is shipped-complete. `spf` / `dmarc` / `mx-rep` / `ssl` / `crt`
plus the awaited `subs` covers the surface. [`dnsbl`](dnsbl.md) shipped
2026-05-26 as the sibling to [`mx-rep`](mx-rep.md): single-IP RBL
check across ten lists — the five `mx-rep` uses plus UCEPROTECT-L2/L3
escalation, PSBL, Mailspike Z, and DNSWL as the allowlist anchor.
Cookbook covers the RFC 5782 reverse-IP mechanism, the 127.0.0.x
response-code convention, per-list rationale (why these ten,
including UCEPROTECT-L3's false-positive caveat), and the Spamhaus
public-resolver poisoning caveat that makes `/etc/resolv.conf`
choice load-bearing for trustworthy results.)

### New category — Crypto utility belt

The seven crypto tools listed under "Shipped tools awaiting cookbook
entries" above will form a new category when their cookbook entries are
written. Category description: *small, focused tools for hashing,
verifying, generating, and decoding the byte strings that underpin
authentication and integrity*. Sits between **File & data forensics** and
**Filesystem** in the index ordering.

### New category — Filesystem

`ls`, `stat`, `tree` plus likely `find`-equivalent will form the
**Filesystem** category. Sits at the end of the shipped-categories list
since these are Cathedral overrides for stdlib utilities and the
cookbook value is more about the *Cathedral-specific output* than the
underlying technique.

### New category — Operational behaviors

Cathedral has so far been a collection of *commands* — verbs the operator
types into the console. The roadmap introduces a category of features
that aren't commands at all but launch-time and runtime behaviors of the
Cathedral app itself. The first such feature is MAC randomization;
future entries here might cover boot-sequence customization, runtime
overlay panels, or per-session credential isolation.

**`MAC randomization at launch` — boot-time hardware-address spoofing.**
Opt-in feature that randomizes the configured network interface's MAC
on each Cathedral launch and restores the burned-in original on exit.
Default mode sets the IEEE 802 locally-administered bit (honest
randomization — anyone inspecting can see the LAA bit set and knows
the address isn't a real OUI); opt-in vendor mode picks a random
prefix from a named vendor's OUI allocations (Cisco / Apple / Intel /
Dell), which is the deception mode and carries the authorized-use
weight.

The cookbook entry will be unusual in shape — there's no command to
demonstrate, no streaming event protocol to document, no worked
examples in the usual sense. The entry will cover instead:

- **IEEE 802 MAC structure.** OUI prefix (24 bits) + NIC-specific
  suffix (24 bits), the LAA bit (bit 1 of octet 0) and the
  multicast bit (bit 0 of octet 0) — what they mean and why the
  default mode sets one and clears the other.
- **Privilege isolation via a setcap'd helper.** Cathedral
  introduces a dedicated `cathedral-spoof` binary carrying
  `CAP_NET_ADMIN`; the Cathedral app itself stays unprivileged
  and shells out to the helper at launch and exit. First setcap'd
  binary in Cathedral's lineup — the cookbook entry documents the
  install-time `setcap cap_net_admin+ep` step.
- **Per-OS implementation paths.** Linux ioctl
  (`SIOCSIFHWADDR` via `golang.org/x/sys/unix`, no third-party
  deps), macOS shell-out to `ifconfig` plus Wi-Fi re-association
  via `networksetup`, Windows registry edit plus
  `netsh`-driven adapter restart. Why each platform requires a
  different technique.
- **Restore-on-exit state design.** The state file at
  `~/.cache/cathedral/spoof-state.json` captures originals before
  any modification; normal exit restores; a crash leaves state
  behind that next-launch detects and cleans up before applying a
  fresh spoof. The failure-mode reasoning is the engineering
  meat.
- **Vendor-OUI impersonation.** Why it's opt-in. The pentest use
  case (defeat MAC-vendor filters on a target network during an
  authorized engagement) versus the misuse case (defeat
  MAC-vendor filters on infrastructure you don't own — the
  defining unauthorized-access act, not a side effect).
- **The OS-built-in alternative.** Modern Linux NetworkManager
  (`wifi.cloned-mac-address=random`), macOS, and Windows all do
  MAC randomization natively. Cathedral's version exists for the
  boot-sequence visual, the per-launch determinism, and the
  vendor-impersonation opt-in — *not* because the OS feature is
  inadequate.

Sits at the end of the cookbook index because it's the first non-
command entry — future operational-behavior entries will join it
here.

**`Tor + obfs4 daemon with opt-in command routing` — anonymity
sidecar plus per-command Tor routing.** Cathedral launches a
bundled `tor` daemon configured with obfs4 bridges (the pluggable
transport that defeats Tor-blocking), exposes a local SOCKS5
endpoint, and adds `--via-tor` to every command that makes
outbound network calls. The HUD gains a live circuit panel
showing Bridge → Guard → Middle → Exit with country flags. Off
by default; opt-in via `tor.enabled = true` in settings.json.

The cookbook entry will be the longest in the cookbook by a
wide margin — anonymity tools demand careful documentation of
what they do and don't protect. Coverage:

- **Tor protocol primer.** Onion routing, the three-hop default
  circuit (guard / middle / exit), the relay consensus, why
  exit-side traffic is *not* anonymous to the exit operator,
  why "use HTTPS" is non-negotiable when routing through Tor.
- **obfs4 specifically.** Pluggable transports as a concept,
  why obfs4 makes Tor traffic look like random TLS-ish bytes,
  which countries block plain Tor (so users know whether they
  need bridges), bridge-acquisition workflows (BridgeDB, moat,
  Telegram), why Cathedral ships baked-in bridges that go stale
  between releases.
- **The daemon architecture.** Long-running-sidecar pattern,
  bundled `tor` binary (Cathedral's first non-Go bundled
  binary — packaging implications), bundled `obfs4proxy` (Go
  binary built from `gitlab.com/yawning/obfs4`), the
  `github.com/cretz/bine` control-port wrapper, the
  `TorState` ChangeNotifier driving the HUD widget.
- **Per-command Tor routing.** Coverage matrix — which commands
  support `--via-tor`, which can't (and why):
  - **HTTP-based, supported:** `http`, `recon`, `dirscan`,
    `headers`, `cookies`, `waf`, `fav`, `tech`, `crt`. Route
    via `golang.org/x/net/proxy` SOCKS5 dialer on a shared
    transport.
  - **TCP-based, supported:** `whois`, `ssl`, `banner`,
    `scan`. SOCKS5 at the `net.Conn` level.
  - **DNS-based, supported:** `dns`, `asn`, `mx-rep`, `dmarc`,
    `spf`, `dnsbl`, `reverse-dns`. Route via Tor's `DNSPort`.
  - **Cannot route via Tor** (raw sockets / ICMP / local
    network): `ping`, `trace`, `lan-scan`, `wifi`, `netinfo`,
    `conns`, `ports`, `discover`. Flag rejected with a clear
    error.
  - **No-op for `geoip`** — local DB lookup, doesn't make
    network calls, flag silently accepted.
- **The leak-audit discipline.** Every `--via-tor`-supporting
  tool needs verification that nothing escapes via the non-Tor
  interface: no OCSP / CRL probe, no DNS-leak via the system
  resolver, no PMTU-discovery quirks. Cookbook entry will
  describe the test methodology (network namespace + tcpdump
  on the host interface during execution).
- **Misuse note.** Anonymity-bug stakes are real and asymmetric:
  a leak is a user who trusted Cathedral. Tor doesn't authorise
  unauthorised activity — `--via-tor` against infrastructure
  you don't own is still unauthorised. HTTP-over-Tor exits as
  plaintext; exit operators have logged credentials before.
  Authorized-testing banner mandatory when `--via-tor` is set
  on dual-use tools.
- **The HUD panel.** Live circuit-hop visualisation with
  country flags is the Hollywood-hacker moment — circuit
  rotation visible as the relays cycle. The widget is its own
  Flutter project; the data plumbing is bine's control-port
  events.

Sits next to MAC randomization in this category because both
are launch-time behaviors of the Cathedral app itself rather
than user-typed commands; the `--via-tor` flag is a routing
modifier, not a standalone command in its own right.

**`Cathedral messaging` — peer-to-peer onion-service chat.**
Encrypted 1-to-1 messaging between Cathedral users. Each
instance exposes its own Tor v3 onion service; contacts add
each other by sharing 56-character .onion addresses; messages
travel between two onion services with neither party knowing
the other's IP. Built on top of the bundled Tor daemon from
the previous feature — same `tor` binary, same `bine` wrapper.
Settled v1 design: online-only (both parties online to
deliver), 1-to-1 only (no group chat), TOFU identity model
(first-seen .onion is the canonical key), file transfer
included (chunked + resumable + sha256-verified).

The cookbook entry will be the longest in the cookbook by a
wide margin — anonymity messaging tools are held to Signal /
Cwtch / Briar standards, and the documentation burden tracks
that bar. Coverage:

- **The two-layer encryption model.** Tor v3 onion service
  provides client-↔-service transport encryption; Noise IK on
  top adds application-layer end-to-end encryption with
  forward-secrecy ratcheting and identity binding to the
  Ed25519 onion key. Why both layers — a bug in either is
  mitigated by the other.
- **Identity = Ed25519 onion-service key.** The .onion address
  derives from the key; the address is the canonical user ID.
  Friendly handles (`crowned-phoenix.cthd`) are display aids.
  Critical UX: the backup-and-restore flow, because losing
  the key = losing the identity and all message history.
- **The TOFU model and its limits.** First-seen .onion address
  pinned as the canonical key; subsequent connections verify
  the same key; mismatch raises a loud warning. The known
  limitation that v1 cannot detect: first-contact key
  substitution by a network adversary positioned at both
  endpoints' initial handshake. Out-of-band verification is
  the only mitigation; the UI nudges toward it but doesn't
  enforce.
- **The file transfer protocol.** Sender announces (filename
  / size / sha256 / mime); receiver accepts or declines;
  sender streams 64 KB chunks with chunk-index for resume
  after circuit drop; receiver verifies sha256 on completion.
  Default cap 1 GB. Filenames hashed on disk to avoid metadata
  leakage via directory listings.
- **Master-passphrase storage encryption.** Argon2id (interactive
  params) → 32-byte key → AES-256-GCM on the SQLite database
  and each file blob. Cathedral starts locked; messaging panel
  shows *locked* and refuses incoming connections until
  unlock. The threat model this protects against (compromised
  disk image without passphrase) versus what it doesn't (live
  RAM dump, keylogged passphrase).
- **The anti-abuse layer.** Contact requests queue for approval
  rather than auto-accepting; block list drops at the protocol
  layer (initiator can't tell if you're online); per-contact
  rate limiting; no global broadcast or contact-discovery
  directory (out-of-band introductions only).
- **Misuse note — the longest section of any cookbook entry.**
  Stakes shift: a bug in `--via-tor` leaks metadata about a
  recon session; a bug here deanonymises real users with real
  privacy needs. Tor's threat-model limits inherited verbatim:
  no defence against country-level adversaries who can
  correlate flows at both ends. Online-only ⇒ presence
  reveals *that* you're using Cathedral even if not *what*.
  v1 has no deniability primitive — conversations are
  cryptographically attributable to the sender. Forward
  secrecy applies to the wire, not the disk.
- **What Cathedral is now.** This feature crosses the line
  from "recon toolkit with aesthetic" to "recon toolkit plus
  anonymity messaging app". Documentation will be explicit
  about that — the two product categories share a binary but
  serve different use cases, and users should understand
  which they're picking up.

Sits next to MAC randomization and the Tor daemon in this
category because all three are launch-time behaviors of the
Cathedral app itself. Cathedral messaging is also the entry
that most justifies the existence of the Operational
behaviors category — it isn't a command, but it earns its
own deep technique reference.

### New category — Offensive tooling (lower priority)

A separate category for the dual-use tools where the authorized-testing
posture matters more than for the recon / inspection tools. Lands later
because each entry needs careful framing and the entries are longer than
typical.

**`sqli` — SQL injection detector.** Three detection methods together:
error-based (SQL-error fingerprint matching across MySQL/PostgreSQL/MSSQL/
Oracle/SQLite), boolean-based blind (compare `AND 1=1` vs `AND 1=2`
responses), and time-based blind (`SLEEP(3)` / `pg_sleep(3)` / `WAITFOR
DELAY` with response-time measurement). Auto-detect URL query parameters,
test each independently with all three methods. Will share
`tls_fallback`, `--rps`, `--conc`, and the authorized-testing guard rails
from [`dirscan`](dirscan.md).

**`crack` — dictionary cracker (multi-mode).** Unified verb with
subcommands for the dictionary-attack targets that come up in audits and
CTFs:
- `crack shadow <file>` — Unix `/etc/shadow` style files
- `crack hash --hash '$6$salt$…'` — single pasted hash
- `crack zip <archive>` — password-protected archives (ZipCrypto + AES)
- `crack web <url>` — HTML login form (with CSRF scrape, cookie jar,
  proper POST encoding — the seed-snippet's bugs documented in ROADMAP)
- `crack ssh <target>` — SSH password auth (with advertised-auth-method
  pre-check, connection leak fix, IPv6 host:port handling)

Shares wordlist discovery (system locations + tiny fallback), streaming
progress, ETA, per-target progress bar. Pure-Go crypt implementations
preserve the static-binary property; AES-aware zip library
(`yeka/zip`) for modern archives.

**`privscan` — local privilege-escalation enumerator (low priority).**
Linux local-recon in the LinPEAS / linenum lineage: SUID/SGID binaries,
world-writable files in sensitive locations, `$PATH` hijack surface,
file capabilities (`cap_*+ep` binaries often missed in SUID sweeps),
sensitive-file readability (`/etc/shadow`, `/root/.ssh/*`), recently-
modified files in staging directories. Low priority because LinPEAS
exists and is excellent; will land only when there's a specific
Cathedral-shaped reason (native JSON output composable with other
Cathedral tools, Flutter finding-panel integration).

---

## What this cookbook won't include

A short list of things deliberately not coming:

- **Per-tool stubs for unbuilt tools.** Cookbook entries describe
  technique; a placeholder name has no technique. Each shipped tool
  gets its entry when the implementation lands. The sketches above are
  *meta* — they describe what the entry will cover when written, not
  the entry itself.
- **Internal-only utilities.** Build helpers, sidecar shims, test
  scaffolding — Cathedral's machinery, not its technique.
- **Wrapper-tutorials for upstream tools Cathedral launches via the
  shell.** When `tshark` or `bettercap` or `linpeas` already covers a
  category well, Cathedral's only reason to build a sibling is a
  specific Cathedral-shaped advantage (native JSON streaming, UI
  integration). If Cathedral never adds the native version, the
  cookbook doesn't tutorial the upstream tool.
- **Aspirational features outside ROADMAP.md.** Ideas that haven't
  graduated to a ROADMAP entry don't appear here either. ROADMAP.md
  is the staging ground for everything before it reaches this doc.

---

## Out of scope for the cookbook entirely

- **Setup, installation, build, packaging.** That's `README.md`
  territory.
- **Architecture / internals docs.** Design docs for the Flutter
  layer, the Go-sidecar protocol, the streaming event envelope — none
  of these are written, none of them belong in the cookbook when they
  are.
- **The Cathedral application UI itself.** The visual panels (globe,
  visual map, system HUD, finding router) are part of the desktop
  app. The cookbook covers the *tools the app exposes*, not the app's
  presentation.
- **Licensing, pricing, distribution.** Covered on the project's
  external pages.

---

## Reading this list as commitment

This document is a *plan*, not a contract. Items shift; some get
deprioritized; some get cut entirely. The cookbook itself is the source
of truth for what's actually been written; ROADMAP.md is the source of
truth for what's actually been promised at the project level. This
roadmap is the bridge between them — best-current-understanding of where
the cookbook is heading.

Last reviewed: 2026-05-26.
