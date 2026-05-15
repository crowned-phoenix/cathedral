# Cathedral

*by [Crowned Phoenix](https://crowned-phoenix.com) · [YouTube](https://www.youtube.com/@crowned.phoenix)*

![Cathedral's CRT-aesthetic terminal — multi-panel layout with phosphor sparklines, an interactive globe, and a side-panel finding router](screenshot.png)

Cathedral is a desktop terminal for security operators — a single
application bundling a curated set of recon, audit, and forensics
tools behind a CRT-aesthetic interface. Sparklines, an interactive
globe for geolocated results, and a phosphor finding panel mean the
output of each tool reads at a glance instead of requiring you to
parse columns of text.

This repository is the **Cathedral cookbook**: a per-command
technical reference covering what each tool does, how it works,
what it doesn't do, and where it fits in real workflows. The tools
themselves ship with the Cathedral application; their technique
lives here, in writing.

---

## Why a cookbook

Security tools live or die on whether their behaviour is legible.
A black-box port scanner is useless to a careful operator; a port
scanner with documented method is reusable, auditable, and
trustable.

The cookbook does for Cathedral what RFCs do for protocols: state
what the tool is, how it does its job, what tradeoffs shaped the
design, and the limits worth knowing before relying on it. Each
entry includes the algorithmic kernel as Go snippets — enough to
understand the technique, not enough to be a drop-in replacement
for the tool itself.

This is the open part of Cathedral. The binaries are the licensed
product. Same shape as Burp Suite, Cobalt Strike, and most modern
security-tooling vendors — open technique, licensed
implementation.

---

## Where to start

Six entries shipped so far, ordered by the path that builds
understanding fastest:

1. [`netinfo`](netinfo.md) — where am I on the network right now
2. [`ping`](ping.md) — is this host reachable, what shape is the latency
3. [`trace`](trace.md) — what's the path between me and that host
4. [`geoip`](geoip.md) — where in the world is an IP, offline
5. [`scan`](scan.md) — what ports are open on this target
6. [`meta`](meta.md) — what metadata is leaking from this document or image

Each entry follows the same structure: lead paragraph + usage,
*What it does*, *What it answers*, *How it works* (with code
snippets), *Worked example* (real output), *Output protocol* (the
JSONL event stream), *Limitations*, *Authorized use*, *Further
reading*.

---

## Index by category

### Reachability & transport
Probing whether a target is reachable, how the latency behaves,
and what's listening.

- [`ping`](ping.md) — ICMP latency probe with sparkline rendering
- [`trace`](trace.md) — path discovery with geolocation
- [`scan`](scan.md) — TCP port scanner with banner grab

### Discovery
Local network state and what's running where.

- [`netinfo`](netinfo.md) — local network introspection with live sparklines

### Identification
Who owns this IP, where is it, what AS does it belong to. Mostly
offline lookups against bundled databases.

- [`geoip`](geoip.md) — offline IP geolocation

### File & data forensics
Reading what's inside a file — metadata, embedded artifacts,
integrity properties.

- [`meta`](meta.md) — document and image metadata extraction

---

## What's planned

Cathedral ships with more tools than the cookbook currently
documents. Entries are added in rough order of how often the tool
is reached for in real workflows. Categories already half-built:

- **Reachability & transport** — `banner`, `discover`, `ssh-audit`,
  `ports`, `conns`
- **Discovery** — `lan-scan`, `wifi`, `sniff`, `reverse-dns`
- **Identification** — `asn`, `whois`, `dns`, `dnsbl`
- **Web app analysis** — `headers`, `tech`, `waf`, `cookies`, `fav`,
  `http`, `recon`
- **Email & certificates** — `spf`, `dmarc`, `mx-rep`, `ssl`, `crt`,
  `subs`
- **Crypto utilities** — `hash`, `pwned`, `entropy`, `bcrypt`,
  `argon2`, `crypt`, `jwt`
- **File & data forensics** — `stego`, `imgforensic` *(planned)*,
  `browser` *(planned)*

The offensive-tooling section lands later — `crack` (multi-mode
dictionary attack), `sqli` (SQL injection detection), `dirscan`
(path enumeration). Those entries are longer because the
authorized-testing posture matters more and the technique behind
each is denser.

---

## Authorized use

Several Cathedral commands are dual-use — useful to defenders for
self-audit and to operators for authorized testing. Each entry's
*Authorized use* section states the specific posture for that
command. The general expectation: target only what you own or have
written permission to test. Cathedral is not a tool for
circumventing detection or evading consent rules.

---

## The product

Cathedral the application is in pre-launch. The cookbook is the
public technical reference and is being written incrementally.

When Cathedral ships, it will be available as a desktop application
for Linux first, macOS and Windows after. Licensing:

- **Personal License** — one-time purchase, for individuals using
  Cathedral on their own systems, for unpaid learning, for CTF, and
  for personal infrastructure auditing.
- **Commercial License** — annual subscription, for security firms,
  managed service providers, and IT departments using Cathedral in
  paid client engagements or at organisational scale.

Pricing, release dates, and the purchase channel will be announced
on [crowned-phoenix.com](https://crowned-phoenix.com) and the
[Crowned Phoenix YouTube channel](https://www.youtube.com/@crowned.phoenix)
when ready.

---

## Reading the cookbook offline

Every entry is self-contained Markdown — no special renderer
required. Clone the repository and read it in any editor, or browse
on GitHub for rendered tables, syntax-highlighted code, and
auto-linked cross-references between entries.

```
git clone <repo-url>
cd cathedral-cookbook
$EDITOR netinfo.md
```

---

## Versioning

The cookbook is versioned alongside Cathedral itself. Each entry's
frontmatter carries:

- `version-introduced` — the Cathedral release the command first
  shipped in
- `status` — `shipped`, `planned`, or `deprecated`
- `last-updated` — ISO date of the most recent substantive revision

When a command's behaviour changes meaningfully between releases,
the entry is updated and the `last-updated` field bumps. Major
behavioural changes also appear in the [`CHANGELOG`](CHANGELOG.md)
*(planned)*.

---

## Licence

The cookbook itself — every Markdown file in this repository — is
published as open documentation. You may read it, link to it, share
it, and reference its technique freely.

The Cathedral application — the Flutter UI and the Go sidecar
binaries that implement each command — is proprietary software
licensed under terms published at
[crowned-phoenix.com](https://crowned-phoenix.com).
