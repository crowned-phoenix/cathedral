---
title: doctor — preflight diagnostics for capabilities, backends, and uplink
command: doctor
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-06-23
related: [netinfo, sniff, wifi]
---

# `doctor` — preflight diagnostics for capabilities, backends, and uplink

`doctor` audits what the current machine can actually do. It checks
your privilege level, the Linux capabilities granted to Cathedral's
tools, the wireless hardware present, which scan backends are
available, and whether there's a network uplink — and for every gap
it finds, it prints the exact command that fixes it.

It runs automatically as Cathedral's **boot sequence**, so the first
thing you see on launch is an honest report of what works on this
machine. You can also run it any time:

```
doctor
```

No flags. Every line of output is a real check against the live
system — nothing here is cosmetic.

## What it does

For each area, `doctor` emits a `check` with a status of `ok`,
`warn`, `degraded`, or `missing`, a short detail, and — where
relevant — a one-line `fix`:

- **privilege level** — are you running as a normal operator, or as
  root? Root works, but Cathedral's posture is per-binary
  capabilities, not whole-app elevation, so root earns a `warn`.
- **bundled sidecars** — how many tool binaries shipped alongside
  Cathedral and are present on disk.
- **external tools** — which of `iw` / `ip` / `nmcli` / `tcpdump`
  are in `PATH` (the binaries some commands shell out to).
- **wireless adapter** — is there a wireless interface in
  `/proc/net/wireless` to scan at all.
- **wifi scan** — which backend [`wifi`](wifi.md) will use: `iw`
  with `CAP_NET_ADMIN` (precise dBm), or `nmcli` (coarse
  percentage). Tells you which you'll get *before* you scan.
- **packet capture** — does [`sniff`](sniff.md) carry `CAP_NET_RAW`,
  read straight from the binary's capability metadata.
- **network uplink** — is there a default route, so the online tools
  ([`dns`](dns.md), [`whois`](whois.md), [`geoip`](geoip.md),
  `identify`) can reach the world. This check is
  **passive** — it reads kernel routing state and sends no packets.

## What it answers

- *"Will the command I'm about to run actually work on this box?"*
  Instead of discovering a missing capability when `sniff` fails
  three commands into a session, you see it at boot with the fix
  attached.
- *"What do I need to set up on a fresh install?"* `doctor` is the
  setup checklist — every `degraded` / `missing` line is a to-do
  with the command already written.
- *"Which wifi backend am I on?"* The difference between precise dBm
  and a coarse percentage is decided by whether `iw` has its
  capability; `doctor` reports the answer directly.

## How it works

### Reading capabilities without `getcap`

The interesting part is how `doctor` knows whether `sniff` or `iw`
carries a capability. It does **not** shell out to `getcap` (from
`libcap2-bin`, which may not be installed). Linux stores file
capabilities in an extended attribute named `security.capability`,
and Cathedral reads and decodes it directly — pure Go, no external
helper, static binary preserved:

```go
// Capabilities live in the file's security.capability xattr.
buf := make([]byte, 64)
sz, err := syscall.Getxattr(path, "security.capability", buf)
if err != nil || sz < 8 {
    return // no capabilities set on this binary
}
magic := binary.LittleEndian.Uint32(buf[0:4])
effective := magic&1 != 0                          // the "+e" flag
permitted := binary.LittleEndian.Uint32(buf[4:8])  // low 32 cap bits
hasNetRaw := permitted&(1<<13) != 0                // CAP_NET_RAW = bit 13
```

`CAP_NET_RAW` is bit 13, `CAP_NET_ADMIN` is bit 12 — both live in
the low 32-bit word, so a single `uint32` read covers every
capability Cathedral cares about. The `effective` flag matters too:
a capability that is *permitted* but not *effective* won't activate
on exec, which is why Cathedral's fix hints always use the `+ep`
form (`setcap cap_net_raw+ep …`). If the bit is present but the
effective flag is clear, `doctor` says so specifically.

### The status taxonomy

| Status     | Meaning                                            | Rendered |
|------------|----------------------------------------------------|----------|
| `ok`       | works as intended                                  | `[ ok ]` |
| `warn`     | works, but worth knowing (e.g. running as root)    | `[ warn ]` |
| `degraded` | partially works / works in a lesser mode           | `[ degraded ]` |
| `missing`  | not available                                      | `[ --- ]` |

`degraded` is the load-bearing one: `wifi` on `nmcli` instead of
`iw` is *degraded*, not broken — you still get a scan, just in
percentages rather than dBm. The fix hint upgrades you; it doesn't
unblock you.

### Capabilities, not whole-app root

`doctor`'s checks mirror Cathedral's privilege model: elevated
abilities live in the specific binaries that need them, granted with
`setcap`, never by running the whole app as root. So the capture
check reads `sniff`'s caps, the wifi check reads `iw`'s caps, and
running as root is flagged as a `warn` — it works, but it's the
blunt instrument the per-binary model exists to avoid.

### Passive by construction

The uplink check reads `/proc/net/route` and looks for a default
(`0.0.0.0`) entry. It does not resolve a name, ping a host, or open
a socket — booting Cathedral sends nothing onto the network. A
machine with no uplink boots silently into a fully-offline posture,
and `doctor` simply notes that the online tools are unavailable.

## Worked example

A fresh install on a laptop where the capabilities haven't been
granted yet. Paths and uid are illustrative:

```
operator@cathedral:~$ doctor
> running preflight diagnostics...

  privilege level........... [ ok ]        operator (uid 1000)
  bundled sidecars.......... [ ok ]        49 tools armed
  external tools............ [ ok ]        present: iw ip nmcli  ·  absent: tcpdump
  wireless adapter.......... [ ok ]        wlan0
  wifi scan................. [ degraded ]  iw present but lacks CAP_NET_ADMIN
       ↳ sudo setcap cap_net_admin+eip /usr/sbin/iw
  packet capture............ [ degraded ]  sniff lacks CAP_NET_RAW
       ↳ sudo setcap cap_net_raw+ep /opt/cathedral/data/flutter_assets/assets/bin/sniff
  network uplink............ [ ok ]        default route present

preflight complete — 4 ok, 2 degraded, 0 missing
```

Reading this, the operator knows immediately: `wifi` will work but
only in percentage mode, and `sniff` won't capture at all — and the
two `setcap` lines are the entire fix. Run them once, relaunch, and
the same boot reports `6 ok`.

A second example — the same machine after the fixes, but unplugged
from the network:

```
  network uplink............ [ degraded ]  no default route — online tools (dns/whois/geoip) unavailable
```

Nothing is broken; Cathedral is simply operating offline, and the
report says so plainly rather than letting `dns` fail later with a
confusing timeout.

## Output protocol

Line-oriented JSON.

```
{"event":"start"}
{"event":"check","area":"…","label":"…","status":"ok|warn|degraded|missing",
                 "detail":"…","fix":"…"}*
{"event":"done","ok":N,"degraded":N,"missing":N}
```

The `fix` field is present only on checks that have an actionable
remedy. `ok` in the `done` summary counts `warn` as passing (root is
a caveat, not a failure). Pipe-friendly — list only what needs
attention:

```
$ doctor | jq -r 'select(.event=="check" and .status!="ok" and .status!="warn")
                  | "\(.label): \(.detail)\n  fix: \(.fix // "—")"'
```

## Limitations

- **Linux-specific.** The capability and routing checks read
  `security.capability` xattrs, `/proc/net/wireless`, and
  `/proc/net/route` — all Linux interfaces. On other platforms the
  relevant checks degrade rather than mislead.
- **Checks prerequisites, not execution.** `doctor` verifies that
  the conditions for a command exist (a capability is granted, a
  backend is present); it does not actually run each tool. A driver
  that advertises a capability but misbehaves is beyond its reach.
- **Capability reads need a readable xattr.** On exotic filesystems
  that don't support extended attributes, or where the binary's
  xattr can't be read, a granted capability may read as absent. The
  fix hint is still correct; it just can't confirm the grant.
- **Not a security audit.** `doctor` reports what's *enabled*, not
  whether it *should* be. Granting `CAP_NET_RAW` is the operator's
  decision; `doctor` only tells you whether it's been made.

## Authorized use

`doctor` is **purely local introspection**. It reads your own
machine's privilege state, file metadata, and kernel routing table,
and sends nothing onto the network. There is no target, no probe,
no traffic — the risk profile is that of `id` or `getcap`. The one
thing worth noting: the output enumerates which capabilities are
granted on the system, which is useful reconnaissance to anyone
*else* on a shared host. Treat it like any other local-config
listing — informative, not secret, but not worth pasting publicly
with full paths intact.

## Further reading

- [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  — the Linux capability model `doctor` reads. `CAP_NET_RAW` and
  `CAP_NET_ADMIN` are the two it cares about.
- [setcap(8)](https://man7.org/linux/man-pages/man8/setcap.8.html)
  — the tool behind every fix hint. Understanding `+ep` vs `+eip`
  is worth a minute before granting capabilities.
- Related Cathedral commands: [`sniff`](sniff.md) (whose capture
  capability `doctor` verifies), [`wifi`](wifi.md) (whose backend
  `doctor` reports), [`netinfo`](netinfo.md) (the local-network
  view that complements this local-capability view).
