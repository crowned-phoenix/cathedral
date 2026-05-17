---
title: conns — active TCP connections with owning process
command: conns
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-05-17
related: [netinfo, ports, scan]
---

# `conns` — active TCP connections with owning process

`conns` enumerates the TCP connections your machine has open right
now, joining each socket to the process that opened it. The
question it answers is: *who is this box talking to, and via what
program?* By default it hides LISTEN sockets (that's
[`ports`](ports.md)) and TIME_WAIT sockets (noise from recently
closed conversations) so what you see is live conversations only.

```
conns                # active conversations
conns --all          # include LISTEN and TIME_WAIT too
conns --twait        # only TIME_WAIT
```

## What it does

For every entry in `/proc/net/tcp` and `/proc/net/tcp6`, `conns`
reports the connection's protocol, local and remote endpoints,
TCP state, owning PID, command name, and the user running it.
Output is sorted by state, then by command, then by remote port —
so groups of related connections (a browser's parallel TLS sessions
to a CDN, an SSH session's forwarded ports) cluster together.

| Flag        | Meaning                                       | Default |
|-------------|-----------------------------------------------|---------|
| `--all`     | also show LISTEN and TIME_WAIT sockets        | off     |
| `--twait`   | show only TIME_WAIT sockets                   | off     |

By default `conns` also hides rows where the kernel has the socket
but no `/proc/*/fd/socket:[…]` symlink links back to a PID — those
are orphan sockets and sockets owned by processes you don't have
permission to inspect. `--all` includes those too.

## What it answers

**Defender / security:** *"Who is my machine talking to?"* A scan
of the live connection list against unexpected destinations is the
fastest "is there something I don't recognise here" check. Egress
to an unknown IP range from a process you didn't start is a real
finding. The PID + command name together are the most useful
attribution; the remote IP alone is rarely enough.

**Operational:** *"Why is this process using bandwidth?"* When a
sluggish system traces back to "something is talking to the network
a lot", `conns` matches the connections to the owning process in
one read. The remote ports tell you *what protocol* (`:443` is
HTTPS, `:993` is IMAPS, `:5432` is Postgres, `:8009` is Google
Cast) without further investigation.

**Troubleshooting:** *"Why is this connection stuck?"* A socket
sitting in `CWAIT` (CLOSE_WAIT) means the remote closed and the
local application hasn't acknowledged the close — classic socket-
leak symptom. `FWAIT2` lingering past a few seconds means the
remote isn't sending its FIN. `conns` surfaces TCP states directly
so half-closed conversations are visible.

**Forensic:** *"Which process opened this connection?"* If you've
noticed an unexpected TCP session in a packet capture or a router
log, `conns` is the local complement: which PID and which user
created the socket, where it lives in `/proc`, and what command
spawned it.

This is not a network-discovery tool. It looks at the kernel state
of the machine it runs on, no probes, no queries to anyone. Same
risk posture as `ss -tnp` or `lsof -i`.

## How it works

### Reading `/proc/net/tcp` directly

Linux exposes every kernel-tracked TCP socket as a line in two
text files:

- `/proc/net/tcp`  — IPv4
- `/proc/net/tcp6` — IPv6

A representative row looks like:

```
sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid timeout inode
 1: 0100007F:1F90 0100007F:E5F0 01 00000000:00000000 00:00000000 00000000  1000        0 5421912 …
```

Cathedral parses these directly rather than calling `ss` or
`netstat`. No external dependencies; one read of two files gives
the full picture.

### The little-endian hex address trick

The `local_address` and `rem_address` fields are **hex-encoded
with each 32-bit word in little-endian byte order** — a kernel
implementation detail that catches everyone the first time they
parse this file. `0100007F:1F90` looks like a public IP at first
glance; it's actually:

- `0100007F` → bytes `01 00 00 7F` → swap → `7F 00 00 01` → `127.0.0.1`
- `1F90` → port `0x1F90` → `8080`

So the row is a loopback connection to `127.0.0.1:8080`. Cathedral
handles the byte-swap:

```go
func parseHexIP(s string) net.IP {
    b, _ := hex.DecodeString(s)
    switch len(b) {
    case 4:  // IPv4: simple byte reversal
        return net.IPv4(b[3], b[2], b[1], b[0])
    case 16: // IPv6: per-word reversal (four 32-bit words)
        out := make(net.IP, 16)
        for i := 0; i < 16; i += 4 {
            out[i]   = b[i+3]
            out[i+1] = b[i+2]
            out[i+2] = b[i+1]
            out[i+3] = b[i]
        }
        return out
    }
    return nil
}
```

### Inode → PID via the /proc fd table

`/proc/net/tcp` carries an `inode` column but no PID — the kernel
tracks sockets, not the processes that own them. The PID mapping
lives in `/proc/<pid>/fd/`, where each open file descriptor is a
symlink. Socket fds point to a virtual target of the form
`socket:[<inode>]`:

```
$ ls -l /proc/1234/fd/
lrwx------ 1 user user 64 May 17 10:00 0 -> /dev/pts/3
lrwx------ 1 user user 64 May 17 10:00 7 -> socket:[5421912]
```

Cathedral walks every `/proc/<numeric>/fd/*` symlink, parses the
inode out of the socket-symlink target, and builds a map of
`inode → (pid, comm, uid)`. Per-process metadata comes from:

- `/proc/<pid>/comm` — the command name
- `/proc/<pid>/status` — the `Uid:` line gives the owning UID
- `user.LookupId(uid)` — resolves UID to username

This is the same mechanism `ss -p`, `lsof -i`, and `netstat -p`
use. Cathedral does it in-process so the result joins cleanly to
the socket table without parsing another command's output.

### TCP states

`/proc/net/tcp` reports states as hex codes; Cathedral
human-labels them:

| Hex | Label    | Meaning                                            |
|-----|----------|----------------------------------------------------|
| 01  | ESTAB    | established — the data-moving state                |
| 02  | SYN-S    | sent SYN, waiting for SYN-ACK                      |
| 03  | SYN-R    | received SYN, sent SYN-ACK, waiting for final ACK  |
| 04  | FWAIT1   | local sent FIN, waiting for remote's FIN-ACK       |
| 05  | FWAIT2   | local FIN ACKed, waiting for remote's FIN          |
| 06  | TWAIT    | TIME_WAIT — recently closed, kernel holds slot     |
| 07  | CLOSE    | closed (rare in /proc/net/tcp; usually transient)  |
| 08  | CWAIT    | CLOSE_WAIT — remote closed, local hasn't yet       |
| 09  | LACK     | LAST_ACK — waiting for final FIN ACK               |
| 0A  | LISTEN   | accepting connections (hidden by default)          |
| 0B  | CLOSING  | both sides sent FIN, waiting for the final ACK     |

Hidden by default: `LISTEN` (belongs in [`ports`](ports.md), the
defender lens) and `TWAIT` (almost always noise from successful
close handshakes). `--all` includes both; `--twait` shows just
TWAIT for "why is this port stuck in TIME_WAIT" investigations.

### Why hide unattributable rows

A socket can appear in `/proc/net/tcp` without a matching
`socket:[…]` symlink in any process's fd table — the process may
have exited mid-read, or it may be a process the user lacks
permission to inspect (root-owned services when running as a
non-root user). By default Cathedral hides these rows because
they're not actionable — you can't trace them back to a program.
`--all` shows them anyway.

## Worked example

A snapshot from a typical workstation. Real connections, sanitised
local user and IP:

```
> enumerating active connections...

  PROTO  STATE    LOCAL                   REMOTE                   PORT    PID  USER        PROCESS
  -----  -------  ----------------------  ----------------------  -----  -----  ----------  --------------------
  tcp    CWAIT    192.168.1.176           185.125.188.36            443   8168  operator    snap-store
  tcp    ESTAB    192.168.1.176           3.173.21.63               443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           104.16.103.112            443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           104.16.102.112            443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           140.82.113.26             443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           151.101.246.73            443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           157.240.205.60            443  120407  operator    brave
  tcp    ESTAB    192.168.1.176           192.168.1.13             8009  120407  operator    brave

8 active connections.
```

Five real findings in this snapshot:

- **`snap-store` in `CWAIT`.** The remote Canonical server has
  closed the connection; snap-store hasn't called `close()` on its
  end yet. A lingering CLOSE_WAIT past a few seconds is the
  classic socket-leak signal — usually means the app forgot to
  close the socket after the protocol completed. One CWAIT entry
  is unremarkable; dozens accumulating over time is a finding.
- **Brave with multiple parallel ESTAB sessions to `104.16.x.x`
  and similar.** That's Cloudflare's IP range (`104.16.0.0/12`).
  Modern browsers maintain parallel HTTPS connections per origin
  for HTTP/2 multiplexing and for fetching subresources from CDNs;
  six ESTAB rows to similar IPs is normal browsing.
- **`brave → 192.168.1.13:8009`.** That's a *LAN* address on port
  8009 — Google Cast / Chromecast protocol. The browser is talking
  to a Cast device on the local subnet without leaving the home
  network. The cross-reference back to [`lan-scan`](lan-scan.md)
  is useful: the 192.168.1.13 endpoint would appear there as a
  device with a Google OUI.

The whole list takes about a glance to read. That's the value —
`conns` makes "what is happening on the network side of this
machine right now" a one-second answer.

## Output protocol

```
{"event":"start", "total":N}
{"event":"row",   "proto":"tcp|tcp6","local":"…","lport":N,
                  "remote":"…","rport":N,"state":"…",
                  "pid":N,"comm":"…","user":"…"}*
{"event":"done",  "total":N}
```

`pid` is `0` and `comm` / `user` are empty when the inode-to-PID
lookup failed (only visible with `--all`).

Group by remote IP to see "where is most of my traffic going":

```
$ conns -j | jq -r 'select(.event=="row") | .remote' |
    sort | uniq -c | sort -rn | head
     11 104.16.103.112
      4 160.79.104.10
      3 127.0.0.1
      2 3.173.21.63
```

Filter to non-localhost outbound only:

```
$ conns -j | jq -r 'select(.event=="row" and (.remote | startswith("127.") | not)) |
                    "\(.comm)\t\(.remote):\(.rport)"' |
    sort -u
```

Find lingering CLOSE_WAIT (potential socket leaks):

```
$ conns -j | jq -r 'select(.event=="row" and .state=="CWAIT") |
                    "\(.pid)\t\(.comm)\t\(.remote):\(.rport)"'
```

## Limitations

- **Linux-only.** The implementation reads `/proc/net/tcp` and
  walks `/proc/*/fd`, both Linux-specific. macOS exposes similar
  data via `lsof` / `netstat`; Cathedral v1 doesn't have a
  cross-platform backend.
- **TCP only.** UDP sockets (`/proc/net/udp`), Unix sockets
  (`/proc/net/unix`), raw sockets, and netlink sockets are not
  enumerated. The `ports` cookbook entry will cover UDP listeners
  separately when it lands.
- **Snapshot only.** `conns` is one-shot — it shows what's open at
  the moment of the call. Connections that opened and closed
  during the read are missed. For continuous monitoring, run
  inside a `watch -n 1 conns` loop, or pipe through `tail -f`
  against a log.
- **PID attribution requires permission.** Sockets owned by
  processes outside your UID will show up without a PID unless
  you run as root (or with `CAP_SYS_PTRACE`). The kernel reads
  the socket table fine; reading `/proc/<other-pid>/fd/` requires
  matching ownership.
- **No bandwidth or packet counters.** `conns` reports state and
  endpoints, not bytes or rates. Per-connection traffic
  accounting needs a different mechanism (eBPF, conntrack, or
  packet capture). The [`netinfo`](netinfo.md) sparklines give
  per-interface aggregate rates as a coarser proxy.
- **`comm` is truncated to 15 characters.** That's the kernel's
  `TASK_COMM_LEN` limit — `comm` is the *short* command name, not
  the full process title. `node`, `python3`, `gunicorn` all show
  up as their basename; for full process names use
  `cat /proc/<pid>/cmdline` separately.
- **Sort key is stable but not bandwidth-aware.** Output is sorted
  by state → command → remote port for readable groupings. There's
  no `--sort=bandwidth` because Cathedral doesn't measure it.

## Authorized use

`conns` reads two kernel files (`/proc/net/tcp`, `/proc/net/tcp6`)
and walks `/proc/<pid>/fd/` for processes you own. No network is
touched. No packets are sent. The risk profile is the same as
`netstat`, `ss`, or opening Task Manager's "Network" tab.

One privacy property worth flagging: the output is a *map of every
remote endpoint your machine is currently talking to*. That's
sensitive even for ordinary use — IP addresses can resolve to
specific services (your bank, your therapist's portal, your
employer's VPN concentrator). Treat `conns` output the way you'd
treat browser history. Don't paste it into public bug reports or
forum posts without scrubbing the remote-IP column.

For inspection of someone else's machine, the same posture
applies as for any local-introspection tool: only do it on systems
you own or have explicit authorisation for. `conns` itself doesn't
help you compromise anything — it shows kernel state that's already
yours to read — but the *insights* it generates can be sensitive.

## Further reading

- [`/proc/net/tcp` format](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt) — the kernel reference
- [RFC 9293 §3.3.2 — TCP states](https://www.rfc-editor.org/rfc/rfc9293#section-3.3.2) — the state machine `conns` decodes
- [Stack Overflow on `socket:[N]` symlinks](https://unix.stackexchange.com/questions/16300/whose-socket-is-this-and-how-do-i-find-out) — the inode-to-PID mapping technique
- Related Cathedral commands: [`netinfo`](netinfo.md) (the umbrella picture — interfaces, gateway, traffic shape),
  [`ports`](ports.md) (the defender lens — what is *this machine* listening on),
  [`scan`](scan.md) (the outbound lens — what is *that machine* listening on)
