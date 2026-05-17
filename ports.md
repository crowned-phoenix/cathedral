---
title: ports — local listening sockets and the processes that own them
command: ports
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-05-17
related: [conns, netinfo, scan]
---

# `ports` — local listening sockets and the processes that own them

`ports` enumerates the sockets *this machine* is listening on, in
both TCP and UDP, IPv4 and IPv6. Each row carries the listening
address, the port, and the process that opened it. It's the
defender lens on the local network surface: *what is reachable on
my box, from where, and which program is responsible.*

```
ports                # listening sockets (TCP + UDP, v4 + v6)
ports --all          # also include rows we couldn't attribute to a PID
```

## What it does

For every entry in `/proc/net/tcp`, `/proc/net/tcp6`, `/proc/net/udp`,
and `/proc/net/udp6`, `ports` reports the protocol, listening
address, port, owning PID, command, and user. TCP entries are
filtered to state `LISTEN`; UDP entries are filtered to those with
a zero remote address (server-shaped sockets that accept from
anyone, not outgoing UDP conversations).

| Flag      | Meaning                                                       | Default |
|-----------|---------------------------------------------------------------|---------|
| `--all`   | include sockets without a resolved PID (other users' daemons) | off     |

By default, sockets the kernel reports but Cathedral can't trace
back to a PID (root-owned daemons when running as a non-root user)
are hidden — they're informative as a count but not actionable.
`--all` includes them.

## What it answers

**Defender (most important):** *"What's listening on my machine
that I didn't expect to be listening?"* This is the canonical
machine-hardening question. A box with `:22`, `:80`, `:443` is
unsurprising. A box that *also* has `:6379` (unprotected Redis),
`:9200` (unprotected Elasticsearch), or `:2375` (unauthenticated
Docker socket) has a story worth chasing.

**Operational:** *"Why can't I bind to this port?"* The fastest
answer to *"address already in use"* — `ports | grep 8080` names
the process holding the port.

**Security audit:** *"Is this service bound where I think it is?"*
The address column is the load-bearing security signal. A
service listening on `127.0.0.1:5432` is reachable only from
the local machine. The same service listening on `0.0.0.0:5432`
is reachable from every interface — every WiFi network the
machine joins, every VPN, every container bridge. Same port,
completely different exposure. `ports` makes this visible at a
glance.

**Inventory:** *"What services does this machine actually run?"*
Periodic `ports` snapshots, diffed over time, surface drift —
new services that appeared, old services that vanished, anything
that the documentation hasn't caught up with.

This is not a network-discovery tool. It introspects the kernel
state of the machine it runs on. Same risk posture as `ss -tlnp`
or `netstat -lntup`.

## How it works

### Sibling to `conns`

`ports` and [`conns`](conns.md) share most of their plumbing —
they both parse `/proc/net/tcp{,6}`, both walk `/proc/*/fd/` to
build the inode-to-PID map, both use the same hex-IP parsing
quirk (little-endian byte order; see the
[`conns` cookbook entry](conns.md#the-little-endian-hex-address-trick)
for the byte-swap details). The differences are:

- **`conns`** asks "*who is my machine talking to right now?"*
  — filters to non-LISTEN TCP states (ESTAB, FWAIT, CWAIT, …).
- **`ports`** asks "*what is my machine listening for?"* —
  filters TCP to state `LISTEN` (hex `0A`), and additionally
  enumerates UDP server-shaped sockets.

Treating them as one mental tool with two lenses is the right
framing. Same kernel data, different filters, complementary
outputs.

### TCP: filter to LISTEN

For TCP, the kernel exposes a TCP-state column. `ports` keeps
only rows where state equals `0A` — `LISTEN`:

```go
all = append(all, parseProcNet("/proc/net/tcp",  "tcp",  "0A", false)...)
all = append(all, parseProcNet("/proc/net/tcp6", "tcp6", "0A", false)...)
```

That single state filter is the entire TCP definition of "this
is a listener, not an active conversation."

### UDP: filter to zero remote address

UDP has no connection state. A UDP socket isn't "listening" the
way TCP sockets are — it's just *open* and the kernel routes
matching datagrams to it. But Cathedral can distinguish
server-shaped UDP sockets from outgoing UDP conversations by
looking at the *remote address* field:

- A UDP server (DNS resolver, mDNS responder, syslog listener,
  NTP server) has a zero remote address — it accepts from
  anyone.
- An outgoing UDP socket (a process that just dialed a remote
  service over UDP) has a non-zero remote address — the kernel
  records who it's connected to.

```go
// UDP: only rows with zero remote addr (server sockets, not outgoing).
all = append(all, parseProcNet("/proc/net/udp",  "udp",  "", true)...)
all = append(all, parseProcNet("/proc/net/udp6", "udp6", "", true)...)
```

This is faithful to the UDP model and matches what `ss -lunp`
shows. The downside is that briefly-connected UDP "servers"
(rare; mostly QUIC implementations doing weird things) won't
appear — they look like outgoing sockets while their conversation
is active.

### inode → PID, same as `conns`

The PID attribution mechanism is identical to
[`conns`](conns.md#inode--pid-via-the-proc-fd-table) — walk
`/proc/<pid>/fd/`, parse `socket:[<inode>]` symlink targets,
build an inode-to-PID map, join to the socket table by inode.
Permissions matter: sockets owned by other users (`root`-owned
system daemons when you're not root) come back with no
attribution, and Cathedral hides them by default. Pass `--all`
to include them — the protocol, port, and user become visible
even when the owning PID stays anonymous.

### The address column is the security signal

This is the bit operators consistently underweight. The same
service bound to different addresses has wildly different
exposure:

| Address       | Reachable from                                              |
|---------------|-------------------------------------------------------------|
| `127.0.0.1`   | this machine only — loopback, never on the wire             |
| `0.0.0.0`     | *every* interface — WiFi, VPN, container bridge, everything |
| `192.168.x.y` | only the LAN that interface is on                           |
| `[::]`        | every IPv6 interface (the v6 equivalent of `0.0.0.0`)       |
| `[::1]`       | loopback IPv6 only                                          |

A Postgres bound to `127.0.0.1:5432` is a *good* configuration
— reachable only by local applications. The same Postgres bound
to `0.0.0.0:5432` is reachable from every network the host
touches, which is rarely the intent. `ports` makes this
discoverable in one line per service rather than buried in
config files.

## Worked example

A snapshot from a typical developer workstation. Most of these
rows are expected — `sshd` on `:22`, `cupsd` for printing,
`avahi-daemon` for mDNS, `chronyd` for time sync. Two are
findings.

```
> enumerating local sockets...

  PROTO  ADDRESS                  PORT      PID  USER        PROCESS
  -----  ----------------------   ------  -----  ----------  --------------------
  tcp    0.0.0.0                      22   1234  root        sshd
  tcp    127.0.0.1                  5432   2890  postgres    postgres
  tcp    127.0.0.1                  6379   3012  redis       redis-server
  tcp    0.0.0.0                    2375   1789  root        dockerd
  tcp    0.0.0.0                    3000  56781  operator    node
  tcp6   [::]                        631   1601  root        cupsd
  udp    0.0.0.0                    5353   1442  avahi       avahi-daemon
  udp6   [::]                       5353   1442  avahi       avahi-daemon
  udp    127.0.0.1                   323   1188  chrony      chronyd

9 sockets listed.
```

Reading the rows in order of *exposure*, not appearance:

- **`sshd` on `0.0.0.0:22`** — the expected case. SSH is
  designed for network exposure; the operator wants this
  reachable from the LAN (or from wherever they SSH in).
- **`postgres` on `127.0.0.1:5432`** and **`redis-server` on
  `127.0.0.1:6379`** — *correct* bindings. Both database
  services bound to loopback, reachable only by local apps.
  This is the configuration you want for a developer's local
  databases.
- **`dockerd` on `0.0.0.0:2375`** — **finding**. Port 2375 is
  the unauthenticated Docker API. Anyone who can reach this
  port can spawn containers as root on the host, which is
  effectively *root on the host* (Docker has no isolation
  between the API socket and the kernel). On a developer
  workstation this almost certainly shouldn't be on `0.0.0.0`
  — the Docker daemon's correct binding is the Unix socket
  (`/var/run/docker.sock`, not in this list because it isn't a
  TCP socket) or `127.0.0.1:2375` at most. A `2375` listening on
  `0.0.0.0` is one of the most-scanned remote-takeover surfaces
  on the public internet.
- **`node` on `0.0.0.0:3000`** — also a finding, milder. A
  development server bound to all interfaces is reachable from
  any LAN the laptop joins (coffee shop WiFi, conference WiFi,
  hotel guest network). The fix is binding to `127.0.0.1` or
  setting the framework's host parameter to `localhost` instead
  of the default `0.0.0.0`. Most dev servers default to
  `0.0.0.0`; most users don't notice; most of the time the dev
  server isn't running anything sensitive — but the *posture*
  is wrong.
- **`cupsd` on `[::]:631`** — IPv6 listener. Printing daemon.
  Unremarkable on a desktop; firewall rules typically prevent
  external access even when the socket itself is on `[::]`.
- **`avahi-daemon` on `0.0.0.0:5353` and `[::]:5353`** — mDNS,
  the local-network service discovery protocol. By design talks
  on every interface; not a finding.
- **`chronyd` on `127.0.0.1:323`** — local NTP control socket,
  loopback-only. Good binding.

The address column did the work. Reading the *bindings* told
the security story much faster than reading the service names.

## Output protocol

```
{"event":"start", "total":N}
{"event":"row",   "proto":"tcp|tcp6|udp|udp6","addr":"…","port":N,
                  "pid":N,"comm":"…","user":"…"}*
{"event":"done",  "total":N}
```

`pid` is `0` and `comm` / `user` are empty when the inode-to-PID
lookup failed (only visible with `--all`).

Filter to publicly-exposed bindings only — the *important*
column:

```
$ ports -j | jq -r 'select(.event=="row" and (.addr=="0.0.0.0" or .addr=="[::]"))
                  | "\(.proto)\t\(.port)\t\(.comm)"'
```

Find services on non-loopback addresses with potentially
sensitive ports:

```
$ ports -j | jq -r '
    select(.event=="row" and (.addr | startswith("127.") | not) and (.addr != "[::1]"))
    | select(.port == 2375 or .port == 5432 or .port == 6379 or .port == 9200 or .port == 27017)
    | "[exposed]  \(.proto)/\(.port)  \(.comm)  \(.addr)"'
[exposed]  tcp/2375  dockerd  0.0.0.0
```

Snapshot for diffing:

```
$ ports -j | jq -r 'select(.event=="row") |
                    [.proto, .addr, .port, .comm] | @tsv' |
    sort > /tmp/ports-today.tsv
```

## Limitations

- **Linux-only.** `/proc/net/{tcp,udp}` is Linux-specific. macOS
  and BSD have similar data via `lsof -i -P -n` / `netstat -anv`
  but the implementation backend would be different. Cathedral
  v1 doesn't have those.
- **TCP and UDP only.** Unix domain sockets (`/proc/net/unix`),
  raw sockets, netlink — none are surfaced. The Docker daemon's
  *intended* socket (`/var/run/docker.sock`) is a Unix socket
  and won't appear in `ports`. That's a separate concern.
- **PID attribution requires permission.** Sockets owned by
  processes outside your UID don't get attributed unless you
  run with `sudo` or `CAP_SYS_PTRACE`. The `--all` flag still
  shows the socket — protocol, address, port — but the PID
  column reads `-` and you'll have to inspect by other means.
- **UDP "server" detection is heuristic.** Cathedral identifies
  server-shaped UDP sockets by their zero remote address. A
  process that briefly opens a UDP socket without connecting it
  may show up; a UDP-based protocol that connects briefly and
  reuses the same socket may not show up while it's connected.
  For all practical services this works correctly.
- **Snapshot only.** One read of `/proc/net/tcp` is one moment
  in time. A service that crashes and respawns between reads
  may appear missing for one snapshot and present in the next.
- **No bandwidth, connection counts, or rate-limiting visibility.**
  `ports` tells you a service is listening; it doesn't tell you
  how many clients are connected to it, how much traffic it's
  serving, or how busy the port is. For that, see
  [`conns`](conns.md) for current connections, and
  [`netinfo`](netinfo.md)'s sparklines for per-interface
  aggregate.
- **`comm` is the kernel-truncated short name.** 15 characters
  max (Linux's `TASK_COMM_LEN`). Full process titles need
  `cat /proc/<pid>/cmdline` separately.

## Authorized use

`ports` reads four kernel files and walks `/proc/<pid>/fd/` for
processes you own. No network traffic of any kind. The risk
profile is the same as `ss`, `netstat`, or `lsof` — pure local
introspection. No authorized-use posture applies.

One thing worth flagging: the *output* of `ports` is a map of
your machine's exposed surface. That's exactly the document an
attacker would want to read to plan a local takeover. On a
shared system, or in a screenshot you're about to paste somewhere
public, treat the output the way you'd treat your shell history
— scrub sensitive bindings before sharing.

## Further reading

- [`/proc/net/tcp` format](https://www.kernel.org/doc/Documentation/networking/proc_net_tcp.txt) — the kernel reference
- [RFC 9293 §3.3.2 — TCP LISTEN state](https://www.rfc-editor.org/rfc/rfc9293#section-3.3.2) — what `LISTEN` actually means in the state machine
- [Docker docs: protect the Docker daemon socket](https://docs.docker.com/engine/security/protect-access/) — context for the `:2375` finding
- Related Cathedral commands: [`conns`](conns.md) (the active-connection lens — same plumbing, different filter),
  [`netinfo`](netinfo.md) (the umbrella picture: interfaces, gateway, traffic shape),
  [`scan`](scan.md) (the outbound counterpart — probe what *another* host is listening on)
