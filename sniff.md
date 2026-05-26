---
title: sniff — passive packet capture with proto/host/port filter
command: sniff
category: discovery
status: shipped
version-introduced: 1.0
authorized-use: medium
last-updated: 2026-05-26
related: [netinfo, lan-scan, discover, conns, ports, wifi]
---

# `sniff` — passive packet capture with proto/host/port filter

`sniff` captures live packets from a network interface and prints a
one-line summary per frame: timestamp, protocol, source-IP(:port),
destination-IP(:port), length, and (where decoded) a per-protocol
info field — TCP flags, ICMP type names, ARP request/reply. Stops
after a configurable packet count or wall-clock duration, whichever
comes first, then emits a summary of seen / filtered-out /
unparsed-frame counts.

Unlike `tshark` and `tcpdump`, Cathedral's sniff is **pure-Go and
static-binary friendly**. It binds an `AF_PACKET` raw socket
directly via Linux syscalls rather than going through libpcap, so
no CGO, no shared-library dependency, no Npcap-on-Windows or
libpcap-on-macOS install ceremony. The trade-off is that it's
**Linux-only**: `AF_PACKET` is a Linux-specific socket family.

```
sniff                              # default: 50 packets or 30s on primary iface
sniff --iface=eth0
sniff --count=200 --duration=60
sniff --filter="proto=tcp"
sniff --filter="port=443"
sniff --filter="host=192.168.1.1"
sniff --filter="proto=tcp,port=443"
```

## What it does

For one invocation:

1. **Pick the interface.** If `--iface=NAME` is supplied, use that
   exact interface. Otherwise scan `net.Interfaces()` for the first
   non-loopback, `FlagUp`, address-having interface — that's
   Cathedral's "primary."
2. **Open a raw `AF_PACKET` socket** bound to that interface,
   protocol `ETH_P_ALL` (catches every Ethernet frame regardless of
   ethertype). 1-second `SO_RCVTIMEO` so the main loop can check
   the stop deadlines.
3. **Loop, parse, filter, emit.** For each frame read:
   - Parse Ethernet header → dispatch on EtherType:
     - `0x0800` IPv4 → parse IP header, dispatch on next-protocol
     - `0x86DD` IPv6 → parse fixed header, dispatch on next-protocol
     - `0x0806` ARP → extract sender/target IPs + request/reply opcode
   - Apply the filter (proto / host / port). Drops increment the
     `filtered` counter.
   - Emit a `packet` event with the parsed fields.
4. **Stop** when either `count` packets have been emitted or
   `duration` seconds have elapsed (whichever first).
5. **Emit `done`** with three counters: `captured` (matched +
   shown), `filtered` (matched no filter), `unparsed` (frame had
   no recognised ethertype / IP header / TCP/UDP/ICMP payload).

| Flag                  | Meaning                                          | Default       |
|-----------------------|--------------------------------------------------|---------------|
| `--iface=NAME`        | Interface to capture on                          | first non-loopback `UP` |
| `--count=N`           | Stop after N matched packets                     | 50            |
| `--duration=SEC`      | Stop after SEC seconds                           | 30            |
| `--filter=EXPR`       | Comma-separated key=value pairs (see below)      | (no filter)    |

### Filter syntax

Cathedral's filter is a tiny subset, **not BPF**. It accepts three
keys:

| Key       | Example         | Meaning                                          |
|-----------|-----------------|--------------------------------------------------|
| `proto`   | `proto=tcp`     | Match only this protocol (`tcp`/`udp`/`icmp`/`icmp6`/`arp`) |
| `port`    | `port=443`      | Match if source OR destination port is this     |
| `host`    | `host=10.0.0.5` | Match if source OR destination IP is this        |

Combine with commas: `proto=tcp,port=443,host=8.8.8.8` filters to
TCP packets to/from 8.8.8.8 with 443 on either side. All conditions
AND; no OR, no negation, no CIDR ranges, no wildcards.

For full BPF expressions (CIDR ranges, time-based filtering,
arbitrary header byte comparisons), drop to `tcpdump` directly.

## What it answers

- What's on the wire on this interface right now?
- Is this host actually sending traffic to that destination?
- Are these ARP/ICMP/UDP exchanges happening at the rate I
  expected?
- Did this connection do a clean SYN→SYN/ACK→ACK handshake, or
  did the server RST?

## How it works

### The `AF_PACKET` raw-socket shortcut

`tcpdump`-class tools traditionally use libpcap, which provides a
cross-platform abstraction layer over per-OS packet-capture APIs
(`AF_PACKET` on Linux, BPF on BSD/macOS, Npcap on Windows). The
abstraction costs a libpcap dependency — for Cathedral, that
would mean either bundling libpcap (CGO, breaks the static-binary
property) or skipping the feature entirely.

The Cathedral shortcut: `AF_PACKET` is reachable directly via
`syscall.Socket(AF_PACKET, SOCK_RAW, ETH_P_ALL)`. Pure Go, no
CGO, no third-party deps. The trade-off is **Linux-only** — the
syscall doesn't exist on macOS / BSD / Windows. For the
cross-platform case, libpcap would still be the right answer;
for a Linux-shipped operator tool, the raw syscall is a clean
win.

```go
fd, err := syscall.Socket(
    syscall.AF_PACKET, syscall.SOCK_RAW,
    int(htons(syscall.ETH_P_ALL)),
)

sll := &syscall.SockaddrLinklayer{
    Protocol: htons(syscall.ETH_P_ALL),
    Ifindex:  ifi.Index,
}
syscall.Bind(fd, sll)
```

`ETH_P_ALL` selects every Ethernet frame the interface sees,
regardless of layer-3 protocol. Note the `htons()` byte-swap:
the protocol field in the bind sockaddr is network-byte-order
even though we're passing a host-byte-order int as the socket
argument — one of the quirky bits of the `AF_PACKET` interface.

### The `CAP_NET_RAW` capability

Raw sockets are privileged. Two options:

- **Run as root** — works but is overkill. The Cathedral binary
  doesn't need any other root privilege; using `sudo sniff` would
  also start Cathedral's *other* commands as root if they
  shared a process, which they don't, but the principle stands.
- **Grant `CAP_NET_RAW` to the binary only** — the modern
  capability model. Once set, the binary can open `AF_PACKET`
  sockets without being root.

```
sudo setcap cap_net_raw+ep /path/to/sniff
```

`+ep` means "effective + permitted." Effective = the capability
is active by default when the process runs; permitted = the
process is allowed to claim it. The third optional flag,
inheritable (`+i`), is only needed if the binary spawns child
processes that also need the capability — sniff doesn't, so `+ep`
is the right minimum.

**Cathedral resolves the binary's installed path automatically.**
On first run without the capability, the error message contains
the exact `setcap` command for your install — whether dev tree,
user install, or system-wide:

```
operator@cathedral:~$ sniff
error: permission denied. Grant CAP_NET_RAW to enable packet capture:
       sudo setcap cap_net_raw+ep /opt/cathedral/data/flutter_assets/assets/bin/sniff
```

Copy-paste, sudo once, sniff works thereafter.

### Frame parsing pipeline

Each frame goes through a small chain of length checks and field
extractions. Anything that fails a check returns `nil` and falls
through to the "unparsed" counter:

```go
// Ethernet (always 14 B): destMAC(6) | srcMAC(6) | ethType(2)
if len(frame) < 14 { return nil }
etherType := binary.BigEndian.Uint16(frame[12:14])

switch etherType {
case 0x0800: // IPv4
    ip := frame[14:]
    ihl := int(ip[0]&0x0F) * 4   // header length in bytes
    srcIP = net.IPv4(ip[12:16]...)
    dstIP = net.IPv4(ip[16:20]...)
    nextProto = ip[9]
    payload = ip[ihl:]            // skip variable-length IHL

case 0x86DD: // IPv6
    ip := frame[14:]
    srcIP = net.IP(ip[8:24])     // fixed 16-byte src
    dstIP = net.IP(ip[24:40])
    nextProto = ip[6]            // Next-Header field
    payload = ip[40:]            // IPv6 header is fixed-length

case 0x0806: // ARP — different shape, return directly
    // sender IP at offset 14, target IP at offset 24
}
```

The IPv4 `ihl` field is the header length in 32-bit words; multiply
by 4 to get bytes. The default is 5 (= 20-byte header) but options
push it higher, which is why we read `ihl` rather than assume 20.

IPv6's "Next Header" is named differently from IPv4's "Protocol"
but plays the same role — picks the layer-4 dispatch. The shipped
parser handles three layer-4 protocols: TCP (6), UDP (17), and
ICMP (1) / ICMPv6 (58); everything else falls into a generic
`ip_proto_<N>` shape.

### TCP flag decoding

TCP's 13th byte (offset 13 in the TCP header) packs six flag bits.
Cathedral decodes them as a pipe-separated string in the `info`
field:

```go
func tcpFlags(b byte) string {
    flags := []string{}
    if b&0x01 != 0 { flags = append(flags, "FIN") }
    if b&0x02 != 0 { flags = append(flags, "SYN") }
    if b&0x04 != 0 { flags = append(flags, "RST") }
    if b&0x08 != 0 { flags = append(flags, "PSH") }
    if b&0x10 != 0 { flags = append(flags, "ACK") }
    if b&0x20 != 0 { flags = append(flags, "URG") }
    return strings.Join(flags, "|")
}
```

So a connection setup looks like:

```
SYN              ← client → server
SYN|ACK          ← server → client
ACK              ← client → server (handshake complete)
PSH|ACK          ← client → server (sending data)
ACK              ← server → client (acknowledging)
FIN|ACK          ← either side closing
```

Reading the flag-string column of a `sniff` output is the fastest
way to spot incomplete handshakes (lots of SYNs without SYN|ACK
replies → SYN flood or unreachable port), connection resets (RST
mid-stream → application-level error or RST-injection), and
keep-alive churn.

### ICMP type decoding

Four ICMP types get named (the rest show as `type=N`):

| Type | Name           |
|------|----------------|
| 0    | echo-reply     |
| 3    | unreachable    |
| 8    | echo-request   |
| 11   | time-exceeded  |

These four cover almost everything a sniff session typically
shows — ping traffic (8/0), traceroute responses (11), unreachable
errors (3) from blackholed destinations. ICMPv6 isn't decoded
in detail; it just shows as `icmp6` with no info field.

### Stop conditions

The capture loop runs until either:

- The packet-count limit is hit (default: 50 matched packets), OR
- The duration limit is hit (default: 30 seconds), OR
- A non-recoverable socket error occurs

The 1-second `SO_RCVTIMEO` lets the recv call return periodically
with `EAGAIN` even on idle interfaces, so the deadline check
actually fires when the duration limit elapses on a quiet
network. Without the timeout, sniff would block forever waiting
for the next packet.

## What Cathedral doesn't do

- **Not a tcpdump replacement.** No PCAP file output. No BPF
  filter expressions. No layer-7 protocol dissection (HTTP
  request/response decode, DNS query/answer parsing, TLS
  SNI extraction). For deep packet analysis, save a PCAP with
  tcpdump and load it in Wireshark.
- **Linux only.** `AF_PACKET` doesn't exist on macOS or Windows.
  On macOS the BPF-device approach works through `/dev/bpf*`;
  on Windows you'd need Npcap. Cathedral's sniff returns an
  error on those platforms — porting it would mean adding the
  libpcap dependency and losing the static-binary property,
  not worth it for the typical operator workflow.
- **No promiscuous mode toggling.** sniff binds the interface
  without explicitly setting `IFF_PROMISC`. If you need to
  capture frames not addressed to your MAC (true network
  monitoring), enable promiscuous separately with
  `sudo ip link set <iface> promisc on`. On wired switched
  networks this only catches broadcast + your own traffic
  regardless — for full traffic visibility you need a SPAN /
  mirror port on the switch.
- **No connection reassembly.** Each frame is parsed
  independently. TCP segments are not stitched back into
  streams; out-of-order packets are not reordered; HTTP
  request bodies that span multiple packets are not stitched.
- **No frame timestamp from the kernel.** The `ts` field is the
  Cathedral-process wall-clock time when the frame was
  dequeued from the socket, not the kernel's hardware /
  receive timestamp. For nanosecond-accurate timing or capture-
  to-application latency analysis, use tcpdump with
  `--time-stamp-precision=nano`.
- **No findings extraction.** The shipped sniff is purely
  "show me packets matching a filter." The richer findings-
  extraction roadmap (DHCP-request device inventory, ARP-spoof
  anomaly detection, plaintext-credential detection across
  HTTP/FTP/SMTP, TLS SNI extraction without decryption) is a
  v2 candidate; see `cookbook/roadmap.md`.

## Worked example

### Default capture on the primary interface

```
operator@cathedral:~$ sniff
> sniffing on wlp3s0 — count=50 duration=30s (no filter)

  TIME          PROTO   SRC                             DST                              LEN  INFO
  ------------  ------  ------------------------------  ------------------------------  -----  ----------------
  19:42:11.034  tcp     192.168.1.23:54812              140.82.121.4:443                 1514  PSH|ACK
  19:42:11.039  tcp     140.82.121.4:443                192.168.1.23:54812                 60  ACK
  19:42:11.041  udp     192.168.1.1:53                  192.168.1.23:51231                 96
  19:42:11.108  arp                                                                       42  arp request
  19:42:11.109  arp                                                                       42  arp reply
  19:42:11.214  tcp     192.168.1.23:54818              23.215.0.137:443                  74  SYN
  19:42:11.234  tcp     23.215.0.137:443                192.168.1.23:54818                74  SYN|ACK
  19:42:11.234  tcp     192.168.1.23:54818              23.215.0.137:443                  66  ACK
  19:42:11.236  tcp     192.168.1.23:54818              23.215.0.137:443                 583  PSH|ACK
  19:42:11.265  icmp    192.168.1.23                    1.1.1.1                           98  echo-request
  19:42:11.279  icmp    1.1.1.1                         192.168.1.23                      98  echo-reply
  …

capture complete — 50 packets shown, 12 filtered out, 4 unparsed frames
```

A typical few seconds of a desktop session: TCP keep-alives
(GitHub at `140.82.121.4`), a DNS response from the gateway,
ARP request/reply, a fresh TCP connection to a CDN (the
SYN/SYN-ACK/ACK handshake reads cleanly in the flags column),
plus a ping that completed. `4 unparsed frames` is normal —
multicast IPv6 router solicitations and similar low-level
chatter that the parser doesn't bother decoding.

### Filter by protocol

```
operator@cathedral:~$ sniff --filter="proto=icmp" --count=10
> sniffing on wlp3s0 — count=10 duration=30s filter: proto=icmp

  TIME          PROTO   SRC                             DST                              LEN  INFO
  ------------  ------  ------------------------------  ------------------------------  -----  ----------------
  19:43:02.115  icmp    192.168.1.23                    8.8.8.8                           98  echo-request
  19:43:02.128  icmp    8.8.8.8                         192.168.1.23                      98  echo-reply
  19:43:03.116  icmp    192.168.1.23                    8.8.8.8                           98  echo-request
  19:43:03.130  icmp    8.8.8.8                         192.168.1.23                      98  echo-reply
  …

capture complete — 10 packets shown, 487 filtered out, 6 unparsed frames
```

Pinging Google DNS in another terminal while sniff runs the
ICMP-only filter. 487 packets filtered means the interface saw
plenty of other traffic — the proto filter just dropped it before
emission.

### Filter by port (TLS connections to 443)

```
operator@cathedral:~$ sniff --filter="proto=tcp,port=443" --count=20
> sniffing on wlp3s0 — count=20 duration=30s filter: proto=tcp,port=443

  TIME          PROTO   SRC                             DST                              LEN  INFO
  ------------  ------  ------------------------------  ------------------------------  -----  ----------------
  19:44:18.221  tcp     192.168.1.23:54902              52.84.150.45:443                  74  SYN
  19:44:18.247  tcp     52.84.150.45:443                192.168.1.23:54902                74  SYN|ACK
  19:44:18.248  tcp     192.168.1.23:54902              52.84.150.45:443                  66  ACK
  19:44:18.251  tcp     192.168.1.23:54902              52.84.150.45:443                 583  PSH|ACK   ← ClientHello
  19:44:18.281  tcp     52.84.150.45:443                192.168.1.23:54902              1514  ACK       ← ServerHello + Certificate
  19:44:18.281  tcp     52.84.150.45:443                192.168.1.23:54902              1514  ACK
  19:44:18.282  tcp     52.84.150.45:443                192.168.1.23:54902               842  PSH|ACK
  19:44:18.282  tcp     192.168.1.23:54902              52.84.150.45:443                  66  ACK
  19:44:18.286  tcp     192.168.1.23:54902              52.84.150.45:443                  90  PSH|ACK   ← Finished
  …
```

A TLS handshake reads clearly even without payload decode. The
ClientHello / ServerHello are the first two PSH|ACK packets after
the TCP 3-way handshake; subsequent ACKs are the certificate
arriving in MTU-sized chunks; the final small PSH|ACK is the
client's Finished message.

### Filter by host

```
operator@cathedral:~$ sniff --filter="host=8.8.8.8" --duration=10
> sniffing on wlp3s0 — count=50 duration=10s filter: host=8.8.8.8

  TIME          PROTO   SRC                             DST                              LEN  INFO
  ------------  ------  ------------------------------  ------------------------------  -----  ----------------
  19:45:31.022  udp     192.168.1.23:51844              8.8.8.8:53                        81
  19:45:31.041  udp     8.8.8.8:53                      192.168.1.23:51844               125
  19:45:34.501  icmp    192.168.1.23                    8.8.8.8                           98  echo-request
  19:45:34.519  icmp    8.8.8.8                         192.168.1.23                      98  echo-reply
  …

capture complete — 8 packets shown, 612 filtered out, 4 unparsed frames
```

A DNS query to Google's resolver followed by a ping. The
`host=8.8.8.8` filter matches when 8.8.8.8 appears as either
the source OR the destination — no separate `src=` / `dst=`
keys.

### Specific interface

```
operator@cathedral:~$ sniff --iface=docker0 --duration=15
> sniffing on docker0 — count=50 duration=15s (no filter)

  TIME          PROTO   SRC                             DST                              LEN  INFO
  ------------  ------  ------------------------------  ------------------------------  -----  ----------------
  19:46:55.318  tcp     172.17.0.3:38712                172.17.0.2:5432                   74  SYN
  19:46:55.318  tcp     172.17.0.2:5432                 172.17.0.3:38712                  74  SYN|ACK
  19:46:55.319  tcp     172.17.0.3:38712                172.17.0.2:5432                   66  ACK
  19:46:55.320  tcp     172.17.0.3:38712                172.17.0.2:5432                  119  PSH|ACK
  …

capture complete — 38 packets shown, 0 filtered out, 2 unparsed frames
```

Capturing the Docker bridge interface — two containers talking
to each other (Postgres on 5432). Useful for development /
debugging containerised services. The Docker bridge is a Linux
bridge that sees both sides of all container-to-container
traffic; on production hosts with overlay networks, the relevant
interface is typically `flannel.1`, `vxlan.calico`, or
`weave`, depending on the CNI plugin.

### The permission-denied path

```
operator@cathedral:~$ sniff
error: permission denied. Grant CAP_NET_RAW to enable packet capture:  sudo setcap cap_net_raw+ep /opt/cathedral/data/flutter_assets/assets/bin/sniff
```

First run on a fresh install. The error message includes the
exact installed path of the sniff binary — copy-paste the
`setcap` command verbatim, sudo once, then sniff works.

After the setcap, the capability is persistent across reboots
(it's stored in the file's extended attributes). You only need
to redo it if Cathedral reinstalls (which replaces the binary
and clears any xattrs).

## Output protocol

Line-oriented JSON. Event types:

| Event   | Fields                                                                       |
|---------|------------------------------------------------------------------------------|
| `start` | `iface`, `count`, `duration`, `filter`                                       |
| `packet`| `ts`, `proto`, `src`, `sport`, `dst`, `dport`, `len`, `info`                 |
| `done`  | `captured`, `filtered`, `unparsed`                                           |
| `error` | `message` — permission-denied or socket-error                                 |

The `sport` / `dport` fields are 0 when the protocol doesn't have
ports (ICMP, ARP, generic IP). For ARP, the `src` and `dst` fields
carry the *ARP* sender / target IPs, not the Ethernet MAC
addresses (the MACs aren't surfaced in the output).

Pipe-friendly with `jq`:

```
# Just the TCP SYN packets (connection attempts)
sniff --duration=60 | jq -r 'select(.event=="packet" and .info=="SYN") | "\(.src):\(.sport) → \(.dst):\(.dport)"'

# Count packets per destination IP
sniff --count=500 | jq -r 'select(.event=="packet") | .dst' | sort | uniq -c | sort -rn

# Detect potential port scan (many SYNs from one source)
sniff --duration=120 | jq -r 'select(.event=="packet" and .info=="SYN") | .src' | sort | uniq -c | awk '$1 > 20'

# Top talker by byte volume
sniff --count=1000 | jq -r 'select(.event=="packet") | "\(.len)\t\(.src)"' | awk '{a[$2]+=$1} END {for(k in a) print a[k], k}' | sort -rn | head
```

## Limitations

- **No PCAP output.** sniff prints summary lines, not the raw
  bytes. For "save it, look later in Wireshark" workflows, use
  `tcpdump -w` to a PCAP file. Cathedral might add `--pcap PATH`
  as a future option, but it would compete with `tcpdump` on
  its home turf without obvious wins.
- **No CIDR filters.** `host=10.0.0.5` matches one IP exactly.
  For "all RFC1918 traffic" or "all traffic to a /24", you
  can't express it. The current filter syntax handles the
  90% of "I want one host's packets" use case; ranged filtering
  would need a real expression grammar.
- **No layer-7 dissection.** TCP/UDP port and TCP flags are as
  deep as the parsing goes. HTTP method, DNS query name, TLS
  SNI, DHCP option codes — none of them. For real protocol
  analysis the right tool remains tcpdump+Wireshark.
- **Linux-only.** macOS / Windows / BSD return immediately with
  a socket error because `AF_PACKET` doesn't exist there.
- **No live filter editing.** The filter is set at startup and
  fixed for the duration of the capture. `tcpdump` has the
  same limitation; for adaptive filtering you'd need a separate
  filter-pipeline tool.
- **Default `--count=50` is small.** For longer sessions, bump
  both `--count` and `--duration`: `sniff --count=10000
  --duration=600` runs for 10 minutes or 10,000 matched
  packets, whichever first.
- **No interface multiplexing.** One invocation, one interface.
  To capture across two interfaces simultaneously, launch
  `sniff` twice with different `--iface` flags.

## Authorized use

Passive packet capture sits squarely in **medium-risk** dual-use
territory. Cathedral makes no attempt to gatekeep — `sniff`
captures whatever the kernel hands it on the chosen interface —
but the operator-side authorization considerations are
substantive:

- **Capturing on your own machine's interfaces** is fine. You
  control the network stack; observing it is a normal admin /
  development activity.
- **Capturing on a network you own or administer** is fine.
  Internal network troubleshooting, performance debugging,
  intrusion detection. This is what packet-capture exists for.
- **Capturing on someone else's network** is wiretap-shaped
  in most jurisdictions. The fact that the packets technically
  arrived on your wireless card doesn't necessarily make
  capturing them legal — coffee-shop Wi-Fi sniffing is the
  textbook example of "technically possible, often illegal."
  Different countries treat this differently (the US Wiretap
  Act, the UK's Investigatory Powers Act, the EU ePrivacy
  Directive all have different stances on consent and
  encrypted-vs-cleartext traffic). Don't sniff a network you
  don't own without explicit written authorization.
- **Capturing other users' traffic on a shared host** has the
  same problem in a different shape. On a multi-tenant VM
  host, on a corporate workstation with admin rights, on a
  university lab machine — the technical capability doesn't
  imply the right to use it. Authorized-testing engagements
  always document this explicitly in scope.
- **Sniffing in promiscuous mode** (where you'd see traffic
  not addressed to your MAC) makes the authorization question
  more pointed. sniff doesn't enable promiscuous mode itself,
  but if you've enabled it manually with `ip link set …
  promisc on`, every adjacent station's traffic becomes
  visible. That's a much larger surface than "traffic this
  device was already going to handle."
- **The `CAP_NET_RAW` capability is set by an operator who
  understands the trust model.** Cathedral doesn't grant it
  automatically because the install script can't reason about
  whether you should have it. The setcap step is a deliberate
  "yes, I want this binary to be able to capture packets"
  acknowledgement.

## Further reading

- [packet(7) — Linux packet socket manual page](https://man7.org/linux/man-pages/man7/packet.7.html)
  — the canonical reference for `AF_PACKET`. Covers the
  protocol-family semantics, the sockaddr_ll structure, and
  the kernel ring-buffer modes (TPACKET_v1/v2/v3) that sniff
  *doesn't* use but tcpdump does for high-volume capture.
- [capabilities(7) — Linux capability list](https://man7.org/linux/man-pages/man7/capabilities.7.html)
  — what `CAP_NET_RAW` actually grants. The capability also
  permits raw IP sockets (not just `AF_PACKET`), which is
  why ping has historically needed it; modern kernels expose
  a separate `CAP_NET_BIND_SERVICE` for low-port binding.
- [setcap(8)](https://man7.org/linux/man-pages/man8/setcap.8.html)
  — the tool itself. The `+ep` / `+eip` / `=ep` syntaxes are
  worth understanding before granting capabilities to other
  binaries.
- [tcpdump expression syntax](https://www.tcpdump.org/manpages/pcap-filter.7.html)
  — the BPF filter language. Cathedral's three-key filter is
  a deliberate simplification; if you find yourself wanting
  "tcp and dst portrange 8000-9000 and not host 192.168.1.0/24",
  the right answer is `tcpdump` rather than expanding
  sniff's filter parser.
- [Wireshark — packet analysis with PCAP](https://www.wireshark.org/docs/)
  — the canonical post-capture analysis tool. `tcpdump -w
  capture.pcap` then `wireshark capture.pcap` is the standard
  workflow when you outgrow line-oriented sniff output.
- [`netinfo`](netinfo.md) — what interfaces exist on this host
  and which one Cathedral picks as "primary" for sniff's
  default.
- [`conns`](conns.md) — local *connections* (the kernel's
  view: established TCP, listening sockets, owning PIDs).
  Complements sniff: conns shows what's *currently
  connected*, sniff shows what's *moving across the wire
  right now*.
- [`lan-scan`](lan-scan.md) and [`discover`](discover.md) —
  active discovery (sends probes). Sniff is the passive
  counterpart that watches without injecting.
