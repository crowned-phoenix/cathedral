---
title: msg — peer-to-peer encrypted messaging over Tor onion services
command: msg
category: privacy
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-11-17
related: [vault, encrypt-decrypt, argon2]
---

# `msg` — peer-to-peer encrypted messaging over Tor onion services

`msg` is one-to-one encrypted chat between Cathedral users with no
server in the middle. Every Cathedral instance publishes its own Tor
v3 onion service; your onion address *is* your identity; contacts
reach each other onion-to-onion, so neither side — and no relay, and
no Cathedral infrastructure, because there is none — learns the
other's IP address. Text messages and file transfers ride a Noise
protocol session inside the Tor circuit, and everything kept on disk
is encrypted under its own passphrase.

```
msg                  # open the messaging pane
```

That is the whole command. Identity creation, Tor, contacts,
conversations and files all live inside the pane:

| Key  | Action                                          |
|------|-------------------------------------------------|
| `↵`  | write to the selected contact                   |
| `n`  | add a contact by onion address                  |
| `y`  | copy *your* address to share                    |
| `u`  | send a file                                     |
| `f`  | file list for this conversation (download / save / `V` to vault) |
| `a` / `x` | accept / decline a contact request         |
| `v`  | mark contact as verified out-of-band            |
| `r` / `b` / `D` | rename / block / delete contact      |
| `T`  | Tor log view                                    |
| `s`  | Tor on / off                                    |
| `L`  | lock (wipe keys from memory)                    |

Cathedral ships its own `tor` binary. Users install nothing.

## What it does

First run creates an identity: a random Ed25519 key, sealed under a
passphrase you choose (separate from the [`vault`](vault.md)
passphrase). Unlocking starts the bundled `tor`, publishes your onion
service, and shows your address along with a friendly display handle
derived from it:

```
crowned-lantern.cthd
tj6emwxmqy3vh334krerdk6hvrdaeeq2vha4n4ksryy6kgi6wfzxlzid.onion
```

The handle is a display aid only — two words picked by hashing the
public key, so it's stable but not unique. The 56-character address
is the identity.

To talk to someone, you exchange addresses out of band and each add
the other. Adding someone who hasn't added you delivers a **contact
request** with an optional short intro (≤ 280 characters); they see
it in their pane and accept, decline, or block. Messages you write
before they accept wait in your outbox and go out automatically once
they do.

Delivery is **online-only and store-and-forward on the sender's
side**: if your contact is offline, the message stays queued locally
(`queued`), Cathedral re-dials contacts with undelivered mail every
45 seconds, and the message moves to `sent` and then `delivered`
when their client acknowledges it. There is no server holding mail
for anyone.

## What it answers

*"How do I talk to another person without a provider learning who I
talk to, when, or from where?"*

Mainstream end-to-end messengers protect message *content* well. They
still run on a provider that knows each account's phone number or
email, IP address, contact graph and online times. `msg` removes the
provider: there's no account to register, no phone number, no
directory, no server to subpoena or breach. What a network observer
sees is Tor traffic. What your contact sees is an onion address — not
your IP, not your location.

For an operator this is the side channel for coordinating an
engagement with a teammate without that coordination living in a
third party's logs. For everyone else, it's a private line to a
handful of people.

## How it works

### Two layers of encryption

```
 ┌──────────── your Cathedral ────────────┐           ┌──── their Cathedral ────┐
 │ UI ⇄ msg serve ── Noise IK session ────┼── Tor ────┼─▶ onion svc ─▶ msg serve │
 │      (keys)     (end-to-end, ChaChaPoly)│  6 hops,  │                (keys)    │
 │                                         │ onion-svc │                          │
 │      bundled tor ── SOCKS ─────────────┼─ circuits ┤                          │
 └─────────────────────────────────────────┘           └──────────────────────────┘
```

1. **Tor onion service.** Connections go client → 3 relays →
   rendezvous ← 3 relays ← service. Tor's own circuit encryption
   protects the transport and hides both endpoints' IP addresses. No
   port forwarding, no NAT traversal tricks: onion services work from
   behind any router that allows outbound Tor.
2. **Noise IK inside the circuit.** On top of the Tor stream, the two
   `msg` sidecars run their own authenticated key exchange
   (`Noise_IK_25519_ChaChaPoly_BLAKE2b`) and encrypt every frame
   end-to-end.

Why both? Tor already encrypts and already authenticates the service
end. The Noise layer exists so that a bug or a compromise in one layer
doesn't expose content: a flaw in Tor's onion-service crypto doesn't
reveal messages, and a flaw in `msg`'s session code still sits inside
an anonymised circuit. It also authenticates the *caller*, which Tor
onion services don't do on their own.

### Identity: one key, three uses

Each identity is a single 32-byte Ed25519 seed. Everything derives
from it:

**The onion address** (rend-spec-v3 §6):

```go
// address = base32(PUBKEY || CHECKSUM || VERSION), 56 chars
// CHECKSUM = SHA3-256(".onion checksum" || PUBKEY || VERSION)[:2]
func onionAddress(pub ed25519.PublicKey) string {
    h := sha3.New256()
    h.Write([]byte(".onion checksum"))
    h.Write(pub)
    h.Write([]byte{0x03})
    raw := append(append(append([]byte{}, pub...), h.Sum(nil)[:2]...), 0x03)
    return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).
        EncodeToString(raw))
}
```

The checksum means a mistyped or truncated address is rejected at
input, not dialled.

**The onion service key.** Tor's control port accepts the *expanded*
Ed25519 secret (SHA-512 of the seed, clamped) via `ADD_ONION`:

```go
func expandedKeyB64(seed []byte) string {
    h := sha512.Sum512(seed)
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    return base64.StdEncoding.EncodeToString(h[:])
}
// → ADD_ONION ED25519-V3:<that> Port=9550,127.0.0.1:<local>
```

The service is created over the control port each time and never
written to Tor's data directory. Tor's directory holds only its
consensus cache; the key exists on disk only inside `msg`'s own
encrypted identity file.

**The Noise static key.** Ed25519 and X25519 are the same curve in
two coordinate systems. The Ed25519 secret scalar is a valid X25519
private key, and any Ed25519 public key maps to its X25519 form with
the birational Edwards → Montgomery map:

```go
func noiseStatic(seed []byte) noise.DHKey {
    h := sha512.Sum512(seed)
    priv := h[:32]                  // X25519 clamps on use
    pub, _ := curve25519.X25519(priv, curve25519.Basepoint)
    return noise.DHKey{Private: priv, Public: pub}
}

func edToX25519(pub []byte) ([]byte, error) {
    p, err := new(edwards25519.Point).SetBytes(pub)
    if err != nil {
        return nil, errors.New("invalid ed25519 public key")
    }
    return p.BytesMontgomery(), nil
}
```

The consequence is the property the whole design rests on: **knowing
someone's onion address means knowing their Noise public key.** There
is no separate key exchange step, no key server, and no window for a
key to be substituted after you have the right address.

### The handshake

Because the initiator dialled an onion address, it already knows the
responder's static key — that's exactly the precondition for Noise's
**IK** pattern, which completes in one round trip:

```
prologue  "cathedral-msg/1"
-> e, es, s, ss          initiator → responder   (empty payload)
<- e, ee, se             responder → initiator   (empty payload)
```

After it, the responder knows the caller's X25519 static key — but an
X25519 key alone loses the Ed25519 sign bit, so it can't be turned
back into an exact onion address. The initiator's first encrypted
message therefore proves which Ed25519 key it holds:

```
hello{ ed:  Ed25519 public key,
       sig: Sign(ed, "cathedral-msg/1 hello" || h) }
```

where `h` is the Noise handshake hash. The responder checks both
`X25519(ed) == the handshake's remote static` and the signature, then
derives the caller's onion address from `ed`:

```go
x, err := edToX25519(h.Ed)
if err != nil || !equal(x, hs.PeerStatic()) {
    return nil, "", errors.New("hello key does not match handshake key")
}
if !ed25519.Verify(h.Ed, append([]byte(helloCtx), hs.ChannelBinding()...), h.Sig) {
    return nil, "", errors.New("hello signature invalid")
}
s.peer = onionAddress(ed25519.PublicKey(h.Ed))
```

Signing the handshake hash is channel binding: `h` covers the
responder's fresh ephemeral key, so a recorded hello can't be replayed
into a new session. That's also why IK message 1 deliberately carries
no payload — IK's first message is replayable by design, so nothing
that matters rides in it.

The responder answers with `welcome{status: accepted|pending}`, and
the policy runs:

| Caller is…                 | Responder does                                   |
|----------------------------|--------------------------------------------------|
| an accepted contact        | `welcome accepted`, session stays open           |
| unknown                    | stores a contact request, `welcome pending`, hangs up |
| a pending request          | refreshes the intro, `welcome pending`, hangs up |
| blocked                    | hangs up silently                                |

A blocked caller sees exactly what an offline peer looks like: the
connection drops. Blocking doesn't announce itself.

### Framing and sessions

After the handshake every frame is
`uint16_be(len) || ChaChaPoly(JSON)`, one JSON message per frame:

| `t`        | Purpose                                         |
|------------|-------------------------------------------------|
| `hello` / `welcome` | authentication and contact status      |
| `msg` / `ack`       | a message (text, or a file offer) and its receipt |
| `ping` / `pong`     | keepalive every 60 s; 3 min silence = dead |
| `fget` / `fdata` / `fdone` / `fcancel` | file transfer       |

Each message carries a random 128-bit ID. The receiver stores it, then
acks; the sender resends anything not yet acked on every new session;
the receiver dedupes by ID and re-acks. That gives at-least-once
delivery on the wire and exactly-once in the history, across dropped
circuits and restarts.

Inbound limits are enforced before anything is stored: 8 KiB of UTF-8
per message, 60 messages per contact per minute, at most 100 pending
contact requests. Over-limit messages simply aren't acked — the
sender's client keeps them queued and tries again later.

### File transfer

A file is a normal message whose `file` field offers name, size and
SHA-256. Nothing else moves until the **receiver** asks — Cathedral
always prompts before downloading. Transfer is receiver-pulled:

```
receiver → fget{id, off}               off = bytes already held
sender   → fdata{id, off, data} × n    32 KiB per frame, in order
receiver → fdone{id}                   after SHA-256 matched
either   → fcancel{id}                 declined / canceled / gone
```

Both sides keep the payload encrypted at rest as fixed-size records:

```
record_i = nonce(24) || XChaCha20-Poly1305(master, chunk_i, ad_i)
ad_i     = "cathedral-msg/v1/file/" peer "/" id "/" i "/" size
```

Fixed-size records let the sender seek straight to any offset and let
the receiver **resume after a dropped circuit** by counting whole
records — `fget` with the current offset picks up where it stopped.
The AD binds every record to its index, file and peer, so records
can't be reordered, swapped between files or spliced between
contacts; the size in the AD plus the record count catches
truncation; and the end-to-end SHA-256 from the offer is checked
before the transfer is declared done. Files up to 2 GiB.

Received files sit in an encrypted inbox. From there you save a
plaintext copy to disk, or import straight into the
[`vault`](vault.md) without a plaintext copy ever touching disk.

### Storage at rest

```
~/.cathedral/msg/
  identity.hdr    Argon2id(passphrase) wraps a random master key
  identity.enc    seal(master, Ed25519 seed)
  contacts.enc    seal(master, contact list)
  threads/<k>.enc seal(master, one conversation)   k = H(master || addr)
  files/<k>.bin   encrypted file records           k = H(master || addr/id)
  tor/            Tor's DataDirectory — consensus cache, no keys
```

This reuses the vault's primitives: Argon2id (64 MiB, 3 passes) wraps
a random master key; every object is XChaCha20-Poly1305 with a
purpose-specific AD; writes are atomic temp-file-then-rename. File
names are keyed hashes, so the directory listing doesn't reveal how
many people you talk to or which thread belongs to whom, and each
thread's AD names its peer so thread files can't be swapped between
contacts.

The sidecar marks itself non-dumpable (`PR_SET_DUMPABLE=0`), takes
passphrases over stdin only, and holds an exclusive lock on the
directory. `L` locks: keys are wiped, Tor stops, the onion goes dark.

### The bundled Tor

`msg` launches its own `tor` with a generated torrc: control and SOCKS
ports on `127.0.0.1:auto`, cookie authentication,
`ClientOnly 1`, `AvoidDiskWrites 1`, and
`__OwningControllerProcess` set to the sidecar's PID with
`TAKEOWNERSHIP` on the control connection — if `msg` dies for any
reason, Tor exits with it instead of lingering as an orphan onion
service. Bootstrap progress and Tor's own log lines stream into the
pane (`T`). Outbound dials go through Tor's SOCKS port with
onion-address hostnames, so no DNS ever leaves the machine.

## Worked example

Two people, illustrative addresses. Operator A shares their address
over a channel they already trust (in person, a voice call):

```
  messaging :: crowned-lantern.cthd                     tor ● online
  ──────────────────────────────────────────────────────────────────
  your address (y to copy):
  tj6emwxmqy3vh334krerdk6hvrdaeeq2vha4n4ksryy6kgi6wfzxlzid.onion
```

B adds it with an intro. On A's side, a request appears:

```
  CONTACTS                    │  REQUEST  quiet-falcon.cthd
  ▸ ? quiet-falcon.cthd       │  3fg6scvfrymzdegy6xs6ah3qkrtjti44
    ● hollow-raven.cthd       │  ljo2lx4o75n4sz6xytvq4jid.onion
    ○ amber-echo.cthd         │
                              │  "hey, it's M. from the meetup —
                              │   this is my cathedral address"
  ──────────────────────────────────────────────────────────────────
  a accept  x decline  b block  ↑↓ select  esc hide
```

A accepts, compares the address with M. over the phone, presses `v`,
and the conversation opens. B had written before being accepted; that
message was waiting in B's outbox and arrives within one retry cycle:

```
  CONTACTS                    │  quiet-falcon.cthd  ✓ verified
    ● quiet-falcon.cthd   ✓   │
    ● hollow-raven.cthd       │  21:04  M.   anything new on the scope doc?
    ○ amber-echo.cthd         │  21:06  me   yes — sending the revised one
                              │  21:06  me   ⎘ scope-v3.pdf  1.8 MB  ✓✓
                              │  21:07  M.   got it, hash matches.
                              │  21:09  me   call tomorrow 10:00?       ✓
  ──────────────────────────────────────────────────────────────────
  ↵ write  u send file  f files  ↑↓ select  n add  r rename  v verify …
```

`●` online, `○` offline, `?` pending request. `✓` sent, `✓✓`
delivered. On M.'s side, the PDF arrived as an offer and was fetched
only after M. pressed `↵` on it in the file list.

## Output protocol

`msg serve` is a long-lived JSON-lines session driven by the UI, like
[`vault`](vault.md). Requests carry an `id`; replies echo it;
asynchronous events carry `event`:

```
→ {"id":3,"op":"unlock","pass":"…"}
← {"id":3,"ok":true}
→ {"id":4,"op":"start"}
← {"event":"bootstrap","progress":45,"summary":"Loading relay descriptors"}
← {"event":"online","address":"tj6e…zid","handle":"crowned-lantern.cthd","socks":"127.0.0.1:41873"}
← {"event":"published","hsdirs":6}
← {"event":"request","addr":"3fg6…jid","intro":"hey, it's M. …"}
→ {"id":9,"op":"send","addr":"3fg6…jid","body":"call tomorrow 10:00?"}
← {"event":"message","addr":"3fg6…jid","message":{"id":"…","out":true,"state":"queued",…}}
← {"event":"msg_state","addr":"3fg6…jid","id":"…","state":"delivered"}
← {"event":"presence","addr":"3fg6…jid","online":true}
```

Ops: `status`, `init`, `unlock`, `lock`, `passwd`, `start`, `stop`,
`ping`, `contacts`, `add`, `accept`, `decline`, `remove`, `block`,
`unblock`, `rename`, `verify`, `send`, `history`, `read`, `send_file`,
`file_get`, `file_cancel`, `file_delete`, `file_save`.

## Limitations

- **Online-only.** Both sides must be running Cathedral with messaging
  unlocked for anything to move. Messages wait in the sender's outbox
  indefinitely; there is no mailbox server, by design.
- **First contact is only as good as the address exchange.** The
  cryptography guarantees you're talking to whoever holds the key for
  the address you dialled. If someone swapped the address before it
  reached you — edited a message, a compromised chat account — you'll
  have a perfectly encrypted conversation with them. Verify the
  address through a second channel (voice, in person) and mark it with
  `v`. The UI nudges; it can't enforce.
- **Session-level forward secrecy, not per-message.** Each Noise
  session uses fresh ephemeral keys, so a later key compromise doesn't
  decrypt recorded *traffic*. There is no Double Ratchet: within one
  long-lived session, all messages share session keys. And forward
  secrecy covers the wire, not the disk — history on disk is readable
  by anyone with your passphrase and the files.
- **IK hides less than XX for the initiator.** The caller's static key
  is encrypted to the responder's long-term key. Someone who later
  steals a responder's identity key and has recorded the traffic can
  learn *which* identities called them — though not what was said.
- **No deniability.** The hello signature binds your identity to each
  session. Messages are authenticated to the sender cryptographically.
- **Presence leaks.** Your onion service being reachable tells anyone
  who knows your address that you're online right now. Contacts are
  probed for presence every five minutes.
- **Tor's limits apply verbatim.** A global adversary who can watch
  traffic at both ends can correlate timing. Tor is blocked or
  conspicuous in some networks; bridges / pluggable transports aren't
  wired up in this version.
- **1-to-1 only.** No groups, no multi-device. One identity lives on
  one machine; moving it means moving the `~/.cathedral/msg`
  directory (and its passphrase).
- **No contact discovery.** There's no directory to find people by
  name, and there won't be — it would be the one place that knows
  everyone's address.
- **Both peers need compatible builds.** Wire-protocol additions (file
  transfer was one) require both sides to update.
- **Unaudited.** This is new cryptographic protocol code. It is
  tested — including adversarial tests for tampering, replay and
  key-mismatch — but it has not had an independent security review.
  Treat it accordingly until it has.

## Authorized use

`msg` sends nothing to anyone you haven't explicitly added, and
accepts nothing from anyone you haven't explicitly accepted. Its
dual-use profile is the profile of every anonymous messenger: the same
property that protects a journalist's source protects someone you'd
rather it didn't. Cathedral's position is the same as Tor's and
Signal's — privacy is a default people are entitled to, and the
response to misuse is the law, not a backdoor.

A note on what this changes about the product. Every other cookbook
entry describes a tool you point *at* something. This one is a
communication channel *between people*, and the stakes are different:
a bug in a recon tool leaks metadata about a scan; a bug here can
expose a person. That's why the design avoids novelty where it can
(Noise, Tor, XChaCha20-Poly1305, Argon2id are all standard), why the
limitations section above is long, and why the honest recommendation
for life-or-death threat models remains a tool with years of public
audit behind it.

## Further reading

- [The Noise Protocol Framework](https://noiseprotocol.org/noise.html) — §7.5 for the IK pattern, §11.2 for channel binding
- [Tor rend-spec-v3](https://spec.torproject.org/rend-spec/) — onion addresses and the v3 onion-service protocol
- [Tor control-spec](https://spec.torproject.org/control-spec/) — `ADD_ONION`, `TAKEOWNERSHIP`
- [RFC 7748 — Elliptic Curves for Security](https://www.rfc-editor.org/rfc/rfc7748) — X25519 and the Edwards↔Montgomery relationship
- [Cwtch](https://cwtch.im/) and [Briar](https://briarproject.org/) — mature onion-service messengers with a similar shape and much longer track records
- Related Cathedral commands: [`vault`](vault.md) (same at-rest crypto; received files import into it),
  [`encrypt` / `decrypt`](encrypt-decrypt.md) (one-shot file encryption to hand to someone)
