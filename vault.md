---
title: vault — encrypted file vault that only Cathedral can open
command: vault
category: privacy
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-11-17
related: [encrypt-decrypt, argon2, msg]
---

# `vault` — encrypted file vault that only Cathedral can open

`vault` is a folder that only Cathedral can open. Files go in, get
encrypted on the way, and from then on exist on disk only as
random-named ciphertext blobs. You browse, preview, edit and extract
them inside Cathedral's vault pane; no other program on the machine —
file manager, indexer, backup agent, another user — ever sees a
plaintext byte or even a file name.

```
vault                          # open the vault pane (create or unlock)
vault add <path>…              # encrypt files/folders in (copy)
vault add --shred <path>…      # encrypt in, then shred the originals
vault mv <path>…               # same as add --shred
```

Everything else — browsing, preview, notes, rename, move, extract,
passphrase change — happens inside the pane.

## What it does

The first `vault` creates a vault under `~/.cathedral/vault` (or
`$CATHEDRAL_VAULT`) protected by a passphrase. After that, `vault`
asks for the passphrase and takes over Cathedral's main pane with a
two-column browser: folder tree on the left, preview on the right.

| Key       | Action                                                    |
|-----------|-----------------------------------------------------------|
| `a`       | add a file or folder (copy — original stays)              |
| `m`       | move in: encrypt, then shred the original                 |
| `n` / `N` | new folder / new encrypted text note                      |
| `↵` / `⌫` | open folder or preview file / go up                       |
| `e`       | edit a text file in Cathedral's editor (saves re-encrypt) |
| `spc`, `c`, `v` | mark, cut, paste — move entries between folders     |
| `r` / `x` / `d` | rename / extract to disk / destroy                  |
| `p` / `L` | change passphrase / lock now                              |

Files can also be dragged in from the desktop file manager. Drag-and-
drop always *copies*; shredding is an explicit choice made per item
(`m`, `vault mv`, `--shred`), never a side effect of a gesture.

The vault locks itself after **five minutes idle**. Locking wipes the
master key from the sidecar, clears any open preview, and flushes
Flutter's image cache so decoded pictures don't linger in the UI
process. An open note with unsaved edits is saved *before* the lock,
not discarded.

## What it answers

**Privacy at rest:** *"How do I keep a handful of files that nobody
else on this machine can read — including programs running as me?"*
Full-disk encryption protects a powered-off laptop; it does nothing
once you're logged in. Everything running under your UID can read your
home directory: the thumbnailer, the desktop search indexer, the
sync client, a compromised browser extension's native helper. The
vault keeps its contents opaque to all of them.

**Engagement hygiene:** *"Where do client artefacts live during an
engagement?"* Scope letters, captured credentials, screenshots and
notes from an authorized test are exactly the material that should
not sit in `~/Documents`. Encrypt them in with `vault mv`, edit notes
in place with `N` / `e`, and nothing touches disk in the clear.

**Handoff from other tools:** files received through
[`msg`](msg.md) can be imported straight into the vault (`V` in the
messaging file list) without ever being written out as plaintext.

## How it works

### Why not a mounted folder

The obvious design — a FUSE mount, like VeraCrypt or gocryptfs — was
rejected on purpose. A mounted folder is plaintext *to every process
that can see the mount point*, which is precisely the set of programs
the vault is meant to exclude. Instead, decryption happens in exactly
one place: a dedicated sidecar process that speaks a small JSON-lines
protocol to the Cathedral UI over a pipe.

```
Cathedral UI  ──stdin──▶  vault serve  ──▶  ~/.cathedral/vault/
              ◀─stdout──  (holds key)        vault.hdr
                                             manifest.enc
                                             blobs/3f9c…  blobs/a01e…
```

The sidecar hardens itself before touching any secret:

```go
// No core dumps, no same-uid ptrace / process_vm_readv of our memory.
unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
unix.Setrlimit(unix.RLIMIT_CORE, &unix.Rlimit{Cur: 0, Max: 0})
```

`PR_SET_DUMPABLE=0` is the important line: it makes
`/proc/<pid>/mem` unreadable and `ptrace` refuse even for processes
running as the same user, so a same-UID attacker can't simply lift
the master key out of the sidecar's heap. The passphrase travels over
stdin, never argv (argv is world-readable through `/proc/*/cmdline`).
An exclusive `flock` on `.lock` stops two Cathedral windows from
opening the same vault and racing on the manifest.

### Three layers of keys

```
passphrase ──Argon2id──▶ pass key ──unwraps──▶ master key ──decrypts──▶ manifest
                                                                           │
                                               per-file key ◀──────────────┘
                                                    │
                                                    ▼
                                               blobs/<random>
```

1. **Passphrase → pass key.** Argon2id with 64 MiB memory, 3 passes,
   4 lanes, random salt — roughly half a second on a desktop. The
   parameters are stored in `vault.hdr`, so they can be raised later
   without breaking old vaults.
2. **Master key.** 32 random bytes, generated once, stored only
   *wrapped* (XChaCha20-Poly1305 under the pass key) in `vault.hdr`.
   Changing the passphrase rewraps this one value; no file is
   re-encrypted.
3. **Per-file keys.** Every file gets its own random key, stored in the
   encrypted manifest next to its real name, folder and size.

The manifest is the only place file names exist. On disk the
directory reveals nothing but a count of blobs and their approximate
sizes:

```go
type entry struct {
    ID     string    `json:"id"`
    Parent string    `json:"parent"` // "" = root
    Name   string    `json:"name"`
    Dir    bool      `json:"dir,omitempty"`
    Size   int64     `json:"size,omitempty"`
    Blob   string    `json:"blob,omitempty"` // random hex file name
    Key    []byte    `json:"key,omitempty"`  // per-file stream key
}
```

Every sealed object carries a distinct associated-data string
(`cathedral-vault/v1/master`, `…/manifest`), so a ciphertext of one
kind can never be passed off as another.

### Blobs: a chunked AEAD stream

Files can be gigabytes, so they're never encrypted in one shot. Each
blob is a **STREAM** construction (Hoang, Reyhanitabar, Rogaway,
Vizár): 64 KiB plaintext chunks, each sealed with XChaCha20-Poly1305
under the file key.

```
"CTHVB1" || noncePrefix(16) || chunk_0 || chunk_1 || … || chunk_n

nonce_i = noncePrefix || uint64_be(i)
ad_i    = blobID || finalFlag        (0x00 inner, 0x01 last chunk)
```

```go
func chunkNonce(prefix []byte, i uint64) []byte {
    n := make([]byte, chacha20poly1305.NonceSizeX) // 24 bytes
    copy(n, prefix)
    binary.BigEndian.PutUint64(n[16:], i)
    return n
}

func chunkAD(blobID string, final bool) []byte {
    ad := append([]byte(blobID), 0)
    if final {
        ad[len(ad)-1] = 1
    }
    return ad
}
```

Each piece of the nonce and AD closes one attack:

| Attack on the ciphertext            | Stopped by                          |
|-------------------------------------|-------------------------------------|
| reorder or duplicate chunks         | chunk counter in the nonce          |
| truncate at a chunk boundary        | final flag in the AD                |
| swap two blobs inside the vault     | blob ID in the AD                   |
| flip any bit anywhere               | Poly1305 tag on every chunk         |

Any failure surfaces as *"blob failed authentication (tampered,
truncated or corrupt)"* and aborts the read. Each chunk is verified
before any of its bytes are released, and a stream that ends without
its final-flagged chunk is an error, not a short file. Because decryption streams
chunk by chunk, previewing a 4 GB file costs 64 KiB of memory, not
4 GB.

### Writes are atomic

Every manifest save and every edited-file save goes to a temp file,
`fsync`s, and `rename`s over the old one. A crash or power cut leaves
either the old version or the new version, never a half-written
manifest that would orphan every file in the vault. Editing a note
encrypts the new content into a *new* blob and swaps the manifest
pointer, so the old blob stays valid until the swap commits.

### Shred, honestly

`vault mv` overwrites the original with random bytes, `fsync`s, then
unlinks it. That is meaningful on a spinning disk with ext4 in the
default `data=ordered` mode. It is **best effort** on SSDs (wear
levelling writes the random bytes somewhere else) and on
copy-on-write or journaling filesystems (btrfs, zfs, ext4
`data=journal`), where old blocks can survive. The UI asks for
confirmation by name before shredding, and the entry says so plainly:
if the original must be unrecoverable, it should never have been
written to that disk in the clear. Create sensitive notes inside the
vault (`N`) instead.

## Worked example

Moving the artefacts of a finished engagement into the vault. Paths
and names are illustrative:

```
operator@cathedral:~/work$ vault mv acme-2026-q4/
> vault: 1 item(s) queued for encryption (originals will be shredded)

  ┌ vault :: sealed ─────────────────────────────────────────────┐
  │ passphrase: ••••••••••••••••••••                              │
  └───────────────────────────────────────────────────────────────┘

  encrypt then SHRED original "~/work/acme-2026-q4"? (y/n)  y

  ▸ adding acme-2026-q4/ ……………………… 38.4 MB  [██████████] 100%
  ▸ shredded 14 files

  vault :: unsealed                              5 entries · 61.2 MB
  ─────────────────────────────────────────────────────────────────
  ▸ acme-2026-q4/                   38.4 MB    2026-11-17 14:02
    personal/                       19.7 MB    2026-10-03 09:41
    keys/                            2.9 MB    2026-09-12 22:15
    passport-scan.jpg              318.0 KB    2026-08-30 11:07
    notes.md                         4.1 KB    2026-11-16 23:48
  ─────────────────────────────────────────────────────────────────
  ↵ open  ⌫ up  spc mark  c cut  v paste  e edit  N note  a add …
```

What sits on disk afterwards:

```
$ ls -la ~/.cathedral/vault ~/.cathedral/vault/blobs | head
-rw-------  1 operator operator     412 Nov 17 14:02 vault.hdr
-rw-------  1 operator operator    6.3K Nov 17 14:02 manifest.enc
-rw-------  1 operator operator       0 Nov 17 13:58 .lock
-rw-------  1 operator operator   2.1M Nov 17 14:02 0b7e41d2c9a8f31e5d6a07b9c4e2f810
-rw-------  1 operator operator   118K Nov 17 14:02 1f93ac0e7d2b5468a9c1e3f70d4b8a26
-rw-------  1 operator operator    14M Nov 17 14:02 4ad2e6b1980f7c35d2e8a1b6f093c47e
…
```

Folder structure, file names, file types, dates: gone. An observer
learns that the vault holds some number of files of roughly these
sizes, and nothing else. Five idle minutes later the pane relocks
itself and the master key leaves memory.

## Output protocol

The vault is not a streaming command; `vault serve` is a long-lived
session driven by the UI. One JSON request per stdin line, replies
carry the request id:

```
→ {"id":1,"op":"unlock","pass":"…"}
← {"id":1,"ok":true}
→ {"id":2,"op":"list","parent":""}
← {"id":2,"ok":true,"entries":[{"id":"…","name":"notes.md","size":4198,…}]}
→ {"id":3,"op":"add","parent":"","path":"/home/operator/scan.png"}
← {"id":3,"progress":65536}
← {"id":3,"ok":true,"entry":{…}}
→ {"id":4,"op":"read","entry":"…","max":8388608}
← {"id":4,"chunk":"<base64>"}*
← {"id":4,"ok":true}
→ {"id":5,"op":"lock"}
← {"id":5,"ok":true}
```

Errors are `{"id":N,"ok":false,"error":"…"}`. Other ops: `init`,
`passwd`, `mkdir`, `rename`, `move`, `remove`, `extract`, `write`,
`new`, `status`.

## Limitations

- **Not a defence against a compromised session.** While the vault is
  unlocked, anything that can drive Cathedral's UI or read its screen
  sees what you see. A keylogger captures the passphrase. The vault
  protects files at rest and from *other programs*, not from malware
  that already owns your desktop session.
- **Preview lives in the UI process.** Decrypted bytes for the file
  being previewed exist in Cathedral's Flutter process, which is not
  marked non-dumpable the way the sidecar is. They are wiped on close
  and lock, but Dart strings and decoded images can't be zeroed
  reliably — a memory snapshot taken *during* a preview can contain
  them.
- **Extract means plaintext.** `x` writes a normal file to disk. From
  that moment it's outside the vault's protection.
- **Sizes leak.** Blob sizes round to the 64 KiB chunk grid plus a
  small overhead, so an observer can tell a 4 KB note from a 2 GB
  video. File count and modification times of `manifest.enc` leak
  activity patterns.
- **No recovery.** Lose the passphrase and the vault is gone. There is
  no escrow, no hint, no backdoor. Back up the whole vault directory
  (it's safe to copy — it's ciphertext) and remember the passphrase.
- **Preview formats.** Text and images preview inline. PDF preview is
  planned; video is deliberately not supported (it would need a system
  media library).
- **Shred is best effort** on SSDs and copy-on-write filesystems; see
  above.
- **Linux-first.** The hardening calls (`prctl`, `flock`) are Linux;
  macOS and Windows builds will need their own equivalents.

## Authorized use

The vault touches nothing but your own files. Its posture is the
posture of any encryption tool: legitimate for personal privacy,
client-data handling and professional confidentiality obligations.
For operators specifically, an encrypted store for engagement
artefacts is often a *contractual* requirement — the vault exists to
make meeting it easy.

## Further reading

- [RFC 9106 — Argon2](https://www.rfc-editor.org/rfc/rfc9106) — the passphrase KDF
- [XChaCha20-Poly1305 draft](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha) — the AEAD with 192-bit nonces
- [Hoang et al., *Online Authenticated-Encryption and its Nonce-Reuse Misuse-Resistance*](https://eprint.iacr.org/2015/189) — the STREAM construction
- [`prctl(2)` — `PR_SET_DUMPABLE`](https://man7.org/linux/man-pages/man2/prctl.2.html)
- Related Cathedral commands: [`encrypt` / `decrypt`](encrypt-decrypt.md) (one-shot file encryption),
  [`argon2`](argon2.md) (the KDF, interactively), [`msg`](msg.md) (shares the same at-rest crypto)
