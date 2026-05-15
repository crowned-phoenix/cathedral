---
title: stego — LSB steganography for PNG carriers
command: stego
category: file forensics
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-15
related: [meta, imgforensic]
---

# `stego` — LSB steganography for PNG carriers

`stego` hides a file inside a PNG by writing one bit of the payload
into the least-significant bit of every red, green, and blue
channel in the image. The carrier remains visually identical to a
human; a second invocation extracts the payload byte-for-byte.

Three subcommands:

```
stego info    <png>                              # capacity + detect existing payload
stego embed   <carrier.png> <secret> <out.png>   # hide a file inside a PNG
stego extract <stego.png>    <out>               # recover the hidden payload
```

## What it does

Classic LSB (least-significant bit) steganography. Three bits of
payload per pixel — one each in R, G, B — encode a byte stream
laid out as:

| Offset | Size | Contents                              |
|--------|------|---------------------------------------|
| 0      | 4    | magic `CTHD`                          |
| 4      | 1    | format version (currently `1`)        |
| 5      | 1    | reserved (always `0`)                 |
| 6      | 4    | payload length, big-endian uint32     |
| 10     | N    | payload bytes                         |

A 1024 × 1024 PNG carries ~393 KB; a 4032 × 3024 phone photo
carries ~4.5 MB. The capacity formula is
`width × height × 3 / 8` bytes — accounted before the 10-byte
header.

Three subcommands, each producing a structured event stream:

- **`info`** reads the carrier, reports its capacity, and tries
  the magic-byte check to detect an existing Cathedral payload.
- **`embed`** loads the carrier, reads the secret, writes the
  header + payload into the LSBs of the carrier's pixels in scan
  order, saves the result as a new PNG.
- **`extract`** reads enough LSBs to validate the magic and
  header, then pulls out exactly `length` payload bytes and
  writes them to disk.

## What it answers

**Capture the flag.** Steganography is a recurring CTF category;
LSB-in-PNG is the most teachable variant of it. `stego` ships
both directions — embed for building challenges, extract for
solving them.

**Tamper-evident channels.** Embedding a hash, signature, or
short audit message into a published image gives a
*deniable-looking* channel for verifying provenance. The image
looks identical to a viewer; the hidden payload survives standard
PNG manipulation (resize, recompress) only when the manipulation
is bit-preserving, so any tampering shows up as a missing or
corrupted extraction. Combine with signing for stronger
guarantees.

**Annotation and journaling.** A small text note inside the photo
it describes — embedded in the file rather than alongside it.
The file is portable; the note travels with it; the visual
content is unchanged. Niche but real.

**Education.** The format is small enough to inspect and the
algorithm is short enough to write on a napkin. `stego` shows
how the technique works rather than wrapping it in opaque
binaries — the entire LSB write loop is twelve lines of Go (see
*How it works* below).

## What it isn't

A privacy primitive. The Cathedral implementation is **honest LSB
steganography** — the magic bytes `CTHD` are written into the
first 32 LSBs in scan order. Anyone with a Cathedral install can
detect a Cathedral-embedded image in milliseconds. Anyone with
LSB-aware statistical tools (chi-squared on pixel histograms,
sample-pair analysis) can detect any LSB stego — Cathedral or
otherwise — without the magic.

For privacy of content, encrypt before embedding. For
detection-resistance, you need denser schemes than LSB — Cathedral
does not pretend to be one of those. See the *Authorized use*
section below for the honest framing.

## How it works

### The LSB write loop

The whole technique is twelve lines:

```go
func writeBitsLSB(img *image.NRGBA, data []byte) error {
    b := img.Bounds()
    bitIdx, totalBits := 0, len(data)*8
    for y := b.Min.Y; y < b.Max.Y; y++ {
        for x := b.Min.X; x < b.Max.X; x++ {
            i := img.PixOffset(x, y)
            for c := 0; c < 3; c++ {                 // R, G, B (skip A)
                if bitIdx >= totalBits { return nil }
                bit := (data[bitIdx/8] >> (7 - bitIdx%8)) & 1
                img.Pix[i+c] = (img.Pix[i+c] & 0xFE) | bit
                bitIdx++
            }
        }
    }
    return nil
}
```

The mask `0xFE` (binary `11111110`) clears the LSB; OR'ing the
payload bit sets it. Each pixel contributes three bits — R, G, B.
The alpha channel is deliberately skipped because changes to
alpha are visually disruptive in a way changes to colour LSBs
aren't.

Bits are packed MSB-first into the byte stream. This is a
deliberate choice — it makes the magic bytes easy to recognise
in a hex dump of the LSBs themselves, which helps debugging the
format.

### Why PNG, not JPEG

LSB embedding survives only lossless transport. PNG is lossless
by definition — the pixel array round-trips bit-for-bit through
the decoder, the LSB modifications survive any number of
re-saves. JPEG is lossy — its DCT-and-quantise compression
discards exactly the kind of low-magnitude detail that LSB
embedding lives in. A Cathedral-stego'd image saved as JPEG
loses the payload completely.

The error-prevention design choice here is *no JPEG output ever*.
The `embed` subcommand writes PNG no matter what extension you
gave the output filename — write `out.jpg` and you'll get a PNG
named `out.jpg`, with a warning where appropriate. This is the
right trade: silent payload corruption is far worse than a
filename mismatch.

### Capacity math

```go
func capacityBytes(img *image.NRGBA) int {
    pixels := img.Bounds().Dx() * img.Bounds().Dy()
    return pixels * 3 / 8
}
```

Three useful reference points:

| Carrier              | Pixels       | Capacity   | Payload after header |
|----------------------|--------------|------------|----------------------|
| 256 × 256 (avatar)   | 65,536       | 24 KB      | ~24 KB               |
| 1024 × 1024          | 1,048,576    | 384 KB     | ~384 KB              |
| 4032 × 3024 (phone)  | 12,192,768   | 4.46 MB    | ~4.46 MB             |
| 7680 × 4320 (8K)     | 33,177,600   | 12.16 MB   | ~12.16 MB            |

Carrier size dominates payload size by ~30× — a 24 KB capacity
in a 256-pixel-square image vastly exceeds typical text-note
payloads (a few hundred bytes). The `fill_pct` reading on the
embed event tells you how much of the carrier you used; the
Cathedral UI flips the colour band at 75% and at 95%, both of
which are reasonable warning thresholds — heavy fills perturb
the pixel histogram more visibly and make statistical detection
easier.

### Detection: the magic-byte check

`stego info` reads the first 80 bits from the carrier's LSBs,
packs them into 10 bytes, and checks whether the first 4 match
`CTHD`:

```go
bits := readBitsLSB(img, headerBytes*8)
hdr := bitsToBytes(bits)
if string(hdr[0:4]) != magic {
    return errors.New("no Cathedral stego payload (magic mismatch)")
}
```

A bare carrier's first 32 LSBs are essentially random bytes; the
probability of accidentally matching `CTHD` is 1 in 2³² ≈ 4
billion. Cathedral-stego'd images match by construction.

This makes Cathedral payloads trivially detectable. That's a
deliberate trade-off: the cookbook's audience uses `stego` for
CTFs and demos where being able to *confirm* a payload is
present matters more than hiding the fact that one is. For
covert applications, neither this tool nor LSB itself is the
right primitive.

## Worked example

A full roundtrip captured on a tiny carrier (the Cathedral icon)
with a short text payload:

```
$ stego info /tmp/cover.png
> inspecting /tmp/cover.png
  dimensions : 256 × 256    (65536 pixels)
  capacity   : 24 K (LSB of R/G/B)
  payload    : none detected (no Cathedral stego payload (magic mismatch))

$ stego embed /tmp/cover.png /tmp/note.txt /tmp/stego.png
> embedding /tmp/note.txt into /tmp/cover.png → /tmp/stego.png
  dimensions : 256 × 256    (65536 pixels)
  capacity   : 24 K (LSB of R/G/B)
  secret     : 77 B    fill 0.4%
                ····················

[ ✓ ] saved /tmp/stego.png   (8.0 K on disk, 77 B hidden)

$ stego info /tmp/stego.png
> inspecting /tmp/stego.png
  dimensions : 256 × 256    (65536 pixels)
  capacity   : 24 K (LSB of R/G/B)
  payload    : Cathedral v1  77 B

$ stego extract /tmp/stego.png /tmp/recovered.txt
> extracting /tmp/stego.png → /tmp/recovered.txt
  header     : magic=CTHD  version=1  length=77 B

[ ✓ ] recovered /tmp/recovered.txt   (77 B)

$ diff /tmp/note.txt /tmp/recovered.txt && echo "match"
match
```

A 256×256 carrier holds 24 KB of payload capacity; the 77-byte
note fills 0.4% of it (the empty bar of dots is the fill meter).
The output PNG is `8 KB` — *smaller* than the 8.7 KB original.

That last detail is the cookbook's surprise: **file-size
comparison is not a stego detector**. Cathedral saves with
`png.BestCompression`; if the carrier was written with a faster
compression preset, the LSB-perturbed re-encoded PNG can come
out smaller than the original it modified. Visual identity is
preserved; PNG bytes are not. Detection must come from the LSB
content itself — `stego info` does that with the magic check —
not from file metadata.

## Output protocol

Three subcommands share a common envelope but emit different
mid-stream events.

### `info`

```
{"event":"start",    "mode":"info","path":"…"}
{"event":"carrier",  "path":"…","width":N,"height":N,"pixels":N,
                     "capacity":N,"capacity_payload":N}
{"event":"embedded", "valid":true,"version":N,"payload_bytes":N}
{"event":"embedded", "valid":false,"reason":"…"}
{"event":"done"}
```

`capacity` is total LSB byte capacity; `capacity_payload` is
capacity minus the 10-byte header.

### `embed`

```
{"event":"start",    "mode":"embed","carrier":"…","secret":"…","out":"…"}
{"event":"carrier",  "width":N,"height":N,"capacity":N}
{"event":"secret",   "path":"…","bytes":N,"fill_pct":N}
{"event":"saved",    "path":"…","out_bytes":N,"embedded":N,"abs_path":"…"}
{"event":"done"}
```

### `extract`

```
{"event":"start",   "mode":"extract","stego":"…","out":"…"}
{"event":"header",  "magic":"CTHD","version":N,"length":N}
{"event":"saved",   "path":"…","bytes":N,"abs_path":"…"}
{"event":"done"}
```

All three emit `{"event":"error","message":"…"}` and exit
non-zero on any failure — unreadable carrier, exceeded capacity,
magic mismatch, write failure.

## Limitations

- **PNG only.** No JPEG output ever (lossy compression destroys
  LSBs). No WebP, no AVIF, no HEIC. The decoder accepts any
  format the Go stdlib reads (`image.Decode`) — paletted PNG,
  grayscale, GIF can serve as carriers — but the output is
  always PNG.
- **Statistically detectable.** Chi-squared, sample-pair, and
  RS-analysis attacks on the pixel histogram identify LSB-stego'd
  images regardless of magic bytes. The Cathedral implementation
  is for learning, demos, and CTFs — not for covert channels
  against motivated analysis.
- **Cathedral magic is trivially detectable.** The first 32 LSBs
  spell `CTHD`. Detection by anyone with Cathedral installed is
  one command (`stego info`).
- **No encryption.** Payload is plaintext bytes-for-bytes
  recoverable by anyone running `extract` on the carrier. Encrypt
  before embedding if the content matters:
  `gpg --symmetric note.txt && stego embed cover.png note.txt.gpg out.png`.
- **No filename or metadata preservation.** Embed `note.txt` and
  recover `out`; the original filename is gone. If you need the
  filename, wrap the payload in a tar / zip / single-entry
  archive first.
- **No error correction.** A single pixel modification anywhere
  in the carrier can corrupt the payload. If the carrier is
  reprocessed by anything that touches LSBs (resize, blur,
  re-encode through a lossy intermediate), extraction fails
  cleanly with a magic mismatch — never silently partial.
- **One bit per channel only.** Cathedral uses the single
  least-significant bit per R/G/B; multi-bit LSB (storing 2 or 3
  bits per channel) is not exposed. Multi-bit increases capacity
  at the cost of visible distortion above ~3 bits — not worth
  shipping in v1.
- **Carrier alpha untouched.** The alpha channel is deliberately
  skipped. Changing alpha is visually disruptive — areas with
  partial transparency show artefacts immediately. Keeping the
  channel untouched preserves visual identity in transparent
  regions.

## Authorized use

`stego` is dual-use in the same shape as `meta` and `imgforensic`:
the tool itself reads and writes files you possess, the risk
profile is low, and the offensive narrative is mostly imaginary.

**Hiding bytes in your own files is not a security event.** The
common use case is CTF puzzle construction, photo journaling,
embedding a content hash for tamper-evidence, or demonstrating
the technique for education. None of these is offensive.

**The covert-channel concern is largely a fiction at this LSB
tier.** A motivated adversary moving sensitive bytes out of a
network has dozens of better techniques than LSB-stego'd PNG
attachments. The technique remains in offensive literature
mostly as a teaching example and a misdirection — defenders
trained to look for steganography often miss simpler exfil
channels that are doing the actual work.

**For privacy of content, encrypt first.** Cathedral embeds raw
bytes; if those bytes matter, GPG-encrypt them before passing
them to `stego embed`. The composition is short:

```
gpg --symmetric note.txt          # produces note.txt.gpg
stego embed cover.png note.txt.gpg out.png
# later
stego extract out.png recovered.gpg
gpg --decrypt recovered.gpg > note.txt
```

**Test your roundtrip before relying on the carrier.** Image
hosts (Twitter, Slack, Discord) sometimes re-encode uploaded
PNGs to optimise size or convert to lossy formats — these
processes destroy LSB payloads. Upload, re-download, and try
`stego extract` before trusting any image-host channel.

## Further reading

- [Steganography: chi-squared detection of LSB embedding (Westfeld & Pfitzmann)](https://www.researchgate.net/publication/2434128) — the canonical statistical attack
- [PNG specification (W3C)](https://www.w3.org/TR/PNG/) — why PNG is lossless
- [`image/png` package](https://pkg.go.dev/image/png) — the Go stdlib decoder Cathedral relies on
- Related Cathedral commands: [`meta`](meta.md) (what metadata a file is leaking),
  [`imgforensic`](imgforensic.md) *(planned)* (integrity / polyglot / trailing-data checks)
