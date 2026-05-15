---
title: meta — document and image metadata extraction
command: meta
category: file forensics
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-13
related: [imgforensic, stego]
---

# `meta` — document and image metadata extraction

`meta` reads metadata from documents and images and surfaces what the file
is leaking about its origin. Author names, GPS coordinates from photos,
filesystem paths embedded in PDF software strings, software versions, and
hidden timestamps — all the things that travel with a file when it's
shared, that the file's owner rarely realises are there.

```
meta vacation.jpg
meta report.pdf
meta --format=pdf scan.bin    # force a specific parser
```

## What it does

`meta` is read-only: it opens a file, parses its embedded metadata, and
emits structured findings. It never modifies the file. It never reaches
the network. v1 supports four format families:

| Family       | Extensions                  | Library              |
|--------------|-----------------------------|----------------------|
| PDF          | `.pdf`                      | `rsc.io/pdf`         |
| EXIF (image) | `.jpg`, `.jpeg`, `.tif`     | `rwcarlsen/goexif`   |
| PNG chunks   | `.png`                      | stdlib + custom      |
| OOXML        | `.docx`, `.xlsx`, `.pptx`   | stdlib `archive/zip` |

The output is a single human-readable summary in the terminal, or a
JSON-line event stream for piping into other Cathedral tools (`-j` flag).

## What it answers

Two recurring questions:

**Defender:** *"What is this file leaking about me when I share it?"*
A PDF saved from a browser embeds the operating-system username in the
`Creator` string. A photo from a phone embeds GPS coordinates accurate
to the meter. A `docx` saved through Office 365 embeds the "Last
Modified By" account. None of this is visible in the document viewer.
All of it travels.

**Recon:** *"What can I learn about a target from a file they published?"*
Public PDFs on a target's website carry the author's name and the
PDF-generation toolchain. Embedded JPEGs in marketing material carry
GPS coordinates and camera serial numbers. The metadata trail predates
the file by years.

Both questions are answered by the same tool: read what's embedded,
present it legibly, tag the leaky bits.

## How it works

### Format detection

`meta` picks the parser via two passes. Extension first, magic-byte
sniff second so renamed files don't mislead.

```go
ext := strings.ToLower(strings.TrimPrefix(filepath.Ext(path), "."))
switch ext {
case "pdf":           return "pdf"
case "jpg", "jpeg":   return "jpeg"
case "tif", "tiff":   return "tiff"
}

// Fallback: read the first 12 bytes.
hdr := make([]byte, 12)
io.ReadFull(f, hdr)
switch {
case string(hdr[:4]) == "%PDF":               return "pdf"
case hdr[0] == 0xFF && hdr[1] == 0xD8:        return "jpeg"
case string(hdr[:4]) == "II*\x00":            return "tiff"
}
```

Extension-first is faster and right 99% of the time; magic-byte
fallback catches the renamed-payload case (`evil.pdf` that's actually
a PNG). Format mismatch is itself a finding worth surfacing.

### PDF: the `/Info` dictionary

PDFs carry a document-info dictionary in the trailer. Standard keys
(PDF 1.7): `Title`, `Author`, `Subject`, `Keywords`, `Creator`,
`Producer`, `CreationDate`, `ModDate`, `Trapped`. Any other keys are
pipeline-specific (`AAPL:Keywords` from Apple Preview,
`xmpmm:Identifier` from Adobe).

The interesting leakage lives in `Creator` and `Producer`. Browsers
save PDFs with strings like:

```
Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)
Chrome/138.0.0.0 Safari/537.36
```

That's a full OS fingerprint. macOS Preview adds:

```
Mac OS X 14.5 Quartz PDFContext
```

…which discloses OS version. Word saves with `Microsoft® Word 2019`
plus an internal path like `C:\Users\jsmith\Documents\…` in `Subject`
if the user typed metadata there. Cathedral flags the path-shaped
strings:

```go
func looksLikePath(s string) bool {
    if strings.HasPrefix(s, "/") && len(s) > 3 {
        return true
    }
    if len(s) >= 3 && s[1] == ':' && (s[2] == '\\' || s[2] == '/') {
        return true // C:\... style
    }
    return strings.Contains(s, "\\Users\\") ||
        strings.Contains(s, "/Users/")    ||
        strings.Contains(s, "/home/")
}
```

When `Creator` or `Producer` matches, the field is tagged `path` and
the leakage verdict bumps up.

### EXIF: rationals to decimal coordinates

GPS coordinates in EXIF are stored as three rationals (degrees,
minutes, seconds) plus a reference letter — `N` or `S` for latitude,
`E` or `W` for longitude. To get a usable decimal value, you have to
convert and sign-flip.

```go
deg := float64(num0) / float64(den0)
min := float64(num1) / float64(den1)
sec := float64(num2) / float64(den2)
v := deg + min/60.0 + sec/3600.0
if ref == "S" || ref == "W" {
    v = -v
}
```

Verified on a sample image: the EXIF rationals
`(40/1, 46/1, 13.2/1)` with ref `N` and `(111/1, 53/1, 28.4/1)` with
ref `W` produce `40.770339, -111.891222` — Salt Lake Temple Square,
which is exactly where the photo was taken.

The negative longitude is the easy thing to get wrong. EXIF's reference
letter is *not* a sign; it's a hemisphere indicator. `W` of the prime
meridian means negative longitude in decimal degrees. Forgetting the
flip puts your image somewhere in China.

### Leakage verdict

After extraction, Cathedral tallies the tagged fields and emits a
one-word verdict:

| Score | Verdict | Example triggers                                                    |
|-------|---------|---------------------------------------------------------------------|
| 0     | NONE    | nothing flagged                                                     |
| 1–2   | LOW     | a single software/version string, or a name, or a path              |
| 3–4   | MED     | GPS alone (3), name + path (4), or path + software (3)              |
| 5+    | HIGH    | GPS + name or path, or multiple categories together                 |

The verdict is heuristic — refining it as more formats land is on the
roadmap.

## Worked example

```
$ meta vacation.jpg
> reading vacation.jpg
  format: jpeg    4231156 bytes

[ camera ]
    camera-make:           Apple
    camera-model:          iPhone 14 Pro

[ exposure ]
    f-number:              1.78
    iso:                   400
    focal-length:          6.86

[ gps ]
  * gps:                   40.770339, -111.891222
  * gps-altitude:          1320 m
  * gps-date:              2024:09:12

[ software ]
  * software:              17.5.1

  ! [med] image carries GPS coordinates: 40.770339, -111.891222

verdict: leakage MED (3 gps · 1 software)
```

The fields prefixed with `*` are leakage-tagged. The Flutter UI
highlights them, and (when running inside the Cathedral interface) the
GPS coordinates pin on the globe view.

## Output protocol

`meta` emits these JSON-line events on stdout:

```
{"event":"start",  "file":"…", "format":"pdf|jpeg|tiff|…", "size":N}
{"event":"field",  "key":"…",  "value":"…", "category":"…", "tag":"…"?}*
{"event":"finding","severity":"info|low|med|high", "message":"…"}*
{"event":"verdict","leakage":"NONE|LOW|MED|HIGH", "counts":{…}}
{"event":"done"}
```

`category` groups fields visually (`document`, `camera`, `gps`,
`software`, `exposure`, `time`, `image`). `tag` flags PII-shaped or
recon-shaped fields (`name`, `path`, `gps`, `software`, `version`).
Findings are higher-signal cross-field notes.

This protocol is what makes `meta` composable. Pipe it through `jq`:

```
$ meta photos/*.jpg -j | jq -r 'select(.event=="verdict") | .leakage' | sort | uniq -c
   12 HIGH
   34 LOW
    8 MED
```

## Limitations

- **No XMP stream extraction yet.** PDFs increasingly carry XMP
  metadata alongside `/Info`, and `rsc.io/pdf` doesn't expose it
  directly. Planned for v1.1.
- **HEIC images not supported.** Same EXIF structure, different
  container. Planned for v1.2.
- **No write capability.** Cathedral does not strip metadata; that's a
  separate tool with different safety properties. Use `exiftool -all=`
  if you need to scrub.
- **OOXML reads core/app props only.** Document revision history,
  redaction artifacts, and embedded objects are out of scope for v1.

## Authorized use

`meta` is read-only and parses files you possess. The risk profile is
the same as opening "Properties" in a file manager — Cathedral just
makes the contents legible across formats from one verb. No
authorized-use banner applies.

That said: extracting EXIF from images you found on someone else's
public website is *recon*, and how you use the resulting GPS
coordinates is governed by the rules of your engagement, not the rules
of this tool.

## Further reading

- [Adobe PDF 1.7 specification, §14.3.3 (Document Information Dictionary)](https://opensource.adobe.com/dc-acrobat-sdk-docs/standards/pdfstandards/pdf/PDF32000_2008.pdf)
- [EXIF 2.32 specification (CIPA DC-008)](https://www.cipa.jp/std/documents/e/DC-008-Translation-2019-E.pdf)
- Related Cathedral commands: [`imgforensic`](./imgforensic.md), [`stego`](./stego.md)
