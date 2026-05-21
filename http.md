---
title: http — terminal HTTP client for recon and probes
command: http
category: web-app-analysis
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-20
related: [headers, tech, recon, banner, ssl, scan]
---

# `http` — terminal HTTP client for recon and probes

`http` is the everyday HTTP client inside Cathedral — the
equivalent of `curl` for quick GETs and one-off API hits, with
ergonomics shaped around the recon workflow rather than scripting.
Default scheme is `https://`, status lines colour by class, headers
come back sorted, the body is truncated to a readable preview, and
TLS verification failures fall back to insecure with a visible
warning rather than refusing the connection. It's not meant to
replace `curl` for build pipelines or `xh`/`HTTPie` for daily
console use — it's the in-Cathedral fast path for *"what does this
endpoint actually return?"*.

```
http GET https://api.example.com
http GET https://api.example.com -h "X-Token: abc" -q page=1 -q limit=50
http POST https://api.example.com name=alice age=30           # auto-JSON body
http POST https://api.example.com -b @payload.json
http DELETE https://api.example.com/users/42 -h X-Auth:secret -k
```

## What it does

For one URL, Cathedral issues a single request with the chosen
method, your headers and query parameters merged in, the body
built from either an explicit `-b` value or the `name=value`
shorthand, and a TLS strict-then-fallback connection. The response
is shown as a coloured status line (green for 2xx, dim for 3xx,
yellow for 4xx, red for 5xx), the final URL after redirects, every
response header in sorted order, and a body preview that detects
text-vs-binary from Content-Type and falls back to a NUL-byte
sniff when Content-Type is generic.

| Flag                | Meaning                                            | Default |
|---------------------|----------------------------------------------------|---------|
| `-h Name:Value`     | request header (repeatable)                        | none    |
| `-q name=value`     | query-string parameter (repeatable)                | none    |
| `-b @file`          | request body from file (Content-Type guessed)      | none    |
| `-b text`           | request body as literal text (no spaces)           | none    |
| `name=value`        | positional → collected into one JSON body object   | —       |
| `-t SEC`            | request timeout in seconds                         | `15`    |
| `-r N`              | maximum redirects to follow                        | `10`    |
| `-k`                | silence the "TLS chain unverified" warning         | off     |
| `-v`                | show the full body (no 2 KB truncation)            | off     |

The `name=value` shorthand is the headline ergonomic difference
from `curl`: passing positional `name=value` pairs builds a single
JSON object body with `Content-Type: application/json` set
automatically. For the common case of "POST this small JSON
object", you skip writing the body to a file and writing `-h
Content-Type:application/json`.

## What it answers

**Defender:** *"What does my endpoint actually return — headers,
shape, edge cases?"* Quick verification that an HSTS header is in
place, that a `Content-Security-Policy` is published, that a 404
response on a sensitive path doesn't leak through error-page
detail. The default truncated-body view stays out of the way
unless you need it; `-v` widens it when you do.

**Recon (authorized testing only):** *"What does this service
look like over the wire?"* The status line + final URL + sorted
headers gives a quick snapshot of how a target reacts to an
arbitrary request. Most fingerprinting questions are answered in
the first 50 ms of response: `Server: nginx/1.24`, `X-Powered-By:
PHP/8.1`, `Set-Cookie: PHPSESSID=…`, `Strict-Transport-Security`
present or absent. For deeper inspection see [`headers`](headers.md);
for full-stack fingerprinting see [`tech`](tech.md). `http` is the
fast `tell me what the wire looks like` reach.

**Investigation:** *"Did this endpoint just change?"* Snapshot the
status + headers + body preview against a saved baseline. The
deterministic header ordering (alphabetical) makes diffs cheap.
Subtle deployment changes — a CDN swap, a TLS chain rotation, a
new server banner — show up as one-line diffs in the headers
view.

**Build & test:** *"Does my API still behave?"* For one-off
manual checks (`http GET /healthz`, `http POST /users name=… …`),
the auto-JSON shorthand makes `http` faster to type than curl for
the common cases. Not a replacement for proper test harnesses, but
a great keystroke-saver during interactive development.

## How it works

### Methods, URL normalisation, schema default

Seven methods are allowed: `GET POST PUT PATCH DELETE HEAD
OPTIONS`. Anything else fails with a clear error; Cathedral doesn't
let you reach for `TRACE`, `CONNECT`, or non-standard verbs (those
are out of scope for the recon use case and add a footgun
surface).

The URL is normalised before the request fires. If you omit the
scheme, `https://` is prepended:

```go
if !strings.Contains(raw, "://") {
    raw = "https://" + raw
}
```

`http example.com/foo` becomes `https://example.com/foo`. This is
the right default for 2026 — HTTP without TLS is increasingly rare
on public endpoints, and getting an HTTPS connection by default
avoids the easy mistake of accidentally querying plaintext. For
endpoints that genuinely only speak HTTP, type `http://` explicitly.

Query parameters from `-q` are merged into the existing URL query
string rather than replacing it:

```go
q := u.Query()
for _, p := range qp {
    q.Add(p[0], p[1])
}
u.RawQuery = q.Encode()
```

`http GET 'https://x.com/items?archived=true' -q page=2` ends up
with both parameters set. `Add` rather than `Set` means `-q
tag=foo -q tag=bar` produces two `tag` parameters — repeated
parameters work the way HTTP allows them to.

### Bodies: `-b` vs `name=value`

Three ways to attach a body, in precedence order:

1. **`-b @file`** — read the file's bytes; guess `Content-Type`
   from the extension (`.json` → `application/json`, `.xml` →
   `application/xml`, otherwise unset).
2. **`-b text`** — literal text body (single token; for bodies
   with whitespace, use `@file`).
3. **Positional `name=value`** — accumulate into a JSON object,
   send with `Content-Type: application/json`. Empty if none
   supplied.

```go
if len(a.bodyFields) > 0 {
    obj := map[string]string{}
    for _, f := range a.bodyFields {
        obj[f[0]] = f[1]
    }
    buf, _ := json.Marshal(obj)
    return buf, "application/json", nil
}
```

For the `name=value` path, every value is a string — JSON numbers
aren't generated. `http POST … age=30` produces `{"age":"30"}`,
not `{"age":30}`. APIs that strictly require typed values need
`-b @file` with hand-written JSON; this is a deliberate
simplification, not an oversight.

### TLS strict-then-fallback

Default TLS verification is strict. On a verification failure
(`x509: certificate signed by unknown authority`,
`certificate has expired`, name mismatch), Cathedral retries the
*same* request with `InsecureSkipVerify: true` and emits a
`tls_warning` event so the fallback is visible:

```go
strict := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
}}
resp, err := strict.Do(req)
if err == nil { return resp, "", nil }
if !isTLSVerifyError(err) { return nil, "", err }

insecure := &http.Client{Transport: &http.Transport{
    TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
}}
return insecure.Do(req.Clone(req.Context()))
```

The fallback is the right default for security-recon work:
self-signed certs on dev servers, expired certs on neglected
hosts, name-mismatched certs on multi-tenant infrastructure are
all *interesting*, and refusing to talk to them would hide signal.
The visible warning ensures the operator knows. `-k` silences the
warning when the fallback is expected (auditing a known
self-signed lab box, for instance) but doesn't change the
behaviour.

Non-verification TLS failures (handshake errors, no shared cipher,
protocol mismatch) propagate up as plain errors — there's no point
retrying those insecurely.

### Response display: status, headers, body

The response sequence is fixed:

```
< HTTP/2.0 200   47ms   3142 B
  url    : https://api.example.com/v1/items

[ headers ]
  Cache-Control                public, max-age=300
  Content-Encoding             gzip
  Content-Type                 application/json
  …

  [body — 3142 B]    application/json
  { "items": [...] }
```

Headers are sorted alphabetically by name, with repeated
header names emitted in document order. Sorting means reruns
produce byte-identical output (modulo elapsed time), so
`http` calls compose cleanly into diffs and snapshots.

The body preview truncates at 2 KB by default and shows the
truncation as `[body — 47813 B, truncated; pass -v for full]`.
The 2 KB default is sized for "I want to see roughly what came
back" rather than "I want to read the whole response" —
that's what `-v` is for.

### Binary vs text body detection

Body is rendered as text if Content-Type starts with `text/`,
contains `json`, `xml`, `javascript`, `html`, `yaml`, or
`x-www-form-urlencoded`. When Content-Type is missing or generic
(`application/octet-stream`), Cathedral sniffs the first 512
bytes: a NUL byte means binary, otherwise text.

```go
if strings.HasPrefix(ct, "text/") ||
    strings.Contains(ct, "json") ||
    strings.Contains(ct, "xml") ||
    strings.Contains(ct, "javascript") ||
    strings.Contains(ct, "html") ||
    strings.Contains(ct, "yaml") {
    return true
}
if ct != "" { return false }
// Sniff for NUL bytes in the first 512 bytes
for _, b := range probe { if b == 0 { return false } }
return true
```

Binary bodies are summarised as `[body — 47813 B binary,
image/png]` plus the first 64 bytes as space-separated hex —
enough to identify the file type by magic number without dumping
the whole payload. For full binary capture, redirect the JSON
event stream and decode `body_binary` events yourself.

## What Cathedral doesn't do

A few deliberate omissions:

- **Cookie jar.** Each `http` invocation is independent — no
  persistent cookie store, no session resumption. For multi-step
  flows that need session cookies, pass them explicitly with
  `-h "Cookie: name=value; …"`. Cathedral's "session"
  abstraction lives at the shell layer (`!` history substitution,
  variables), not in the HTTP client.
- **Multipart / file upload.** `multipart/form-data` requires
  boundary handling and per-field metadata that doesn't fit the
  current arg shape. `-b @file` sends the file as the *whole
  body*, not as one field of a multipart payload. Use `curl
  -F` for true file upload.
- **Auth helpers.** No `--basic`, no `--bearer` wrapper. Basic
  auth: pass `-h "Authorization: Basic $(echo -n user:pass |
  base64)"`. Bearer token: `-h "Authorization: Bearer …"`.
  Cathedral keeps the auth surface explicit because surprises in
  request headers cost more than the convenience saves.
- **HTTP/3 / QUIC.** Cathedral negotiates HTTP/2 over TLS via
  ALPN when the server offers it; HTTP/3 support requires a
  QUIC stack that's not yet in scope.
- **WebSocket / SSE.** `http` does one request, reads one
  response, exits. Long-lived bidirectional protocols are out of
  scope.
- **Load testing.** No `-n N` for repeated requests, no
  concurrency knob, no histogram output. `vegeta` or `wrk` are
  the right reach for that work; Cathedral's `http` is for
  single-shot inspection.
- **Body diff.** Cathedral renders the response; comparing two
  responses is a job for `diff` or `jd` against captured JSON
  output (`http … -j | jq .body.text > snapshot`).

## Worked example

### Simple GET

```
operator@cathedral:~$ http GET https://api.acme-supplies.example/v1/health
> GET https://api.acme-supplies.example/v1/health

< HTTP/2.0 200   34ms   87 B
  url    : https://api.acme-supplies.example/v1/health

[ headers ]
  Cache-Control                no-store
  Content-Length               87
  Content-Type                 application/json
  Date                         Wed, 20 May 2026 16:42:08 GMT
  Server                       envoy
  Strict-Transport-Security    max-age=63072000; includeSubDomains
  X-Envoy-Upstream-Service-Time 12

  [body — 87 B]    application/json
  {"status":"ok","commit":"acb12f9","uptime_s":2418357}
```

The status line carries everything you'd want at a glance:
HTTP/2, 200 OK, 34 ms wall-clock, 87 bytes. The presence of
Envoy headers and the `X-Envoy-Upstream-Service-Time` reveal an
Envoy reverse proxy in front of the actual service. HSTS is
published with `includeSubDomains` — a competent baseline.

### Headers and query parameters

```
operator@cathedral:~$ http GET https://api.acme-supplies.example/v1/orders \
    -h "Authorization: Bearer eyJhbGciOi…" \
    -q status=pending \
    -q limit=25
> GET https://api.acme-supplies.example/v1/orders?status=pending&limit=25

< HTTP/2.0 200   58ms   3142 B
  url    : https://api.acme-supplies.example/v1/orders?status=pending&limit=25

[ headers ]
  Cache-Control                private, no-cache
  Content-Type                 application/json
  ETag                         "W/\"c4e2f1b8\""
  RateLimit-Limit              1000
  RateLimit-Remaining          997
  RateLimit-Reset              42

  [body — 3142 B]    application/json
  {"orders":[{"id":"ord_91Hk2","status":"pending","amount_cents":4900,…
```

Query params show up appended to the URL — and crucially, the
*final URL after redirects* is reported separately on the `url:`
line, so you see both what you asked for and where you ended up.
The `RateLimit-*` headers are visible at-a-glance for sustainable
batch work.

### POST with auto-JSON shorthand

```
operator@cathedral:~$ http POST https://api.acme-supplies.example/v1/contacts \
    -h "Authorization: Bearer …" \
    name=Alice \
    email=alice@example.com \
    role=admin
> POST https://api.acme-supplies.example/v1/contacts   body 56 B

< HTTP/2.0 201   71ms   142 B
  url    : https://api.acme-supplies.example/v1/contacts

[ headers ]
  Content-Type                 application/json
  Location                     /v1/contacts/cnt_91xK
  Server                       envoy

  [body — 142 B]    application/json
  {"id":"cnt_91xK","name":"Alice","email":"alice@example.com","role":"admin","created_at":"2026-05-20T16:42:08Z"}
```

The `body 56 B` indicator on the request line is computed from
the JSON object that was built — three name=value pairs serialised
to `{"name":"Alice","email":"…","role":"admin"}`. The `Location:
/v1/contacts/cnt_91xK` header on the response gives back the
new resource path; `201 Created` confirms the contract.

### POST with explicit file body

```
operator@cathedral:~$ http POST https://api.acme-supplies.example/v1/import \
    -h "Authorization: Bearer …" \
    -b @inventory.json
> POST https://api.acme-supplies.example/v1/import   body 41827 B

< HTTP/2.0 202   213ms   58 B
  url    : https://api.acme-supplies.example/v1/import

[ headers ]
  Content-Type                 application/json
  Location                     /v1/imports/imp_22zN

  [body — 58 B]    application/json
  {"id":"imp_22zN","status":"queued","items":342}
```

`-b @inventory.json` reads the file, sets `Content-Type:
application/json` automatically from the extension, and sends
the 41 KB payload. The 202 Accepted plus Location header is the
canonical async-job pattern: the server acknowledged receipt,
the actual processing happens in the background, and the
returned URL lets you poll for status.

### TLS auto-fallback on self-signed cert

```
operator@cathedral:~$ http GET https://lab-staging.acme-supplies.example
> GET https://lab-staging.acme-supplies.example
  ! TLS chain UNVERIFIED — continuing insecure
    x509: certificate signed by unknown authority

< HTTP/1.1 200   47ms   1842 B
  url    : https://lab-staging.acme-supplies.example/

[ headers ]
  Content-Type                 text/html; charset=utf-8
  Server                       gunicorn/21.2.0

  [body — 1842 B]    text/html; charset=utf-8
  <!doctype html>
  <html><head><title>acme-supplies — staging</title>…
```

The two-line TLS warning is the salient detail. The strict
verification attempt failed (`x509: certificate signed by unknown
authority` — the staging environment uses an internal CA);
Cathedral retried insecurely so the operator can still see the
response. The warning is loud enough to be visible but doesn't
block the work. `-k` would suppress the warning if you're
intentionally auditing a known-insecure target.

### Binary response

```
operator@cathedral:~$ http GET https://api.acme-supplies.example/v1/avatar/alice.png
> GET https://api.acme-supplies.example/v1/avatar/alice.png

< HTTP/2.0 200   28ms   2841 B
  url    : https://api.acme-supplies.example/v1/avatar/alice.png

[ headers ]
  Cache-Control                public, max-age=86400
  Content-Length               2841
  Content-Type                 image/png

  [body — 2841 B binary, image/png]
  hex: 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00 00 00 80 00 00 00 80 08 06 00 00 00 c3 3e 61 cb …
```

The `89 50 4e 47 0d 0a 1a 0a` opening is the PNG magic number —
exactly what the Content-Type advertises. The hex preview is the
fast way to confirm "yes, this really is a PNG" without dumping
the whole binary to the console. To capture the body, redirect
the JSON event stream and decode the `body_binary` event's
`bytes` field externally.

### HEAD and OPTIONS for surface inspection

```
operator@cathedral:~$ http HEAD https://api.acme-supplies.example/v1/items/42

< HTTP/2.0 200   31ms   0 B
  url    : https://api.acme-supplies.example/v1/items/42

[ headers ]
  Content-Length               1842
  Content-Type                 application/json
  ETag                         "W/\"7c8b1d23\""
  Last-Modified                Tue, 18 May 2026 12:00:00 GMT
```

```
operator@cathedral:~$ http OPTIONS https://api.acme-supplies.example/v1/items

< HTTP/2.0 204   24ms   0 B

[ headers ]
  Access-Control-Allow-Methods GET, POST, PATCH, DELETE
  Access-Control-Allow-Origin  *
  Access-Control-Max-Age       86400
  Allow                        GET, POST, PATCH, DELETE
```

`HEAD` is the bandwidth-cheap version of "does this resource
exist and how big is it"; `OPTIONS` reports CORS posture and the
allowed-methods set. Both are fast and unobtrusive — useful first
reaches before issuing a real request to an unfamiliar endpoint.

## Output protocol

```
{"event":"start",       "method":"GET","url":"…","body":N}
{"event":"tls_warning", "message":"x509: …"}                              # optional
{"event":"response",    "status":N,"proto":"HTTP/2.0","url":"…",
                        "server":"…","bytes":N,"elapsed_ms":N}
{"event":"header",      "name":"…","value":"…"}                           *
{"event":"body_text",   "text":"…","bytes":N,"truncated":true|false,
                        "content_type":"…"}                               # one of
{"event":"body_binary", "bytes":N,"content_type":"…","hex":"89 50 4e …"}  # one of
{"event":"done"}
{"event":"error",       "message":"…"}
```

`response.url` is the final URL after redirect chasing — different
from `start.url` when redirects fired. `body` on the start event
is the request body length; `bytes` on the response event is the
response body length (capped at 4 MB by the reader).

Pipe to extract just one header value:

```
$ http GET https://api.acme-supplies.example -j |
    jq -r 'select(.event=="header" and .name=="Server") | .value'
envoy
```

Snapshot headers + status for diffing:

```
$ http GET https://api.acme-supplies.example -j |
    jq -r 'select(.event=="header") | "\(.name): \(.value)"' \
    > /tmp/headers-today.txt
# … one day later …
$ diff /tmp/headers-yesterday.txt /tmp/headers-today.txt
```

Quick check for HSTS posture across a list of hosts:

```
$ for h in $(cat hosts.txt); do
    hsts=$(http GET "https://$h" -j |
      jq -r 'select(.event=="header" and .name=="Strict-Transport-Security") | .value')
    printf '%-40s %s\n' "$h" "${hsts:-MISSING}"
  done
```

## Limitations

- **One request, one response.** No multi-step flows, no session
  cookies, no persistent state between invocations.
- **Body capped at 4 MB.** Larger responses are truncated at the
  reader level (not just the preview). For large downloads, `curl
  -O` remains the right tool.
- **Body preview is 2 KB without `-v`.** The preview is a
  *preview*, not a capture. For complete body access in scripts,
  use the JSON event stream rather than relying on the rendered
  output.
- **JSON shorthand values are strings.** `name=30` yields
  `"30"`, not `30`. For typed JSON bodies (numbers, booleans,
  nested objects), use `-b @file`.
- **TLS fallback is automatic and visible.** Cathedral does not
  *fail closed* on TLS errors — it falls back to insecure and
  warns. If your security model requires failing closed, use a
  different client; the recon use case Cathedral targets values
  signal over enforcement.
- **No connection reuse.** Each invocation opens a fresh TCP +
  TLS connection. For per-request latency testing the warm-up
  cost (TLS handshake) is included in the elapsed time.
- **No HTTP/3.** ALPN negotiates HTTP/2 over TLS where the
  server offers it; HTTP/3 / QUIC support is not yet present.
- **Default timeout 15 s.** Long-running endpoints (intentional
  long-poll, slow backends) need explicit `-t`.

## Authorized use

`http` is **a general-purpose HTTP client**. Whether it counts as
"recon", "testing", or "ordinary work" depends entirely on what
you ask it to talk to. Targeting public marketing pages is
unremarkable; targeting authenticated endpoints on
infrastructure you don't own is not.

Three notes worth attaching:

**You're the source IP.** Every request goes out from your
machine's IP. There's no anonymisation layer, no rotating proxy.
Targets log your requests; rate-limit systems count them against
your address. For sensitive testing, route through a Burp /
mitmproxy / authorised testing proxy.

**Don't probe rate-limited APIs in a loop without permission.**
Single requests are unremarkable. Bulk patterns (especially
patterns that resemble enumeration of identifiers) trip both
abuse-detection systems and trigger legal exposure for
unauthorised access. The constraints are policy, not technical
ones — `http` enforces nothing.

**TLS fallback hides cert errors.** Cathedral's default behaviour
is to retry insecurely and warn. For environments where TLS errors
are themselves the finding (compliance audits, certificate
hygiene checks), record the `tls_warning` event from the JSON
output rather than relying on the rendered warning to surface in
operator attention.

## Further reading

- [RFC 9110 — HTTP Semantics](https://www.rfc-editor.org/rfc/rfc9110) — the modern HTTP specification (supersedes RFC 7230–7235)
- [RFC 9112 — HTTP/1.1](https://www.rfc-editor.org/rfc/rfc9112) — wire format for HTTP/1.1
- [RFC 9113 — HTTP/2](https://www.rfc-editor.org/rfc/rfc9113) — binary framing protocol
- [RFC 6797 — HTTP Strict Transport Security (HSTS)](https://www.rfc-editor.org/rfc/rfc6797) — the header most recon checks look for first
- [HTTPie documentation](https://httpie.io/docs) — the ergonomic ancestor of the `name=value` JSON shorthand
- Related Cathedral commands: [`headers`](headers.md) (depth-focused header inspection — what each header *means*),
  [`tech`](tech.md) (full-stack fingerprinting via response patterns),
  [`recon`](recon.md) (breadth-first HTTP discovery — robots.txt, sitemap, .well-known),
  [`banner`](banner.md) (single-port banner grab — the layer below HTTP),
  [`ssl`](ssl.md) *(planned — TLS certificate inspection)*,
  [`scan`](scan.md) (TCP port scanner with banner grab)
