---
title: web — a lynx-style text browser, with forms, Tor and reader mode
command: web
category: browsing
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-11-23
related: [msg, ai, headers, ssl, tech, waf, http]
---

# `web` — a lynx-style text browser, with forms, Tor and reader mode

`web` is a web browser in Cathedral's main pane. It renders pages as
text, the way lynx does. Every link and form field gets a number, you
move between them with the arrow keys, and nothing on the page runs
code. There's no JavaScript engine, so there are no trackers, no
fingerprinting scripts and no pop-ups. One key switches every request
onto Tor, and `.onion` addresses switch it on by themselves.

```
web                          # reopen where you left off (or the start page)
web <url>                    # https://go.dev/doc, file:///…, http://localhost:8080
web <host>                   # go.dev, en.wikipedia.org/wiki/Lynx → https://
web <path>                   # ./report.html, ~/notes/index.html → file://
web <search words>           # anything else → DuckDuckGo (no-JS HTML edition)
web -b                       # bookmarks
```

## What it does

The page takes over the main pane. The title and URL sit across the
top, the page fills the middle, and a status line at the bottom shows
the selected link's URL, or what Enter will do on a form field.

| Key          | Action                                                       |
|--------------|--------------------------------------------------------------|
| `↑` `↓` `Tab`| previous / next link or form field                           |
| `↵`          | follow the link, edit / toggle / pick / submit the field     |
| `12↵`        | jump straight to item `[12]`                                 |
| `←` `⌫` `→`  | back / forward (cached: instant and offline)                 |
| `g` / `G`    | go to a URL or search / edit the current URL                 |
| `/` `n` `N`  | find in page, next / previous match                          |
| `Space` `b`  | page down / up                                               |
| `z`          | reader mode: just the article                                |
| `i`          | image gallery, dithered into phosphor green                  |
| `T`          | Tor mode on / off                                            |
| `v` or `\`   | view source in the editor                                    |
| `A`          | send the page to the [`ai`](ai.md)                           |
| `R`          | recon this site: `headers` `ssl` `tech` `waf` `dns` `whois` `geoip` |
| `d`          | download the selected link to `~/Downloads`                  |
| `a` / `B`    | bookmark this page / list bookmarks                          |
| `r` `y`      | reload / copy the URL                                        |
| `Esc`        | stop loading, clear the find, or go back to the console      |

The mouse works too. Click a link to follow it, click an `[image]` to
preview it, and select text to copy it with `Ctrl+C`.

## What it answers

**"What does this page actually say?"** A text rendering strips a
page down to what's written on it. Reader mode goes further and drops
the menus, sidebars, share buttons and footers. That leaves something
the [`ai`](ai.md) can summarise in one keypress, because you can send
it a page without pasting into a cloud service.

**"What is this site, really?"** `R` hands the current site to
Cathedral's recon commands, and the output lands in the console. You
go from reading a page to its TLS chain, security headers, WAF and
technology stack in two keystrokes. `v` opens the raw HTML in the
editor with syntax highlighting, so you can look for comments,
endpoints or a version string.

**"Can I look at this without being seen?"** Tor mode routes every
request through Tor, including the hostname lookup, and keeps its own
cookies. A Tor request can't fall back to your real IP. `.onion`
services just work.

**"Can I browse something sketchy safely?"** A browser that runs no
JavaScript, plays no media and renders no fonts or SVG has a much
smaller attack surface than a full browser. That doesn't make a
hostile page harmless (see *Limitations*), but it's a reasonable way
to look at a phishing kit's landing page or a link from an incident
ticket.

## How it works

### A sidecar that fetches, a UI that lays out

```
Cathedral UI ──stdin──▶ web serve ──HTTP(S)──▶ the site
             ◀─stdout── (sidecar)  ──SOCKS5──▶ bundled tor ──▶ the site / .onion
               JSON lines
```

`web serve` is a Go sidecar. It owns the HTTP clients, the cookie
jars, character-set decoding and HTML parsing (`golang.org/x/net/html`,
the same tokenizer the Go project uses). It doesn't send the UI text
that's already wrapped. It sends **structured blocks**: headings,
paragraphs, list items with their bullets, code, quotes, tables and
collapsible sections, each made of styled *runs*. Flutter does the
layout, because only the UI knows how wide the pane is.

```go
type Run struct {
	S   string `json:"s"`
	L   int    `json:"l,omitempty"`   // link number, 0 = plain text
	B   bool   `json:"b,omitempty"`   // bold
	I   bool   `json:"i,omitempty"`   // italic
	C   bool   `json:"c,omitempty"`   // code
	Fld int    `json:"fld,omitempty"` // form field
	Im  int    `json:"im,omitempty"`  // image
}
```

### Numbering links like lynx

The renderer walks the DOM once. Each `<a href>` it meets is resolved
against the page URL (or `<base href>`) and appended to the page's
link list. Its number is its position in that list, so the numbers
read top to bottom, in document order. Form controls and `<summary>`
toggles are numbered from the same counter, which is how `↓` and
`12↵` reach them too.

A few rules keep the numbering clean:

```go
case atom.A:
	href := strings.TrimSpace(attr(n, "href"))
	if href == "" || strings.HasPrefix(strings.ToLower(href), "javascript:") {
		r.children(n) // not a real link: render the text, no number
		return
	}
	u, _ := r.base.Parse(href)
	dest := unwrapRedirect(u).String()
	r.page.Links = append(r.page.Links, Link{Href: dest})
	r.link = len(r.page.Links)
	before := r.runCount()
	r.children(n)
	if r.runCount() == before { // the link had no text: an icon
		if k := len(r.page.Links); k >= 2 && r.page.Links[k-2].Href == dest {
			r.page.Links = r.page.Links[:k-1] // favicon next to its title: drop it
			return
		}
		r.addRun(Run{S: firstNonEmpty(attr(n, "aria-label"), attr(n, "title"), tail(u))})
	}
```

`unwrapRedirect` strips the click-tracking wrappers search engines
put around results (`duckduckgo.com/l/?uddg=…`, `google.com/url?q=…`).
The status line then shows the real destination, and following the
link goes straight there.

Other rules, each learned from a real page:

- An image without alt text is decoration and is skipped. An image
  with alt text renders as `[alt]`.
- Form controls outside any `<form>` are JavaScript UI (Wikipedia's
  menu checkboxes and `[hide]` buttons) and are dropped.
- Anything with `hidden`, `aria-hidden="true"` or an inline
  `display:none` is skipped.
- Two links touching with no whitespace between them get a space.
  A graphical browser would separate them with CSS, which a text
  renderer doesn't run.

### Tables: data or layout?

Plenty of old sites lay out the whole page with `<table>`. A text
browser that drew every table as a grid would draw the page frame as
one. So the renderer classifies each table first:

```go
// Layout tables nest other tables or are marked presentational.
// Data tables have ≥2 rows and ≥2 columns somewhere.
func isDataTable(n *html.Node) bool {
	role := strings.ToLower(attr(n, "role"))
	if role == "presentation" || role == "none" {
		return false
	}
	rows, maxCols, nested := countRows(n)
	return !nested && rows >= 2 && maxCols >= 2 && maxCols <= 30
}
```

A layout table flows row by row, the way prose does. A data table
becomes one block whose cells carry their own runs, colspan and
header flag, including any links and form fields inside them. The UI
lays it out as a grid of monospace character widths. Each column
first gets its natural width, the longest cell. If the table doesn't
fit the pane, every column keeps at least its longest word and the
remaining width is shared out in proportion. Cells wrap inside their
column, and a horizontal scroll is the last resort. A Wikipedia
infobox comes out as a two-column fact sheet, and Hacker News comes
out as rank │ vote │ title.

### Reader mode

`z` re-renders the current page from the sidecar's cache of recent
page bodies, with no refetch. This time the renderer starts at the
content container instead of `<html>`. Explicit markers are ranked
from most specific to least:

```go
switch {
case id == "mw-content-text" || hasClass(n, "post-content", "entry-content",
	"article-body", "markdown-body"):
	rank = 3 // a known content container
case n.DataAtom == atom.Article:
	rank = 2
case n.DataAtom == atom.Main || attr(n, "role") == "main":
	rank = 1 // often wraps the sidebar too
}
```

If no marker holds at least 200 characters of text, it falls back to
scoring every `<p>`. Each paragraph adds its text length to its
parent's score and half of it to its grandparent's. The highest
scorer is where the article lives, the same idea as the classic
readability algorithms. Inside that root, `<nav>`, `<aside>`,
`<footer>`, forms, and elements whose class or id has tokens like
`sidebar`, `share`, `cookie`, `navbox` or `editsection` are dropped.

On Wikipedia this takes an article from about 1,150 numbered links to
about 400. The infobox and the text stay. The site menus, the "edit"
links and the navigation boxes at the bottom go.

### Forms

Forms are the part that makes a text browser genuinely useful: search
boxes, logins, filters. The renderer records each `<form>` (action,
method, enctype) and each control in it, including hidden ones,
because those have to be submitted even though they're never shown.

In the UI, Enter on a field depends on its type:

- **Text and password fields** open a one-line editor in the bottom
  bar. Passwords show as `•••`.
- **Enter in that editor** moves to the form's next text field, and on
  the last one it submits. A login is username `↵` password `↵`, as
  in a graphical browser.
- **Checkboxes and radios** toggle. **`<select>`** opens a picker.
  **Buttons** submit.

What gets sent follows the HTML specification's rules for building a
form's entry list. Controls are included in document order. Disabled
and unnamed controls are skipped. Checkboxes and radios are included
only when checked. Only the button you pressed is included. An image
button sends `name.x=0&name.y=0`. Pressing Enter in a text field
counts as the form's first submit button, as browsers do. The sidecar
then builds the request:

```go
if method == "POST" {
	body := encodeFields(fields)            // ordered, unlike url.Values
	rq, _ = http.NewRequestWithContext(ctx, "POST", action, strings.NewReader(body))
	rq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
} else {
	u.RawQuery = encodeFields(fields)        // GET replaces the action's query
	rq, _ = http.NewRequestWithContext(ctx, "GET", u.String(), nil)
}
```

The session's cookie jar follows the redirect after a login, so the
session cookie set by the POST is sent on the page after it. What you
typed into a form survives going back and forward in history.

### Tor mode, and why it never falls back

The sidecar starts its **own** copy of the bundled Tor (the same
signature-verified build [`msg`](msg.md) uses) with its own data
directory, a control port, and `__OwningControllerProcess` so Tor dies
with the sidecar. Once Tor reports 100% bootstrap, Tor requests go
through a second HTTP client:

```go
d, _ := proxy.SOCKS5("tcp", tp.socks, nil, proxy.Direct)
client := &http.Client{
	Jar:     torJar,                      // never shares cookies with clearnet
	Timeout: 90 * time.Second,            // circuits are slow, onions slower
	Transport: &http.Transport{
		DialContext: d.(proxy.ContextDialer).DialContext,
		Proxy:       nil,                 // no env proxy on top of tor
	},
}
```

The SOCKS5 dialer sends Tor the hostname, not an IP address, so Tor
resolves it. That's what makes `.onion` addresses work, and it means
no clearnet DNS query leaks your browsing. The two clients never mix:

```go
client := clear
if r.Tor {
	client = tor.current()
	if client == nil {
		// Never fall back to the clear client for a tor request.
		return fail(errors.New("tor is not running (T to start it)"))
	}
}
```

Downloads, view-source fetches and image previews from a page loaded
over Tor also go over Tor. `R` recon refuses to run in Tor mode, and
says why. The recon tools are separate programs that connect
directly, so running them would show the site your real address in
the middle of a Tor session.

### Image previews

A text browser normally shows an image as its alt text, and so does
`web`, until you press `i`. The sidecar then fetches the image (PNG,
JPEG, GIF, WebP or BMP; SVG is skipped because Go has no rasteriser
for it). It shrinks the image to fit 320×240 and dithers it into four
phosphor greens. The UI draws it at 2× with nearest-neighbour scaling,
so it reads as the same CRT as the rest of the screen.

```go
// Floyd–Steinberg error diffusion onto 4 phosphor levels.
for y := 0; y < h; y++ {
	for x := 0; x < w; x++ {
		v := clamp01(g[y][x])
		q := int(v*3 + 0.5)                 // nearest of 4 levels
		img.SetRGBA(x, y, phosphor[q])
		e := v - float64(q)/3                // push the error onto neighbours
		g[y][x+1] += e * 7 / 16
		g[y+1][x-1] += e * 3 / 16
		g[y+1][x] += e * 5 / 16
		g[y+1][x+1] += e * 1 / 16
	}
}
```

The dither happens pixel by pixel in Go, not as a colour filter in
the UI. A colour-matrix filter can't express the error diffusion, and
negative weights in one render as solid black.

### Downloads

Opening a URL that turns out not to be text (a zip, a PDF, an ISO)
doesn't read it into memory. The sidecar replies with `"binary": true`,
the content type and the size. The UI asks
`download archive.zip (application/zip, 12.4 MB) to ~/Downloads? y/n`.
`d` on a selected link skips the question.

The file name comes from `Content-Disposition`, or failing that the
URL's last path segment. It's reduced to a bare base name, so
`../../.bashrc` becomes `bashrc`. The download streams to
`name.part`, with progress shown in the header, and is renamed only
when complete. An existing file is never overwritten: the new one
becomes `name (1).zip`. The download directory comes from
`XDG_DOWNLOAD_DIR`, falling back to `~/Downloads`.

## Worked example

Reading Go documentation, searching, and opening a hidden service.
Sites, numbers and timings are illustrative:

```
operator@cathedral:~$ web go.dev/doc/effective_go
> web: https://go.dev/doc/effective_go

  Effective Go - The Go Programming Language        https://go.dev/doc/effective_go
  ────────────────────────────────────────────────────────────────────────────────
  Effective Go

  Introduction
  Go is a new language. Although it borrows ideas from existing languages, it has
  unusual properties that make effective Go programs different in character from
  programs written in its relatives. …

  Formatting
  With Go we take an unusual approach and let the machine take care of most
  formatting issues. The [14]gofmt program (also available as [15]go fmt, which
  operates at the package level rather than source file level) reads a Go program…

    type T struct {
        name    string // name of the object
        value   int    // its value
    }
  ────────────────────────────────────────────────────────────────────────────────
  [14/212]  https://go.dev/cmd/gofmt/          ↑↓ links  ↵ follow  ← back  z reader…
```

`/` `defer` `↵` jumps to the first match and highlights every one. `v`
opens the HTML as `source-go.dev-effective_go.html` in the editor.

A search with the form filled from the keyboard:

```
  g  golang context cancellation  ↵

  golang context cancellation at DuckDuckGo   https://html.duckduckgo.com/html/?q=golang…
  ────────────────────────────────────────────────────────────────────────────────
  [1]DuckDuckGo
  [2][golang context cancellation__] [3][ Search ]
  [4][All Regions ▾]  [5][Any Time ▾]

  [6]Go Concurrency Patterns: Context - The Go Programming Language
  [7]go.dev/blog/context
  [8]In Go servers, each incoming request is handled in its own goroutine…

  [9]context package - context - Go Packages
  [10]pkg.go.dev/context
  ────────────────────────────────────────────────────────────────────────────────
  [5/39]  select "df" · ↵ choose   → GET https://html.duckduckgo.com/html/
```

`↵` on `[5]` opens the picker. Choosing *Past week* and pressing `↵`
on `[3]` reruns the search with the filter applied.

Then a hidden service. Tor isn't running yet, so the `.onion` address
starts it:

```
  g  http://exampleqx7…ad.onion/  ↵

  —                                       ◌ tor 45% loading relay descriptors
  ...
  Example Onion Mirror        http://exampleqx7…ad.onion/              ◉ TOR
  ────────────────────────────────────────────────────────────────────────────────
  Mirror of the public documentation, reachable only over Tor.
  [1]Documentation   [2]Downloads   [3]Signing keys
  ────────────────────────────────────────────────────────────────────────────────
  tor on — every request now goes through tor
```

`R` here would only explain itself: recon tools can't reach `.onion`
sites, and would unmask a Tor session on clearnet sites. `T` switches
Tor off again and stops the Tor process.

## Output protocol

Like [`vault`](vault.md) and [`ai`](ai.md), `web serve` is a
long-lived session, not a streaming command. One JSON request per
stdin line. Replies carry the request id, and requests run
concurrently, so a new navigation can cancel the previous one.

```
← {"event":"ready","tor":true}
→ {"id":1,"op":"open","url":"https://go.dev/doc/"}
← {"id":1,"ok":true,"url":"https://go.dev/doc/","status":200,"ctype":"text/html",
   "title":"Documentation - The Go Programming Language",
   "blocks":[{"t":"h","lvl":1,"runs":[{"s":"Documentation"}]},…],
   "links":[{"href":"https://go.dev/","text":"Go"},…],
   "forms":[…],"fields":[…],"folds":[…],"images":[…],
   "bytes":48211,"ms":143}
→ {"id":2,"op":"submit","url":"https://site/login","method":"POST",
   "fields":[["user","operator"],["pw","…"]]}
→ {"id":3,"op":"render","url":"https://go.dev/doc/","reader":true}
→ {"id":4,"op":"source","url":"https://go.dev/doc/"}
← {"id":4,"ok":true,"text":"<!DOCTYPE html>…","ctype":"text/html; charset=utf-8"}
→ {"id":5,"op":"image","url":"https://…/photo.jpg"}
← {"id":5,"ok":true,"png":"<base64>","w":320,"h":214,"srcW":1600,"srcH":1067}
→ {"id":6,"op":"download","url":"https://…/tool.zip"}
← {"id":6,"progress":1048576,"total":12998123}*
← {"id":6,"ok":true,"path":"/home/operator/Downloads/tool.zip","bytes":12998123}
→ {"id":7,"op":"tor"}
← {"id":7,"progress":45,"summary":"Loading relay descriptors"}*
← {"id":7,"ok":true}
→ {"id":8,"op":"open","url":"http://…onion/","tor":true}
→ {"id":9,"op":"cancel","target":8}
```

Block types are `h`, `p`, `li`, `pre`, `quote`, `hr`, `table` and
`summary`. Opening a non-text URL replies
`{"ok":true,"binary":true,"ctype":…,"length":…,"filename":…}` without
reading the body. Other ops: `tor-stop`. Errors are
`{"id":N,"ok":false,"error":"…"}`.

## Limitations

- **No JavaScript.** This is the point, and it has a cost. Web apps
  (webmail, dashboards, most single-page sites) render mostly empty,
  exactly as in lynx. Sites that load their content with JavaScript
  show only what's in the initial HTML.
- **Not a security boundary.** `web` runs no page code, but it still
  parses hostile HTML and decodes untrusted images in Go. Both are
  memory-safe, but they're not sandboxed. A downloaded file is just a
  file. Opening it is up to you, and the browser doesn't scan it.
- **Tor mode protects the connection, not you.** It hides your IP
  from the site and your browsing from your network. It doesn't stop
  you from logging in as yourself. The text renderer is also
  distinctive: a site can tell it isn't Tor Browser, which matters if
  you need to blend in with other Tor users. There's no "new
  identity" key yet.
- **Recon in Tor mode is refused, not proxied.** Running the recon
  tools over Tor is a planned improvement.
- **Forms:** file uploads and `<select multiple>` aren't supported.
  Text areas are edited on one line. Cookies last only as long as
  Cathedral is running.
- **Tables:** `rowspan` is ignored, and long tables don't repeat their
  header row. The data-or-layout decision is a heuristic and can
  misjudge a page.
- **Reader mode is a heuristic too.** On an unusual page it can pick a
  sidebar or cut part of the article. `z` takes you back to the full
  page instantly.
- **Pages are capped at 8 MB**, and only the 30 most recent page
  bodies are cached for view-source and reader mode. Older pages are
  fetched again.
- **Linux-first,** like the bundled Tor.

## Authorized use

Browsing is browsing. `web` sends ordinary GET and POST requests with
a lynx-style User-Agent, and fetches only what you navigate to. The
dual-use part is `R`: the recon commands it starts follow their own
entries' rules, and pointing them at a site you're reading doesn't
make that site in scope. Tor mode is for privacy. The terms of
service and the law of the sites you reach still apply.

## Further reading

- [WHATWG HTML — constructing the entry list](https://html.spec.whatwg.org/multipage/form-control-infrastructure.html#constructing-the-form-data-set) — which controls a form submits
- [WHATWG HTML — tables](https://html.spec.whatwg.org/multipage/tables.html) — and why layout tables are discouraged
- [Lynx users guide](https://lynx.invisible-island.net/lynx_help/Lynx_users_guide.html) — the browser `web` takes its keys from
- [Tor Project — SOCKS and DNS](https://support.torproject.org/) — why the hostname, not the IP, goes to Tor
- [Floyd & Steinberg, *An adaptive algorithm for spatial greyscale* (1976)](https://en.wikipedia.org/wiki/Floyd%E2%80%93Steinberg_dithering) — the dither
- [Mozilla Readability](https://github.com/mozilla/readability) — the content-scoring idea behind reader mode
