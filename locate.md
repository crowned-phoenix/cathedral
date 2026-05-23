---
title: locate — address-to-satellite-view with phosphor map render
command: locate
category: identification
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-23
related: [geoip, whois, asn, dns, reverse-dns]
---

# `locate` — address-to-satellite-view with phosphor map render

`locate` takes a free-text address, resolves it to a coordinate via
the Photon (Komoot) geocoder, drops a phosphor pin on the GLOBE
panel, and renders a tinted satellite-view (or street-view) of the
location into the VISUAL MAP panel as a stitched 3×3 tile grid with
a deep-zoom cross-fade to z+1 detail. The globe auto-centres on the
new pin via a smooth 1.4-second spin; the visual map dissolves from
its idle MatrixRain into the satellite image with a horizontal
scanline sweep, then performs a cinematic zoom-in to lock onto the
crosshair. This is Cathedral's first command that drives *two* HUD
panels simultaneously — the highest-impact "spy-display" moment in
the toolkit.

Where [`geoip`](geoip.md) answers "given this IP, where on the map
is it?", `locate` answers the inverse: "given this address, where on
the map is it?". Both share the globe-pin infrastructure; `locate`
adds the rich satellite-view render that turns the visual map panel
from idle decoration into a working operational display.

```
locate empire state building
locate "1600 Pennsylvania Ave"
locate paris --map=street
locate berlin --zoom=14
locate tokyo --pin-only
locate --clear
```

## What it does

For a single free-text address Cathedral runs four pipeline stages
in sequence, each emitting events the Flutter side translates into
the multi-panel choreography:

1. **Geocode** — Photon API call returns `(lon, lat)` + address
   metadata.
2. **Globe pin** — `GeoPin` added to `GeoState`; the globe widget
   auto-centres on the new pin (1.4 s ease-in-out tween).
3. **Wide stitch** — 3×3 grid of tile fetches at the chosen zoom
   level, stitched into a single PNG, cached to disk, signalled
   to the visual map.
4. **Close stitch** — same lat/lon at `zoom + 1` for deep-zoom
   detail; the visual map cross-fades from the wide layer to the
   close layer during the final stretch of its zoom animation.

| Flag                | Meaning                                          | Default      |
|---------------------|--------------------------------------------------|--------------|
| `--zoom=N`          | tile zoom (13-18 useful range)                   | `16`         |
| `--map=satellite\|street` | tile source                                | `satellite`  |
| `--pin-only`        | drop globe pin only; skip tile fetch + render    | off          |
| `--clear`           | clear all locate pins; reset visual map to idle  | —            |

The `--clear` form is handled entirely Flutter-side (no Go process
spawn). All other flags pass through to the Go binary.

## What it answers

**Defender:** *"Where on the planet is this address?"* — for any of
the operational reasons you'd want a precise map view in a recon
console without pivoting to a browser. Site-survey reports,
infrastructure mapping, asset photography cross-reference, brand-
protection footprint of regional offices.

**Recon (authorized testing only):** *"What does this target's
publicly-listed address look like from the air?"* The satellite-view
quickly distinguishes a real office from a virtual-office address
or PO box. Combined with the street-view layer, it gives the on-the-
ground context that whois alone never carries — what's the actual
building, what surrounds it, what does the entrance face.

**Investigation:** *"Is this address what it claims to be?"* A
domain's whois says it's registered in Wilmington, Delaware; you
`locate "Corporation Trust Center 1209 Orange Street"` and see the
single building that's the registered address for ~285,000 other
companies. Pattern obvious. Same approach for shell-company
registrations, virtual-office services, and the recurring "all the
sketchy companies are at this one address" finding.

**Identification:** *"Pin this on the globe so I can see it in
context with my other pins."* `locate` shares `GeoState` with
[`geoip`](geoip.md), so a sequence of `geoip <ip>` followed by
`locate <known-address>` gives both points on the same globe with
the great-circle line implicit between them — useful for "is this
IP near this office?" type questions.

## How it works

### The geocoder: Photon (Komoot)

[Photon](https://photon.komoot.io/) is Komoot's OSM-backed
geocoding service. Cathedral uses it because it's the only major
geocoder with all three properties: free, no API key, and
production-grade quality. The API is a simple HTTP GET:

```
https://photon.komoot.io/api/?q=<query>&limit=1&lang=en
```

Response is a GeoJSON `FeatureCollection`. Each feature has a
`geometry.coordinates: [lon, lat]` pair and a `properties` block
with `name`, `street`, `housenumber`, `city`, `state`, `postcode`,
`country`, `osm_type`, `osm_id`, `osm_key`, `osm_value`. Cathedral
takes the first feature (highest-ranked match), extracts the
coordinates, and formats the address for the LOCATED summary line.

```go
type photonFeature struct {
    Properties struct {
        Name, Street, Housenumber, City, State, Postcode,
        Country, OsmType, OsmKey, OsmValue, Type string
        OsmID int64
    } `json:"properties"`
    Geometry struct {
        Coordinates []float64 `json:"coordinates"` // [lon, lat]
    } `json:"geometry"`
}
```

Note the `[lon, lat]` ordering — GeoJSON convention is longitude
first. Mixing this up is the canonical OSM-newbie bug; Cathedral
explicitly extracts `Coordinates[0]` as lon and `[1]` as lat.

Photon's licence requires attribution. Cathedral renders
`photon.komoot.io · openstreetmap contributors` in the panel
attribution footer when it's appropriate (visible from inside the
shipped tile-attribution strings rather than the `start` event,
since the console-side attribution is automatic via Photon's URL).

### Web Mercator slippy tiles

Both tile sources Cathedral uses follow the standard Web Mercator
"slippy tile" addressing — the same `{z}/{x}/{y}` convention every
OSM-style tile URL uses. The lat/lon → tile coordinate conversion
is the standard one:

```go
func deg2tile(lat, lon float64, z int) (x, y int) {
    n := math.Pow(2, float64(z))
    x = int(math.Floor((lon + 180.0) / 360.0 * n))
    latRad := lat * math.Pi / 180.0
    y = int(math.Floor((1.0 - math.Log(math.Tan(latRad)+1.0/math.Cos(latRad))/math.Pi) / 2.0 * n))
    return
}
```

At zoom 16 (Cathedral's default), each tile covers ~600 m of
ground at the equator, narrowing toward the poles. A 3×3 grid
gives ~1.8 km of context around the centre point — enough to see
the building plus the surrounding block structure.

### Two tile sources, two pipelines

**Satellite** — Esri World Imagery: `https://server.arcgisonline.com/
ArcGIS/rest/services/World_Imagery/MapServer/tile/{z}/{y}/{x}`. Real
aerial photography, global coverage, no API key required. Tile
size 256×256, served as JPEG. **Note the URL coordinate order is
`/z/y/x`, not the OSM-standard `/z/x/y`** — Esri inverts row and
column from the convention. This is baked into Cathedral's
`tileURL` helper; mixing it up gives tiles for the wrong
hemisphere.

**Street** — Carto Voyager: `https://basemaps.cartocdn.com/
rastertiles/voyager/{z}/{x}/{y}@2x.png`. OSM-style rendering with
labels, road network, water, parks, building outlines.
Cathedral fetches the `@2x` (HiDPI) variant — 512×512 tiles
instead of 256×256, giving 4× the pixel density for crisp
rendering when scaled to the panel.

The earlier iterations of `locate` used Carto's `dark_all`
basemap for street mode — its dark theme felt natively Cathedral —
but `dark_all` has very low intrinsic luminance contrast (everything
sits in the 0.05-0.25 range), which made all the structural
features wash out once any kind of phosphor tint was applied on
top. Voyager has full luminance range and works far better with
the Sobel-based street processing described below.

### The 3×3 stitch

Same pipeline for both sources:

```go
cx, cy := deg2tile(lat, lon, zoom)
half := gridSize / 2  // gridSize = 3, half = 1
tilePx := tilePxFor(mapSrc)  // 256 for satellite, 512 for street @2x
stitched := image.NewRGBA(image.Rect(0, 0, tilePx*gridSize, tilePx*gridSize))

// Fetch 9 tiles in parallel (bounded worker pool, 4 concurrent)
for dy := -half; dy <= half; dy++ {
    for dx := -half; dx <= half; dx++ {
        go func(dx, dy int) {
            img, _ := fetchTile(mapSrc, zoom, cx+dx, cy+dy)
            offX, offY := (dx+half)*tilePx, (dy+half)*tilePx
            draw.Draw(stitched, image.Rect(offX, offY, offX+tilePx, offY+tilePx),
                img, image.Point{0, 0}, draw.Src)
        }(dx, dy)
    }
}
```

Output dimensions:
- Satellite: 768×768 (3 × 256)
- Street: 1536×1536 (3 × 512, HiDPI)

The stitched PNG is cached to `~/.cache/cathedral/locate/
<sha256-of-query>-<zoom>-<map>.png` with a 7-day TTL. Repeat
queries skip the network entirely on cache hit.

### Phosphor green: Flutter matrix vs. Go pixel-level

Two completely different pipelines based on source character:

**Satellite tiles** are processed at render time via a Flutter
`ColorFilter.matrix` — the standard BT.601 luma → green-channel
mapping (`0.299·R + 0.587·G + 0.114·B` driven into G; R and B
zeroed). Satellite imagery has natural luminance variation —
buildings bright, roads dim, vegetation mid — so a positive luma
matrix produces good structural contrast immediately. Applied at
render in Flutter, never baked into the PNG, so the same cached
image could in principle be re-tinted with a different colour.

**Street tiles** are pre-processed in Go *before* the PNG is
cached. The visible bug that drove this design: Flutter's
`ColorFilter.matrix` with negative luma weights (which would be
the natural way to invert bright source pixels into dim phosphor)
renders uniformly near-black despite the per-pixel math evaluating
correctly. Likely a premultiplied-alpha interaction with negative
weights in Skia's colour-matrix filter; not investigated further
since the Go-side workaround is cleaner anyway.

The Go-side processing combines two signals per pixel:

```go
// Pre-compute luma buffer
luma[y*w+x] = 0.299*r + 0.587*g + 0.114*b

// Dark-source signal: gamma-curved inverted luma
inverted := (255.0 - lumaHere) / 255.0
darkSignal := math.Pow(inverted, inversionGamma) * span  // gamma=2.0, span=215

// Edge signal: Sobel 3×3 gradient magnitude
gx := -p00 + p02 - 2*p10 + 2*p12 - p20 + p22
gy := -p00 - 2*p01 - p02 + p20 + 2*p21 + p22
mag := math.Sqrt(gx*gx + gy*gy)
edgeSignal := mag * edgeScale  // edgeScale = 0.6

// Combine via max: whichever signal is stronger wins
chosen := math.Max(darkSignal, edgeSignal)
gOut := inversionFloor + chosen  // floor = 40
```

The two-signal design is essential because Voyager renders roads
as *light-grey fills*, not dark lines. The inverted-luma signal
alone has nothing dark to brighten in the road interior. The
Sobel edge signal picks up the structural boundary — light-grey
road meets white background — and lifts those edge pixels to
bright phosphor regardless of fill direction. Net effect: roads
render as bright outlines (their fill stays at the dim floor),
building blocks as fainter outlines, labels as bright filled
strokes (where the dark text is *both* dark-source *and* high-
edge-density). The "tactical line-art" look.

The Cathedral-aesthetic decision baked into the pipeline:
**brightness lift requests almost always mean contrast
amplification, not absolute brightness**. Iterations during the
build went: linear inversion (everything bright but indistinct) →
gamma curve (better separation) → gamma + edge detection
(tactical line-art with clearly readable road structure). The
final tuning constants (`inversionGamma=2.0`, `inversionFloor=40`,
`edgeScale=0.6`) live at the top of `phosphorInvert` in
`tools/locate/main.go` and are well-commented.

### Deep-zoom: wide + close cross-fade

After the wide-pass stitch completes and `image_ready` fires,
Cathedral kicks off a second pass at `zoom + 1` for genuine
higher-resolution detail. Same lat/lon, same pipeline, different
cache file. When `image_ready_close` fires, the Flutter side
hands the close-pass path to `LocateState`, which triggers the
final phase of the visual-map animation.

The geographic continuity: z=16 at scale 2.0 shows exactly the
same ground area as z=17 at scale 1.0. The Flutter `LocateView`
exploits this — during the last 25% of the zoom animation, the
wide layer's opacity fades out while the close layer's opacity
fades in, with the wide layer at its peak scale (2.0) and the
close layer at its native scale (1.0). The viewer sees a
seamless transition from "scaled-up satellite" to "native-detail
satellite" with no visible content jump.

If the close-pass fetch fails (network blip, tile server hiccup),
the wide layer holds at full opacity through the end of the
animation. A `warn` event surfaces the failure; `done` still
fires; "locate complete." still prints. Non-fatal degradation.

### Multi-panel orchestration: globe pin + visual map

Cathedral's first command to drive two HUD panels simultaneously.
The shared state mechanism:

- **`GeoState` (lib/geo/geo_state.dart)** — `ChangeNotifier`
  holding a list of `GeoPin` records. `locate` calls
  `geo.clearSource('locate')` (so successive locates replace
  rather than stack on the globe) then `geo.addPin(GeoPin(...,
  kind: PinKind.target, source: 'locate', highlight: true))`.
- **`LocateState` (lib/locate/locate_state.dart)** — separate
  `ChangeNotifier` holding the current `LocateResult` with the
  query / address / lat / lon / zoom / mapSource / wide image
  path / close image path. The visual-map panel listens.
- **Auto-centre on highlighted pins** — `_GlobeState._onUpdate`
  detects newly-added pins; if `highlight: true`, it tweens
  `_userYaw` along the shortest angular path so the pin's
  longitude lands at the front of the visible hemisphere
  (1.4 s, `easeInOutCubic`). Then holds 700 ms before
  resuming the auto-rotation. Non-highlighted pins (e.g.,
  trace's per-hop pins) don't trigger the centring — would
  cause constant globe jitter as hops stream in.

The panel-selection logic in `_SideStack.build` reads:
`pin.active → PinView; locate.active → LocateView; trace.hops
non-empty → WorldMap; else MatrixRain`. Most-recent-wins
precedence between locate and trace; the visual map shows
whichever the operator triggered last.

### The cinematic timing

Wall-clock breakdown of a fresh (cache-miss) `locate empire
state building`:

| t (ms) | Console event | Globe | Visual map |
|---|---|---|---|
| 0 | `> resolving target...` | rotating | MatrixRain idle |
| 200-500 | (Photon round-trip) | rotating | MatrixRain idle |
| ~500 | `[ LOCATED ]` card | pin drops with phosphor flash + concentric pulse | (still idle — wide image not ready yet) |
| ~500-1900 | rotating + auto-centring | tweens `easeInOutCubic` over 1.4 s along shortest path to pin's longitude | (idle continues) |
| ~1500-2500 | `fetching tiles…` `stitched 768×768 →` | centred, holding 700 ms | (idle continues) |
| ~2500 | `image_ready` event | auto-rotation resumes | dissolve starts: MatrixRain fades out, satellite image fades in over 900 ms with horizontal scanline sweep |
| ~3400 | (silent) | rotating | dissolve complete; hold 200 ms |
| ~3600 | (silent) | rotating | zoom-in animation starts (image scales 1.0 → 2.0 over 2.4 s, `easeOutCubic`) |
| ~3500-5000 | `deep zoom fetching tiles… deep zoom ready` | rotating | continues zooming |
| ~5400 | (visual map zoom enters crossover) | rotating | wide layer fades out as close (z=17) layer fades in over the final 25 % of the zoom animation |
| ~6000 | `locate complete.` | rotating | settled on close-pass image, zoomed and centred on crosshair |

On cache hit the same flow runs but tiles_fetching is replaced
with cache_hit and `image_ready` arrives within ~700 ms of
launch — the animation timing is the same, just the network
delay collapses.

## What Cathedral doesn't do

A few deliberate omissions:

- **No reverse-geocoding (coords → address).** A deliberate
  privacy choice: typing a lat/lon and getting back the precise
  street address would compound the surveillance footprint
  beyond what an address-search tool should. `locate` accepts
  coords as input (Photon handles them as a query string) but
  doesn't *enrich* them with more detail than Photon returns.
- **Only Photon.** Other geocoders exist (Nominatim, OpenCage,
  MapBox, Google) but none combine no-key + free + high-quality
  the way Photon does. Cathedral's no-credentials posture rules
  out the key-gated services.
- **Only Esri satellite + Carto Voyager street.** No API-key
  tile sources in v1. Stadia/Stamen/MapBox/MapTiler would all
  improve quality but require auth.
- **No `--via-tor` yet.** Will land when the Tor + obfs4 feature
  ships (see `ROADMAP.md`). For now, every geocode and tile
  fetch goes direct from your IP.
- **No bonus signals.** Local time at the target, sunrise/
  sunset, distance from your netinfo-primary location, weather —
  all sketched in the original `locate` ROADMAP entry, all
  deferred. The current scope is "show me the place"; the
  context overlays come later.
- **Single locate at a time.** Successive `locate` calls
  *replace* the previous pin on the globe (the `clearSource
  ('locate')` call before each new `addPin`). Stacking multiple
  located pins to show a route would require dropping that
  call or using `--pin-only` mode and accepting the lack of
  visual-map render for the older pins.
- **No customizable grid size.** Always 3×3. A 5×5 grid would
  show more context but increase fetch time and cache size by
  ~3×; not worth the configurability surface for the marginal
  gain.

## Worked example

A typical address lookup, the street-vs-satellite contrast, and
the cache-hit case.

### Typical address lookup (satellite)

```
operator@cathedral:~$ locate acme-supplies headquarters
> resolving target...
  query    : acme-supplies headquarters
  source   : photon.komoot.io

[ LOCATED ]
  address  : Acme Supplies HQ, 4280 Industrial Boulevard, 60601 Chicago, United States
  coords   : 41.8781°N  87.6298°W
  category : office / company
  osm      : way/4892374

  fetching tiles    9 from satellite (z=16)
  stitched          768×768 → /home/operator/.cache/cathedral/locate/8a3c9f.png
  deep zoom         fetching 9 tiles from satellite (z=17)
  deep zoom ready   768×768 (z=17) → /home/operator/.cache/cathedral/locate/3e1b2d.png

locate complete.
```

While this prints, on screen:
- Globe gains a phosphor-amber pin near the upper-front area
  (Chicago's latitude/longitude), with concentric pulse rings.
- Globe smoothly spins to centre that pin (about 1.4 s).
- Visual map panel: MatrixRain dissolves into a phosphor-tinted
  aerial photograph of the address area, with a horizontal
  scanline sweep during the dissolve.
- Crosshair locks onto the panel centre (the resolved lat/lon
  is exactly at the centre of the stitched grid).
- After the wide image settles, the camera zooms in — image
  scales from 1.0 to 2.0, then cross-fades to the z=17 close-
  pass at scale 1.0 for the final detail level.
- Bottom-left of panel: `imagery © esri · maxar · earthstar`
- Bottom-right: `z=16  satellite`
- Top-right of panel: `41.8781°N  87.6298°W` ticker

### Street mode

```
operator@cathedral:~$ locate "1600 pennsylvania ave" --map=street
> resolving target...
  query    : 1600 pennsylvania ave
  source   : photon.komoot.io

[ LOCATED ]
  address  : The White House, 1600 Pennsylvania Avenue Northwest, 20500 Washington, United States
  coords   : 38.8977°N  77.0365°W
  category : tourism / attraction
  osm      : way/238241022

  fetching tiles    9 from street (z=16)
  stitched          1536×1536 → /home/operator/.cache/cathedral/locate/4f8e1a.png
  deep zoom         fetching 9 tiles from street (z=17)
  deep zoom ready   1536×1536 (z=17) → /home/operator/.cache/cathedral/locate/9c2d5b.png

locate complete.
```

Note the stitched size — `1536×1536` rather than satellite's
`768×768` — because the street pipeline fetches HiDPI @2x tiles
(512px each instead of 256). The console line reports the actual
file dimensions. The cache file is correspondingly larger
(~700 KB instead of ~400 KB) but the visible result is
considerably sharper.

The visual map render now shows the road network as bright
phosphor outlines (Pennsylvania Ave, the surrounding grid),
labels visible in bright filled strokes ("The White House",
"Lafayette Square", "The Ellipse"), building blocks as fainter
outline clusters, everything else at the dim phosphor floor.

### Pin-only

```
operator@cathedral:~$ locate tokyo --pin-only
> resolving target...
  query    : tokyo
  source   : photon.komoot.io

[ LOCATED ]
  address  : Tokyo, Japan
  coords   : 35.6768°N  139.7639°E
  category : place / province
  osm      : relation/1543125

  pin              dropped (no tile render)

locate complete.
```

Globe gets the pin and centres on it; visual map stays on its
current display (MatrixRain idle, or a previous locate's image,
or a trace's WorldMap). Useful for adding context pins without
disrupting the visual map.

### Cache hit (repeat query)

```
operator@cathedral:~$ locate "1600 pennsylvania ave" --map=street
> resolving target...
  query    : 1600 pennsylvania ave
  source   : photon.komoot.io

[ LOCATED ]
  address  : The White House, 1600 Pennsylvania Avenue Northwest, 20500 Washington, United States
  coords   : 38.8977°N  77.0365°W
  category : tourism / attraction
  osm      : way/238241022

  cache             hit
  deep zoom cache   hit

locate complete.
```

Photon is still queried (the lat/lon could in principle have
changed, though for stable OSM features it never does), but
both tile-grid fetches skip the network entirely. Total
completion: usually under 800 ms.

### Clearing pins

```
operator@cathedral:~$ locate --clear
locate pins cleared.
```

Removes all locate-source pins from the globe via
`geo.clearSource('locate')` and resets `LocateState`, which
returns the visual map to MatrixRain idle. Doesn't affect pins
from other sources (geoip, trace, etc.).

## Output protocol

```
{"event":"start",                "query":"…","source":"photon.komoot.io"}
{"event":"geocode_result",       "lat":N,"lon":N,"address":"…","category":"…","osm":"…"}
{"event":"tiles_fetching",       "count":9,"source":"satellite|street","z":N}
{"event":"cache_hit",            "path":"…"}                                # alternative to tiles_fetching
{"event":"tiles_done",           "count":9,"failed":N}
{"event":"image_ready",          "path":"…","size":N,"z":N}
{"event":"tiles_fetching_close", "count":9,"source":"…","z":N+1}            # close pass
{"event":"cache_hit_close",      "path":"…"}                                # alternative
{"event":"tiles_done_close",     "count":9,"failed":N}
{"event":"image_ready_close",    "path":"…","size":N,"z":N+1}
{"event":"pin_only"}                                                        # with --pin-only
{"event":"warn",                 "message":"…"}                             # non-fatal warnings
{"event":"done"}
{"event":"error",                "message":"…"}
```

Notable details:

- `size` field is the *stitched* image size in pixels per side
  (`tilePxFor(mapSrc) * gridSize`): 768 for satellite, 1536 for
  street. Both close and wide passes report their own size.
- `path` is the absolute filesystem location of the cached PNG.
  Useful if you want to open the image in an external viewer.
- The `warn` event most commonly indicates a close-pass failure.
  The wide pass already succeeded; the operator can still read
  the visual map, just without the deep-zoom layer.

For JSONL-pipeline use cases, extract just the coordinates:

```
$ locate "empire state building" -j |
    jq -r 'select(.event=="geocode_result") | "\(.lat) \(.lon)"'
40.7484 -73.9857
```

Bulk-resolve a list of addresses to a CSV:

```
$ while read addr; do
    locate "$addr" --pin-only -j |
      jq -r --arg addr "$addr" \
        'select(.event=="geocode_result") |
         [$addr, .lat, .lon, .address] | @csv'
  done < addresses.txt
"acme hq",41.8781,-87.6298,"Acme Supplies HQ, 4280 Industrial Boulevard, 60601 Chicago, United States"
"empire state building",40.7484,-73.9857,"Empire State Building, 350 5th Avenue, 10118 New York, United States"
…
```

Find the stitched PNGs for the most recent locate:

```
$ locate "paris" -j |
    jq -r 'select(.event=="image_ready" or .event=="image_ready_close") | .path'
/home/operator/.cache/cathedral/locate/8a3c9f.png
/home/operator/.cache/cathedral/locate/3e1b2d.png
```

## Limitations

- **Photon rate limits.** Komoot runs the public Photon service
  for free and asks operators not to abuse it. Bulk queries (one
  per second is fine, hundreds per minute is not) will trip the
  service-side rate limit, returning empty results or errors.
  For high-volume use cases, host your own Photon (the source
  is freely available) and point Cathedral at it via a future
  `--photon-host` flag.
- **Tile server rate limits.** Esri's free imagery endpoint and
  Carto's basemap CDN both have reasonable per-IP rate limits.
  In practice you won't hit them with interactive use, but a
  scripted-loop of `locate` against thousands of addresses will
  eventually 429.
- **Cache size growth.** Each street-mode locate adds
  ~700 KB × 2 (wide + close) = ~1.4 MB to the local cache.
  Cache TTL is 7 days but there's no automatic size cap.
  Manual cleanup: `rm ~/.cache/cathedral/locate/*.png`.
- **Photon match quality.** Photon ranks results by OSM
  popularity + text-match quality. For ambiguous queries
  ("springfield", "main street") it picks one match without
  surfacing alternatives. The `osm` field in the LOCATED card
  is the OSM URL fragment — copy into `https://openstreetmap.
  org/<type>/<id>` to see which exact feature Photon picked.
- **Esri imagery age.** Esri's satellite tiles can be 2-5
  years old in some regions (urban centres are typically newer;
  rural areas can be quite stale). For recent imagery, Sentinel
  Hub or Planet Labs would be required — both paid.
- **No street view (ground-level photos).** Mapillary has an
  open API for street-level imagery; that's a v2 candidate
  (it'd add a third panel mode).
- **Privacy footprint.** Every query reaches Photon's servers
  with the query string; every tile fetch reaches Esri/Carto
  with coordinates. Combined with your source IP, that's a
  meaningful surveillance trace. Tor routing is planned for
  the broader `--via-tor` feature.

## Authorized use

`locate` is **passive recon against public datasets**. Photon's
data is OSM-derived (Wikipedia-style community-maintained); the
tile imagery is satellite/aerial photography compiled by Esri
and Maxar from public satellite archives. Querying these for any
address is no different in posture from typing the address into
Google Maps — the target's infrastructure never sees any of the
activity.

Two notes worth attaching:

**Your queries are logged.** Komoot (Photon) and Esri / Carto
all log requests. A pattern of `locate` queries around a specific
target or geographic region traces an interest profile in their
access logs. For sensitive recon, route through a privacy-
respecting resolver chain or wait for the planned `--via-tor`
integration.

**Address-search is a search.** Cathedral isn't tracking anyone;
the geocoder is public infrastructure. But repeated `locate`
queries around a specific person or location have the *shape* of
surveillance, even when the targeted data is all public-by-
design. The console echoes back the exact query string, which
is the audit trail.

## Further reading

- [Photon API](https://photon.komoot.io/) — Komoot's geocoder
  documentation
- [OpenStreetMap](https://www.openstreetmap.org/) — the source
  data behind Photon's results
- [Web Mercator tile coordinate system](https://wiki.openstreetmap.org/wiki/Slippy_map_tilenames) —
  the canonical `{z}/{x}/{y}` addressing scheme
- [Esri World Imagery](https://www.arcgis.com/home/item.html?id=10df2279f9684e4a9f6a7f08febac2a9) —
  Esri's free satellite tile service + attribution requirements
- [Carto basemaps](https://carto.com/basemaps/) — Voyager + other
  free OSM-style raster tilesets
- [Mapillary](https://www.mapillary.com/) — open street-level
  imagery; planned ground-view companion to `locate`
- [Sentinel Hub](https://www.sentinel-hub.com/) — Sentinel-2
  recent satellite imagery (paid; replaces Esri's older tiles
  when freshness matters)
- Related Cathedral commands: [`geoip`](geoip.md) (IP →
  coordinate; complementary direction to `locate`),
  [`whois`](whois.md) (registry-listed address often becomes the
  query string for the next `locate`),
  [`asn`](asn.md) (BGP attribution for hosts; pair with `locate`
  to plot organisational geography),
  [`dns`](dns.md) (resolve hostnames before plotting),
  [`reverse-dns`](reverse-dns.md) (PTR sweep; pair with `locate`
  to map adjacent infrastructure)
