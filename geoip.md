---
title: geoip — offline IP geolocation
command: geoip
category: identification
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-05-13
related: [trace, asn, whois]
---

# `geoip` — offline IP geolocation

`geoip` answers *where* an IP is registered, using a local database
shipped with Cathedral. No network calls, no third-party logging, no
API keys — the lookup happens against a memory-mapped file on disk.
Each result pins on the Cathedral globe; multiple results from one
session accumulate until you run `globe clear`.

```
geoip 8.8.8.8
geoip 1.1.1.1 github.com cloudflare.com
geoip target.example.com
```

## What it does

Resolves the target (hostname → IP if needed, IPv4 preferred), looks
the IP up in a bundled MaxMind-format database, and emits the
result: city, region, country, lat/lon, continent. The Cathedral UI
pins it on the globe and prints a short summary in the terminal.

Multi-target invocations process each input in sequence; misses
(unresolvable hostnames, IPs not in the database) emit a `miss`
event and the run continues.

## What it answers

**Identification:** *"Where is this IP I'm looking at?"* This is the
defining first-step question of any audit. Cathedral's
`audit-ip.cthd` script chains `geoip` → `asn` → `whois` → `dnsbl` as
the identification block before any active probing — three offline
lookups and one reputation check that together build a picture of
the target before a single packet is sent at it.

**Recon:** *"Is the target where I expected it?"* A web property
hosted on a cloud edge in Frankfurt while its registered company
sits in California is a normal pattern — Cloudflare, Akamai, Fastly
all do this. A web property hosted on a sketchy VPS in a country
that doesn't match the rest of the target's infrastructure is a
finding. `geoip` doesn't tell you which is which; it tells you where
the box is so you can decide.

**Forensic:** *"This log entry shows an IP — where was the
connection from?"* `geoip` reads stdin-friendly multi-target input,
so piping a column of IPs from auth logs through it is fast triage.

**Privacy-preserving composition.** This is the
distinguishing feature: `geoip` doesn't talk to anyone. Unlike
[`trace`](./trace.md), which sends every public hop to `ip-api.com`,
`geoip` works offline. If you ran a trace with `--no-geo` to keep
the path private, `geoip` is what you reach for to enrich the
captured hops without leaking them.

## How it works

### The MMDB format

The database is a MaxMind MMDB file — the same binary format used by
GeoIP2, MaxMind's commercial product, and a long list of free
alternatives. MMDB is purpose-built for fast IP lookups:

- **Memory-mapped.** The file is `mmap`'d once at open; lookups are
  pointer chases, not disk reads. A million queries per second on a
  laptop is achievable.
- **Binary search tree by IP prefix.** Each node branches left or
  right based on a bit of the queried address. For a 32-bit IPv4 a
  full lookup is at most 32 hops; in practice much less because the
  tree compresses runs.
- **Self-describing.** The metadata block at the file's end carries
  the build date, database type, and schema version. Cathedral reads
  the build epoch and surfaces it in the `start` event.

The Go reader is `oschwald/maxminddb-golang` — pure Go, no CGO, no
external dependencies. Keeps the static-binary property.

### DB-IP City Lite, not MaxMind GeoLite

Cathedral ships **DB-IP City Lite** as the bundled database. Why this
specifically:

| Option            | License signup     | Update cadence | Schema                |
|-------------------|--------------------|----------------|-----------------------|
| MaxMind GeoLite2  | Required (free)    | Twice weekly   | The "standard" MMDB   |
| **DB-IP City Lite** | **None**         | **Monthly**    | **MaxMind-compatible**|
| IPinfo Lite       | Required (free)    | Daily          | Custom-ish            |

DB-IP requires no account, no API key, no signup flow — Cathedral
can bundle a fresh copy with each release without users needing to
register anywhere. The schema is MaxMind-compatible, so the same
reader code works against either DB if you want to swap them out
(the DB locator walks several candidate paths; drop a `geolite2.mmdb`
in `assets/geoip/` and Cathedral picks it up).

### The DB locator

`geoip` searches several candidate locations to find the database:

```go
candidates := []string{
    "assets/geoip/dbip-city-lite.mmdb",
    filepath.Join(exeDir, "..", "assets", "geoip", "dbip-city-lite.mmdb"),
    filepath.Join(exeDir, "..", "..", "assets", "geoip", "dbip-city-lite.mmdb"),
    filepath.Join(exeDir, "data", "flutter_assets", "assets", "geoip", "dbip-city-lite.mmdb"),
}
// Also walk upward from cwd looking for assets/geoip/dbip-city-lite.mmdb
cwd, _ := os.Getwd()
for d := cwd; d != "" && d != "/"; d = filepath.Dir(d) {
    candidates = append(candidates, filepath.Join(d, "assets", "geoip", "dbip-city-lite.mmdb"))
    ...
}
```

This covers the four real deployment shapes: dev (`flutter run` from
project root), Linux bundle (executable in `/opt/cathedral/`), Flutter
asset bundle (`data/flutter_assets/assets/geoip/`), and user-installed
DBs anywhere up the working directory tree. First match wins; if
nothing matches, the tool errors clearly rather than silently
returning empty results.

### Hostname resolution

If the target isn't a parseable IP, `geoip` resolves it via the
system resolver. When the hostname has both IPv4 and IPv6, v4 is
preferred — most geo databases are v4-centric, and v4 paths are
better-instrumented in practice. The DNS resolution is the only
network call `geoip` ever makes, and only when the input is a
hostname.

## Worked example

```
$ geoip 8.8.8.8 1.1.1.1 github.com
> geoip 3 target(s)  via DBIP-City-Lite (build 2026-04-29)

[ 8.8.8.8 → 8.8.8.8 ]
  location : Mountain View, California, United States  (US)
  lat/lon  : 37.4220, -122.0850
  continent: North America

[ 1.1.1.1 → 1.1.1.1 ]
  location : Sydney, New South Wales, Australia  (AU)
  lat/lon  : -33.8688, 151.2090
  continent: Oceania

[ github.com → 140.82.121.3 ]
  location : Frankfurt am Main, Hesse, Germany  (DE)
  lat/lon  : 50.1109, 8.6821
  continent: Europe

lookup complete — 3 pinned on globe (3 total).
```

Three real lookups, three teaching moments:

- **8.8.8.8** → Mountain View. Google's anycast resolver IP geolocates
  to Google's headquarters. The actual server is probably a few
  milliseconds away from wherever you are.
- **1.1.1.1** → Sydney. Cloudflare anycast geolocates to *Sydney*
  in DB-IP City Lite, but to *South Brisbane* via `ip-api.com` (the
  service `trace` uses). Different databases, different registered
  addresses, same anycast quirk.
- **github.com** → Frankfurt. GitHub's hostname resolved (from this
  Estonian network) to a German anycast edge. The Frankfurt result
  is correct for *that specific IP*; it does not mean GitHub is
  hosted in Germany. It means the GitHub edge nearest to the
  caller, at lookup time, was the one in Frankfurt.

The continent and country are reliable. The city is *registered*
location, not server location.

## Output protocol

```
{"event":"start",  "db":"…", "build":N, "db_type":"…", "targets":N}
{"event":"result", "target":"…", "ip":"…", "city":"…", "region":"…",
                   "country":"…", "country_iso":"…", "continent":"…",
                   "lat":N, "lon":N, "timezone":"…"}*
{"event":"miss",   "target":"…", "ip":"…"?, "error":"…"}*
{"event":"done"}
```

`build` is the database's build epoch (Unix seconds); the Cathedral
UI renders it as a human date in the `start` event header.
`timezone` is empty on City Lite — the lite tier doesn't include
that field.

Composition with `jq`:

```
$ cat suspicious-ips.txt | xargs geoip -j | jq -r '
    select(.event=="result") |
    "\(.country_iso)\t\(.ip)\t\(.city)"' | sort | uniq -c | sort -rn
```

This collapses a column of IPs into "how many connections from
each country" — straightforward log triage.

## Limitations

- **City Lite tier limitations.** No timezone, no postal code,
  reduced city-level precision compared to commercial tiers. Country
  and continent are reliable; city is correct most of the time but
  expect occasional shifts to the nearest large metro.
- **Database freshness.** The bundled DB is built monthly. IP block
  allocations change less frequently than that, but it does happen —
  a cloud provider expanding into a new region might have IP ranges
  Cathedral's DB hasn't seen yet. The build date is in the `start`
  event so you can tell if you're querying against stale data.
- **Anycast addresses geolocate to registered owner, not edge
  location.** This is a property of the entire geolocation industry,
  not of Cathedral specifically. Every anycast IP every database
  returns is wrong about where the *server* is. Read these as "who
  owns this prefix" rather than "where is the physical box."
- **Cloud provider IPs map to provider HQ.** An EC2 instance in
  Frankfurt geolocates to *Seattle* on most databases because that's
  Amazon's registered headquarters. Use `asn` to identify cloud
  ownership and don't trust city-level geo for IPs you've confirmed
  are inside AWS / GCP / Azure ranges.
- **Mobile carrier IPs geolocate to carrier HQ.** Same shape:
  T-Mobile in Bellevue, Vodafone in Newbury. Mobile traffic is
  globally distributed; the geo lookup says the carrier's office.
- **IPv6 coverage is thinner than IPv4.** DB-IP City Lite covers v6,
  but the city-level resolution on v6 is less granular than on v4
  for most regions.
- **No automatic update mechanism.** Cathedral ships a recent DB but
  doesn't fetch newer versions on its own. Drop a manually-downloaded
  `dbip-city-lite.mmdb` into `assets/geoip/` if you want to refresh
  between Cathedral releases.

## Authorized use

`geoip` makes no network calls and writes nothing. The risk profile
is the same as `grep`: it's a local lookup against a local file. The
authorized-testing posture doesn't apply.

The one privacy property worth noting (and the reason this tool
exists alongside `trace`'s online geo): *your queries don't leave the
machine*. If you're auditing an IP and don't want the lookup to
appear in some third party's logs as "someone at $YOUR_IP just
asked about this target," `geoip` is the tool to reach for.

## Further reading

- [MaxMind DB File Format Specification](https://maxmind.github.io/MaxMind-DB/) — the binary layout
- [DB-IP City Lite](https://db-ip.com/db/lite.php) — license, schema, monthly download
- Related Cathedral commands: [`trace`](./trace.md) (path + online geo),
  [`asn`](./asn.md) (AS attribution — pairs with `geoip` for cloud detection),
  [`whois`](./whois.md) (registry / owner attribution)
