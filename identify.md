---
title: identify — identifier-to-public-footprint OSINT search
command: identify
category: identification
status: shipped
version-introduced: 1.0
authorized-use: high
last-updated: 2026-06-23
related: [whois, geoip, locate, oui]
---

# `identify` — identifier-to-public-footprint OSINT search

`identify` takes a single identifier — an email address, username,
person name, company name, or phone number — classifies what kind
of thing it is, and searches a curated set of **free, keyless,
public** sources for the digital footprint attached to it. Findings
stream in as they arrive, an avatar grid of candidate portraits
builds in the HUD, and the console closes with an aggregated
`[ IDENTITY ] / [ RESULTS ] / [ SUMMARY ]` report.

This is the most sensitive command in Cathedral, and the only one
gated behind an explicit acknowledgement. OSINT against a person is
powerful and easy to misuse; the **[Authorized use](#authorized-use)**
section is not boilerplate here — read it.

```
identify jane@example.com
identify torvalds
identify "Jane Doe"
identify "Crowned Phoenix OÜ"
identify +15551234567
identify "Jane Doe @ example.com"      # name + domain pivot
```

On first run, `identify` prints an authorized-use notice and stops.
Re-run with `--i-understand` once to record your acknowledgement;
it won't ask again on that machine.

## What it does

For one identifier, `identify`:

1. **Classifies the input** into exactly one of six kinds — email,
   phone, username, person name, company, or `name @ domain` — or
   refuses to run if it can't tell what the input is.
2. **Builds a source plan** — only the sources relevant to that
   kind. A username doesn't trigger company-filing lookups; a phone
   number doesn't trigger a knowledge-base query.
3. **Runs every planned source in parallel**, each as a goroutine
   under a shared 60-second budget, streaming a `hit` per finding
   and a `face` per candidate portrait.
4. **Aggregates** the raw hits into a structured identity report:
   facts (name, occupation, employer, location, …), a
   search-engine-style list of every URL found, and a per-source
   contribution summary.

Every source is **free, public, and needs no API key** (one
optional exception — see Brave below). Nothing is paid, nothing is
breach-data, nothing requires credentials.

## What it answers

The authorized framings the tool exists for:

- **Self-audit** — *"What does the open internet say about me?"*
  Run `identify` on your own email / usernames / name and see your
  exposed footprint the way anyone else could.
- **Due diligence with consent** — vetting a counterparty,
  contractor, or hire where you have documented authority to do so.
- **Journalism and authorized investigations** — building the
  public-record picture of a subject.
- **CTF, training, and authorized red-team** — footprinting a
  target that's in scope.

## How it works

### Strict classification (and refusing to guess)

Before any source runs, `identify` classifies the input with a
first-match-wins ladder:

| Order | Kind | Shape |
|-------|------|-------|
| 1 | **email** | `local@host.tld`, one `@`, no spaces |
| 2 | **name @ domain** | `Jane Doe @ example.com` (space in the local part) |
| 3 | **phone** | only digits + `+ - . ( )`, 7–15 digits after cleanup |
| 4 | **company** | trailing corporate suffix (`OÜ`, `Inc`, `Ltd`, `GmbH`, `AS`, `LLC`, …) |
| 5 | **name** | 2–4 letter-leading words (Unicode-aware) |
| 6 | **username** | alnum + `. _ -`, 2–39 chars, **must contain a letter** |
| — | **unknown** | refuse to run |

The "must contain a letter" rule on usernames is load-bearing: it's
what stops a phone number from being mis-read as a username and
firing a pointless 50-site username sweep. And the **refusal** on
unknown input is deliberate — identifying *nothing* beats
identifying *noise*:

> identify: cannot identify this input. Cathedral identifies email
> addresses, phone numbers, usernames, person names (First Last), or
> company names (with trailing OÜ / Inc / Ltd / GmbH / etc.). For
> ambiguous input, pass `--kind=…` explicitly.

You can override the classifier with `--kind=email|phone|username|name|company`.

### The source plan per kind

Each kind runs only the sources that make sense for it:

| Kind | Sources |
|------|---------|
| **email** | gravatar, keyserver, ghcode, wayback, duckduckgo, websearch |
| **phone** | websearch, duckduckgo |
| **username** | sherlock, github, wayback, websearch |
| **name** | wikipedia, wikidata, openalex, duckduckgo, edgar, websearch, imagesearch, ghcode, wayback |
| **company** | wikipedia, wikidata, duckduckgo, edgar, websearch, imagesearch, wayback |
| **name @ domain** | the name set + `emailguess` (which fans out to gravatar + keyserver per candidate) |

`--only=src,...` and `--skip=src,...` refine the plan further.

### The sources

All keyless, all public:

- **sherlock** — username sweep across ~50 high-value sites
  (GitHub, GitLab, Reddit, Instagram, …). Cap with `--sherlock-n`.
- **github** — public profile via `api.github.com/users/<u>`:
  name, bio, company, blog, follower/repo counts, avatar.
- **ghcode** — public-code mentions of an email or name via GitHub
  code search (surfaces commit emails, config leaks).
- **gravatar** — `md5(email)` → avatar URL + profile JSON. The
  canonical email→face pivot.
- **keyserver** — `keys.openpgp.org` lookup: does this email have a
  published PGP key.
- **wayback** — Web Archive CDX search for archived URLs mentioning
  the identifier.
- **wikipedia** — narrative biography (REST summary) for notable
  names and companies.
- **wikidata** — structured facts: birth/death, occupation,
  employer, nationality, education, place of birth.
- **openalex** — academic affiliations and works for researchers.
- **duckduckgo** — DDG Instant Answer abstract (curated knowledge
  panel text).
- **edgar** — SEC EDGAR full-text search for US public-company
  filings; aggregates the most-mentioned companies for a name.
- **websearch** — DuckDuckGo-lite web scrape: real search-result
  URLs for footprints that aren't Wikipedia-famous.
- **imagesearch** — DDG image search for portrait candidates.
- **brave** — *opt-in.* Joins the plan only when
  `CATHEDRAL_BRAVE_API_KEY` is set; otherwise it's omitted from the
  plan entirely (so the `start` event lists only sources that will
  actually run).

### Portraits and confidence

Hits that carry an avatar emit a `face` with a confidence tier,
which the HUD renders into a portrait grid that fills as the search
runs:

- **high** — self-hosted avatars (Gravatar, GitHub) tied directly
  to the identifier.
- **med** — OpenGraph images scraped from confirmed profile pages.
- **low** — heuristic image-search matches.

A portrait is trusted by **the page it was found on, not the image's
domain**. An image-search face is displayed only when its source
page is a reliable result, and withheld when that page is a weak /
different-identity / geography-only match — so a photo on a strong
press release (even one served from a CDN like `cision.com`) is
shown, while a high-domain photo (say a LinkedIn image) of a
*different* same-named person is dropped because its page didn't
match the target. Directly-resolved avatars (Gravatar/GitHub/
Wikipedia) are always shown. If every candidate's source page is
weak, the panel shows no portrait rather than a misleading one. The
confidence tier above is then used only to order the carousel.

### Region bias

`--region=EE` (or `et_EE`, or inferred from `LANG`/`LC_ALL`) biases
knowledge-base and web-search queries toward a locale, so a name
common in several countries surfaces the regionally-relevant result
first.

### The aggregated report

Per-hit lines are intentionally *silent* in the console — a name
search can return 50+ URLs, and pouring them through as they arrive
buries the signal. Instead, everything lands in state and is
rendered once on completion as three blocks:

- **`[ IDENTITY ]`** — structured facts as an aligned table (name,
  occupation, employer, born, location, nationality, education,
  email, PGP, US filings, GitHub stats, website) plus a bio
  paragraph (Wikipedia → DDG abstract → GitHub bio fallback). For
  ordinary people with no knowledge-base entry, this block is
  skipped entirely.
- **`[ RESULTS ]`** — a search-engine-style list of every URL
  found, deduplicated across sources: title, URL, snippet. The
  clustering pass sorts them into three confidence tiers by weighing
  *positive* evidence, not just keyword overlap:
  - **strong** — the full name tied to the target's corroborated
    companies, or a page that explicitly states their role
    ("owner is …"; such a page also *promotes* its company to an
    anchor, so other pages naming it resolve too).
  - **uncertain — verify** — either an incomplete name match (only
    the surname) or a *different* company but the **same geography**
    as the target. The target's geography is derived from the
    countries its addresses geocode to (so it's grounded in real
    resolved locations, not a keyword list) — and an address only
    counts as the target's when it's corroborated across pages or
    appears in an address context (an "Aadress:" label, beside the
    target's name, or led by one of the target's companies in the
    "Company, address" registered-office pattern), so a stray
    address-shaped string in a footer is ignored rather than
    plotted. Geography is matched across
    languages — a target in Estonia still matches a page that only
    says "Eesti". Shared geography is treated as corroboration, so a
    same-country page lands here, never in "different".
  - **different identity** — a confident name collision: its own
    unrelated company *and* a different geography (likely another
    person who happens to share the name).
- **`[ SUMMARY ]`** — hit / portrait / source counts, plus the
  per-source contribution roll-up so you can see provenance.

### The dossier graph

The side panel shows the candidate portrait; **maximize it** (the
panel's expand control, or the maximize modal) to open the full
dossier — the **portrait beside the *entity-graph map***, like an
ID card: the photo (the "who") on the left, the linked-entity map
(the "what") on the right. The portrait stays steppable (the `‹`/`›`
chevrons and the modal's arrow keys still cycle candidates). The map
is a radial graph of everything the harvest resolved around the
target. The target is the hub; companies, linked people, emails,
phones, addresses, and enriched domains radiate out as colour-coded
spokes. A node's **distance from the centre** encodes corroboration
(better-corroborated facts are pulled inward) and its **size** grows
with the number of distinct pages that mention it. Faint chords
between two entities mean they co-occurred on the same source page —
the same page-level corroboration the clustering pass uses, made
visible. Hover any node for its full value and page count. The map
plots only entities corroborated by a reliable page — anything whose
every source was a weak / different-identity / geography-only result
is left off, so the dossier reflects the target, not a wrong-person
page that happened to share the name. (With no portrait found, the
map takes the whole modal; the compact side panel always keeps the
picture.)

### The authorized-use gate

On first run with no acknowledgement marker, `identify` emits the
authorized-use banner and a `needs_ack` event, then exits without
searching. Passing `--i-understand` writes a marker file
(`~/.cache/cathedral/identify/.acknowledged`) and proceeds; later
runs see the marker and skip the prompt. The gate is per-user,
per-machine — a deliberate, recorded "I understand what this is
for" rather than a click-through nobody reads.

## Worked example

> Illustrative output — fabricated to show the shape, not a real
> lookup. (`identify` results depend entirely on the live public
> internet.)

A self-audit of a username — the safest and most common use:

```
operator@cathedral:~$ identify m.harrington --i-understand
> searching public footprint...
  identifier : m.harrington
  kind       : username
  sources    : sherlock, github, wayback, websearch

[ IDENTITY ]
  name    : Morgan Harrington
  github  : 214 followers · 37 public repos
  website : https://mharrington.dev
  bio     :
            Backend engineer. Distributed systems, Go, and the
            occasional synthesizer build.

[ RESULTS ]

  Morgan Harrington (@m.harrington) · GitHub
  https://github.com/m.harrington

  m.harrington — Mastodon
  https://hachyderm.io/@m.harrington

  Morgan Harrington - Reddit
  https://reddit.com/user/m.harrington

[ SUMMARY ]
  6 hits · 2 portraits · 4 sources ran
  sources : sherlock (3) · github (2) · websearch (1)
```

The portrait grid in the HUD panel fills with the GitHub and
Gravatar avatars (confidence **high**) as the scan runs; maximize
it (`Ctrl+Shift+M`) to see the faces full-size.

### When the input can't be classified

```
operator@cathedral:~$ identify "????"
identify: cannot identify this input. Cathedral identifies email
addresses, phone numbers, usernames, person names (First Last), or
company names …

  examples:
    identify jane@example.com            (email)
    identify +15551234567                (phone)
    identify "Jane Doe"                  (person name)
    identify "Crowned Phoenix OÜ"        (company)
    identify torvalds                    (username)
```

No partial run, no source noise — a clean refusal with guidance.

## Output protocol

Line-oriented JSON.

```
{"event":"start",       "identifier":"…","kind":"…","sources":[…],"region":"…?"}
{"event":"banner",      "lines":[…]}              # first run, before ack
{"event":"needs_ack",   "marker":"<path>"}        # first-run gate
{"event":"needs_kind",  "message":"…"}            # unclassifiable input
{"event":"source_start","source":"…"}
{"event":"hit",         "source":"…","kind":"…","title":"…","url":"…",
                        "avatar_url":"…?","fields":{…}}
{"event":"face",        "source":"…","url":"…","confidence":"high|med|low"}
{"event":"source_done", "source":"…","hits":N,"err":"…?"}
{"event":"done",        "total_hits":N,"faces":N,"sources_ran":N}
{"event":"warn",        "message":"…"}            # non-fatal
{"event":"error",       "message":"…"}            # fatal
```

Each `hit`'s `fields` map carries source-specific structured data
(`name`, `email`, `employer`, `date_of_birth`, `followers`, `form`
for EDGAR, …) which the summary aggregates by category.

```
# Just the profile URLs found
identify torvalds --i-understand | jq -r 'select(.event=="hit") | .url'

# Which sources contributed
identify "Ada Lovelace" --i-understand |
  jq -r 'select(.event=="source_done") | "\(.source): \(.hits)"'
```

## Limitations

- **Free sources, free-source limits.** Keyless public APIs
  rate-limit and occasionally block. A `source_done` with an `err`
  is normal — one source timing out doesn't fail the run.
- **No breach data, no paid sources.** `identify` does not query
  paid breach databases, "people-search" brokers, or anything
  requiring credentials. It surfaces what's *publicly* indexed,
  not what's *for sale*.
- **Knowledge-base coverage is for the notable.** Wikipedia /
  Wikidata / OpenAlex / EDGAR return useful structured facts only
  for public figures, researchers, and US-filing companies. For an
  ordinary person, expect `[ RESULTS ]` and portraits but no
  `[ IDENTITY ]` table — that's the tool working correctly, not
  failing.
- **Portraits are candidates, not confirmations.** A `low`/`med`
  confidence face is a heuristic match; don't treat an image-search
  result as identity confirmation.
- **Classification can be wrong on the margins.** Ambiguous inputs
  (a name that looks like a username, a numeric handle) may
  mis-classify; `--kind` is the override.
- **Phone identification is thin by design.** There's no public
  knowledge base keyed on phone numbers — only web mentions
  (business contact pages, directory listings). Expect little.
- **Brave needs a key.** The one optional source; without
  `CATHEDRAL_BRAVE_API_KEY` it's silently omitted.

## Authorized use

This is a **high-sensitivity** command, and the gate is real, not
decorative.

`identify` aggregates public data about a *person*. The fact that
each individual datum is public does not make assembling them into a
dossier harmless — the aggregation *is* the capability, and it can
be turned to stalking, doxxing, or harassment as easily as to
self-audit. Cathedral's posture is explicit:

- **Run it on yourself, or on subjects you have authority over.**
  Self-audit, consented due diligence, authorized investigation or
  engagement. That's the whole legitimate set.
- **Do not run it on third parties without consent or legal
  authority.** "It's all public" is not authorization. Many
  jurisdictions regulate the *aggregation and processing* of
  personal data independently of whether each source is public
  (the EU GDPR is the clearest example).
- **The acknowledgement is recorded, not waved through.** The
  first-run `--i-understand` gate writes a marker so the
  acknowledgement is a deliberate act. Cathedral exists to make
  defenders strong — not to weaponise public data against people
  who didn't ask to be looked up.
- **Treat the output like the dossier it is.** A completed
  `identify` report is concentrated personal information. Don't
  paste it into public issues, don't retain it beyond the
  authorized purpose.

## Further reading

- [GitHub REST API — Users](https://docs.github.com/en/rest/users) — the `github` source.
- [Wikidata](https://www.wikidata.org/) and [OpenAlex](https://openalex.org/) — the structured-fact and academic sources.
- [Gravatar](https://gravatar.com/) and [keys.openpgp.org](https://keys.openpgp.org/) — the email→avatar and email→PGP pivots.
- [SEC EDGAR full-text search](https://efts.sec.gov/LATEST/search-index?q=) — the US public-company filing source.
- [Sherlock](https://github.com/sherlock-project/sherlock) — the username-sweep technique Cathedral's `sherlock` source is modelled on.
- Related Cathedral commands: [`whois`](whois.md) (domain/registrant records), [`geoip`](geoip.md) (IP → location), [`locate`](locate.md) (address → map).
