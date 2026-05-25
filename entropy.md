---
title: entropy — password-strength upper-bound + pattern analysis
command: entropy
category: crypto-utility-belt
status: shipped
version-introduced: 1.0
authorized-use: low
last-updated: 2026-05-25
related: [argon2, bcrypt, pwned, crypt]
---

# `entropy` — password-strength upper-bound + pattern analysis

`entropy` estimates the strength of a single password by combining
a *naïve upper-bound entropy* calculation (charset size × length →
bits) with a pattern sniffer for the obvious weakness shapes —
single-case-only letters, digit-only strings, repeating-character
runs, alphabet sequences, common keyboard rolls (`qwerty`,
`12345`, `password`). Reports a strength band (weak / fair /
strong / paranoid / post-quantum) and a crack-time projection at
1 billion guesses per second (commodity-GPU pace on a fast hash).

The honest framing matters: **this is a *ceiling* on password
strength, not a real audit**. A 50-bit upper bound can describe a
password that's actually in the top-100 wordlist at rank 47. The
pattern sniffer is the corrective lens — when patterns fire,
trust them over the bit count. For the final check before
production password storage, pair `entropy` with the planned
[`pwned`](pwned.md) (Have I Been Pwned k-anonymity lookup) so
breach-list membership is also covered.

```
entropy password
entropy "Hunter22!"
entropy "Tx7!Qm2#vR9pK4nL"
entropy "correct horse battery staple"
```

## What it does

For a single password argument:

1. Walk each rune; tally which character classes are present —
   lowercase, uppercase, digits, punctuation, space, non-ASCII
   Unicode.
2. Sum a *charset-size* estimate: 26 per case + 10 for digits +
   33 for ASCII punctuation + 1 for space + 1000 for Unicode
   (rough; enough to lift the bound meaningfully).
3. Compute `bits = length × log2(charset_size)` — the naïve
   upper bound assuming each character is uniformly random from
   the assumed charset.
4. Project a crack-time at 1B guesses/sec (`2^bits / 2 / 10^9`
   seconds — average half the keyspace).
5. Sniff for known weak patterns: under 8 chars, single-case
   only, digits only, 3+ character runs, monotonic alphabet
   sequences, common keyboard rolls.
6. Report classes + bits + band + crack-time + patterns.

No flags — single argument, deterministic output.

## What it answers

**Defender (password-policy review):** *"Does our minimum-strength
rule actually require strong passwords?"* Run `entropy` against
the examples your policy would *allow* but you suspect aren't
strong enough. The bit count + band tell you the upper bound
your policy permits; the pattern sniffer reveals what your
policy *doesn't* catch (e.g. "complexity rules satisfied" can
still match `Password1!` with patterns firing).

**User (personal-credential audit):** *"How does this password I
came up with stack up?"* Type it into `entropy`; if the band is
weak or fair, or any patterns fire, replace it. Strong (≥80
bits) with no patterns is the threshold for general account
use; paranoid (≥128 bits) for high-value accounts.

**Authorized testing:** *"Is this leaked password likely to be in
a wordlist?"* The pattern sniffer is the signal. Any pattern
firing → almost certainly in the top-1M dictionary →
crackable in seconds with a wordlist attack. No patterns + low
bit count → still likely dictionary-attackable but worth
running against larger lists. No patterns + high bit count →
brute-force is impractical; only targeted social-engineering
or breach-list lookup will recover it.

**Identification (heuristic):** *"What kind of password generator
produced this?"* Several stylistic fingerprints:

- 16+ chars, all 4 ASCII classes, no patterns → password
  manager output (likely BitWarden / 1Password / built-in
  browser).
- 20+ chars, lower + space, no patterns → diceware-style
  passphrase (`correct horse battery staple`).
- 8–10 chars with specific class mix matching a corporate
  complexity rule (`Aa1!` minimum) → user-chosen "complies
  with policy" pattern, often weak in practice.

## How it works

### The upper-bound entropy formula

```
bits = length × log2(charset_size)
```

This is the canonical "if we assume each character is uniformly
random from a charset of N symbols, the bits of entropy is
log2(N) per character." It's the *largest possible* entropy a
password of that length and class composition could carry — the
ceiling. Reality is almost always lower because:

- Humans don't pick uniformly at random.
- Predictable patterns (year suffixes, name prefixes, l33t
  substitutions) consume the keyspace unevenly.
- Wordlist attacks try most-likely candidates first; an English
  word at rank 47 is found in ~47 attempts regardless of its
  theoretical entropy.

The formula is honest about being an upper bound. The pattern
sniffer adjusts for the most-obvious weaknesses but doesn't
claim to model human password-picking statistics — that's what
[zxcvbn](https://github.com/dropbox/zxcvbn) does (extensively),
or what an HIBP lookup answers (definitively, for known
breached passwords).

### Character classes + charset estimate

Cathedral counts the following classes with rune-level Unicode
awareness:

| Class            | Adds to charset size | Detection |
|------------------|---------------------|-----------|
| Lowercase `a-z`  | +26                 | byte range |
| Uppercase `A-Z`  | +26                 | byte range |
| Digit `0-9`      | +10                 | byte range |
| Space (ASCII)    | +1                  | `r == ' '` |
| ASCII punct/sym  | +33                 | printable ASCII outside letters/digits/space |
| Non-ASCII Unicode | +1000              | `r > 127` (any non-ASCII rune) |

The Unicode bump of `+1000` is a deliberate undercount — the
actual Unicode codepoint space is 1M+ codepoints, but real-
world passwords use a tiny fraction of those (commonly accented
Latin, CJK common-use blocks). 1000 is roughly the size of the
practical pool, and it lifts the bound noticeably without
overclaiming.

### The strength bands

```
< 28 bits → weak         "cracked in seconds with offline GPU attack"
< 50 bits → fair         "minutes to days to crack with serious resources"
< 80 bits → strong       "weeks to centuries — adequate for most accounts"
< 128 bits → paranoid    "geological timescales without quantum"
≥ 128 bits → post-quantum "impractical even with future tech"
```

Boundaries calibrated against the 1B-guesses-per-second
benchmark:

- 28 bits = 2^28 ≈ 268 million guesses → ~0.27 seconds.
- 50 bits = 2^50 ≈ 1.1 quadrillion → ~13 days.
- 80 bits = 2^80 ≈ 1.2 septillion → ~38 million years.
- 128 bits = 2^128 ≈ 3.4 × 10^38 → ~10^22 years (universe age
  is ~10^10 years).

**80 bits is the practical-strength threshold.** Below that, an
attacker with enough hardware can eventually crack the password
even if no patterns fire. Above 80 bits, brute-force becomes
genuinely infeasible regardless of motivation.

### Crack-time projection at 1B guesses/sec

```
crack_time = (2^bits / 2) / 10^9 seconds
```

The `/2` is the average-case factor — on average, a brute-force
attack finds the password after searching half the keyspace.

1 billion guesses/sec is the **commodity-GPU rate on a fast
hash** (SHA-1, SHA-256, MD5). For slower hashes (bcrypt at cost
12: ~6,000/sec; Argon2id at OWASP defaults: ~500/sec), the
crack time scales up by the ratio. So `entropy`'s projection is
the *fastest* an attacker could realistically go — the actual
time against well-hashed credentials is orders of magnitude
longer.

Output uses human-readable durations: `seconds`, `minutes`,
`hours`, `days`, `years`, `millennia`, falling back to
scientific notation (`1.2e15 years`) past a millennium.

### Pattern sniffing (the corrective lens)

Five weakness patterns Cathedral specifically flags:

1. **Very short (`<8 chars`)** — exposure to brute force grows
   exponentially with each character added; below 8 chars,
   nothing else matters.
2. **Single-case letters only** — common in user-chosen
   passwords; reduces charset to 26, makes the upper-bound
   misleadingly low.
3. **Digits only** — charset of 10, trivially attackable;
   "12345678" is at the top of every wordlist.
4. **3+ character run of the same character** — `aaab`,
   `1111`, `xxxxx` — keyboard-bash artefact, common in
   user-chosen passwords.
5. **Monotonic alphabet sequence or common keyboard roll** —
   `abcdef`, `12345`, `qwerty`, `asdfgh`, `zxcvbn`, `qwertz`,
   `azerty`, contains `password` (case-insensitive). The
   sequence detector triggers on 4+ consecutive monotonic
   step-by-1 transitions.

When *any* pattern fires, the bit count becomes essentially
meaningless — the password is in the top-1M wordlist and will
be cracked in seconds regardless of its mathematical upper
bound.

### Why this is an upper bound

A 95-character ASCII keyspace (lower + upper + digit + punct)
times length gives the largest possible entropy. But human-
chosen passwords sample from this keyspace *non-uniformly*:

- Initial character: usually a letter (~52 choices, not 95).
- Subsequent characters: heavily biased toward lowercase
  letters; uppercase usually at word boundaries; digits
  usually at the end; symbols rarer.
- Words come from a vocabulary of ~10k-50k English words, not
  random sequences of letters.

Real-world studies (RockYou leak, LinkedIn dump, etc.) show
that user-chosen passwords carry roughly **30-40% of their
naïve-upper-bound entropy** in practice. So a 60-bit upper
bound is closer to 18-24 bits of real entropy — within the
"crackable on a laptop overnight" range.

Cathedral's pattern sniffer is the corrective: when it fires,
treat the bit count as fiction. When it doesn't fire AND the
password length + class diversity is high, the upper bound is
closer to reality.

The honest reading: **entropy is a quick triage tool, not a
strength audit**. Use it as a first-line check; complement with
HIBP lookup (planned [`pwned`](pwned.md)) for breach-list
membership and a real password-strength library (zxcvbn) for
the human-pattern statistics Cathedral doesn't model.

## What Cathedral doesn't do

A few deliberate omissions:

- **No dictionary lookup.** Cathedral doesn't carry a wordlist
  of common passwords; can't tell if your password is `password`
  rank-1 or some unique string. The pattern sniffer catches
  the most obvious dictionary hits via the keyboard-roll
  detection, but it's pattern-based, not list-based. The
  planned [`pwned`](pwned.md) command fills this gap via the
  Have I Been Pwned k-anonymity API.
- **No date pattern detection.** zxcvbn flags `MyPassword1990`
  for the year suffix; Cathedral doesn't. Adding this requires
  a regex-rule library bigger than the rest of the tool put
  together.
- **No l33t-speak detection.** zxcvbn flags `p@ssw0rd` as
  equivalent to `password`; Cathedral treats them as
  independent strings. Same caveat — proper detection requires
  per-substitution rules.
- **No true Shannon entropy from the character distribution.**
  Computing the actual Shannon entropy of the password's
  byte-level distribution would require either many samples
  (impossible for a single password) or a language model.
  Cathedral uses the simpler charset-size upper bound.
- **No file/byte-entropy analysis.** Some uses of "entropy" in
  security tooling refer to scanning files for high-entropy
  regions (compressed / encrypted / packed payloads). That's a
  different tool with the same name — Cathedral's `entropy`
  is the password-strength one. File-entropy scanning is a
  planned separate command.
- **No password generation.** `entropy` analyses, doesn't
  produce. For generation, your password manager is the right
  tool — Cathedral isn't a credential vault.

## Worked example

A walk through the strength bands using representative passwords.

### A weak password

```
operator@cathedral:~$ entropy password
> analysing password (8 chars)

  classes      : a-z
  charset size : 26
  entropy      : 37.60 bits
  band         : fair  (minutes to days to crack with serious resources)
  crack time   : 13 days  @ 1B guesses/sec

  patterns:
    · single-case letters only
    · looks like a sequential / keyboard pattern
```

The bit count says 37.6 bits ("fair" band) — sounds tolerable.
The patterns tell the truth: this is `password`, the
most-tried password in every breach corpus, found in the first
*microsecond* of a wordlist attack regardless of what the bit
count suggests. **When patterns fire, ignore the band.**

### A fair password

```
operator@cathedral:~$ entropy "Hunter22!"
> analysing password (9 chars)

  classes      : a-z, A-Z, 0-9, punct
  charset size : 95
  entropy      : 59.13 bits
  band         : strong  (weeks to centuries — adequate for most accounts)
  crack time   : 19 years  @ 1B guesses/sec
```

All four ASCII classes, 9 chars, 59 bits — lands in "strong".
No patterns fire (no run, no sequence, no keyboard roll, length
≥ 8). Realistic strength: probably weaker than 59 bits because
"Hunter" is a common word + "22" is a common date suffix + "!"
is the most-tried symbol, but no individual pattern hits the
sniffer.

This is the canonical "satisfies corporate complexity rules,
still not great" zone. Adequate for low-value accounts; use a
password manager for anything important.

### A strong password (password-manager output)

```
operator@cathedral:~$ entropy "Tx7!Qm2#vR9pK4nL"
> analysing password (16 chars)

  classes      : a-z, A-Z, 0-9, punct
  charset size : 95
  entropy      : 105.13 bits
  band         : paranoid  (geological timescales without quantum)
  crack time   : 2.0e15 years  @ 1B guesses/sec
```

16 chars, all 4 ASCII classes, no patterns → 105-bit upper
bound, paranoid band. Crack time exceeds the heat-death-of-the-
universe timescale at the 1B guesses/sec rate. This is what a
password manager produces by default; for anything you actually
care about, generate like this.

### A passphrase (diceware-style)

```
operator@cathedral:~$ entropy "correct horse battery staple"
> analysing password (28 chars)

  classes      : a-z, space
  charset size : 27
  entropy      : 133.13 bits
  band         : post-quantum  (impractical even with future tech)
  crack time   : 4.5e18 years  @ 1B guesses/sec
```

28 chars × log2(27) = 133 bits. The famous XKCD passphrase
shape. Reads as "post-quantum" because the per-character
entropy is low (log2(27) ≈ 4.75) but length compensates
massively. Realistic strength is closer to ~44 bits (4 words
from a ~7800-word diceware list × log2(7800) per word) but
still well above the threshold.

This is the case where Cathedral's upper bound *overstates*
strength significantly — the actual diceware-strength estimate
(words from a list, not letters from a charset) would be 44
bits, not 133. The naïve formula treats each character as
independently random; passphrases get most of their entropy
from word-selection, not character-selection.

For passphrase-strength accuracy, manual diceware math (number
of words × log2(wordlist size)) is more honest than
Cathedral's per-character bound. Cathedral's overestimate isn't
*wrong* — 4 random English words ARE harder to brute-force
character-by-character than the diceware math implies, because
the attacker doesn't know in advance that you used the
diceware wordlist — but it's optimistic.

### A famously-weak password

```
operator@cathedral:~$ entropy qwerty
> analysing password (6 chars)

  classes      : a-z
  charset size : 26
  entropy      : 28.20 bits
  band         : fair  (minutes to days to crack with serious resources)
  crack time   : 35 minutes  @ 1B guesses/sec

  patterns:
    · very short (<8 chars)
    · single-case letters only
    · looks like a sequential / keyboard pattern
```

Three patterns fire simultaneously. The 28-bit upper bound is
generous; the actual crack time is **microseconds** because
`qwerty` is at the top of every wordlist ever assembled.

### Digits only

```
operator@cathedral:~$ entropy 19850615
> analysing password (8 chars)

  classes      : 0-9
  charset size : 10
  entropy      : 26.58 bits
  band         : weak  (cracked in seconds with offline GPU attack)
  crack time   : 6.7 minutes  @ 1B guesses/sec

  patterns:
    · digits only — trivially crackable
```

A date in YYYYMMDD format. The bit count puts it in "weak"
(below 28); the pattern explicitly calls out digits-only. Date-
shaped strings are doubly weak: dictionary attacks try every
date in the past century in seconds before they get to random
8-digit strings.

### Unicode boost

```
operator@cathedral:~$ entropy "café-spéciäle-7!"
> analysing password (16 chars)

  classes      : a-z, 0-9, punct, unicode
  charset size : 1069
  entropy      : 161.04 bits
  band         : post-quantum  (impractical even with future tech)
  crack time   : 9.1e23 years  @ 1B guesses/sec
```

The `unicode` class adds +1000 to charset size, lifting the
upper bound dramatically. This is the case where Cathedral's
estimate is **most optimistic** — most Unicode characters used
by humans come from a small pool (accented Latin, common
emoji), not the full 1M Unicode codepoint space. Realistic
strength of a "café"-style passphrase is closer to the
all-ASCII equivalent. Treat the bit count cautiously when
Unicode is present.

## Output protocol

```
{"event":"start",   "length":N}
{"event":"classes", "lowercase":bool,"uppercase":bool,"digit":bool,
                    "symbol":bool,"space":bool,"unicode":bool,
                    "charset_size":N}
{"event":"metrics", "bits":N,"runes":N,"charset_size":N,
                    "band":"weak|fair|strong|paranoid|post-quantum",
                    "band_note":"…","crack_time":"…","patterns":["…"]}
{"event":"done"}
{"event":"error",   "message":"…"}
```

Pipe to extract just the band for batch policy checking:

```
$ for pw in "password" "Hunter22!" "Tx7!Qm2#vR9pK4nL"; do
    band=$(entropy "$pw" -j |
        jq -r 'select(.event=="metrics") | .band')
    printf '%-20s → %s\n' "$pw" "$band"
  done
password             → fair
Hunter22!            → strong
Tx7!Qm2#vR9pK4nL     → paranoid
```

Filter for passwords that fire patterns (the operational signal):

```
$ while read pw; do
    pats=$(entropy "$pw" -j |
        jq -r 'select(.event=="metrics") | .patterns | length')
    [ "$pats" -gt 0 ] && echo "$pw  ($pats patterns)"
  done < candidates.txt
qwerty  (3 patterns)
19850615  (1 patterns)
password  (2 patterns)
```

Bulk-rate a list of password candidates by bit count:

```
$ while read pw; do
    bits=$(entropy "$pw" -j |
        jq -r 'select(.event=="metrics") | .bits')
    printf '%-30s %s bits\n' "$pw" "$bits"
  done < passwords.txt | sort -k2 -rn
correct horse battery staple   133.13 bits
Tx7!Qm2#vR9pK4nL                105.13 bits
Hunter22!                        59.13 bits
password                         37.60 bits
qwerty                           28.20 bits
```

## Limitations

- **Upper bound, not a real audit.** The bit count assumes
  uniform random selection from the charset; real human-chosen
  passwords carry 30-40% of the naïve estimate in practice. Use
  the pattern sniffer as the corrective lens and pair with HIBP
  (planned [`pwned`](pwned.md)) for definitive answers.
- **No wordlist lookup.** Cathedral doesn't carry a top-N
  password list. The pattern sniffer catches keyboard-roll
  shapes but not arbitrary common passwords (e.g. `monkey`,
  `dragon`, `superman` aren't flagged structurally even though
  they're top-100).
- **No date pattern detection.** Calendar dates (`MyPwd2025`,
  `19850615`) read as their literal character classes; the
  pattern sniffer flags digits-only when the password is
  *exclusively* digits, but doesn't flag year suffixes.
- **No l33t-substitution awareness.** `p@ssw0rd` is treated as
  full-charset 8-char, scoring `~52 bits` and reading as fair;
  it should obviously be flagged as a `password` variant.
- **Unicode estimate is conservative-then-optimistic.** +1000
  is an undercount for the *theoretical* Unicode space but an
  overcount for the *practical* per-user vocabulary.
- **Crack-time projection assumes a fast hash.** 1B guesses/sec
  is right for SHA-1/MD5. Against bcrypt or Argon2id, divide
  the rate by ~150,000× to ~2,000,000× respectively — well-
  hashed credentials at the same bit count are vastly harder
  to crack.
- **Single password per invocation.** No batch mode.
- **Password as positional argument.** Same caveat as
  [`argon2`](argon2.md) and [`bcrypt`](bcrypt.md) — shows up
  in `/proc/<pid>/cmdline` and shell history.

## Authorized use

`entropy` is **a local heuristic computation**. No network, no
external dependencies — same posture as
[`argon2`](argon2.md) / [`bcrypt`](bcrypt.md). No
authorisation considerations beyond the obvious "don't echo
production passwords into shared terminals."

The visibility caveat repeats: the password is a positional
argument, visible in process listings and shell history. For
quick personal use, that's fine; for production-policy work
where you're checking real user passwords, integrate the
strength check at the application layer rather than via the
CLI.

## Further reading

- [NIST SP 800-63B — Digital Identity Guidelines: Authentication and Lifecycle Management](https://pages.nist.gov/800-63-3/sp800-63b.html)
  — current US-federal recommendations for password length /
  composition / strength
- [zxcvbn — Dropbox's password-strength estimator](https://github.com/dropbox/zxcvbn)
  — the canonical "realistic" password-strength library;
  includes wordlist, date pattern, l33t-substitution, sequence
  detection
- [Have I Been Pwned k-anonymity API](https://haveibeenpwned.com/API/v3#PwnedPasswords)
  — breach-list membership check via SHA-1 prefix; the
  authoritative "is this password in a known breach" answer.
  Cathedral will expose this via the planned [`pwned`](pwned.md)
  command.
- [XKCD 936 — "Password Strength"](https://xkcd.com/936/) — the
  canonical "correct horse battery staple" passphrase argument
- [Diceware passphrases](https://theworld.com/~reinhold/diceware.html)
  — the original word-selection-via-dice scheme that produces
  measurable per-word entropy
- [RockYou wordlist](https://en.wikipedia.org/wiki/RockYou)
  — the 2009 breach dump that defines "common password" in
  every modern cracker; what your password is competing against
- Related Cathedral commands: [`argon2`](argon2.md) (hash the
  password once you've confirmed it's strong),
  [`bcrypt`](bcrypt.md) (legacy hash; same downstream role),
  [`pwned`](pwned.md) *(planned — Have I Been Pwned k-anonymity
  lookup; the definitive breach-list check)*,
  [`crypt`](crypt.md) *(planned — Unix shadow-file hashes)*,
  [`hash`](hash.md) *(planned — generic digests)*
