---
title: edit — the built-in editor, file tree and syntax highlighting
command: edit
category: workspace
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-11-23
related: [vault, ai, web]
---

# `edit` — the built-in editor, file tree and syntax highlighting

`edit` opens files in Cathedral's own editor. It's a tabbed text
editor in the main pane, with a project tree on the left, syntax
colouring in the same phosphor palette as the rest of the screen, and
links into the [`vault`](vault.md), the [`ai`](ai.md) and the side
terminal. It isn't trying to replace your IDE. It's there so that
writing a runbook, fixing a config, or reading a script you just
pulled from a target doesn't mean leaving the terminal.

```
edit                     # empty buffer; the name is chosen at save time
edit <file> [<file>…]    # one tab per file (created on save if missing)
edit <folder>            # open the tree rooted there (edit . for the cwd)
```

## What it does

| Key                 | Action                                          |
|---------------------|-------------------------------------------------|
| `^S` / `^⇧S`        | save (asks for a name if untitled) / save as    |
| `^N` / `^O` / `^W`  | new tab / open a file / close the tab           |
| `^Tab` `^⇧Tab`      | next / previous tab                             |
| `Alt+1`…`Alt+9`     | jump to a tab                                   |
| `^B`                | pick a tab from a list                          |
| `^F`                | find                                            |
| `^E` / `^⇧E`        | show or hide the file tree / focus it           |
| `^⇧A`               | send the selection (or the whole tab) to the ai |
| `Esc`               | close the editor (tabs stay open)               |
| `F1`                | every key                                       |

In the **file tree**:

- **Mouse:** click selects (and opens or closes folders), and
  double-click opens a file.
- **Keyboard:** `↑↓←→ ↵`, `⌫` to move the root up a level, `F2` to
  rename, `Del` to delete, `F5` to refresh, and type-ahead to jump
  to a name.
- **Right-click** offers: new file or folder (`sub/dir/file.go`
  creates the folders too), rename (open tabs follow the file), move
  to trash, copy path, *run*, *terminal here* and *ask ai*.

**Run** depends on the file type. A `.cthd` runbook runs in the
console. A `.sh`, `.py`, `.go`, `.js`, `.rb`, `.pl` or `.dart` file
runs in the side-panel terminal, which then drops into a shell so the
output stays readable. The editor itself stays on screen.

## What it answers

**"Let me fix this one line."** A config, a wordlist, a `.cthd`
runbook the [`ai`](ai.md) drafted. Opening, editing and saving all
happen without leaving Cathedral or losing the system and globe
panels at the side.

**"What's in this project?"** `edit .` shows the folder as a tree
with `git status` markers (`M` `A` `D` `R` `?` `U`, plus a `•` on a
folder that contains changes). The tree updates live as files change
on disk.

**"Read this script before I run it."** A shell script fetched during
an engagement, a page's HTML from [`web`](web.md) (`v`), a JSON
response. All of it opens with syntax colouring, so structure,
strings and comments are readable at a glance.

## How it works

The editor is part of the Flutter UI, not a sidecar. Each tab is a
buffer with its own text controller. That keeps the cursor,
selection, undo history and scroll position per tab, intact across
tab switches. Files over 1 MB are refused, and so is any file with a
NUL byte in its first 4 KB, because that means it's binary. A
buffer can also be *virtual*. A vault file opens decrypted in memory,
and `^S` encrypts it back into the vault instead of writing plaintext
to disk.

### The tree: lazy, watched, honest about deletes

Folders are listed only when you expand them, so opening a large
repository doesn't walk all of it. Each expanded folder is watched
with inotify, so files created or deleted by a build or `git
checkout` show up without a refresh. If the system's inotify limit
is reached, the tree falls back to manual `F5` refresh. Git markers
come from one `git status --porcelain=v1` per repository, not one
call per file.

*Delete* never unlinks anything. It moves the file to the
freedesktop.org trash, the same one your file manager uses, so it can
be restored from there:

```dart
// ~/.local/share/Trash/{files,info}: move the file, write the receipt.
await infoFile.writeAsString(
  '[Trash Info]\nPath=${Uri.encodeFull(path)}\nDeletionDate=$date\n',
);
await File(path).rename('${files.path}/$name');   // same filesystem: atomic
```

If the file is on a different filesystem from the trash, the rename
fails and nothing is deleted. You get an error instead of a silent
copy-then-delete.

### Syntax highlighting without a parser

Colouring covers about twenty file types:

- **Languages:** Go, Dart, JavaScript/TypeScript, Python, shell
  (including `.cthd` runbooks), C/C++, Rust, and Java, Kotlin, C#
  and Swift.
- **Data and config:** JSON, YAML, TOML/INI/`.env`/`.gitignore`,
  SQL, and `go.mod`.
- **Markup:** Markdown, HTML/XML/SVG, and CSS/SCSS.
- **Build files and patches:** Dockerfile, Makefile, and diff/patch.

The type comes from the file name or extension. For extensionless
files it comes from a `#!` line, so `#!/usr/bin/env python3` colours
as Python. Save-as to a new extension switches the colouring at once.

Each language is a short list of regular expressions, compiled into
**one** alternation, so a whole file is coloured in a single
`allMatches` pass:

```dart
final _go = Language('go', const [
  _Rule(r'//[^\n]*', Tok.comment),
  _Rule(r'/\*[\s\S]*?(?:\*/|(?![\s\S]))', Tok.comment),  // unterminated → to EOF
  _Rule(r'`[^`]*`?', Tok.string),                         // raw strings span lines
  _Rule(r'"(?:\\[\s\S]|[^"\\\n])*"?', Tok.string),
  _Rule(_num, Tok.number),
  _Rule(r'[A-Za-z_]\w*', Tok.ident),                      // classified below
], keywords: …, types: …, builtins: …, capsAreTypes: true);
```

The order of the rules matters. At any position, the leftmost match
wins, and among matches at the same position the earlier rule wins.
Listing comments and strings before identifiers is what stops
`"// not a comment"` from being coloured as a comment. An
unterminated `/*` or string runs to the end of the file. That's what
you see in every other editor while typing one, and it means a
missing quote shows up immediately.

Identifiers are classified after matching. A keyword is a keyword.
`name(` is a function call. In Go, Dart, Java and Rust a capitalised
word is a type and an ALL_CAPS word is a constant. The colours come
from the phosphor theme: keywords cyan-green, types pale sky blue,
strings soft amber, numbers orange, calls lime, comments dim green
italic. Each colour carries a faint glow in its own hue.

### Fast enough for every keystroke

Re-colouring the whole file on every keystroke would cost about 45 ms
at 256 KB. That's more than a frame, and you'd feel it while typing.
So the editor re-colours **incrementally**:

1. Diff the new text against the old to find the common prefix and
   suffix.
2. Keep every coloured token that ends safely before the change. The
   margin covers lookahead, such as the `(` check that marks function
   calls.
3. Rescan from the last kept token, which is exactly where a full
   scan would have resumed.
4. As soon as a new match starts where an old one started (shifted by
   the length difference) and past the change, the rest of the file
   is provably unchanged. The old tokens are reused, shifted.

```dart
if (m.start >= resync.after) {
  final j = resync.oldIndexOfStart(m.start - resync.delta);
  if (j >= 0) {                      // same text, same start, same regex:
    for (final o in old.skip(j)) {   // the rest of the scan is identical
      out.add(o.shift(resync.delta));
    }
    return;
  }
}
```

A keystroke in the middle of a 256 KB file costs about 1.5 ms. A fuzz
test makes thousands of random edits across six languages, including
opening and closing comments and strings, and checks the incremental
result against a full rescan after every one. Files over 256 KB are
shown without colour.

## Worked example

Opening a project, fixing a runbook and running it. Paths and names
are illustrative:

```
operator@cathedral:~/engagements/acme$ edit .

  [ editor :: ~/engagements/acme/runbooks/sweep.cthd ]
  ┌─ acme/ ───────────┐ ┌ sweep.cthd ● ┐ notes.md   scope.yml
  │ ▾ runbooks/     • │  1  # Weekly external sweep for ACME
  │     sweep.cthd  M │  2  for TARGET in $@
  │     mail.cthd     │  3    echo "=== $TARGET ==="
  │ ▸ loot/           │  4    headers https://$TARGET
  │   notes.md      M │  5    ssl $TARGET
  │   scope.yml       │  6    if $TARGET contains mail
  │   wordlist.txt  ? │  7      dmarc $TARGET
  └───────────────────┘  8    endif
                         9  endfor
  ──────────────────────────────────────────────────────────────────
  [ ~/engagements/acme/runbooks/sweep.cthd ]  [modified]  L7 C17   shell
  ^S save  ^⇧S save as  ^N new  ^O open  ^W close tab  ^B tabs  F1 keys
```

In the editor, `#` comments are dim, `for`/`if`/`endif`/`endfor` are
keywords, `$TARGET` is coloured as a variable, and the quoted strings
are amber. `^S` saves. Right-clicking `sweep.cthd` and choosing *run*
runs it in the console with the targets you type. `wordlist.txt`
shows `?` because git doesn't track it yet.

## Limitations

- **Not an IDE.** There's no language server, so no completion,
  go-to-definition or inline errors. There's no multi-cursor and no
  split view.
- **Highlighting is lexical.** It colours tokens, it doesn't parse.
  It can't tell a Go type from an exported variable (both are
  capitalised). It doesn't colour `$x` inside strings, or JavaScript
  embedded in HTML.
- **Limits:** files over 1 MB don't open, and files over 256 KB open
  without colour.
- **Long lines wrap.** There's no horizontal scrolling mode.
- **The tree doesn't move files by drag-and-drop yet,** doesn't dim
  `.gitignore`d entries, and doesn't remember its root and expansion
  across restarts. A fuzzy `^P` *go to file* is planned.
- **Linux-first.** inotify watching and the freedesktop trash are
  Linux conventions.

## Authorized use

An editor touches only the files you open. Running a file from the
tree runs it with your own permissions, the same as typing the
command yourself, so read a script before you run it. Syntax colouring
helps with that, but it isn't a review.

## Further reading

- [freedesktop.org Trash specification](https://specifications.freedesktop.org/trash-spec/latest/) — the `.trashinfo` format
- [`inotify(7)`](https://man7.org/linux/man-pages/man7/inotify.7.html) — and its per-user watch limit
- [`git status --porcelain`](https://git-scm.com/docs/git-status#_porcelain_format_version_1) — the stable machine format the markers parse
- [ECMAScript RegExp](https://tc39.es/ecma262/#sec-regexp-regular-expression-objects) — leftmost-alternative semantics the tokenizer relies on
