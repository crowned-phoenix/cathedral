---
title: ai — a local language model wired into the terminal
command: ai
category: assistant
status: shipped
version-introduced: 1.0
authorized-use: none
last-updated: 2026-11-23
related: [vault, doctor, conns, sniff]
---

# `ai` — a local language model wired into the terminal

`ai` is a chat with a language model that runs entirely on this
machine. There's no API key and no cloud account. Once a model is
downloaded, it works with the network cable unplugged. It knows
Cathedral's own commands, it can read what other tools just printed,
and it suggests the next command as a card you approve before
anything runs.

```
ai [question…]                  # open the pane (and ask)
<command> | ai [question]       # ask about a command's output
ai --last [question]            # … about the previous command's output
ai --pin [question]             # … about what's pinned in the side panel
ai --session [question]         # … about the terminal session on screen
ai draft <what>                 # write a .cthd runbook → new editor tab
ai models                       # downloaded + available models
ai pull <model|url.gguf>        # download (checksum-verified, resumable)
ai use <model|path.gguf>        # load a model
ai rm <model>                   # delete a downloaded model
ai off                          # stop the model, give the RAM back
```

## What it does

`ai` opens a chat pane above Cathedral's console. The first time, `^O`
shows a short catalog of small open-weight models. Pick one and it
downloads into `~/.cathedral/models`, gets its SHA-256 checked, and
loads. After that every `ai` reloads the last model you used.

| Key            | Action                                              |
|----------------|-----------------------------------------------------|
| `↵` / `⇧↵`     | send / new line                                     |
| `Esc`          | stop the answer that's streaming, or hide the pane  |
| `^N`           | new chat                                            |
| `^O`           | model picker (download, load, delete)               |
| `^S`           | seal the chat into the [`vault`](vault.md)          |
| `y` / `⇧Y`     | run the suggested command / run a flagged one       |
| `n` / `e`      | skip the card / edit it in the console first        |
| `F1`           | every key                                           |

Context can come from anywhere in the app:

- **Pipes:** `conns | ai which of these look odd?`
- **The last command:** `ai --last`. You ran something, the output
  confused you, and you didn't think to pipe it.
- **The side panel:** `ai --pin`, or the **✦ ai** button on whatever
  is pinned there.
- **A terminal session:** `ai --session` attaches the terminal
  session on screen.
- **The editor:** `^⇧A` sends the selection, or the whole tab if
  nothing is selected.

Context without a question waits as a chip above the input. Press
Enter on an empty line and the model is asked to *explain this, point
out anything notable or worth investigating, and suggest next steps*.

## What it answers

**"What am I looking at?"** Security tools produce dense output:
cipher-suite lists, DMARC records, a packet capture summary, a JWT
header. `ai` gives a reading of it in plain language, next to the
output itself, without pasting anything into a website.

**"What should I run next?"** The model is given Cathedral's `help`
catalog, so its suggestions are real Cathedral commands with the
hosts and IPs from your conversation already filled in. You don't get
generic `nmap` advice.

**"Write me the runbook."** `ai draft check mail posture for a list
of domains` returns a `.cthd` script in a new, unsaved editor tab.
You read it, edit it and save it yourself. It never runs.

**Privacy:** *"Can I use an assistant on engagement data at all?"*
Scope letters and client output often can't go to a third-party API
under the engagement contract. A model running on loopback on your
own CPU removes that problem.

## How it works

### Two processes, one loopback socket

```
Cathedral UI ──stdin──▶ ai serve ──spawns──▶ llama-server
             ◀─stdout── (sidecar)            127.0.0.1:<random>
               JSON lines    │                 Bearer <random key>
                             └── HTTP, SSE ──▶ /v1/chat/completions
```

The `ai` sidecar is a small Go program with only standard-library
dependencies. It handles the model files and supervises a bundled
**llama.cpp `llama-server`**, a pinned official CPU build. The build's
tarball is checked against a SHA-256 when Cathedral is packaged, and
it ships for both x86-64 and arm64. The UI never talks HTTP itself. It
sends one JSON request per line and gets the answer back as a stream
of `delta` events.

llama-server is an HTTP server, so it can't be left open to every
process on the machine:

```go
port, _ := freePort()          // net.Listen("tcp", "127.0.0.1:0")
b.apiKey = randomKey()         // 24 random bytes, hex

args := []string{
    "--model", modelPath,
    "--host", "127.0.0.1",
    "--port", strconv.Itoa(port),
    "--ctx-size", strconv.Itoa(ctxSize),
    "--parallel", "1",
    "--jinja",                 // use the model's own chat template
    "--no-webui",
}
cmd := exec.Command(llamaBin, args...)
// The key goes via env, not argv (argv is world-readable in /proc).
cmd.Env = append(os.Environ(), "LLAMA_API_KEY="+b.apiKey)
// Own process group + parent-death signal: llama-server never
// outlives the sidecar, even if the sidecar is SIGKILLed.
cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
```

The server binds to loopback only, so nothing off-box can reach it. It
uses a random port, so nothing can count on finding it. A random
bearer key, passed in the environment, stops other local users and
processes from using your model. `Pdeathsig` handles a nastier
failure: when Cathedral crashes, the kernel kills the 3 GB model
process along with it. You don't find it in `top` an hour later.

The sidecar waits for `/health` before it reports the model as
loaded. If llama-server dies later (usually out of memory), the
sidecar keeps the last twelve stderr lines and finds the most useful
one (`error`, `failed`, `out of memory`), so the UI can say *why* it
died.

### Models: a small pinned catalog, verified end to end

The catalog is five GGUF models, all quantised to **Q4_K_M**. For
CPU inference that's the usual sweet spot: quality close to 8-bit at
about half the RAM.

| Key            | Size   | Notes                                       |
|----------------|--------|---------------------------------------------|
| `qwen3-4b`     | 2.3 GB | default — best all-round on CPU             |
| `qwen2.5-1.5b` | 1.0 GB | fastest, lighter answers                    |
| `llama3.2-3b`  | 1.9 GB | Meta's small model                          |
| `gemma3-4b`    | 2.3 GB | Google's small model                        |
| `qwen3-8b`     | 4.7 GB | smartest, slower — reasons before answering |

Each catalog entry pins the Hugging Face repo, file name, exact byte
size and SHA-256. `ai pull` also takes any `https://…/*.gguf` URL.
When the URL is a Hugging Face `resolve` link, the sidecar looks the
digest up in the repo's file listing (the LFS object ID *is* the
SHA-256), so most custom models get verified too. You can also drop
a `.gguf` into the models folder by hand and it shows up in the
picker too, though nothing has checked it.

Model files are several gigabytes, so a download has to survive a
dropped connection:

```go
part := final + ".part"
f, _ := os.OpenFile(part, os.O_RDWR|os.O_CREATE, 0o600)

h := sha256.New()
have, _ := io.Copy(h, f)       // re-hash what an earlier attempt fetched
if have > 0 {
    req.Header.Set("Range", fmt.Sprintf("bytes=%d-", have))
}
// … 206 → append; 200 → server ignored Range, restart from zero …

if hex.EncodeToString(h.Sum(nil)) != t.SHA256 {
    os.Remove(part)            // never keep a file that failed the check
    return errDigest
}
os.Rename(part, final)         // only a verified file gets the real name
```

The hash covers the *whole* file, including bytes fetched in an
earlier session. A `.part` file someone tampered with between runs
fails the check just like a bad download would. Cancelling a pull
leaves the `.part` in place, and pulling again resumes it.

### Fitting a conversation into 8,192 tokens

The sidecar starts llama-server with an 8K context window. On a CPU
that's a reasonable trade between memory, prompt-processing time and
how much the model can see. Each turn, the UI builds the prompt
from scratch:

1. **System prompt:** who the model is, that it's running locally, the
   card format for commands, the `.cthd` runbook grammar, and
   Cathedral's `help` catalog.
2. **History, newest first,** added until a budget of about
   `(ctx − 1536) × 3` characters is spent. That's roughly 3 characters
   per token, with 1,536 tokens kept free for the answer. Older turns
   are dropped and the status line says so.
3. **Attachments,** each limited to its share of about half the
   window. An oversized attachment is cut **head and tail**: the first
   60% of the budget comes from the top, the rest from the bottom, and
   `… [N lines omitted] …` goes in between. Tool output puts its
   headers at the top and its errors and summaries at the bottom, so
   the middle is the cheapest part to lose.

````
Context — sniff -c 400 (trimmed; 1,812 lines originally):
```
SNIFF  eth0  filter: none
…
… [1,388 lines omitted] …
…
summary: 400 packets · 31 flows · 3 hosts > 50% of bytes
```
Which of these flows should I look at first?
````

### Command cards: suggestion, approval, execution

One rule holds throughout: **the model never runs anything.** It's told to put commands in a ```` ```cathedral ```` block
of one to three lines. The UI parses each finished answer and turns
such a block into **cards**, one per command, each with its own
approval:

```
┌ ssl mail.example.org:465 ───────────────────────── y run · n skip · e edit ┐
┌ dmarc example.org ──────────────────────────────── y run · n skip · e edit ┐
```

A block becomes a *draft* instead (the **→ editor** button, never
cards) when it's longer than three commands, uses control flow (`if`,
`for`, `while`, `do`, …), or contains a heredoc or a line
continuation. It also does when any line doesn't start like a command,
which catches blocks of example output dressed up as code.

Some cards are flagged and need a deliberate **Shift+Y**:

| Flag                          | Triggered by                                  |
|-------------------------------|-----------------------------------------------|
| runs as root                  | `sudo`, `su`, `pkexec`, `doas`                |
| can change or destroy data    | `rm`, `dd`, `mkfs.*`, `shred`, `chmod`, `kill`, `iptables`, `systemctl`, … |
| writes to a file              | `>` / `>>` redirection                        |
| pipes a download into a shell | `curl … \| sh`, `wget … \| bash`              |
| recursive ai call             | the model suggesting `ai …`                   |

This is not a sandbox and doesn't claim to be. The approval is the
safety mechanism. The flags make the dangerous approvals slower, so
holding down `y` can't wipe a disk. A card with a `<placeholder>`
(`scan <target-ip>`) is never run as-is. `y` puts it in the console
input for you to finish.

When an approved command finishes, its output is **attached to your
next question**. That closes the loop: the model suggests `ssl`, you
approve it, and the next turn can ask *"is that chain OK?"* without
any copy-paste.

### Reasoning models

`qwen3-8b` reasons before it answers. llama-server sends that
reasoning in a separate `reasoning_content` field. The sidecar
forwards it as `think` events, and the pane shows it collapsed under
a dim **reasoning** fold. You can open it to see *why* the model
suggested something. It isn't sent back as history on later turns, so
it doesn't use up the context window.

### Chats are not files

The sidecar never writes a chat to disk. A conversation lives in the
UI's memory until you close it, unless you press `^S`. Then the
transcript is sealed into the [`vault`](vault.md) under `/ai/` and
re-saved after every answer (the footer shows **🔒 vault-synced**).
Either the chat stays in memory or it's encrypted. There's no option
that leaves a plaintext `chat-history.json` in your home directory.

## Worked example

Asking about a suspicious connection list, then letting the model
drive two follow-ups. Hosts, addresses and processes are
illustrative:

```
operator@cathedral:~$ conns | ai anything here I should worry about?
> ai: opening

  ✦ ai · qwen3-4b · ctx 8192 ─────────────────────────────────────────
  you   ▸ context: conns (14 lines)
          anything here I should worry about?

  ai    Most of this is ordinary: firefox to a CDN, your ssh session
        to homeserver.lan, syncthing on its usual port, and postgres
        on loopback.

        One stands out: `python3` (pid 48211) has an established
        connection to 203.0.113.77:4444. Port 4444 is a common
        default for reverse shells and Metasploit handlers, and
        nothing else on this machine talks to that network.

        Find out who owns that address and what the process is:

        ┌ whois 203.0.113.77 ──────────────── y run · n skip · e edit ┐
        ┌ ports ───────────────────────────── y run · n skip · e edit ┐

        If it turns out to be unwanted, kill the process:

        ┌ kill 48211 ───── ⚠ can change or destroy data (kill) · ⇧Y ┐

                                                   11.8 tok/s · 212 tok
  ──────────────────────────────────────────────────────────────────
  ▸ ran `whois 203.0.113.77` · 23 lines attached — ask a follow-up,
    or Enter to explain · y/n for the next card
  ↵ send  ⇧↵ line  Esc stop  ^N new  ^O models  ^S vault  F1 keys
```

`y` ran `whois` and attached its output. `n` skipped `ports`. The
`kill` card is still waiting, and a plain `y` on it only shows the
warning. Pressing Enter next asks the model about the whois record
it just got.

The model picker on a fresh install:

```
operator@cathedral:~$ ai models
[ models ] ~/.cathedral/models
  ● qwen3-4b            2.3 GB  best all-round on CPU
  ✓ qwen2.5-1.5b        1.0 GB  fastest, lighter answers
    llama3.2-3b         1.9 GB  Meta's small model
    gemma3-4b           2.3 GB  Google's small model
    qwen3-8b            4.7 GB  smartest, slower — reasons before answering
  ✓ downloaded   ● loaded   — `ai pull <key>` to download
```

## Output protocol

Like [`vault`](vault.md), `ai serve` is a long-lived session, not a
streaming command. One JSON request per stdin line. Replies and
stream events carry the request id:

```
← {"event":"ready","dir":"/home/operator/.cathedral/models","llama":true,"ctx":8192}
→ {"id":1,"op":"pull","model":"qwen3-4b"}
← {"id":1,"file":"Qwen3-4B-Instruct-2507-Q4_K_M.gguf","total":2497281120,"verified":true}
← {"id":1,"progress":524288000,"total":2497281120}*
← {"id":1,"ok":true,"path":"…","verified":true,"key":"qwen3-4b"}
→ {"id":2,"op":"load","model":"qwen3-4b"}
← {"id":2,"loading":"qwen3-4b"}
← {"id":2,"ok":true,"name":"qwen3-4b","ctx":8192}
→ {"id":3,"op":"chat","messages":[{"role":"system","content":"…"},{"role":"user","content":"…"}]}
← {"id":3,"think":"…"}*
← {"id":3,"delta":"Most of"}*
← {"id":3,"ok":true,"finish":"stop","tokens":212,"prompt_tokens":1840,"tps":11.8}
→ {"id":4,"op":"stop"}
← {"event":"server_exit","error":"… out of memory …"}
```

Errors are `{"id":N,"ok":false,"error":"…"}`. Other ops: `status`,
`cancel` (a pull or chat by `target` id; a cancelled pull resumes on
the next `pull`), `unload`, `delete`, `quit`. Only one chat runs at a
time. A second one is refused with *"still answering — stop it
first"*. When the sidecar's stdin closes because Cathedral exited, it
stops llama-server and exits.

`ai serve --endpoint URL` points the sidecar at any OpenAI-compatible
server instead of spawning llama-server, for example one on a
GPU box on your LAN. The protocol stays the same. Privacy then depends
on where that server is.

## Limitations

- **Small models get things wrong.** A 4B model running on a laptop
  CPU is useful, but it isn't an expert. It can misread a cipher
  suite, invent a CVE number, or call a benign port suspicious.
  Treat what it says as a lead to check with a real tool. That's why
  its suggestions are commands you run and read yourself.
- **Speed is CPU-bound.** Expect roughly 8–15 tokens per second for a
  4B model on a recent laptop CPU, and about half that for `qwen3-8b`.
  A large attachment costs time before the first word appears, because
  prompt processing scales with context length. There's no GPU
  offload yet.
- **RAM stays held while a model is loaded.** That's about 3 GB for a
  4B model and 6 GB for the 8B one, until `ai off` or you close
  Cathedral. Automatic unloading after an idle period is planned.
- **8K context.** Long sessions drop their oldest turns, and big
  attachments are trimmed head and tail. The model really doesn't see
  the omitted middle, so it can't tell you about something that was in
  it.
- **Approval is the only safeguard.** The risk flags are heuristics
  over the command text. `bash -c "…"` or an alias can hide a
  destructive command from them. Read every card before you press `y`.
- **Prompt injection through context.** Attached output is untrusted
  text. A web page's `<title>`, a TXT record or a log line can contain
  instructions aimed at the model, and a small model may follow them.
  The worst it can do is *suggest* a command, which you still have to
  approve. Watch for suggestions that have nothing to do with your
  question.
- **The chat lives in the UI process** until it's sealed into the
  vault. As with vault previews, Dart strings can't be reliably
  zeroed.
- **Saved chats can't be reopened** to continue them yet. They're
  readable in the vault, and resuming them is planned.
- **Linux-first.** `Pdeathsig` and process-group signalling are Linux.
  The bundled llama-server is the Ubuntu x64/arm64 build.

## Authorized use

`ai` reads only what you give it and runs only what you approve. Its
posture is that of the commands it suggests. Recommending `scan`
against a host doesn't authorise scanning that host, and a model
proposing a target isn't a scope letter. The local-only design is
there so engagement data can be analysed without breaking
confidentiality terms. Check that your contract treats on-device
processing the way you assume it does.

## Further reading

- [llama.cpp](https://github.com/ggml-org/llama.cpp) and its
  [`llama-server` README](https://github.com/ggml-org/llama.cpp/tree/master/tools/server)
- [GGUF format specification](https://github.com/ggml-org/ggml/blob/master/docs/gguf.md)
- [Hugging Face Hub — download files / LFS](https://huggingface.co/docs/hub/storage-backends)
- [OWASP Top 10 for LLM Applications — LLM01 Prompt Injection](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
- [`prctl(2)` — `PR_SET_PDEATHSIG`](https://man7.org/linux/man-pages/man2/prctl.2.html)
- Related Cathedral commands: [`vault`](vault.md) (where chats are
  saved), [`conns`](conns.md) and [`sniff`](sniff.md) (good things to
  pipe in), [`doctor`](doctor.md)
