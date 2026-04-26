# Recovering Passwords from PFS Professional Write 1988

A short whitepaper on the password storage scheme used by **PFS
Professional Write 1988** (PW.EXE), the vulnerability that exposes the
password directly from the file, and the way the vulnerability was
discovered by Anthropic's Claude in a Cowork session (using Opus 4.7).

The companion tool that operationalizes this — `pfs_cipher.py` in this
folder — uses the same recovered cipher to scan folders for PFS
documents and recover the password from each encrypted one in
microseconds.

---

## Part 1: What this tool is

`pfs_cipher.py` is a folder scanner and password recovery utility for
PFS Professional Write 1988 documents. Pointed at a folder, it walks
every file, decides whether each one is a PFS document (encrypted or
plain), and for the encrypted ones recovers the protecting password
without any guessing, brute force, or interaction with the original
PW.EXE binary.

The recovery is not a brute-force attack and is not slowed by long
passwords. It runs in time linear in the number of files scanned, with
each per-file step taking microseconds. A folder with thousands of
PFS documents reports its full inventory in well under a second.

That this is possible at all is the vulnerability: the password is
stored *inside* every encrypted PFS file, encoded with a fixed
substitution scheme that has no key material beyond a constant lookup
table and a constant per-position shift schedule. The encoding is
fully reversible. Knowing the algorithm — which is what the rest of
this document is about — is equivalent to knowing the password of
every encrypted PFS file ever made.

The scanner exists because, in 2026, anyone with a folder of legacy
1988-era PFS documents and a few seconds of compute can read the
passwords back out. Confidentiality of those documents under their
PFS-native protection should be considered void.

---

## Part 2: The PFS encryption scheme, plain English

PFS Professional Write 1988 was a popular DOS word processor sold by
Software Publishing Corporation. It allowed the user to mark a
document as encrypted at save time, prompting twice for a password (up
to 20 characters) and producing a single file that could only be
reopened by typing the same password back. There is no recovery flow
in the product.

If you'd asked a knowledgeable user in 1988 how PW.EXE protects a
document, the answer would be vague but reasonable: "it scrambles the
file with the password, and without the password you can't unscramble
it." That is the mental model: password is the key, the document is
the ciphertext, and unscrambling without the key is hard.

In reality the protection is split into two pieces:

1. The **password itself** is stored inside the file, in a fixed
   location near the top, encoded with a simple substitution scheme.
2. The **document body** is scrambled with a stream of bytes derived
   from the first ~8 characters of the password.

Crucially, the password storage in step 1 doesn't depend on any
secret. PW.EXE encodes the typed password into a slot, and at
re-open time it reads the slot back, decodes it, and asks "is what
the user just typed equal to what's in the slot?" If yes, decrypt the
body. If no, show the wrong-password dialog. The "key" used to
encode the slot is hard-coded into PW.EXE itself.

The consequence: the password is, in a meaningful sense, **stored
inside the file in a recoverable form**. Once you know how the encoding
works, you read it straight out of the file. No trying combinations,
no brute force. The body cipher is incidental — once you have the
password you can simply re-open the document in PW.EXE and read it
normally.

A modern password store needs three properties — it must be one-way
(reading the stored form must not let you recover the password),
salted (two users with the same password must produce different stored
forms), and slow (verification must take real CPU time so brute force
is throttled). PW.EXE has none of these. The encoding is reversible,
unsalted, and trivially fast. In 1988 this was acceptable engineering
for a consumer word processor — the threat model was a co-worker
glancing at the file, not a serious adversary. But it means the
protection is obfuscation, not security.

---

## Part 3: Technical details

### File format

A PFS Pro Write 1988 document has a 1024-byte (`0x400`) fixed header
followed by the encrypted document body. The fields relevant to
password storage are:

| Offset                | Length | Meaning                                                 |
|-----------------------|--------|---------------------------------------------------------|
| `0x000-0x343`         | 836    | Document template/header (constant across files)        |
| `0x344`               | 1      | Encryption flag: `0x01` = encrypted, `0x00` = plaintext |
| `0x345`               | 1      | `0x00` (always)                                         |
| `0x346`               | 1      | Password length `N` in bytes (1..20)                    |
| `0x347 + i`           | 1      | Encoded byte for password position `i`, for `i < N`     |
| `0x347 + N` ..`0x3FF` | --     | Zero padding                                            |
| `0x400` ..            | rest   | Encrypted document body (separate cipher)               |

Empirically PW.EXE truncates input passwords to 20 bytes at create
time, so `N` is always bounded by 20 even though the slot would
syntactically allow more.

The scanner in this folder uses byte `0x344` as its primary
classifier: any value other than `0x00` or `0x01` rules a file out as
"not a PFS document".

### The slot cipher

For each `i` in `[0, N)`:

```
enc[i] = SBOX[ (lower(pwd[i]) + SHIFT[i]) & 0xff ]
```

`lower()` lowercases ASCII letters. `SBOX` is a fixed 256-entry
substitution table baked into PW.EXE. `SHIFT` is a fixed 20-entry
table:

```
SHIFT = [
    0x00, 0x00, 0x02, 0x1a, 0x14, 0x17, 0x1d, 0x1a, 0x0f, 0x16,
    0x18, 0x0a, 0x1d, 0x0f, 0x12, 0x14, 0x10, 0x10, 0x12, 0x2a,
]
```

The cipher has no per-file randomness, no salt, no nonce. Two
documents protected with the same password produce identical encoded
slots.

### The S-box

The S-box has structure. Three regions, each largely affine in the
input, plus a period-4 reservation that interleaves a "control byte"
ladder:

| Region                  | Regular formula      | Reserved (every 4th)                        |
|-------------------------|----------------------|---------------------------------------------|
| A: `k < 0x47`           | `(k - 0x47) & 0xff`  | none observed                               |
| B: `0x47 <= k <= 0x6f`  | `k - 0x47`           | `(k-0x4a) % 4 == 0`: `0x32 - (k-0x4a)/4`    |
| C: `k >= 0x70`          | `0x118 - k`          | `(k-0x71) % 4 == 0`: `0x49 + (k-0x71)/4`    |

The reserved entries (in regions B and C) ride a clean ladder of
small ASCII bytes (`0x32, 0x31, 0x30, ...` and `0x49, 0x4a, 0x4b, ...`)
that displaces what would otherwise be format-significant bytes
(`0x07, 0x0b, 0x1b, 0x1f, 0x23, 0x27, 0xa3, 0xa7, ...`). The most
plausible reading is that PW.EXE's authors chose the table so that
no byte in the encoded slot collides with bytes the rest of the file
format treats as control codes (text-end markers, length escapes,
etc). The S-box was structured for *file format robustness*, not
cryptographic strength.

The implementation in `pfs_cipher.py` carries 60+ measured table
entries that override the formula. These were collected from a
sample set covering all printable-ASCII passwords at every position;
on the 53-sample verification corpus there is zero formula/measurement
disagreement within printable-ASCII range.

### Decryption

Because `SBOX` is a true substitution table (each output value can be
produced by one or two distinct inputs — mostly one), decoding is:

```python
INV[v] = { k : SBOX[k] == v }

def decode_position(enc_byte, i):
    cands = [(k - SHIFT[i]) & 0xff for k in INV[enc_byte]]
    return [chr(c) for c in cands if 0x20 <= c <= 0x7e]
```

The reference implementation prefers lowercase-letter / digit
candidates first, which matches the case observed in real-world files
where users typed mixed-case passwords. When ambiguity is genuine the
implementation surfaces all candidates and picks the highest-scoring
one. In practice PFS users typed natural words, so the printable
filter alone resolves the slot.

### Length cap

PW.EXE silently truncates passwords to 20 bytes. Passwords typed at
26+ characters fail to write at all (the input form rejects them).
The SHIFT table therefore needs only 20 entries.

### Body cipher

The document body (`0x400+`) is encrypted with a separate stream
cipher whose keystream depends on roughly the first 8 characters of
the password. Recovering the body cipher analytically wasn't
necessary for password recovery — once the slot is decoded, PW.EXE
itself decrypts the body when given the recovered password. (For
folks who need to read encrypted PFS documents *without* PW.EXE,
the sibling `pfsonline3/` browser app implements byte-perfect body
encryption/decryption for a shipped library of password prefixes.)

### Security analysis

The slot cipher is a fixed substitution-permutation construction with
no key material beyond a constant lookup table and a constant shift
schedule. This makes it equivalent to a public encoding: the password
is, in effect, stored in plaintext under a known transform. Notable
properties:

* **No salt.** Same password produces same bytes in every file.
* **No work factor.** Decoding is O(N) for an N-character password.
* **No keyed component.** There is nothing that would make decoding
  computationally hard for an attacker, given the file.
* **Format-aware.** The S-box is structured to avoid format-significant
  bytes, suggesting the design priority was robustness against the
  rest of the file parser, not cryptographic strength.

Modern equivalents use a slow keyed hash (Argon2id, scrypt, bcrypt)
to derive a verification token, salt it per record, and encrypt the
body under a key derived from the password through a separate KDF
binding. PFS does none of this. Recovery from the file alone is
trivial.

### Recommended remediation for legacy PFS data

If you have legacy PFS Pro Write documents and need ongoing
confidentiality, the only sound option is to (a) recover the
password using this tool, (b) export the document to a modern format
out of PW.EXE, and (c) re-protect it with a contemporary tool. The
PFS-native protection should not be relied on for any modern threat
model.

---

## Part 4: How Claude found the flaw

This section is a writeup of the discovery process itself, because
the strategy is more interesting than the cipher. The work was done
in a Cowork session driven by Anthropic's Claude. The interesting
bit isn't that Claude wrote the final cipher in Python — that's a few
hundred lines of straightforward code. The interesting bit is the
strategy Claude chose to **discover** the cipher in the first place,
given a 1988 DOS binary and no source code.

### The toolchain

Claude was working from a Linux sandbox with shell access. To
interact with PW.EXE it assembled the following stack inside the
sandbox:

* **DOSBox** — x86 + DOS emulator, run as a subprocess.
* **DOSBox-X with debug build** — installed in case live tracing was
  needed (more on this below).
* **Xvfb** — a virtual X11 framebuffer, so DOSBox could render its
  graphical screen with no real display attached.
* **xdotool** — a CLI keystroke / mouse injector targeting the Xvfb
  display, used to drive the PW.EXE menu system as if a human were
  typing.
* **Python 3** — for sample generation, byte-level diffing, S-box and
  shift solving, and the final reference cipher.

The result was a fully headless, scriptable rig that could open
PW.EXE, type a plaintext, save it with an arbitrary password, and
read the resulting encrypted file out of the DOSBox mount — all from
a single shell command, in roughly five seconds per sample.

### The two attack vectors Claude considered

Faced with an unknown 1988 cipher, there were two obvious approaches:

**A. Static / dynamic reverse engineering.** Disassemble `PW.COM`,
`PW.OV0`, `PW.OV1`. Find the password-input routine. Trace the data
flow to the encryption code. If the disassembly is unreadable, fire
up DOSBox-X's debugger, set a breakpoint at the suspected encryption
routine, single-step a known plaintext + known password through it,
and log register state at every byte transform.

**B. Black-box differential cryptanalysis.** Treat PW.EXE as an
oracle. Feed it carefully chosen passwords. Observe the encrypted
files it produces. Diff them. Reverse-engineer the cipher from input /
output behavior alone, without ever looking at the disassembly.

Claude initially planned to do (A), and went so far as to install
`dosbox-debug` from Ubuntu Jammy, confirm it boots under Xvfb, and
use `ndisasm` to start poking at PW.OV1. The plan was to breakpoint
the encryption routine in debug mode and capture the exact transform.

Then Claude paused and reconsidered. The black-box approach was
strictly cheaper if it worked: no disassembly to read, no segment-
register confusion, no real-mode addressing, no x86 16-bit calling
conventions, no patience to sit through INT 21h DOS service calls.
And the cost of trying it was just generating a handful of files and
diffing them — cheap in the sandbox. Claude tried (B) first, planning
to fall back to (A) if it failed.

It didn't fail.

### What worked: the black-box plan

The pipeline that ended up cracking the cipher was:

**1. Build the headless oracle.** Wrote `gen_samples.py`, which boots
DOSBox under Xvfb, mounts a workdir as `D:\`, launches PW, and uses
`xdotool` to drive the menu sequence:

```
1               (Create / Edit)
<plaintext>     (the document content)
Ctrl+S          (save)
<filename>
Tab Tab E       (move to "File type" field, type E for Encrypted)
Enter
<password>
Enter
<password>      (PFS asks twice for new files)
Enter
```

This was the most fragile step — getting the timing right on the
xdotool key injections so PW saw them in the right order. It required
several iterations, including discovering that `PW.SET` hard-codes the
working directory to `D:\pfs\` (so the workdir had to contain a
`\pfs` subdir), and that bash in this sandbox runs each call in its
own PID namespace (so backgrounded DOSBox processes from one call were
dead by the next — the whole save flow had to live in a single bash
call).

**2. Generate "fingerprint" samples that isolate one variable at a
time.** Same plaintext, same filename, varying only one piece of the
password:

* `pw_len01.PRO` ... `pw_len11.PRO` — passwords `a`, `ab`, `abc`,
  ..., `abcdefghijk`. Same content, same plaintext, differ only in
  password length and trailing characters.
* `var_*` and `L1*` samples — vary the *character* at a fixed
  position while holding everything else constant. (e.g. password
  `aaaa` vs `aaba` vs `aaza` to see how position-2's encoding
  responds to changing only that character.)
* `diff_p4_b`, `diff_p4_z` — probes designed to confirm that the
  encoding at position `i` depends only on `pwd[i]` and the position
  index, not on neighboring characters.

**3. Diff the files at the byte level.** Compared each pair of
samples against `pw_len01.PRO` byte-by-byte. The diff produced a
clean signal:

* Bytes `0x000-0x343` were identical across every sample. (Header
  template.)
* Byte `0x344` was always `0x01`. (Encryption flag.)
* Byte `0x346` was the integer length of the password. (Length byte.)
* Bytes `0x347 + i` differed as a deterministic function of `pwd[i]`
  and `i`. (The encoded password slot.)
* Bytes `0x400+` differed (encrypted body), but stabilized once the
  password reached length 8 — meaning the body cipher only consumed
  the first ~8 password chars, so the body is not where the password
  length is encoded.

That last observation was the pivot: it meant the slot at `0x347+`
was the *full* password verifier, and recovering the slot was
sufficient to recover the password. No need to crack the body at all.

**4. Solve for the per-position shift table.** With the all-`a`
samples (`pw_len01` ... `pw_len11`), every byte in the slot was
`SBOX[(0x61 + SHIFT[i])]` for the corresponding position. By
generating one sample per length, Claude got a column of S-box outputs
at known inputs — effectively a slice of the S-box at each
position-shifted input.

**5. Solve for the S-box.** Holding position 0 fixed (where
`SHIFT[0] = 0`, confirmed empirically), Claude varied the position-0
character across the printable ASCII range. Each sample's first slot
byte was now `SBOX[ord(c)]` directly, which means each sample painted
in one entry of the S-box. With ~60 samples covering ASCII letters and
digits plus a few punctuation marks, the S-box table was filled in for
every input value the model needed.

**6. Spot the structure.** Looking at the resulting S-box table,
Claude noticed an obvious pattern: within each region (`< 0x47`,
`0x47-0x6f`, `>= 0x70`) the values were affine in the input, except
that every fourth value was hijacked by a separate "control byte
ladder" of small ASCII numbers. This is when the cipher stopped being
a pile of measurements and turned into a closed-form formula. The
formula plus the measured-overrides table covers every printable input
deterministically.

**7. Verify with a held-out test.** Generated one new sample with a
password the formula had never been calibrated on —
`abcdefghij1234567890`, mixing all 26 letters and 10 digits across all
20 positions. Predicted the 20 slot bytes from the formula. Compared
to the actual file. Twenty out of twenty matched.

**8. Find the length cap.** Generated samples at lengths 12, 15, 20,
22, 25, 28, and 30. Lengths 12-20 stored exactly as expected. Lengths
22 and 25 stored only the first 20 bytes (the length byte was 0x14).
Lengths 28 and 30 failed to write at all — PW's input form rejected
them. Conclusion: PW.EXE silently truncates to 20, so the SHIFT table
only ever needs 20 entries.

### Why debug mode wasn't needed

Claude prepared `dosbox-debug` and was ready to set breakpoints in the
password-handling code. In the end the static + dynamic RE attack
vector was abandoned because the black-box vector won outright — a few
hundred targeted samples and some byte-diffing produced a fully
validated cipher, complete with a closed-form S-box, in less time
than it would have taken to locate the encryption routine in the
disassembly.

The lesson, for anyone reading this with another vintage product to
crack: **try the oracle attack first**. If the program will let you
run it with arbitrary inputs and observe its outputs, you may not need
to read a single instruction. You only need to read instructions when
behavior alone is ambiguous — and a 1988 substitution cipher is not
ambiguous, it's just unfamiliar.

### Why this was a good fit for an LLM agent

A few things made this a productive task for Claude in particular,
and they generalize to similar reverse-engineering chores:

* **The work decomposed cleanly into small, verifiable subtasks.**
  Generate one sample, diff two files, solve one byte. Each step had
  an objective pass / fail check (did the byte match? did the
  round-trip succeed?), so Claude could grind through dozens of
  iterations without the risk of compounding error that haunts
  open-ended generation.
* **The toolchain assembly** (DOSBox + Xvfb + xdotool + Python) is
  exactly the kind of plumbing that consumes a human afternoon and
  takes a model a few minutes — lots of small recipes, no creativity
  required.
* **The pattern-spotting moment** (recognizing the affine + period-4
  structure of the S-box) is something the model and a human are
  about equally good at, but the model gets there faster because it
  has already loaded all 60 measured entries into context.
* **The willingness to back off** mattered. Switching from "let's
  read the disassembly" to "let's just probe the program" required
  Claude to abandon a half-built investigation and redirect, which
  it did because the cheaper plan was visibly cheaper.

### From cipher to scanner

The cipher itself was implemented as `pfs_cipher.py` in the original
`pfcracker/` folder — 108 lines, no dependencies. Producing it took
roughly 53 generated samples and a handful of verification rounds.

This folder, `pfcracker2/`, is the next step: turning the recovered
cipher into a tool that's actually useful for someone with a folder
of legacy PFS files on their hard drive. The scanner walks the
folder, classifies each file by its `0x344` flag byte, and runs the
slot cipher in reverse to recover passwords from encrypted hits — all
in a single pass, in seconds, with output filters (`--encrypted-only`,
`--hide-unknown`, `--hide-single-char`) that make the report easy to
read on directories that mix many file types.

The same recovered cipher also powers the browser-side editor in
`../pfsonline3/`, which can read and write byte-perfect PFS files
without any DOS emulator in the loop.

