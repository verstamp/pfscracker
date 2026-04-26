# PFS Professional Write Password Cracker

A folder scanner for PFS Professional Write 1988 encrypted documents.
Walks a directory, identifies every file that looks like a PFS document
(encrypted or plain), and recovers passwords from the encrypted ones in
the same pass. Single-file Python script, no dependencies beyond the
standard library.

The script can also be used against a single specified file.

## Quick start

```sh
python3 pfs_cipher.py --scan /path/to/folder
```

The script will recursively walk the folder and print a row per file:

```
Scanning /path/to/folder (recursive)
------------------------------------------------------------------------------
ENCRYPTED        2048  DOC1.PRO   pwd='example' (len 7)
ENCRYPTED        1280  DOC2.PRO   pwd='secret'  (len 6)
PFS-PLAIN        1409  NOTES.PRO
PFS-PLAIN        2352  LETTER.PRO
------------------------------------------------------------------------------
Summary: 2 encrypted (2 passwords recovered), 2 unencrypted PFS, 0 non-PFS, 0 unreadable
```

## Modes

| Flag                  | Effect                                                     |
|-----------------------|------------------------------------------------------------|
| `--scan FOLDER`       | Recursively scan FOLDER. Default mode.                     |
| `--no-recursive`      | Don't descend into subfolders.                             |
| `--all`               | Also list non-PFS files (with the byte that ruled them out). |
| `--encrypted-only`    | Show only encrypted hits. Suppress PFS-plain, non-PFS, unreadable. |
| `--hide-unknown`      | Hide encrypted rows whose password could not be decoded (the `pwd=???` rows). |
| `--hide-single-char`  | Hide encrypted rows whose slot length is 1. Almost always false positives. |

The filters compose. A typical "high-confidence hits only" invocation:

```sh
python3 pfs_cipher.py --scan FOLDER --encrypted-only --hide-unknown --hide-single-char
```

The summary line at the end always reports the full underlying counts,
even when filters have hidden rows from the listing — so you don't lose
sight of what was suppressed.

## Single-file mode (legacy)

The original per-file behavior is preserved. Pass one or more paths to
decode their passwords:

```sh
python3 pfs_cipher.py FILE.PRO [FILE2.PRO ...]
```

Prints `path password` per line, or `path ERROR: <reason>` if the file
isn't a PFS encrypted document.

## How the classifier decides

A file is treated as a PFS Professional Write 1988 document iff:

1. It is at least `0x400` bytes (1024) — the fixed PFS header size.
2. The byte at offset `0x344` is either `0x00` (plain PFS) or `0x01`
   (encrypted PFS). Any other value means "not a PFS file".

For encrypted files, the slot cipher is run in reverse to recover the
password from offsets `0x346` (length byte) and `0x347+` (encoded
slot). See `WHITEPAPER.md` for the cipher details.

## Library API

If you want to call this from your own Python:

```python
from pfs_cipher import classify_file, scan_folder, password_from_file

kind, info = classify_file("/path/to/file.PRO")
# kind in {"encrypted", "unencrypted", "not_pfs", "unreadable"}
# info dict shape depends on kind; see classify_file's docstring.

for full_path, kind, info in scan_folder("/some/dir", recursive=True):
    if kind == "encrypted" and info["password"] is not None:
        print(full_path, "->", info["password"])

# Or just the legacy "give me the password from this file" entry point:
print(password_from_file("/path/to/file.PRO"))
```

## Path quoting

Always quote folder paths that contain spaces or shell metacharacters.
Bash, PowerShell, and cmd all interpret `(`, `)`, spaces, and `'`
before the script ever runs. Examples:

```sh
# bash / Git Bash / WSL — double quotes
python3 pfs_cipher.py --scan "/path/to/My Folder (archive)/" --encrypted-only

# PowerShell — double quotes
python3 pfs_cipher.py --scan "C:\path\to\My Folder (archive)\" --encrypted-only

# cmd — double quotes
python3 pfs_cipher.py --scan "C:\path\to\My Folder (archive)\" --encrypted-only
```

If you forget to quote and bash *does* manage to invoke Python (i.e. the
path has spaces but no other metacharacters), the script will reassemble
the leftover positional tokens into the original path and proceed,
printing a one-line note suggesting you quote it next time. If bash
rejects the command outright with `syntax error near unexpected token
'('`, the script never runs — that's a shell error, not a script
error, and the only fix is to quote.

## What this tool does NOT do

- It does not decrypt the document **body**. The slot cipher recovers
  the password; once you have the password, the practical move is to
  reopen the document in PW.EXE (under DOSBox or otherwise) and read
  it there.
- It does not write anything. It only reads files, classifies them,
  and prints a report.
- It does not modify the files it scans, even when password recovery
  succeeds.

## Files

```
pfcracker2/
  pfs_cipher.py    -- the scanner + library
  README.md        -- this file
  WHITEPAPER.md    -- technical writeup of the PFS cipher and the
                      discovery process
```
