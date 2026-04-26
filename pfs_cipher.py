#!/usr/bin/env python3
"""
pfs_cipher.py - PFS Professional Write 1988 password slot encrypt/decrypt,
plus a folder scanner that identifies PFS-encrypted files.

Recovered by black-box differential cryptanalysis. See ../pfcracker/PROGRESS.md.

The encrypted PFS file has a fixed 0x400-byte header. The password is encoded
into a fixed slot at offset 0x347, length-prefixed by the byte at 0x346.
PFS Professional Write 1988 silently truncates passwords to 20 characters,
so the maximum recoverable password length is 20.

    enc[i] = SBOX[ (lower(pwd[i]) + SHIFT[i]) & 0xff ]

Usage:
    python3 pfs_cipher.py FILE [FILE ...]                  # decode passwords
    python3 pfs_cipher.py --scan FOLDER                    # scan folder for PFS files
    python3 pfs_cipher.py --scan FOLDER --encrypted-only   # only show encrypted hits
    python3 pfs_cipher.py --scan FOLDER --hide-unknown     # hide pwd=??? rows
    python3 pfs_cipher.py --scan FOLDER --hide-single-char # hide length-1 hits (false positives)
    python3 pfs_cipher.py --scan FOLDER --all              # also list non-PFS files
    python3 pfs_cipher.py --scan FOLDER --no-recursive
"""

import os

# Per-position additive shift, derived empirically from single-char-per-position
# samples generated in a DOSBox-emulated PW.EXE. PFS Pro Write 1988 hard-caps
# stored passwords at 20 chars (input beyond pos 19 is truncated by PW.EXE).
SHIFT = [
    0x00, 0x00, 0x02, 0x1a, 0x14, 0x17, 0x1d, 0x1a, 0x0f, 0x16,
    0x18, 0x0a, 0x1d, 0x0f, 0x12, 0x14, 0x10, 0x10, 0x12, 0x2a,
]

MAX_PASSWORD_LEN = 20

# Empirically measured SBOX entries (from sample-set differential analysis).
_MEASURED = {
    0x30: 0xe8, 0x31: 0xea, 0x33: 0xec, 0x34: 0xed, 0x35: 0xee, 0x37: 0xf0,
    0x40: 0xf9, 0x44: 0xfd, 0x45: 0xfe, 0x47: 0x00, 0x48: 0x01, 0x49: 0x02,
    0x4b: 0x04, 0x4c: 0x05, 0x4d: 0x06, 0x4e: 0x31, 0x4f: 0x08, 0x51: 0x0a,
    0x52: 0x30, 0x53: 0x0c, 0x61: 0x1a, 0x62: 0x2c, 0x63: 0x1c, 0x64: 0x1d,
    0x65: 0x1e, 0x66: 0x2b, 0x67: 0x20, 0x68: 0x21, 0x69: 0x22, 0x6a: 0x2a,
    0x6b: 0x24, 0x6c: 0x25, 0x6d: 0x26, 0x6e: 0x29, 0x6f: 0x28, 0x70: 0xa8,
    0x71: 0x49, 0x72: 0xa6, 0x73: 0xa5, 0x74: 0xa4, 0x75: 0x4a, 0x76: 0xa2,
    0x77: 0xa1, 0x78: 0xa0, 0x79: 0x4b, 0x7a: 0x9e, 0x7b: 0x9d, 0x7c: 0x9c,
    0x7d: 0x4c, 0x7e: 0x9a, 0x7f: 0x99, 0x80: 0x98, 0x82: 0x96, 0x83: 0x95,
    0x84: 0x94, 0x89: 0x4f, 0x8e: 0x8a, 0x90: 0x88, 0x91: 0x51, 0x92: 0x86,
    0x94: 0x84, 0x97: 0x81,
}


def sbox(k):
    """SBOX with formulaic fallback for unmeasured k."""
    k &= 0xff
    if k in _MEASURED:
        return _MEASURED[k]
    if 0x47 <= k <= 0x6f:
        if (k - 0x4a) % 4 == 0 and 0x4a <= k <= 0x6e:
            return (0x32 - (k - 0x4a) // 4) & 0xff
        return (k - 0x47) & 0xff
    if k >= 0x70:
        if (k - 0x71) % 4 == 0:
            return (0x49 + (k - 0x71) // 4) & 0xff
        return (0x118 - k) & 0xff
    return (k - 0x47) & 0xff


def encode_password(pwd):
    pwd = pwd.lower()
    if not (1 <= len(pwd) <= MAX_PASSWORD_LEN):
        raise ValueError("password length out of range 1..%d" % MAX_PASSWORD_LEN)
    return bytes(sbox((ord(c) + SHIFT[i]) & 0xff) for i, c in enumerate(pwd))


def _build_inverse():
    inv = {}
    for k in range(0x20, 0x100):
        v = sbox(k)
        inv.setdefault(v, set()).add(k)
    return inv


_INV_SBOX = _build_inverse()


def decode_password(enc, length):
    if not (1 <= length <= MAX_PASSWORD_LEN):
        raise ValueError("length out of range 1..%d" % MAX_PASSWORD_LEN)
    enc = enc[:length]
    out = []
    for i, e in enumerate(enc):
        chars = []
        for k in _INV_SBOX.get(e, set()):
            c = (k - SHIFT[i]) & 0xff
            if 0x20 <= c <= 0x7e:
                chars.append(chr(c))
        if not chars:
            raise ValueError("no plaintext char for enc[%d]=0x%02x" % (i, e))
        chars.sort(key=lambda c: (not (c.islower() or c.isdigit()), c))
        out.append(chars[0])
    return "".join(out)


def password_from_file(path):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x400 or data[0x344] != 0x01:
        raise ValueError("not a PFS encrypted file")
    length = data[0x346]
    return decode_password(data[0x347:0x347 + length], length)


# --- Folder scanning -------------------------------------------------------
#
# A PFS Professional Write 1988 file has a fixed 0x400-byte header. The
# encryption flag lives at offset 0x344: 0x01 means the file is encrypted,
# 0x00 means it is a plain PFS document. Anything that is too short or whose
# flag byte is some other value is not a PFS file from this era.
#
# `classify_file` is the library entry point; it returns a tuple
# (kind, info) where kind is one of "encrypted", "unencrypted", "not_pfs",
# or "unreadable".

def classify_file(path):
    """Classify a single file. Returns (kind, info_dict)."""
    try:
        with open(path, "rb") as f:
            data = f.read(0x400)
        size = os.path.getsize(path)
    except (OSError, IOError) as e:
        return ("unreadable", {"reason": str(e)})

    if len(data) < 0x400:
        return ("not_pfs", {"size": size,
                            "reason": "file shorter than 0x400 byte header"})

    flag = data[0x344]
    if flag == 0x01:
        length = data[0x346]
        if not (1 <= length <= MAX_PASSWORD_LEN):
            return ("encrypted",
                    {"length": length, "password": None,
                     "password_error": "bad length byte 0x%02x" % length,
                     "size": size})
        try:
            pwd = decode_password(data[0x347:0x347 + length], length)
            return ("encrypted",
                    {"length": length, "password": pwd,
                     "password_error": None, "size": size})
        except ValueError as e:
            return ("encrypted",
                    {"length": length, "password": None,
                     "password_error": str(e), "size": size})
    elif flag == 0x00:
        return ("unencrypted", {"size": size})
    else:
        return ("not_pfs",
                {"size": size,
                 "reason": "encryption flag at 0x344 is 0x%02x" % flag})


def scan_folder(folder, recursive=True):
    """Yield (full_path, kind, info) for every regular file under folder.

    Set recursive=False to scan only the immediate folder contents.
    """
    folder = os.path.abspath(folder)
    if not os.path.isdir(folder):
        raise ValueError("not a directory: " + folder)
    if recursive:
        walker = os.walk(folder)
    else:
        names = [n for n in os.listdir(folder)
                 if os.path.isfile(os.path.join(folder, n))]
        walker = [(folder, [], names)]
    for root, _dirs, files in walker:
        for name in sorted(files):
            full = os.path.join(root, name)
            kind, info = classify_file(full)
            yield full, kind, info


def _format_scan_row(rel_path, kind, info):
    if kind == "encrypted":
        if info["password"] is not None:
            extra = "pwd='%s' (len %d)" % (info["password"], info["length"])
        else:
            extra = ("pwd=??? (len %d, %s)"
                     % (info["length"], info["password_error"]))
        return "ENCRYPTED    %8d  %s  %s" % (info["size"], rel_path, extra)
    if kind == "unencrypted":
        return "PFS-PLAIN    %8d  %s" % (info["size"], rel_path)
    if kind == "unreadable":
        return "UNREADABLE          -  %s  (%s)" % (rel_path, info["reason"])
    return None


def _cmd_scan(folder, recursive=True, show_all=False, encrypted_only=False,
              hide_unknown=False, hide_single_char=False):
    counts = {"encrypted": 0, "unencrypted": 0, "not_pfs": 0,
              "unreadable": 0, "decoded": 0,
              "hidden_unknown": 0, "hidden_single_char": 0}
    folder_abs = os.path.abspath(folder)
    notes = []
    if encrypted_only:
        notes.append("encrypted-only")
    elif show_all:
        notes.append("all files")
    if hide_unknown:
        notes.append("hide-unknown")
    if hide_single_char:
        notes.append("hide-single-char")
    mode_note = (" (" + ", ".join(notes) + ")") if notes else ""
    print("Scanning %s%s%s" %
          (folder_abs,
           " (recursive)" if recursive else "",
           mode_note))
    print("-" * 78)
    for full, kind, info in scan_folder(folder, recursive=recursive):
        counts[kind] = counts.get(kind, 0) + 1
        if kind == "encrypted" and info["password"] is not None:
            counts["decoded"] += 1
        rel = os.path.relpath(full, folder_abs)
        # --encrypted-only suppresses everything except encrypted hits.
        if encrypted_only and kind != "encrypted":
            continue
        # --hide-unknown suppresses encrypted hits whose password did not
        # decode (the rows that would otherwise print "pwd=???").
        if (hide_unknown and kind == "encrypted"
                and info["password"] is None):
            counts["hidden_unknown"] += 1
            continue
        # --hide-single-char suppresses encrypted hits whose password slot
        # length is 1. These are almost always false positives in the wild
        # (random files whose 0x344 byte happens to be 0x01 plus whose 0x346
        # byte happens to be 0x01).
        if hide_single_char and kind == "encrypted" and info["length"] == 1:
            counts["hidden_single_char"] += 1
            continue
        if kind == "not_pfs" and not show_all:
            continue
        if kind == "not_pfs":
            print("not-PFS      %8d  %s  (%s)"
                  % (info["size"], rel, info["reason"]))
            continue
        line = _format_scan_row(rel, kind, info)
        if line is not None:
            print(line)
    print("-" * 78)
    summary = ("Summary: %d encrypted (%d passwords recovered), "
               "%d unencrypted PFS, %d non-PFS, %d unreadable"
               % (counts["encrypted"], counts["decoded"],
                  counts["unencrypted"], counts["not_pfs"],
                  counts["unreadable"]))
    extras = []
    if hide_unknown and counts["hidden_unknown"]:
        extras.append("%d row(s) hidden: password unknown"
                      % counts["hidden_unknown"])
    if hide_single_char and counts["hidden_single_char"]:
        extras.append("%d row(s) hidden: single-char password"
                      % counts["hidden_single_char"])
    if extras:
        summary += " (" + "; ".join(extras) + ")"
    print(summary)
    return counts


def _resolve_scan_path(scan_arg, extra_paths):
    """Repair an unquoted path-with-spaces passed to --scan.

    Shells split unquoted arguments at whitespace, so e.g.
        --scan /tmp/My Folder (test)
    arrives as scan_arg='/tmp/My' and extra_paths=['Folder', '(test)'].
    If scan_arg by itself isn't a directory but joining it with the leftover
    positional tokens produces one, return the joined path. Otherwise return
    the original scan_arg unchanged so the caller can produce the normal
    "not a directory" error.
    """
    if os.path.isdir(scan_arg) or not extra_paths:
        return scan_arg, list(extra_paths)
    # Try progressively appending leftover tokens until a directory matches.
    candidate = scan_arg
    consumed = 0
    for token in extra_paths:
        candidate = candidate + " " + token
        consumed += 1
        if os.path.isdir(candidate):
            remaining = extra_paths[consumed:]
            return candidate, list(remaining)
    return scan_arg, list(extra_paths)


if __name__ == "__main__":
    import argparse
    import sys
    parser = argparse.ArgumentParser(
        description="PFS Professional Write 1988 password tool. "
                    "Decode passwords from individual .PRO files, "
                    "or scan a folder for PFS-encrypted files.")
    parser.add_argument("paths", nargs="*",
        help="File path(s) to decode the password from.")
    parser.add_argument("--scan", metavar="FOLDER",
        help="Recursively scan FOLDER and identify PFS-encrypted files.")
    parser.add_argument("--no-recursive", action="store_true",
        help="With --scan, do not descend into subfolders.")
    parser.add_argument("--all", action="store_true",
        help="With --scan, also list non-PFS files.")
    parser.add_argument("--encrypted-only", action="store_true",
        help="With --scan, list ONLY encrypted PFS files "
             "(suppress unencrypted, non-PFS, and unreadable rows).")
    parser.add_argument("--hide-unknown", action="store_true",
        help="With --scan, hide encrypted rows whose password could not "
             "be decoded (the rows printed as 'pwd=???').")
    parser.add_argument("--hide-single-char", action="store_true",
        help="With --scan, hide encrypted rows whose password slot length "
             "is 1. Single-character matches are almost always false "
             "positives (random files that happen to have 0x01 at offset "
             "0x344 and 0x346).")
    args = parser.parse_args()

    if args.scan:
        if args.encrypted_only and args.all:
            parser.error("--encrypted-only and --all are mutually exclusive")
        # Repair unquoted paths-with-spaces. If --scan got truncated at a
        # space and the leftover positional tokens reassemble it into a real
        # directory, use that and clear the leftovers. Tell the user we did
        # this so they know to quote next time.
        scan_path, leftover = _resolve_scan_path(args.scan, args.paths)
        if scan_path != args.scan:
            print("note: --scan argument reassembled from unquoted tokens "
                  "(quote the path next time): %r" % scan_path,
                  file=sys.stderr)
        args.paths = leftover
        if args.paths:
            print("note: ignoring %d leftover positional path(s) after --scan: %s"
                  % (len(args.paths), args.paths),
                  file=sys.stderr)
        if not os.path.isdir(scan_path):
            parser.error(
                "--scan path is not a directory: %r "
                "(if the path contains spaces or shell metacharacters "
                "like '(' or ')', quote it: --scan \"%s\")"
                % (scan_path, scan_path))
        _cmd_scan(scan_path,
                  recursive=not args.no_recursive,
                  show_all=args.all,
                  encrypted_only=args.encrypted_only,
                  hide_unknown=args.hide_unknown,
                  hide_single_char=args.hide_single_char)
    elif args.paths:
        for path in args.paths:
            try:
                print(path, password_from_file(path))
            except Exception as e:
                print(path, "ERROR:", e)
    else:
        parser.print_help()
