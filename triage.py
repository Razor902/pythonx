# © 2026 Curtis Ray Dyess · Crimson Rose LLC
#!/usr/bin/env python3
"""
triage.py -- PythonX triage: "is this blob worth deciphering?"

Before the beam search spends its steps, triage looks at an unknown blob
and answers one question: does this look like something structured hiding
under layers, or is it just noise? Structured blobs get peeled; noise
gets skipped; the unsure middle gets a "maybe".

Five signals, each 0.0 (noise) to 1.0 (structured), blended into one
verdict. Every signal is a single pass over the bytes -- O(n) time,
O(1) extra space -- so triage is cheap next to the search it saves.

The signals, in plain words:
  1. entropy ..... Shannon entropy per byte. Real text and code sit
                   around 4-6 bits; packed or encrypted noise sits near
                   8. Mid-range entropy is the smell of structure.
  2. signature ... known magic bytes and wrappers -- gzip, zip, PNG,
                   PDF, PEM armor, JSON/XML brackets, and friends.
  3. alphabet .... how much of the blob lives in a recognizable alphabet
                   (printable text, hex digits, base64).
  4. squeeze ..... how well the first 4K compresses. Structure squeezes;
                   noise does not.
  5. repetition .. repeated patterns and tiny unique-byte counts --
                   padding, filler, simple encodings.

Use:
  from triage import triage, rank_blobs
  verdict, score, reasons = triage(blob)   # "peel" | "maybe" | "skip"
  for name, verdict, score, reasons in rank_blobs({"a.bin": data}):
      ...

  python3 triage.py file1.bin file2.bin   # verdicts on the command line

Stdlib only. No internet. Runs anywhere python3 runs, Termux included.
"""

import math
import os
import sys
import zlib

# ---------------------------------------------------------------------------
# Verdicts and thresholds.
# ---------------------------------------------------------------------------

PEEL = "peel"    # structured: hand it to the decipher engine
MAYBE = "maybe"  # unsure: worth a look if nothing better is waiting
SKIP = "skip"    # noise or filler: the beam search would only burn steps

PEEL_AT = 0.60
MAYBE_AT = 0.35

# ---------------------------------------------------------------------------
# Signal 1: entropy -- "how surprised is each byte?"
# ---------------------------------------------------------------------------


def shannon_entropy(data: bytes) -> float:
    """Bits of surprise per byte: ~4 for text, ~8 for noise."""
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def entropy_score(data: bytes) -> float:
    """Map entropy to structured-ness. The sweet spot is 3.0-6.2 bits."""
    h = shannon_entropy(data)
    if h < 1.5:
        return 0.2   # nearly one repeated byte: filler, not a puzzle
    if h < 3.0:
        return 0.2 + 0.6 * (h - 1.5) / 1.5
    if h <= 6.2:
        return 1.0
    if h < 7.2:
        return 1.0 - 0.8 * (h - 6.2)
    return 0.0     # 7.2+: packed or encrypted noise


# ---------------------------------------------------------------------------
# Signal 2: signature -- "do I recognize the wrapping?"
# ---------------------------------------------------------------------------

_MAGIC = [
    (b"\x1f\x8b", "gzip"),
    (b"\x78\x01", "zlib"),
    (b"\x78\x9c", "zlib"),
    (b"\x78\xda", "zlib"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG", "png"),
    (b"%PDF", "pdf"),
    (b"GIF8", "gif"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"BM", "bmp"),
    (b"MZ", "exe"),
    (b"\x7fELF", "elf"),
    (b"BZh", "bzip2"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"-----BEGIN", "pem"),
]


def signature_hit(data: bytes):
    """Return (kind, strength) of the best magic-byte match, or (None, 0)."""
    if not data:
        return None, 0.0
    for magic, kind in _MAGIC:
        if data[:len(magic)] == magic:
            return kind, 1.0
    stripped = data.strip()
    if stripped[:1] in (b"{", b"["):
        return "json", 0.7
    if stripped[:1] == b"<":
        return "xml", 0.7
    return None, 0.0


# ---------------------------------------------------------------------------
# Signal 3: alphabet -- "what script is it written in?"
# ---------------------------------------------------------------------------

_WS = (9, 10, 13, 32)  # tab, newline, carriage return, space


def _frac(data: bytes, ok) -> float:
    return sum(1 for b in data if ok(b)) / len(data)


def alphabet_score(data: bytes):
    """How much of the blob lives in a recognizable alphabet.

    Returns (score, name of the alphabet it looks like).
    """
    if not data:
        return 0.0, "none"
    printable = _frac(data, lambda b: 32 <= b < 127 or b in _WS)
    if printable >= 0.95:
        return 1.0, "printable text"
    b64 = _frac(data, lambda b: 65 <= b <= 90 or 97 <= b <= 122
                or 48 <= b <= 57 or b in (43, 47, 61) or b in _WS)
    if len(data) >= 16 and b64 >= 0.95:
        return 0.9, "base64-shaped"
    if printable >= 0.70:
        return 0.6, "mostly printable"
    return printable * 0.5, "mixed"


# ---------------------------------------------------------------------------
# Signal 4: squeeze -- "does it compress?"
# ---------------------------------------------------------------------------

_SQUEEZE_SAMPLE = 4096


def squeeze_score(data: bytes) -> float:
    """Structure squeezes; noise does not. One quick zlib probe."""
    if len(data) < 128:
        return 0.5  # too small to judge fairly: zlib's fixed overhead
                    # dwarfs the signal on tiny inputs
    sample = data[:_SQUEEZE_SAMPLE]
    try:
        ratio = len(zlib.compress(sample, 1)) / len(sample)
    except Exception:
        return 0.5
    if ratio >= 1.0:
        return 0.0
    if ratio <= 0.6:
        return 1.0
    return (1.0 - ratio) / 0.4


# ---------------------------------------------------------------------------
# Signal 5: repetition -- "is it the same thing over and over?"
# ---------------------------------------------------------------------------


def repetition_score(data: bytes):
    """Tiny unique-byte counts mean padding or filler.

    Returns (score, is_filler).
    """
    if not data:
        return 0.0, False
    n = len(data)
    uniq = len(set(data))
    if n >= 32 and uniq <= 2:
        return 1.0, True   # filler: triage says skip, not peel
    if n >= 64 and uniq <= 16:
        return 0.7, False
    return 0.3, False


# ---------------------------------------------------------------------------
# The verdict.
# ---------------------------------------------------------------------------

# Blend weights: entropy and signature carry the call; alphabet and
# squeeze are the deputies; repetition is the tiebreaker.
_W = (0.25, 0.25, 0.20, 0.20, 0.10)


def triage(data: bytes):
    """Judge one blob. Returns (verdict, score, reasons).

    verdict is "peel", "maybe", or "skip"; score is 0.0-1.0;
    reasons is a short human-readable list of why.
    """
    if not data:
        return SKIP, 0.0, ["empty"]
    reasons = []

    e = entropy_score(data)
    reasons.append(f"entropy {shannon_entropy(data):.1f} bits/byte")

    kind, s = signature_hit(data)
    if kind:
        reasons.append(f"magic: {kind}")

    a, aname = alphabet_score(data)
    reasons.append(f"alphabet: {aname}")

    q = squeeze_score(data)
    reasons.append(f"squeeze {q:.2f}")

    r, filler = repetition_score(data)
    if filler:
        return SKIP, 0.10, ["filler: nearly one repeated byte, nothing hidden"]

    score = _W[0] * e + _W[1] * s + _W[2] * a + _W[3] * q + _W[4] * r
    if s >= 1.0:
        # A hard magic-byte hit outranks a muddy blend: the wrapper is
        # named, so there is definitely something to unwrap.
        score = max(score, 0.75)
        reasons.append("named wrapper: peel regardless of blend")
    if score >= PEEL_AT:
        return PEEL, round(score, 2), reasons
    if score >= MAYBE_AT:
        return MAYBE, round(score, 2), reasons
    return SKIP, round(score, 2), reasons


def rank_blobs(blobs):
    """Triage many blobs. Takes {name: bytes}, returns a list of
    (name, verdict, score, reasons) with the peel-worthy first."""
    order = {PEEL: 0, MAYBE: 1, SKIP: 2}
    ranked = []
    for name, data in blobs.items():
        verdict, score, reasons = triage(data)
        ranked.append((name, verdict, score, reasons))
    ranked.sort(key=lambda t: (order[t[1]], -t[2], t[0]))
    return ranked


def _cli(paths):
    blobs = {}
    for p in paths:
        try:
            with open(p, "rb") as f:
                blobs[p] = f.read()
        except OSError as exc:
            print(f"{p}: cannot read ({exc})")
    for name, verdict, score, reasons in rank_blobs(blobs):
        print(f"{verdict:5s} {score:.2f}  {name}")
        for r in reasons:
            print(f"           - {r}")


if __name__ == "__main__":
    if len(sys.argv) < 2 or sys.argv[1] in ("-h", "--help"):
        print(__doc__)
        sys.exit(0 if len(sys.argv) > 1 else 1)
    _cli(sys.argv[1:])
