#!/usr/bin/env python3
"""
pythonx.py -- PythonX v1.5, the PhantomX payload decipher.

v1.5 upgrade over v1.4 (2026-10-02) -- the Matrix Key sequence:
  - PythonX now ships its companion cipher, matrix_sequence.py: the
    nine-layer Matrix Key stack, built with Curtis -- plugboard (where
    the memory lies), rotor, Vigenere under BOOGIEMAN, Divincy mirror
    wrap, columnar transposition under PHANTOMX, atbash, reflector,
    full reverse, and the flash between characters (the hidden message
    rides in zero-width gaps, where nobody looks);
  - this is the telecommunication cipher of the future: communication
    for loved ones, near and far -- fast and reliable;
  - the decipher engine itself is untouched in v1.5: every bench case
    that solved before solves still. The beam keeps its discipline.

v1.4 upgrade over v1.3 (2026-10-01) -- the optimization pass:
  - the Vigenere text-gate: Vigenere analysis now runs only on
    text-like states; base64, hex, and binary states skip the
    expensive crack entirely;
  - the histogram-sort hoist: the expected frequency distribution is
    sorted once, not 256 times per state -- algebraically identical
    scoring;
  - the UTF-8/CJK XOR razor: finds XOR keys hiding Chinese where the
    histogram and base64/hex razors are blind;
  - the Chinese unigram tie-break: tells a true CJK key from its
    bit-neighbors, which also decode as CJK.
  - measured: standard bench 7.5s -> ~3.7s (v1.2 parity); the
    chinese-xor case v1.3 never solved now solves in ~0.1s; all 11
    bench cases solve.

v1.2 upgrade over v1.1:
  - the Divincy layer: Da Vinci's mirror writing joins the peelers --
    the mirror alphabet (atbash) on its own, and the full mirror
    wrap (backwards + mirror alphabet) as a single named peel, so a
    payload hidden the Leonardo way opens in one step.

v1.3 upgrade over v1.2:
  - cryptography joins the peelers: Vigenere (key lengths 2-6, every
    key position cracked as its own Caesar cipher -- classical
    frequency analysis, not brute force) and columnar transposition
    (column counts 2-8);
  - the sign layer: ASL fingerspelling handshapes as an encoding --
    "fist-thumb-side|flat-hand|cup-hand" -- read back into letters
    by peel_signspell;
  - Chinese: the scorer recognizes solved Chinese text by CJK
    character density, so layered payloads hiding Chinese plaintext
    open the same way English ones do.

v1.1 upgrades over v1, measured on the bench against it:
  - a quadgram language-model scorer: text is judged on four-letter
    chunks ("tion", "ther") instead of single letters alone -- the
    algorithm carrying the seed of the language model it will become;
  - a compiled C core (fastcore.c, loaded via ctypes when present)
    for the counting hot paths: letter histograms for all 256 XOR
    keys in one pass, letter streams, byte counts. If the compiled
    core is missing, v1.1 falls back to the pure-Python paths.

What it does, in plain words:
  A payload is usually plain words wrapped in layers -- hex, base64,
  a letter rotation, an XOR mask, compression, and so on. Peeling the
  layers by brute force means trying EVERY combination, and the
  combinations multiply until the search drowns.

  PythonX peels smarter. It works like a good tracker:
    - try every known way to peel one layer,
    - SCORE each result by how much it looks like real language,
    - keep only the best few trails (the "beam"),
    - drop trails already walked (no wasted steps),
    - stop the moment the words read clean.

  That is the whole trick: score-guided beam search with deduping.
  It turns an exponential swamp into a short walk.

Stdlib only. No internet. Runs anywhere python3 runs, Termux included.

Use:
  python3 pythonx.py "<payload>"          decipher one payload string
  python3 pythonx.py --file payload.txt   decipher a payload from a file
  python3 pythonx.py --naive "<payload>"  run BOTH engines and compare
  python3 pythonx.py --bench              run the built-in test bench

  The Matrix Key sequence (v1.5 companion, matrix_sequence.py):
  python3 matrix_sequence.py                run the sequence roundtrip tests
"""

import base64
import binascii
import bz2
import ctypes
import gzip
import hashlib
import io
import json
import lzma
import math
import os
import sys
import time
import zlib

__version__ = "1.5"

# v1.5 -- the Matrix Key sequence rides alongside the decipher.
# Guarded: pythonx.py still stands alone without it.
try:
    from matrix_sequence import (
        encrypt as matrix_encrypt,
        decrypt as matrix_decrypt,
        sequence as matrix_sequence_layers,
        PLUGBOARD_PAIRS as MATRIX_PLUGBOARD,
    )
    MATRIX_KEY_AVAILABLE = True
except ImportError:
    MATRIX_KEY_AVAILABLE = False

# ---------------------------------------------------------------------------
# The scorer: "how much does this look like real language?"
# Returns roughly 0.0 (noise) to 1.0 (clean readable text).
# ---------------------------------------------------------------------------

LETTER_FREQ = {
    "a": 8.2, "b": 1.5, "c": 2.8, "d": 4.3, "e": 12.7, "f": 2.2,
    "g": 2.0, "h": 6.1, "i": 7.0, "j": 0.15, "k": 0.8, "l": 4.0,
    "m": 2.4, "n": 6.7, "o": 7.5, "p": 1.9, "q": 0.1, "r": 6.0,
    "s": 6.3, "t": 9.1, "u": 2.8, "v": 1.0, "w": 2.4, "x": 0.15,
    "y": 2.0, "z": 0.07, " ": 13.0,
}

COMMON_WORDS = [
    b" the ", b" and ", b" of ", b" to ", b" in ", b" is ", b" you ",
    b" that ", b" it ", b" was ", b" for ", b" on ", b" are ", b" with ",
    b" his ", b" they ", b" this ", b" from ", b" have ", b" an ",
    # quantum-flavored words, so a real quantum payload scores too
    b"openqasm", b"qreg", b"creg", b"qubit", b"measure", b"include",
]

GOOD_ENOUGH = 0.80  # score at which we call a payload deciphered

# ---------------------------------------------------------------------------
# The compiled core (fastcore.c). Optional: when libpxfast.so sits next to
# this script and loads, the counting hot paths run in C; otherwise the
# pure-Python paths below do the same work more slowly.
# ---------------------------------------------------------------------------

_HERE = os.path.dirname(os.path.abspath(__file__))
FAST = None
try:
    _lib = ctypes.CDLL(os.path.join(_HERE, "libpxfast.so"))
    _lib.px_counts.restype = None
    _lib.px_letters.restype = ctypes.c_int
    _lib.px_razor.restype = ctypes.c_int
    FAST = _lib
except Exception:
    FAST = None

_SYMBOLS = "abcdefghijklmnopqrstuvwxyz "  # index 26 is the space


def _counts27(data: bytes):
    """(counts list of 27, printable_count) for data -- one pass,
    in C when the compiled core is present."""
    if FAST is not None:
        letters = (ctypes.c_int * 26)()
        stats = (ctypes.c_int * 2)()
        FAST.px_counts(data, len(data), letters, stats)
        return list(letters) + [stats[1]], stats[0]
    counts = [0] * 27
    printable = 0
    for b in data:
        if 97 <= b <= 122:
            counts[b - 97] += 1
        elif 65 <= b <= 90:
            counts[b - 65] += 1
        elif b == 32:
            counts[26] += 1
        if 32 <= b < 127 or b in (9, 10, 13):
            printable += 1
    return counts, printable


def _letters_stream(data: bytes) -> bytes:
    """Uppercase letters-only stream of data (the quadgram input)."""
    if FAST is not None:
        out = ctypes.create_string_buffer(len(data))
        m = FAST.px_letters(data, len(data), out)
        return out.raw[:m]
    return bytes(b if 65 <= b <= 90 else b - 32
                 for b in data if 97 <= b <= 122 or 65 <= b <= 90)


# ---------------------------------------------------------------------------
# The quadgram language model. quadgrams.txt holds four-letter chunk
# counts harvested from plain English text; a candidate's average
# log-probability under that table is a far sharper "is this real
# language?" signal than single-letter fit -- measured on this table:
# clean bench English averages -4.15, rotated or random text -7.6.
# ---------------------------------------------------------------------------

_QUAD_LOGP = {}
_QUAD_FLOOR = -8.33
try:
    _total = 0
    _raw = {}
    with open(os.path.join(_HERE, "quadgrams.txt")) as _fh:
        for _line in _fh:
            _q, _c = _line.split()
            _raw[_q] = int(_c)
            _total += int(_c)
    _QUAD_LOGP = {q: math.log10(c / _total) for q, c in _raw.items()}
    _QUAD_FLOOR = math.log10(0.01 / _total)
except Exception:
    _QUAD_LOGP = {}


def quad_fit(data: bytes) -> float:
    """Quadgram language-model fit, 0..1. 1 = reads like English."""
    if not _QUAD_LOGP:
        return 0.0
    stream = _letters_stream(data)
    if len(stream) < 4:
        return 0.0
    get = _QUAD_LOGP.get
    s = stream.decode("ascii")
    avg = sum(get(s[i:i + 4], _QUAD_FLOOR)
              for i in range(len(s) - 3)) / (len(s) - 3)
    return max(0.0, min(1.0, (avg + 7.6) / 3.5))


def letter_fit(data: bytes) -> float:
    """Chi-squared closeness of the letter mix to English. 0..1, 1 = perfect."""
    counts, _p = _counts27(data)
    total = sum(counts)
    if total < 4:
        return 0.0
    chi = 0.0
    for i, c in enumerate(_SYMBOLS):
        expected = total * LETTER_FREQ[c] / 100.0
        if expected > 0:
            chi += (counts[i] - expected) ** 2 / expected
    # chi per character: clean English sits low, noise sits high.
    return max(0.0, 1.0 - (chi / total) / 12.0)


def hist_fit(data: bytes) -> float:
    """Letter-histogram fit, blind to WHICH letter is which.
    A rotation (or any letter substitution) scrambles the chi-squared
    fit to zero but cannot change the histogram's shape -- so mid-peel,
    when a layer of rotation may still be on, this is the tracker that
    still smells English. 0..1, 1 = perfect."""
    counts, _p = _counts27(data)
    return _hist_from_counts(counts)


_EXP_PROPS = sorted((p / 100.0 for p in LETTER_FREQ.values()), reverse=True)


def _hist_from_counts(counts) -> float:
    # Same math as before, rearranged: chi/total = sum(((g/total - p)^2)/p),
    # so the expected histogram is sorted ONCE at import instead of once
    # per call -- the ranking hot path calls this 256x per state.
    total = sum(counts)
    if total < 4:
        return 0.0
    got = sorted(counts, reverse=True)
    inv = 1.0 / total
    s = 0.0
    for g, p in zip(got, _EXP_PROPS):
        d = g * inv - p
        s += (d * d) / p
    return max(0.0, 1.0 - s / 12.0)


def cjk_fit(data: bytes) -> float:
    """Fraction of decoded characters that are CJK ideographs, 0..1.
    Lets the scorer recognize solved Chinese text -- without this,
    UTF-8 Chinese scores near zero on every English signal, so a
    payload hiding Chinese plaintext could never read as solved."""
    if len(data) < 4 or max(data) < 128:
        return 0.0  # ASCII bytes can never be CJK; skip the decode
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return 0.0
    if len(text) < 4:
        return 0.0
    n = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff"
            or "\u3400" <= ch <= "\u4dbf"
            or "\U00020000" <= ch <= "\U0002a6df"
            or "\uf900" <= ch <= "\ufaff")
    return n / len(text)


_COMMON_ZH = frozenset(
    "的一是不了我有在人这中大为上个国以要他时来用们生到作地于出就分对成会可主发年动同工"
    "也能下过子说产种面而方后多定行学法所民得经十三之进着等部度家电力里如水化高自二理"
    "起小物现实加量都两体制机当使点从业本去把性好应开它合还因由其些然前外天政四日那"
    "社义事平形相全表间样与关各重新线内数正心反你明看原又么利比或但质气第向道命此变"
    "条只没结解问意建月公无系军很情者最立代想已通并提直题党程展五果料象员革位入常文"
    "总次品式活设及管特件长求老头基资边流路级少图山统接知较将组见计别她手角期根论运"
    "农指几九区强放决西被干做必战先回则任取据处队南给色光门即保治北造百规热领七海口"
    "东导器压志世金增争济阶油思术极交受联什认六共权收证改清己美再采转更单风切打白教"
    "速花带安场身车例真务具万每目至达走积示议声报斗完类八离华名确才科张信马节话米整"
    "空元况今集温传土许步群广石记需段研界拉林律叫且究观越织装影算低持音众书布复容儿"
    "须际商非验连断深难近矿千周委素技备半办青省列习响约支般史感劳便团往酸历市克何除"
    "消构府称太准精值号率族维划选标写存候毛亲快效斯院查江型眼王按格养易早")


def score(data: bytes) -> float:
    """Full language score for one candidate state."""
    if not data:
        return 0.0
    # Structured data that parses is solved by definition.
    stripped = data.strip()
    if stripped[:1] in (b"{", b"["):
        try:
            json.loads(stripped.decode("utf-8"))
            return 0.99
        except Exception:
            pass
    _counts, printable_n = _counts27(data)
    printable = printable_n / len(data)
    fit = letter_fit(data)
    quad = quad_fit(data)
    padded = b" " + data.lower() + b" "
    hits = sum(1 for w in COMMON_WORDS if w in padded)
    word_score = min(1.0, hits / 4.0)
    spaces = data.count(b" ") / len(data)
    space_score = 1.0 if 0.04 <= spaces <= 0.30 else max(0.0, 0.5 - abs(spaces - 0.15))
    # v1.1 blend: the quadgram model carries the most weight -- it is
    # the sharpest language signal -- with letter fit as its deputy.
    english = (0.20 * printable + 0.15 * fit + 0.40 * quad
               + 0.15 * word_score + 0.10 * space_score)
    # v1.3: Chinese. The English signals sit near zero on UTF-8
    # Chinese, so CJK density stands in for them -- clean Chinese
    # lands at 1.0, past GOOD_ENOUGH, the same as clean English.
    cjk = cjk_fit(data)
    if cjk >= 0.60:
        try:
            text = data.decode("utf-8")
            up = sum(1 for ch in text if ch.isprintable()) / len(text)
            zh = sum(1 for ch in text if ch in _COMMON_ZH) / len(text)
        except UnicodeDecodeError:
            up = 0.0
            zh = 0.0
        # Unigram tie-break: XOR bit-neighbors of real Chinese still
        # decode as CJK -- density alone cannot tell them apart -- but
        # their characters are rare neighbors. Common-character density
        # separates the true key cleanly (measured on the bench's
        # near-keys: 0.64 true vs <= 0.09 wrong).
        return max(english, 0.20 * up + 0.55 * cjk + 0.25 * zh)
    return english


# ---------------------------------------------------------------------------
# The peelers: every known way to remove ONE layer.
# Each yields (name, new_bytes) or nothing when the layer does not apply.
# ---------------------------------------------------------------------------

def _try(fn):
    try:
        out = fn()
        return out if out else None
    except Exception:
        return None


def peel_hex(data):
    d = data.strip()
    if len(d) >= 2 and len(d) % 2 == 0 and all(c in b"0123456789abcdefABCDEF" for c in d):
        out = _try(lambda: binascii.unhexlify(d))
        if out is not None:
            yield "hex-decode", out


def peel_base64(data):
    d = data.strip()
    if len(d) >= 4 and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in d):
        padded = d + b"=" * (-len(d) % 4)
        out = _try(lambda: base64.b64decode(padded, validate=True))
        if out is not None:
            yield "base64-decode", out


def peel_base32(data):
    d = data.strip().upper()
    if len(d) >= 8 and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=" for c in d):
        padded = d + b"=" * (-len(d) % 8)
        out = _try(lambda: base64.b32decode(padded))
        if out is not None:
            yield "base32-decode", out


def peel_base85(data):
    d = data.strip()
    if len(d) >= 5:
        out = _try(lambda: base64.b85decode(d))
        if out is not None:
            yield "base85-decode", out


def _rot(data, n):
    out = bytearray()
    for b in data:
        if 97 <= b <= 122:
            out.append((b - 97 + n) % 26 + 97)
        elif 65 <= b <= 90:
            out.append((b - 65 + n) % 26 + 65)
        else:
            out.append(b)
    return bytes(out)


def peel_rot(data):
    # Only worth trying when there are letters to rotate.
    if any(97 <= b <= 122 or 65 <= b <= 90 for b in data):
        for n in range(1, 26):
            yield f"rot-{n}", _rot(data, n)


def _xor(data, key):
    return bytes(b ^ key for b in data)


def best_xor_keys(data, keep=8):
    """Rank all 256 XOR keys by histogram fit alone and keep the best.
    Measured on the bench: pure histogram fit ranks the true key 1st
    on every test state, while blending in letter fit -- which scores
    a still-rotated layer as zero -- buries the true key under
    accidental near-matches. Keep the tracker pure.
    v1.1: with the compiled core, all 256 keys' histograms are counted
    in ONE C pass instead of 256 Python rescans."""
    if FAST is not None:
        out = (ctypes.c_int * (256 * 27))()
        FAST.px_xor_all_counts(data, len(data), out)
        ranked = sorted(range(256),
                        key=lambda k: _hist_from_counts(out[k * 27:(k + 1) * 27]),
                        reverse=True)
        return ranked[:keep]
    return sorted(range(256), key=lambda k: hist_fit(_xor(data, k)), reverse=True)[:keep]


_B64_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_HEX_CHARS = frozenset(b"0123456789abcdefABCDEF")


def razor_xor_keys(data, keep=8):
    """The charset razor. When an XOR mask hides ENCODED text (base64
    or hex), the letter histogram goes flat -- measured on the bench,
    the true key ranked 60th of 256 by histogram on a masked base64
    state. But only the true key restores the encoding's alphabet:
    scored by 'fraction of output inside the base64 alphabet', the
    true key ranked 1st at 1.000 against 0.888 for the best wrong key.
    This scan finds those keys (in C when the core is loaded)."""
    if len(data) < 16:
        return []
    if FAST is not None:
        buf = (ctypes.c_int * 256)()
        m = FAST.px_razor(data, len(data), buf)
        return list(buf[:m])[:keep]
    hits = []
    for k in range(1, 256):
        out = _xor(data, k)
        for charset in (_B64_CHARS, _HEX_CHARS):
            frac = sum(1 for b in out if b in charset) / len(out)
            if frac >= 0.98:
                hits.append((frac, k))
                break
    hits.sort(reverse=True)
    return [k for _f, k in hits[:keep]]


def _utf8_cjk_keys(data, keep=8):
    """The UTF-8 razor: when an XOR mask hides non-English text, the
    letter histogram goes flat and the base64/hex razor finds nothing --
    but only the true key decodes to valid UTF-8 dense with CJK
    ideographs. Gated on high-bit bytes so ASCII states never pay the
    255 trial decodes."""
    if len(data) < 16 or max(data) < 128:
        return []
    hits = []
    for k in range(1, 256):
        out = _xor(data, k)
        try:
            text = out.decode("utf-8")
        except UnicodeDecodeError:
            continue
        if len(text) < 4:
            continue
        n = sum(1 for ch in text if "\u4e00" <= ch <= "\u9fff"
                or "\u3400" <= ch <= "\u4dbf"
                or "\U00020000" <= ch <= "\U0002a6df"
                or "\uf900" <= ch <= "\ufaff")
        if n / len(text) >= 0.50:
            hits.append((n / len(text), k))
    hits.sort(reverse=True)
    return [k for _f, k in hits[:keep]]


def peel_xor_guided(data):
    """PythonX way: only carry the few XOR keys the scorer believes in --
    the histogram's best guesses, plus any key the charset razor cuts
    loose (an XOR mask over encoded text reveals itself that way)."""
    seen = set()
    for k in list(best_xor_keys(data)) + razor_xor_keys(data) + _utf8_cjk_keys(data):
        if k and k not in seen:
            seen.add(k)
            yield f"xor-0x{k:02x}", _xor(data, k)


def peel_xor_all(data):
    """Naive way: every key, no guidance."""
    for k in range(1, 256):
        yield f"xor-0x{k:02x}", _xor(data, k)


def peel_reverse(data):
    if len(data) >= 2:
        yield "reverse", data[::-1]


def _atbash(data):
    """The mirror alphabet: a<->z, b<->y, c<->x -- each letter swapped
    for its reflection. Its own undoing: mirror a mirror and the words
    come back."""
    out = bytearray()
    for b in data:
        if 97 <= b <= 122:
            out.append(219 - b)  # ord('a') + ord('z')
        elif 65 <= b <= 90:
            out.append(155 - b)  # ord('A') + ord('Z')
        else:
            out.append(b)
    return bytes(out)


def peel_atbash(data):
    """The Divincy layer, letter side: Da Vinci's mirror writing.
    Only worth trying when there are letters to mirror."""
    if any(97 <= b <= 122 or 65 <= b <= 90 for b in data):
        yield "atbash-mirror", _atbash(data)


def peel_divincy(data):
    """The full Divincy wrap in one peel: the text written backwards
    AND in the mirror alphabet -- mirror writing whole, the way
    Leonardo filled his notebooks. One named step so the beam can
    undo the whole wrap at once instead of spending two layers."""
    if len(data) >= 2 and any(97 <= b <= 122 or 65 <= b <= 90 for b in data):
        yield "divincy-mirror", _atbash(data[::-1])


def _bitrot(data, n, left=True):
    out = bytearray()
    for b in data:
        if left:
            out.append(((b << n) | (b >> (8 - n))) & 0xFF)
        else:
            out.append(((b >> n) | (b << (8 - n))) & 0xFF)
    return bytes(out)


def peel_bitrot(data):
    for n in range(1, 8):
        yield f"bitrot-left-{n}", _bitrot(data, n, True)
        yield f"bitrot-right-{n}", _bitrot(data, n, False)


def peel_decompress(data):
    out = _try(lambda: zlib.decompress(data))
    if out is not None:
        yield "zlib-open", out
    out = _try(lambda: zlib.decompress(data, -15))
    if out is not None:
        yield "deflate-open", out
    out = _try(lambda: gzip.decompress(data))
    if out is not None:
        yield "gzip-open", out
    out = _try(lambda: bz2.decompress(data))
    if out is not None:
        yield "bz2-open", out
    out = _try(lambda: lzma.decompress(data))
    if out is not None:
        yield "lzma-open", out


# ---------------------------------------------------------------------------
# v1.3 -- cryptography: Vigenere and columnar transposition.
# Solved the classical way, with frequency analysis -- never brute force.
# ---------------------------------------------------------------------------

def _wrap_vigenere(data, key):
    """Vigenere wrap (for tests): key advances per letter."""
    out = bytearray()
    ki = 0
    for b in data:
        n = key[ki % len(key)]
        if 97 <= b <= 122:
            out.append((b - 97 + n) % 26 + 97)
            ki += 1
        elif 65 <= b <= 90:
            out.append((b - 65 + n) % 26 + 65)
            ki += 1
        else:
            out.append(b)
    return bytes(out)


def _best_vigenere_key(data, k):
    """Crack one Vigenere key length: every key position is its own
    Caesar cipher -- solve each by letter fit and return the shift
    list, or None when a position is too thin to judge."""
    cols = [bytearray() for _ in range(k)]
    li = 0
    for b in data:
        if 97 <= b <= 122 or 65 <= b <= 90:
            cols[li % k].append(b)
            li += 1
    if any(len(c) < 4 for c in cols):
        return None
    shifts = []
    for col in cols:
        col = bytes(col)
        best_n, best_s = 0, -1.0
        for n in range(26):
            s = letter_fit(_rot(col, n))
            if s > best_s:
                best_s, best_n = s, n
        shifts.append(best_n)
    return shifts


def _vigenere_decrypt(data, shifts):
    out = bytearray()
    k = len(shifts)
    li = 0
    for b in data:
        if 97 <= b <= 122 or 65 <= b <= 90:
            base = 97 if b >= 97 else 65
            out.append((b - base + shifts[li % k]) % 26 + base)
            li += 1
        else:
            out.append(b)
    return bytes(out)


_VIG_OK = frozenset(b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ .,;:!?'\t\n\r-|/")


def _looks_classical(data):
    """Cheap gate for the classical peelers: Vigenere acts on text, so
    if more than 3% of the bytes aren't text-like (digits, +/=, raw
    binary), the expensive crack is skipped -- base64/hex/binary states
    never pay it. Measured: ~35% of bench time was cracking states that
    could never be Vigenere."""
    ok = 0
    for b in data:
        if b in _VIG_OK:
            ok += 1
    return ok >= 0.97 * len(data)


def peel_vigenere(data):
    """Vigenere, cracked the classical way: for key lengths 2-6, each
    key position is solved as its own Caesar cipher by letter fit.
    Bounded to five candidates so the beam stays lean."""
    n_letters = sum(1 for b in data if 97 <= b <= 122 or 65 <= b <= 90)
    if n_letters < 24 or len(data) > 4096:
        return
    if not _looks_classical(data):
        return
    for k in range(2, 7):
        shifts = _best_vigenere_key(data, k)
        if shifts is not None:
            yield f"vigenere-k{k}", _vigenere_decrypt(data, shifts)


def _wrap_transposition(data, cols):
    """Columnar transposition wrap (for tests): pad, write rows,
    read down the columns."""
    pad = (-len(data)) % cols
    if pad:
        data = data + bytes([pad]) * pad
    rows = len(data) // cols
    out = bytearray()
    for c in range(cols):
        for r in range(rows):
            out.append(data[r * cols + c])
    return bytes(out)


def _peel_transposition(data, cols):
    if len(data) % cols != 0 or len(data) < 2 * cols:
        return None
    rows = len(data) // cols
    grid = bytearray(len(data))
    i = 0
    for c in range(cols):
        for r in range(rows):
            grid[r * cols + c] = data[i]
            i += 1
    pad = grid[-1]
    if 1 <= pad <= cols and grid[-pad:] == bytes([pad]) * pad:
        grid = grid[:-pad]
    return bytes(grid)


def peel_transposition(data):
    """Columnar transposition: try column counts 2-8, write the
    ciphertext down the columns, read the rows back. Cheap -- seven
    candidates, one pass each."""
    if len(data) < 16 or len(data) > 4096:
        return
    for cols in range(2, 9):
        out = _peel_transposition(data, cols)
        if out is not None:
            yield f"transpos-{cols}", out


# ---------------------------------------------------------------------------
# v1.3 -- the sign layer: ASL fingerspelling handshapes as an encoding.
# A payload can hide its words as a stream of hand descriptions --
# "fist-thumb-side|flat-hand|cup-hand" -- and PythonX reads the hands
# back into letters.
# ---------------------------------------------------------------------------

SIGN_TOKENS = {
    "a": "fist-thumb-side", "b": "flat-hand", "c": "cup-hand",
    "d": "index-up", "e": "claw-fingers", "f": "ok-circle",
    "g": "pinch-sideways", "h": "two-sideways", "i": "pinky-up",
    "j": "pinky-hook", "k": "v-thumb-between", "l": "ell-shape",
    "m": "three-folded", "n": "two-folded", "o": "o-ring",
    "p": "k-point-down", "q": "g-point-down", "r": "fingers-crossed",
    "s": "fist-thumb-front", "t": "fist-thumb-under",
    "u": "two-together-up", "v": "v-sign", "w": "three-up",
    "x": "index-hook", "y": "horns-thumb-pinky", "z": "z-trace",
}
_SIGN_LOOKUP = {v: k for k, v in SIGN_TOKENS.items()}


def _wrap_signspell(data):
    """Sign wrap (for tests): letters become handshape tokens joined
    by '|', spaces become '/'. Anything else passes through -- tests
    use clean letters-and-spaces text."""
    parts = []
    for b in data:
        if 97 <= b <= 122:
            parts.append(SIGN_TOKENS[chr(b)])
        elif 65 <= b <= 90:
            parts.append(SIGN_TOKENS[chr(b + 32)])
        elif b == 32:
            parts.append("/")
        else:
            parts.append(chr(b))
    return "|".join(parts).encode("ascii")


def peel_signspell(data):
    """Read the hands: a pure stream of handshape tokens (and '/'
    for spaces) decodes straight to letters. Strict -- every token
    must be a known handshape, so a hit is hard evidence."""
    if b"|" not in data or len(data) < 8:
        return
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError:
        return
    tokens = text.split("|")
    if len(tokens) < 4:
        return
    out = []
    for tok in tokens:
        if tok == "/":
            out.append(" ")
        elif tok in _SIGN_LOOKUP:
            out.append(_SIGN_LOOKUP[tok])
        else:
            return
    yield "signspell-decode", "".join(out).encode("ascii")


GUIDED_PEELERS = [
    peel_hex, peel_base64, peel_base32, peel_base85, peel_rot,
    peel_xor_guided, peel_reverse, peel_atbash, peel_divincy,
    peel_bitrot, peel_decompress, peel_vigenere, peel_transposition,
    peel_signspell,
]
NAIVE_PEELERS = [
    peel_hex, peel_base64, peel_base32, peel_base85, peel_rot,
    peel_xor_all, peel_reverse, peel_atbash, peel_divincy,
    peel_bitrot, peel_decompress, peel_vigenere, peel_transposition,
    peel_signspell,
]

# Strict peelers only succeed when the data truly is that format -- a
# successful strict peel is hard evidence we are on the real trail, so
# the beam never throws those states away, however noisy they look.
STRICT_PEELERS = {peel_hex, peel_base64, peel_base32, peel_base85,
                  peel_decompress, peel_signspell}
STRICT_OPS = {
    "hex-decode", "base64-decode", "base32-decode", "base85-decode",
    "zlib-open", "deflate-open", "gzip-open", "bz2-open", "lzma-open",
    "signspell-decode",
}


_MAGIC_HEADS = (b"\x1f\x8b", b"\x78\x9c", b"\x78\x01", b"\x78\xda",
                b"BZh", b"\xfd7zXZ", b"PK\x03\x04")
_deep_cache = {}


def _deep_potential(data: bytes) -> float:
    """Two-step lookahead for masked encoded text. Rotations of a
    masked base64 state all tie on every one-step signal -- same
    histogram, same flat quadgram score -- and the true rotation lost
    the beam's tie-break by lottery. But only the true rotation is
    ONE xor away from a strict decode that opens on a known magic
    header. This probe checks exactly that, cached per state."""
    if len(data) < 16 or len(data) > 8192:
        return 0.0
    key = hashlib.sha1(data).digest()
    if key in _deep_cache:
        return _deep_cache[key]
    bonus = 0.0
    for k in razor_xor_keys(data):
        peeled = _xor(data, k)
        for peeler in (peel_base64, peel_base32, peel_hex, peel_base85):
            for _name, out in peeler(peeled):
                head = out[:6].lstrip()
                if out[:2] in _MAGIC_HEADS or out[:3] in _MAGIC_HEADS \
                        or out[:6] in _MAGIC_HEADS or head[:1] in (b"{", b"["):
                    bonus = 0.30
                    break
            if bonus:
                break
        if bonus:
            break
    if len(_deep_cache) < 20000:
        _deep_cache[key] = bonus
    return bonus


def potential(data: bytes) -> float:
    """How much a state looks like it still holds a peelable layer.
    A half-peeled payload is often binary noise with a low language
    score -- this keeps the tracker from abandoning the true trail."""
    if not data:
        return 0.0
    p = _deep_potential(data)
    if data[:2] == b"\x1f\x8b":
        p += 0.25  # gzip magic number
    if data[:1] == b"\x78":
        p += 0.10  # zlib header byte
    d = data.strip()
    if len(d) >= 8 and len(d) % 2 == 0 and all(c in b"0123456789abcdefABCDEF" for c in d):
        p += 0.15  # still looks like hex waiting to be peeled
    elif len(d) >= 8 and all(c in b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=" for c in d):
        p += 0.10  # still looks like base64 waiting to be peeled
    return p


# ---------------------------------------------------------------------------
# Engine 1 -- PythonX: score-guided beam search with deduping.
# Keep only the best BEAM_WIDTH trails each layer; never walk a trail twice.
# ---------------------------------------------------------------------------

BEAM_WIDTH = 28
MAX_DEPTH = 6


def _beam_from(root: bytes, root_path, width):
    """One dive: beam search starting from a single root state.
    Returns (best_tuple, states_tried) where best_tuple is
    (score, bytes, full_path)."""
    tried = 1
    best = (score(root), root, list(root_path))
    if best[0] >= GOOD_ENOUGH:
        return best, tried
    seen = {hashlib.sha1(root).digest()}
    beam = [(best[0], root, list(root_path))]
    for _depth in range(MAX_DEPTH):
        strict_pool = []
        pool = []
        for _s, data, path in beam:
            for peeler in GUIDED_PEELERS:
                for name, out in peeler(data):
                    tried += 1
                    key = hashlib.sha1(out).digest()
                    if key in seen:
                        continue
                    seen.add(key)
                    s = score(out)
                    new_path = path + [name]
                    if s > best[0]:
                        best = (s, out, new_path)
                    strict_ops = sum(1 for op in new_path if op in STRICT_OPS)
                    entry = (s + 0.30 * hist_fit(out) + potential(out)
                             + 0.20 * strict_ops, out, new_path)
                    if peeler in STRICT_PEELERS:
                        strict_pool.append(entry)
                    else:
                        pool.append(entry)
        if best[0] >= GOOD_ENOUGH or (not pool and not strict_pool):
            break
        strict_pool.sort(key=lambda t: t[0], reverse=True)
        pool.sort(key=lambda t: t[0], reverse=True)
        # Strict peels are protected (up to 4 slots); the rest of the
        # beam fills by rank, one state per byte-signature -- rotations
        # and reversals of the same junk share a signature and would
        # otherwise crowd out every genuinely different trail.
        keep = []
        sigs = set()
        for entry in strict_pool[:4] + strict_pool[4:] + pool:
            if len(keep) >= width:
                break
            sig = bytes(sorted(entry[1].lower()))
            if sig in sigs:
                continue
            sigs.add(sig)
            keep.append(entry)
        beam = [(s, out, path) for s, out, path in keep]
    return best, tried


def decipher_beam(payload: bytes):
    """Returns (best_bytes, path_list, states_tried, seconds).

    The search dives once per root: the payload itself, plus one dive
    per strict decode of the payload. A single shared beam let junk
    families (loose transforms of the wrapper text, false decodes)
    crowd the true trail out of its slots; separate dives mean the
    trail behind a real decode only competes with its own family."""
    start = time.time()
    tried = 0
    best = (score(payload), payload, [])
    if best[0] >= GOOD_ENOUGH:
        return payload, [], 1, time.time() - start
    roots = [(payload, [])]
    seen_roots = {hashlib.sha1(payload).digest()}
    for peeler in (peel_hex, peel_base64, peel_base32, peel_base85,
                   peel_decompress, peel_signspell):
        for name, out in peeler(payload):
            key = hashlib.sha1(out).digest()
            if key in seen_roots:
                continue
            seen_roots.add(key)
            roots.append((out, [name]))
    for root, root_path in roots:
        width = BEAM_WIDTH if not root_path else 14
        dive_best, dive_tried = _beam_from(root, root_path, width)
        tried += dive_tried
        if dive_best[0] > best[0]:
            best = dive_best
        if best[0] >= GOOD_ENOUGH:
            break
    return best[1], best[2], tried, time.time() - start


# ---------------------------------------------------------------------------
# Engine 2 -- the old way: blind depth-first brute force.
# Every combination, no scoring guidance, no deduping -- it drowns.
# A node budget keeps it from running forever; hitting the budget = failure.
# ---------------------------------------------------------------------------

def decipher_naive(payload: bytes, node_budget=150_000):
    """Returns (best_bytes_or_None, path_list, states_tried, seconds)."""
    start = time.time()
    state = {"tried": 0, "best": (score(payload), payload, [])}

    def walk(data, path):
        if state["tried"] >= node_budget:
            return False
        for peeler in NAIVE_PEELERS:
            for name, out in peeler(data):
                state["tried"] += 1
                s = score(out)
                if s > state["best"][0]:
                    state["best"] = (s, out, path + [name])
                if s >= GOOD_ENOUGH:
                    return True
                if len(path) + 1 < 4 and walk(out, path + [name]):
                    return True
                if state["tried"] >= node_budget:
                    return False
        return False

    walk(payload, [])
    s, data, path = state["best"]
    if s < GOOD_ENOUGH:
        return None, path, state["tried"], time.time() - start
    return data, path, state["tried"], time.time() - start


# ---------------------------------------------------------------------------
# The test bench: known payloads with known answers, timed head to head.
# ---------------------------------------------------------------------------

PLAIN = (b"the engineer reads the payload and the payload tells the truth "
         b"about the machine and the mission")


def _wrap_xor(data, key):
    return bytes(b ^ key for b in data)


def _gzip(data):
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", mtime=0) as f:
        f.write(data)
    return buf.getvalue()


def bench_payloads():
    return [
        ("one layer: base64",
         base64.b64encode(PLAIN)),
        ("two layers: gzip then base64",
         base64.b64encode(_gzip(PLAIN))),
        ("three layers: rot, xor, hex",
         binascii.hexlify(_wrap_xor(_rot(PLAIN, 5), 0x2A))),
        ("four layers: rot, xor, base64, hex",
         binascii.hexlify(base64.b64encode(_wrap_xor(_rot(PLAIN, 7), 0x5A)))),
        ("five layers: gzip, base64, xor, rot, hex",
         binascii.hexlify(_rot(_wrap_xor(base64.b64encode(_gzip(PLAIN)), 0x3C), 9))),
    ]


# v1.3 bench: the new layers. Chinese plaintext mirrors the English
# one -- the engineer reads the payload, and the payload tells the
# truth about the machine and the mission.
PLAIN_ZH = "工程师读懂了载荷 载荷说出了机器与使命的真相".encode("utf-8")


def bench13_payloads():
    return [
        ("v1.3 crypto: vigenere-k5, base64",
         base64.b64encode(_wrap_vigenere(PLAIN, [4, 19, 7, 21, 11]))),
        ("v1.3 crypto: transpos-6, hex",
         binascii.hexlify(_wrap_transposition(PLAIN, 6))),
        ("v1.3 sign: hands, xor, base64",
         base64.b64encode(_wrap_xor(_wrap_signspell(PLAIN), 0x2A))),
        ("v1.3 chinese: base64 over utf-8",
         base64.b64encode(PLAIN_ZH)),
        ("v1.3 chinese: xor, base64",
         base64.b64encode(_wrap_xor(PLAIN_ZH, 0x5A))),
        ("v1.3 combo: signspell, vigenere, hex",
         binascii.hexlify(_wrap_vigenere(_wrap_signspell(PLAIN), [9, 2, 17]))),
    ]


def run_bench13():
    print("PythonX v1.3 test bench -- the new layers")
    print(f"fast core: {'ON (compiled C)' if FAST is not None else 'OFF (pure Python fallback)'}")
    print("=" * 64)
    cases = [(label, payload, PLAIN) for label, payload in bench13_payloads()[:3]]
    cases += [(label, payload, PLAIN_ZH) for label, payload in bench13_payloads()[3:5]]
    cases += [(bench13_payloads()[5][0], bench13_payloads()[5][1], PLAIN)]
    for label, payload, want in cases:
        out, path, tried, secs = decipher_beam(payload)
        ok = out == want
        print(f"\n[{label}]")
        print(f"  PythonX : {'SOLVED' if ok else 'best effort'} "
              f"| {secs:.3f}s | {tried} states | path: {' -> '.join(path) or '(none)'}")


def run_bench():
    print("PythonX v1.1 test bench -- same payloads, both engines")
    print(f"fast core: {'ON (compiled C)' if FAST is not None else 'OFF (pure Python fallback)'}")
    print("=" * 64)
    for label, payload in bench_payloads():
        out, path, tried, secs = decipher_beam(payload)
        ok = out == PLAIN
        print(f"\n[{label}]")
        print(f"  PythonX : {'SOLVED' if ok else 'best effort'} "
              f"| {secs:.3f}s | {tried} states | path: {' -> '.join(path) or '(none)'}")
        n_out, n_path, n_tried, n_secs = decipher_naive(payload)
        n_ok = n_out == PLAIN
        verdict = "SOLVED" if n_ok else "gave up (node budget spent)"
        print(f"  old way : {verdict} "
              f"| {n_secs:.3f}s | {n_tried} states | path: {' -> '.join(n_path) or '(none)'}")
        if ok and n_ok:
            if secs < n_secs:
                print(f"  speedup : states {n_tried / max(tried,1):.1f}x fewer, "
                      f"time {n_secs / max(secs, 0.000001):.1f}x faster")
            else:
                print("  note    : both solved; too shallow for the beam to "
                      "earn its keep -- it wins at depth")
        elif ok:
            print(f"  speedup : old way never arrived; PythonX did it in "
                  f"{secs:.3f}s over {tried} states")


# ---------------------------------------------------------------------------
# Command line
# ---------------------------------------------------------------------------

def show(payload: bytes, label="input"):
    out, path, tried, secs = decipher_beam(payload)
    print(f"PythonX decipher -- {label}")
    print(f"  wrapped : {payload[:72]!r}{'...' if len(payload) > 72 else ''}")
    print(f"  path    : {' -> '.join(path) if path else '(already plain)'}")
    try:
        text = out.decode("utf-8")
    except UnicodeDecodeError:
        text = repr(out[:120])
    print(f"  plain   : {text}")
    print(f"  score   : {score(out):.2f} | states tried: {tried} | time: {secs:.3f}s")
    return out


def main(argv):
    if "--bench" in argv:
        run_bench()
        return 0
    if "--bench13" in argv:
        run_bench13()
        return 0
    if "--file" in argv:
        i = argv.index("--file")
        with open(argv[i + 1], "rb") as f:
            payload = f.read().strip()
        show(payload, label=f"file {argv[i + 1]}")
        return 0
    args = [a for a in argv[1:] if not a.startswith("--")]
    if not args:
        print(__doc__)
        return 0
    payload = args[0].encode()
    if "--naive" in argv:
        show(payload)
        n_out, n_path, n_tried, n_secs = decipher_naive(payload)
        print(f"\nold way : {'SOLVED' if n_out else 'gave up (node budget spent)'} "
              f"| {n_secs:.3f}s | {n_tried} states | path: {' -> '.join(n_path) or '(none)'}")
    else:
        show(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
