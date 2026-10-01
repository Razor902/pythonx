#!/usr/bin/env python3
"""
pythonx.py -- PythonX, the PhantomX decipher algorithm.

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
"""

import base64
import binascii
import bz2
import gzip
import hashlib
import io
import json
import lzma
import sys
import time
import zlib

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


def letter_fit(data: bytes) -> float:
    """Chi-squared closeness of the letter mix to English. 0..1, 1 = perfect."""
    counts = {}
    total = 0
    for b in data.lower():
        c = chr(b)
        if c in LETTER_FREQ:
            counts[c] = counts.get(c, 0) + 1
            total += 1
    if total < 4:
        return 0.0
    chi = 0.0
    for c, pct in LETTER_FREQ.items():
        expected = total * pct / 100.0
        if expected > 0:
            chi += (counts.get(c, 0) - expected) ** 2 / expected
    # chi per character: clean English sits low, noise sits high.
    return max(0.0, 1.0 - (chi / total) / 12.0)


def hist_fit(data: bytes) -> float:
    """Letter-histogram fit, blind to WHICH letter is which.
    A rotation (or any letter substitution) scrambles the chi-squared
    fit to zero but cannot change the histogram's shape -- so mid-peel,
    when a layer of rotation may still be on, this is the tracker that
    still smells English. 0..1, 1 = perfect."""
    counts = {}
    total = 0
    for b in data.lower():
        c = chr(b)
        if c in LETTER_FREQ:
            counts[c] = counts.get(c, 0) + 1
            total += 1
    if total < 4:
        return 0.0
    got = sorted(counts.values(), reverse=True)
    exp = sorted((total * p / 100.0 for p in LETTER_FREQ.values()), reverse=True)
    n = max(len(got), len(exp))
    got += [0] * (n - len(got))
    exp += [0.0] * (n - len(exp))
    chi = sum((g - e) ** 2 / e for g, e in zip(got, exp) if e > 0)
    return max(0.0, 1.0 - (chi / total) / 12.0)


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
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13)) / len(data)
    fit = letter_fit(data)
    padded = b" " + data.lower() + b" "
    hits = sum(1 for w in COMMON_WORDS if w in padded)
    word_score = min(1.0, hits / 4.0)
    spaces = data.count(b" ") / len(data)
    space_score = 1.0 if 0.04 <= spaces <= 0.30 else max(0.0, 0.5 - abs(spaces - 0.15))
    return 0.30 * printable + 0.35 * fit + 0.25 * word_score + 0.10 * space_score


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
    accidental near-matches. Keep the tracker pure."""
    return sorted(range(256), key=lambda k: hist_fit(_xor(data, k)), reverse=True)[:keep]


def peel_xor_guided(data):
    """PythonX way: only carry the few XOR keys the scorer believes in."""
    for k in best_xor_keys(data):
        if k:
            yield f"xor-0x{k:02x}", _xor(data, k)


def peel_xor_all(data):
    """Naive way: every key, no guidance."""
    for k in range(1, 256):
        yield f"xor-0x{k:02x}", _xor(data, k)


def peel_reverse(data):
    if len(data) >= 2:
        yield "reverse", data[::-1]


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


GUIDED_PEELERS = [
    peel_hex, peel_base64, peel_base32, peel_base85, peel_rot,
    peel_xor_guided, peel_reverse, peel_bitrot, peel_decompress,
]
NAIVE_PEELERS = [
    peel_hex, peel_base64, peel_base32, peel_base85, peel_rot,
    peel_xor_all, peel_reverse, peel_bitrot, peel_decompress,
]

# Strict peelers only succeed when the data truly is that format -- a
# successful strict peel is hard evidence we are on the real trail, so
# the beam never throws those states away, however noisy they look.
STRICT_PEELERS = {peel_hex, peel_base64, peel_base32, peel_base85, peel_decompress}
STRICT_OPS = {
    "hex-decode", "base64-decode", "base32-decode", "base85-decode",
    "zlib-open", "deflate-open", "gzip-open", "bz2-open", "lzma-open",
}


def potential(data: bytes) -> float:
    """How much a state looks like it still holds a peelable layer.
    A half-peeled payload is often binary noise with a low language
    score -- this keeps the tracker from abandoning the true trail."""
    if not data:
        return 0.0
    p = 0.0
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
                    entry = (s + 0.45 * hist_fit(out) + potential(out)
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
    for peeler in (peel_hex, peel_base64, peel_base32, peel_base85, peel_decompress):
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
    ]


def run_bench():
    print("PythonX test bench -- same payloads, both engines")
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
