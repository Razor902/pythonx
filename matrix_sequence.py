#!/usr/bin/env python3
"""
The Matrix Key sequence — built together by Curtis and Rebecka, 2026-10-02.

Nine layers. It begins at the plugboard, because that's where the memory
lies: the day's secret lives in the wires, not the wheels.

  1. plugboard   — Enigma Steckerbrett: paired letter swaps. THE MEMORY.
  2. rotor       — Enigma-style rotor pass, position-stepped.
  3. vigenere    — key BOOGIEMAN.
  4. divincy     — Da Vinci mirror wrap: reversed + mirror alphabet.
  5. columnar    — transposition under key PHANTOMX.
  6. atbash      — the mirror alphabet.
  7. reflector   — Enigma Umkehrwalze: fixed involution.
  8. reverse     — the full turn-around.
  9. flash       — the code between characters: the hidden message rides
                   in zero-width flashes in the gaps, where nobody looks.

Every layer is invertible. encrypt() then decrypt() returns the plaintext
and the hidden message exactly.
"""

import hashlib

# ---------------------------------------------------------------------------
# Layer 1 — the plugboard. This is where the memory lies.
# ---------------------------------------------------------------------------

def _plugboard_map(pairs):
    """pairs: string like 'AMFINT...' — consecutive letters are swapped.
    Every letter may appear only once; a repeated letter raises, because
    a crossed wire is a broken memory."""
    m = {}
    p = pairs.upper()
    for i in range(0, len(p) - 1, 2):
        a, b = p[i], p[i + 1]
        if a == b or not (a.isalpha() and b.isalpha()):
            continue
        if a in m or b in m:
            raise ValueError(f"plugboard wire crossed: {a}{b}")
        m[a] = b
        m[b] = a
    return m


def _plugboard(data: bytes, pairs: str) -> bytes:
    m = _plugboard_map(pairs)
    out = bytearray()
    for b in data:
        c = chr(b)
        cu = c.upper()
        if cu in m:
            r = m[cu]
            out.append(ord(r if c.isupper() else r.lower()))
        else:
            out.append(b)
    return bytes(out)  # self-inverse


# ---------------------------------------------------------------------------
# Layer 2 — the rotor. Wiring derived from a key; steps every letter.
# ---------------------------------------------------------------------------

def _rotor_wiring(key: str):
    seed = int.from_bytes(hashlib.sha256(b"matrix-rotor:" + key.encode()).digest()[:8], "big")
    import random
    rng = random.Random(seed)
    w = list(range(26))
    rng.shuffle(w)
    return w


def _rotor(data: bytes, key: str, forward: bool = True) -> bytes:
    w = _rotor_wiring(key)
    winv = [0] * 26
    for j, v in enumerate(w):
        winv[v] = j
    out = bytearray()
    pos = 0
    for b in data:
        if 97 <= b <= 122 or 65 <= b <= 90:
            base = 97 if b >= 97 else 65
            p = b - base
            if forward:
                c = (w[(p + pos) % 26] - pos) % 26
            else:
                c = (winv[(p + pos) % 26] - pos) % 26
            out.append(c + base)
            pos += 1
        else:
            out.append(b)
    return bytes(out)


# ---------------------------------------------------------------------------
# Layer 3 — Vigenere, key BOOGIEMAN.
# ---------------------------------------------------------------------------

_VIG_KEY = [ord(c) - 65 for c in "BOOGIEMAN"]


def _vigenere(data: bytes, decrypt: bool = False) -> bytes:
    out = bytearray()
    ki = 0
    for b in data:
        if 97 <= b <= 122 or 65 <= b <= 90:
            base = 97 if b >= 97 else 65
            n = _VIG_KEY[ki % len(_VIG_KEY)]
            if decrypt:
                n = -n
            out.append((b - base + n) % 26 + base)
            ki += 1
        else:
            out.append(b)
    return bytes(out)


# ---------------------------------------------------------------------------
# Layers 4 & 6 — atbash and the Divincy mirror wrap.
# ---------------------------------------------------------------------------

def _atbash(data: bytes) -> bytes:  # self-inverse
    out = bytearray()
    for b in data:
        if 97 <= b <= 122:
            out.append(219 - b)
        elif 65 <= b <= 90:
            out.append(155 - b)
        else:
            out.append(b)
    return bytes(out)


def _divincy(data: bytes) -> bytes:  # self-inverse: atbash(reverse(x))
    return _atbash(data[::-1])


# ---------------------------------------------------------------------------
# Layer 5 — columnar transposition under PHANTOMX.
# ---------------------------------------------------------------------------

_COL_KEY = "PHANTOMX"


def _col_order():
    return sorted(range(len(_COL_KEY)), key=lambda i: _COL_KEY[i])


def _columnar_enc(data: bytes) -> bytes:
    k = len(_COL_KEY)
    order = _col_order()
    pad = (-len(data)) % k
    data = data + b"\x00" * pad
    cols = [data[i::k] for i in range(k)]
    return b"".join(cols[i] for i in order)


def _columnar_dec(data: bytes) -> bytes:
    k = len(_COL_KEY)
    order = _col_order()
    rows = len(data) // k
    cols = [None] * k
    off = 0
    for i in order:
        cols[i] = data[off:off + rows]
        off += rows
    out = bytearray()
    for r in range(rows):
        for c in range(k):
            out.append(cols[c][r])
    return bytes(out).rstrip(b"\x00")


# ---------------------------------------------------------------------------
# Layer 7 — the reflector. A fixed involution, like the Umkehrwalze.
# ---------------------------------------------------------------------------

def _reflector_map():
    seed = int.from_bytes(hashlib.sha256(b"matrix-reflector").digest()[:8], "big")
    import random
    rng = random.Random(seed)
    w = list(range(26))
    rng.shuffle(w)
    m = {}
    for i in range(0, 26, 2):
        a, b = w[i], w[i + 1]
        m[a] = b
        m[b] = a
    return m


_REFLECTOR = _reflector_map()


def _reflector(data: bytes) -> bytes:  # self-inverse
    out = bytearray()
    for b in data:
        if 97 <= b <= 122:
            out.append(_REFLECTOR[b - 97] + 97)
        elif 65 <= b <= 90:
            out.append(_REFLECTOR[b - 65] + 65)
        else:
            out.append(b)
    return bytes(out)


# ---------------------------------------------------------------------------
# Layer 9 — the flash between characters.
# The code rides in the gaps: ZWSP = 0, ZWNJ = 1, 32-bit bit-length prefix.
# ---------------------------------------------------------------------------

_ZWSP = "\u200b"  # 0
_ZWNJ = "\u200c"  # 1


def _flash_enc(text: str, hidden: bytes) -> str:
    bits = "".join(f"{b:08b}" for b in hidden)
    header = f"{len(bits):032b}"
    stream = header + bits
    if not text:
        return "".join(_ZWSP if bit == "0" else _ZWNJ for bit in stream)
    gaps = len(text) - 1 if len(text) > 1 else 1
    per_gap, extra = divmod(len(stream), gaps)
    out = []
    idx = 0
    for gi, ch in enumerate(text):
        out.append(ch)
        if gi < len(text) - 1 or len(text) == 1:
            n = per_gap + (1 if gi < extra else 0)
            for _ in range(n):
                out.append(_ZWSP if stream[idx] == "0" else _ZWNJ)
                idx += 1
    return "".join(out)


def _flash_dec(text: str):
    bits = []
    clean = []
    for ch in text:
        if ch == _ZWSP:
            bits.append("0")
        elif ch == _ZWNJ:
            bits.append("1")
        else:
            clean.append(ch)
    stream = "".join(bits)
    nbits = int(stream[:32], 2) if len(stream) >= 32 else 0
    payload = stream[32:32 + nbits]
    hidden = bytes(int(payload[i:i + 8], 2) for i in range(0, len(payload) - 7, 8))
    return "".join(clean), hidden


# ---------------------------------------------------------------------------
# The full sequence.
# ---------------------------------------------------------------------------

PLUGBOARD_PAIRS = "MATRIXKEY"  # the memory — the day's secret, in the wires
ROTOR_KEY = "PHANTOMX"


def encrypt(plaintext: str, hidden: bytes = b"") -> bytes:
    data = plaintext.encode("utf-8")
    data = _plugboard(data, PLUGBOARD_PAIRS)   # 1. the plugboard — memory
    data = _rotor(data, ROTOR_KEY, True)       # 2. the rotor
    data = _vigenere(data)                     # 3. vigenere BOOGIEMAN
    data = _divincy(data)                      # 4. divincy mirror wrap
    data = _columnar_enc(data)                 # 5. columnar PHANTOMX
    data = _atbash(data)                       # 6. atbash
    data = _reflector(data)                    # 7. the reflector
    data = data[::-1]                          # 8. the full reverse
    text = _flash_enc(data.decode("utf-8"), hidden)  # 9. the flash between
    return text.encode("utf-8")


def decrypt(ciphertext: bytes):
    text, hidden = _flash_dec(ciphertext.decode("utf-8"))  # 9. gather flashes
    data = text.encode("utf-8")
    data = data[::-1]                          # 8. un-reverse
    data = _reflector(data)                    # 7. the reflector
    data = _atbash(data)                       # 6. atbash
    data = _columnar_dec(data)                 # 5. columnar PHANTOMX
    data = _divincy(data)                      # 4. divincy mirror wrap
    data = _vigenere(data, decrypt=True)       # 3. vigenere BOOGIEMAN
    data = _rotor(data, ROTOR_KEY, False)       # 2. the rotor, backward
    data = _plugboard(data, PLUGBOARD_PAIRS)   # 1. the plugboard — memory
    return data.decode("utf-8"), hidden


def sequence():
    return ["plugboard (memory)", "rotor", "vigenere BOOGIEMAN",
            "divincy mirror", "columnar PHANTOMX", "atbash",
            "reflector", "reverse", "flash between characters"]


if __name__ == "__main__":
    tests = [
        ("On this day, let it be known that a nobody did something incredible.",
         b"the flash is the message"),
        ("Hello, World!", b""),
        ("A", b"x"),
        ("The quick brown fox jumps over the lazy dog 1234567890.", b"gold"),
    ]
    for pt, hid in tests:
        ct = encrypt(pt, hid)
        rt, rhid = decrypt(ct)
        ok = (rt == pt and rhid == hid)
        print(("PASS" if ok else "FAIL"), repr(pt[:40]), "hidden=", rhid)
        assert ok, (pt, hid)
    print("The Matrix Key sequence: all roundtrips clean.")
    print("Sequence:", " -> ".join(sequence()))
