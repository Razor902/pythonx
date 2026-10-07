# © 2026 Curtis Ray Dyess · Crimson Rose LLC
#!/usr/bin/env python3
"""Tests for triage.py -- the "is this blob worth deciphering?" module.

Run:  python3 test_triage.py
All randomness is seeded, so the suite is deterministic.
"""

import base64
import os
import random
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from triage import (PEEL, MAYBE, SKIP, alphabet_score, entropy_score,
                    rank_blobs, repetition_score, shannon_entropy,
                    signature_hit, squeeze_score, triage)

_rng = random.Random(20261007)

TEXT = (b"The quick brown fox jumps over the lazy dog. "
        b"Pack my box with five dozen liquor jugs. ") * 6


def check(name, cond, detail=""):
    status = "ok " if cond else "FAIL"
    print(f"[{status}] {name}" + (f" -- {detail}" if detail and not cond else ""))
    return cond


def main():
    passed = failed = 0

    def t(name, cond, detail=""):
        nonlocal passed, failed
        if check(name, cond, detail):
            passed += 1
        else:
            failed += 1

    # --- entropy sanity -------------------------------------------------
    t("entropy of text is text-like",
      3.5 <= shannon_entropy(TEXT) <= 5.5, f"{shannon_entropy(TEXT):.2f}")
    noise = _rng.randbytes(2000)
    t("entropy of noise is noise-like",
      shannon_entropy(noise) >= 7.5, f"{shannon_entropy(noise):.2f}")
    t("entropy_score(text) is high", entropy_score(TEXT) >= 0.9)
    t("entropy_score(noise) is zero", entropy_score(noise) == 0.0)
    t("entropy_score(empty) is low", entropy_score(b"") <= 0.3)

    # --- signatures ------------------------------------------------------
    kind, s = signature_hit(zlib.compress(TEXT))
    t("zlib magic recognized", kind == "zlib" and s == 1.0, f"{kind}")
    kind, s = signature_hit(b"PK\x03\x04" + b"\x00" * 20)
    t("zip magic recognized", kind == "zip" and s == 1.0)
    kind, s = signature_hit(b'  {"a": 1}  ')
    t("json bracket recognized", kind == "json" and s == 0.7)
    kind, s = signature_hit(b"<html></html>")
    t("xml bracket recognized", kind == "xml" and s == 0.7)
    kind, s = signature_hit(b"hello")
    t("no magic on plain text", kind is None and s == 0.0)

    # --- alphabets -------------------------------------------------------
    a, name = alphabet_score(TEXT)
    t("printable text scores 1.0", a == 1.0 and name == "printable text")
    b64 = base64.b64encode(TEXT)
    a, name = alphabet_score(b64)
    t("base64 scores high", a >= 0.9, f"{a:.2f} {name}")
    hx = TEXT.hex().encode()
    a, name = alphabet_score(hx)
    t("hex scores high", a >= 0.8, f"{a:.2f} {name}")
    a, _ = alphabet_score(noise)
    t("noise alphabet is low", a < 0.5, f"{a:.2f}")

    # --- squeeze ---------------------------------------------------------
    t("text squeezes well", squeeze_score(TEXT) >= 0.9)
    t("noise does not squeeze", squeeze_score(noise) == 0.0)
    t("tiny blob is neutral", squeeze_score(b"ab") == 0.5)
    t("short blob is neutral", squeeze_score(b"x" * 100) == 0.5)

    # --- repetition ------------------------------------------------------
    r, filler = repetition_score(b"\x00" * 200)
    t("zero-fill flagged as filler", filler and r == 1.0)
    r, filler = repetition_score(TEXT)
    t("text is not filler", not filler)

    # --- full verdicts ---------------------------------------------------
    v, s, reasons = triage(TEXT)
    t("english text -> peel", v == PEEL, f"{v} {s}")
    v, s, reasons = triage(noise)
    t("random noise -> skip", v == SKIP, f"{v} {s}")
    v, s, reasons = triage(b64)
    t("base64 text -> peel", v == PEEL, f"{v} {s}")
    v, s, reasons = triage(hx)
    t("hex text -> peel", v == PEEL, f"{v} {s}")
    v, s, reasons = triage(b"\x00" * 200)
    t("zero-fill -> skip", v == SKIP, f"{v} {s}")
    v, s, reasons = triage(b"")
    t("empty -> skip", v == SKIP and s == 0.0)
    v, s, reasons = triage(zlib.compress(TEXT))
    t("zlib blob -> peel (magic)", v == PEEL, f"{v} {s}")
    v, s, reasons = triage(b'{"key": "value", "n": 42}')
    t("json -> peel", v == PEEL, f"{v} {s}")
    v, s, reasons = triage(_rng.randbytes(24))
    t("tiny noise does not crash", v in (PEEL, MAYBE, SKIP))

    # reasons are human-readable
    v, s, reasons = triage(TEXT)
    t("reasons explain themselves",
      all(isinstance(r, str) and r for r in reasons) and len(reasons) >= 3)

    # --- ranking ---------------------------------------------------------
    ranked = rank_blobs({"noise.bin": noise, "text.txt": TEXT,
                         "pad.bin": b"\xff" * 100})
    names = [r[0] for r in ranked]
    t("rank puts peel first", names[0] == "text.txt", str(names))
    t("rank puts skip last", names[-1] in ("noise.bin", "pad.bin"), str(names))
    verdicts = {r[0]: r[1] for r in ranked}
    t("rank verdicts sane",
      verdicts["text.txt"] == PEEL and verdicts["noise.bin"] == SKIP,
      str(verdicts))

    print(f"\n{passed} passed, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
