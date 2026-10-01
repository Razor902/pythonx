# PythonX

**A score-guided decipher engine for layered-encoded payloads.**
Built by Curtis Ray Dyess (PhantomX), October 2026.

## The idea

A payload is usually plain words wrapped in layers — hex, base64, a
letter rotation, an XOR mask, compression, and so on. Peeling the
layers by brute force means trying *every* combination, and the
combinations multiply until the search drowns.

PythonX peels smarter. It works like a good tracker:

- try every known way to peel one layer,
- **score** each result by how much it looks like real language,
- keep only the best few trails (a beam search),
- never walk the same trail twice,
- stop the moment the words read clean.

That is the whole trick: score-guided beam search with deduping. It
turns an exponential swamp into a short walk. PythonX is the algorithm
itself — and the algorithm is designed to grow into a language model:
the scoring *is* the model's core, not a part bolted onto one.

## Files

| File | What it is |
|---|---|
| `pythonx.py` | **v1.4 (Oct 1, 2026)** — the current engine (stdlib only) |
| `pythonx11.py` | v1.1 — quadgram scorer + compiled C core + charset razor |
| `fastcore.c` | the optional compiled core (counting hot paths) |
| `quadgrams.txt` | four-letter-chunk frequency table for the v1.1 scorer |
| `compare.py` | v1 vs v1.1 on the same five-case bench |
| `build.sh` | builds `libpxfast.so` (v1.1 falls back to pure Python without it) |
| `pythonx-schematic.svg/png` | the "for dummies" schematic of how a decipher runs |

## Run it

```sh
python3 pythonx.py "<payload>"      # decipher one payload string (current engine)
python3 pythonx.py --file p.txt     # decipher a payload from a file
python3 pythonx.py --bench         # the built-in standard bench
python3 pythonx.py --bench13       # the v1.3 bench (Vigenere, transposition, sign, Chinese)
python3 pythonx11.py "<payload>"   # v1.1 engine, for comparison
python3 compare.py                  # v1 vs v1.1, side by side
./build.sh                          # optional: build the C core first
```

Stdlib only. No internet. Runs anywhere Python 3 runs — developed and
benched on a Samsung Galaxy A16 in Termux.

## v1 → v1.1, measured

Bench: known-answer payloads at 1–5 layers (base64; gzip+base64;
rot+xor+hex; rot+xor+base64+hex; gzip+base64+xor+rot+hex).

| | v1 | v1.1 |
|---|---|---|
| Cases 1–4 | solved | solved, same state counts, 1.3–1.5× faster |
| Case 5 (five layers) | gave up after 16,802 states | **solved in 8,852 states** |

Five-layer wall time: 4.40s → 1.28s (workstation), 11.07s → 4.55s (phone).

What made the difference:

- **Quadgram language model.** Text is judged on four-letter chunks,
  not single letters. Clean bench English scores 0.98; rotated junk
  scores 0.0.
- **Compiled C core.** Letter histograms for all 256 XOR keys in one
  pass, letter streams, and the razor scan — via ctypes, with a
  pure-Python fallback.
- **The charset razor.** Over XOR-masked base64, the letter histogram
  ranked the true key 60th of 256. The razor asks a different
  question — *which key restores the encoding's alphabet?* — and the
  true key ranked 1st (1.000 of output inside the alphabet vs 0.888
  for the best wrong key).
- **Two-step lookahead.** Rotations of a masked state tie on every
  one-step signal, and the true rotation was being lost at the beam's
  edge. A state now earns a bonus when it sits one XOR away from a
  strict decode that opens on a known file header.

## Design notes

- Peelers: hex, base64, base32, base85, rot-1..25, guided XOR,
  reverse, bit rotations, zlib/deflate/gzip/bz2/lzma.
- Strict peels (a decode that only succeeds on real data) get
  protected slots in the beam — hard evidence beats a noisy score.
- The search dives separately from the payload and from each strict
  decode of it, so a real trail only competes with its own family.

*Change the world one day at a time.*

## Credits

**Lead engineer:** Curtis Ray Dyess — PhantomX (his company), Crimson Root
Linux study team.

**Engine:** PythonX v1.4 — October 1, 2026 —
Vigenere text-gating, histogram-sort hoist, UTF-8/CJK XOR razor, and a
Chinese unigram tie-break. All 11 bench cases pass (5 standard + 6
v1.3); the standard bench runs back at v1.2 parity after a 2× v1.3
regression, and a Chinese-XOR payload that never solved before now
solves in 0.11s.

Built and benched on a Samsung Galaxy A16 in Termux. Python 3,
standard library only, no internet needed.

*Permission first. Scope defined. Then fearless inside it.*
