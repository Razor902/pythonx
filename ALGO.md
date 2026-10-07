# Triage — "Is this blob worth deciphering?"

**Status:** gathered — built 2026-10-07. Lives in `triage.py`, tested by `test_triage.py`.

## What it does

PythonX's beam search is strong but it spends steps on everything you hand
it — including pure noise. Triage is the bouncer at the door: it looks at an
unknown blob and answers one question before the expensive search begins.

- **peel** — structured, hand it to the decipher engine.
- **maybe** — unsure, worth a look if nothing better is waiting.
- **skip** — noise or filler; the beam search would only burn steps.

Give it a folder of unknown blobs and `rank_blobs` sorts them peel-first,
so the engine always works the most promising lead first.

## How it works — five signals

Every signal is one pass over the bytes. Each scores 0.0 (noise) to 1.0
(structured), then they blend with weights: entropy 25%, signature 25%,
alphabet 20%, squeeze 20%, repetition 10%.

1. **Entropy** — Shannon entropy, bits of surprise per byte. Real text and
   code sit around 4–6 bits; packed or encrypted noise sits near 8. The
   sweet spot (3.0–6.2 bits) scores 1.0; above 7.2 scores 0.
2. **Signature** — known magic bytes: gzip, zip, PNG, PDF, PEM armor, and
   friends, plus JSON/XML brackets. A hard magic hit outranks a muddy
   blend — if the wrapper is named, there is definitely something to unwrap.
3. **Alphabet** — how much of the blob lives in a recognizable alphabet:
   printable text (1.0), base64-shaped (0.9), mostly printable (0.6).
4. **Squeeze** — one quick zlib probe on the first 4K. Structure squeezes;
   noise does not. Tiny blobs (under 128 bytes) are judged neutral, because
   zlib's fixed overhead dwarfs the signal at that size.
5. **Repetition** — nearly one repeated byte means filler or padding, and
   triage says **skip**: there is nothing hidden in 200 zero bytes worth a
   beam search.

Verdict lines: score ≥ 0.60 → peel; ≥ 0.35 → maybe; below → skip.

## Time complexity

**O(n)** time in the blob length — five single passes, no nesting — and
**O(1)** extra space (the byte-count table is a fixed 256 slots; the squeeze
probe caps at 4K). Triage is cheap next to the search it saves, which is the
whole point: spend a millisecond per blob deciding, save seconds per blob
deciphering.

## Limits — said plainly

- **Encrypted data looks exactly like noise.** Triage cannot tell a
  well-encrypted payload from random bytes, and it does not try. If you
  know a blob is encrypted, skip triage and go straight to key work.
- **Base64 of noise scores high.** Triage sees a structured *wrapper* and
  says peel; the beam search then finds nothing inside. The wrapper was
  real, the contents were not — triage judges the envelope, not the letter.
- **Tiny blobs can't earn full confidence.** A 40-byte sentence gets
  "maybe", not "peel" — there just isn't enough signal at that size.
- **It is a triage nurse, not a doctor.** It decides what deserves the
  engine's time; the engine still does the deciphering.

## How it plugs into PythonX

`triage.py` stands alone — `from triage import triage, rank_blobs`, or
`python3 triage.py *.bin` on the command line. The natural next step,
when Curtis says so: call `triage()` at the top of `decipher()` in
`pythonx13.py` and skip blobs that come back `skip`, spending the beam
budget where the structure is. That wiring is proposed, not yet done —
the engine itself is untouched.

© 2026 Curtis Ray Dyess · Crimson Rose LLC
