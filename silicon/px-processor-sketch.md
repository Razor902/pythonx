# PythonX Processor Sketch

© 2026 Curtis Ray Dyess — PhantomX / Crimson Root. All rights reserved.

**Status: design document. Nothing here is built.** This is a paper
sketch of what a PythonX accelerator would look like, drawn directly
from the v1.4 engine's real hot paths (`pythonx.py`, `fastcore.c`).

Curtis's framing stands: **the algorithm is the seed; the processor
gets built around it, not from it.** PythonX is a search strategy.
Silicon only earns its keep on the inner loops — the counting, the
scoring, the transforms. Everything else stays on the host CPU.

---

## 1. What it is / what it isn't

**It is:** a domain accelerator. The analogy is exact: a TPU doesn't
replace a CPU, it accelerates matrix math for neural nets. A PythonX
unit wouldn't replace a CPU either — it accelerates score-guided
deciphering and language scoring. It sits beside the host, takes jobs,
returns ranked candidates.

**It isn't:** a general-purpose processor. There is no instruction
set here, no branch predictor, no operating system. It cannot run
Python. It cannot run anything except the decipher pipeline. Anyone
telling you otherwise is selling something.

**Where the line sits:** the host CPU keeps the judgment — the beam
loop, the deduping, the "is this solved" call, the path bookkeeping.
The accelerator does the arithmetic the host currently burns time on:
histograms, XOR key ranking, quadgram scoring, byte transforms,
razor pre-filters, top-K selection. This split is honest about
Amdahl's law: control flow is cheap on a CPU and miserable in
fixed-function logic; data-parallel counting is the reverse.

---

## 2. Primitive ops, extracted from the real hot paths

Every op below exists in the v1.4 code today. Each is a pure function
over a byte buffer — no pointers, no judgment, just arithmetic. That
is exactly why the C core (`fastcore.c`) was writable, and exactly
why these are silicon-friendly: integer math, fixed vocabularies,
data-parallel by construction.

| Op | What it computes | Widths | Why it's silicon-friendly |
|---|---|---|---|
| `COUNT27` (`px_counts`) | 26 letter bins + printable/space stats, one pass | 8-bit in, 32-bit counters | Byte lanes; a comparator + increment per lane |
| `XOR_ALL_COUNTS` (`px_xor_all_counts`) | 256 keys × 27-bin histogram in one pass | 8-bit in; 256×27 counters out | 256 parallel lanes — the single most valuable block; this is the XOR key ranker |
| `LETTERS_STREAM` (`px_letters`) | filter to A–Z, uppercase | 8-bit in/out | Predicate + pack; trivial |
| `RAZOR_B64HEX` (`px_razor`) | per-key XOR, fraction of output inside base64/hex alphabet ≥ 98% | 255 keys × n bytes | 255 parallel counter+comparator lanes; two 256-entry membership LUTs |
| `RAZOR_CJK` (`_utf8_cjk_keys`) | trial XOR → valid UTF-8 with ≥50% CJK ideographs | 255 keys | Parallel, but UTF-8 decode is variable-length — the awkward one; note below |
| `HIST_FIT` (`_hist_from_counts`) | sorted-histogram χ² vs 27 expected proportions | 27-element sort + fixed-point MAC | 27-wide sorting network is small; the expected table is sorted once (v1.4 hoist) |
| `LETTER_FIT` (`letter_fit`) | 27-bin χ² vs English frequency table | 27 fixed-point MACs | Pure datapath, no memory |
| `QUAD_FIT` (`quad_fit`) | per-4-gram log-prob lookup, accumulate, average | 49,794-entry table; 16-bit fixed-point log-probs | Memory-bound, not compute-bound — the table is the cost (see §5) |
| `WORD_HITS` (`COMMON_WORDS`) | 26 fixed substring patterns present? | 26 parallel comparators | Fixed vocabulary → hardwired, Aho-Corasick optional |
| `ZH_UNIGRAM` (`_COMMON_ZH`) | 543-codepoint membership density | 543-entry ROM | Small lookup table; the v1.4 tie-break lives here |
| `XFORM` (xor/rot/atbash/bitrot/reverse) | byte-lane substitution | 8-bit lanes | Single-cycle per byte; rot is mod-26 add, atbash is `219−b`, bitrot is a wire permutation — nearly free |
| `VIGENERE_SOLVE` (`_best_vigenere_key`) | per key-length 2–6, per column: 26 rotations × letter-fit → argmax | ~520 parallel χ² evals | The most parallel block in the engine; screams for lanes |
| `TRANSPOSE` (`_peel_transposition`) | grid permute, cols 2–8 | address generator | No ALU at all — a permute network / DMA pattern |
| `SIGNSPELL` (`peel_signspell`) | 26-token dictionary decode, strict | 26-entry CAM | Content-addressable lookup; strict match = hard evidence |
| `DECODE_STRICT` (hex/b64/b32/b85) | alphabet-validate + decode | LUT + pack | Small; gzip/zlib inflate is real but large — mark host-only for now |
| `TOPK` (beam arbiter) | keep best 28 of ~hundreds by fixed-point score | bitonic/tournament network | Score = s + 0.30·hist + potential + 0.20·strict — one MAC per candidate, then sort |
| `DEDUP_HASH` | 64-bit hash per state + seen-set | FNV-1a + CAM/Bloom | Replaces SHA-1 + the sorted-bytes signature (which is an O(n log n) sort per candidate in software — too heavy for gates; the hash alone is enough) |

Two honest footnotes:

- `RAZOR_CJK`'s UTF-8 decode is the only op with variable-length
  parsing. In silicon it becomes a small state machine, or the CJK
  check moves to a byte-pattern pre-filter (lead-byte ranges
  E4–E9 cover the common CJK block) with full decode on the host.
  Don't gold-plate it in v1 of the sketch.
- `score()` blends five English signals plus the CJK branch. In
  fixed point (Q16 or even 8-bit), the blend is a weighted sum —
  cheap. The *weights* stay programmable registers so the blend can
  be tuned without new silicon.

---

## 3. Fixed-function units

One unit per op family. Small, single-purpose, no firmware:

- **CU** — count unit: `COUNT27`, `LETTERS_STREAM`, printable stats.
- **XCU** — XOR count array: `XOR_ALL_COUNTS`, 256 lanes × 27 counters.
  The crown jewel. Everything XOR in the engine flows through here.
- **SU** — score unit: `HIST_FIT` + `LETTER_FIT` + `QUAD_FIT` +
  `WORD_HITS` + `ZH_UNIGRAM` pipelines feeding one weighted-sum
  blend with programmable weights.
- **TU** — transform lanes: `XFORM` byte ops (xor-k, rot-n, atbash,
  bitrot, reverse), wide SIMD lanes.
- **RB** — razor bank: `RAZOR_B64HEX`, `RAZOR_CJK` pre-filter,
  the `_looks_classical` text gate (97% text-like bytes — one pass,
  nearly free, and it saved ~35% of bench time in v1.4).
- **VA** — Vigenere array: `VIGENERE_SOLVE`, ~520 parallel
  rotation+χ² lanes with per-column argmax.
- **BA** — beam arbiter: `TOPK` selection, width 28 (programmable
  down, not up — area is area).
- **DU** — dedup unit: `DEDUP_HASH` + seen-set; a Bloom filter
  sized for ~10⁵ states keeps the false-positive rate negligible
  at a fraction of a CAM's area.

Decompression (gzip/bz2/lzma) and the signspell CAM stay on the
host for the prototype. Inflate-in-hardware is a solved problem but
it's a whole project on its own; it doesn't belong in the first
sketch.

---

## 4. Pipeline sketch

```
                 ┌────────────┐
  payload bytes  │  RAZOR     │  cheap gates first:
 ───────────────▶│  BANK      │  text-like? b64/hex-shaped?
                 │  (RB)      │  XOR keys worth carrying?
                 └─────┬──────┘
                       │ surviving states + key shortlists
                 ┌─────▼──────┐
                 │ TRANSFORM  │  xor-k / rot-n / atbash /
                 │  LANES     │  bitrot / reverse / transpose
                 │  (TU)      │  one cycle per byte-lane
                 └─────┬──────┘
                       │ candidate states
          ┌────────────▼────────────┐
          │  SCORE UNIT (SU)        │
          │  hist ┐                 │
          │  letter┼─▶ blend ─▶ s    │  fixed-point,
          │  quad ┘    (weights      │  table lookups
          │  words      programmable) │  in SRAM
          │  cjk  ┘                 │
          └────────────┬────────────┘
                       │ (score, state) pairs
                 ┌─────▼──────┐
                 │  BEAM      │  top-28 tournament,
                 │  ARBITER   │  dedup via DU
                 │  (BA+DU)   │
                 └─────┬──────┘
                       │ ranked beam → back to host
                 ┌─────▼──────┐
                 │    HOST    │  loop: solved? feed next
                 │    CPU     │  layer back in. Judgment
                 └────────────┘  lives here, not in gates.
```

The host runs the beam loop; the accelerator is a fast inner
loop. One job = one state through RB→TU→SU→BA. The host feeds
states, collects the ranked beam, checks `GOOD_ENOUGH`, and either
stops or feeds the next layer. No control flow on the chip beyond
the pipeline itself.

---

## 5. Memory model

- **Quadgram table: the big rock.** 49,794 entries. Stored as
  (32-bit key, 16-bit fixed-point log-prob) = 6 bytes/entry ≈
  **300 KB**. That fits in on-chip SRAM (block RAM) on a
  mid-range FPGA — tight but real. The obvious diet: keep the top
  8–16k quadgrams, which carry nearly all the signal; the floor
  value covers the rest. This is a software decision first
  (measure the accuracy delta in Python), a hardware win second.
- **Small tables: free.** `LETTER_FREQ` (27 entries), the sorted
  expected histogram (27), `COMMON_WORDS` (26 patterns),
  `_COMMON_ZH` (543 codepoints), signspell tokens (26) — all fit
  in registers, LUTs, or a tiny ROM. Rounding error.
- **Beam state:** width 28 × states up to 8 KB ≈ 224 KB worst
  case, typically far less (bench payloads are hundreds of
  bytes). Double-buffered SRAM FIFO; spill to external DRAM only
  if someone feeds it megabyte payloads, which the engine's own
  gates (4096-byte caps on Vigenere/transposition) already
  discourage.
- **Bandwidth:** states are small. Even at thousands of
  states/second, host↔accelerator traffic is megabytes/second —
  MMIO or a single PCIe lane is idle most of the time. This
  design is compute-and-table bound, never I/O bound.

---

## 6. Host interface (sketch level)

- A command queue the host writes and the accelerator drains:
  each **job descriptor** = {opcode, input address/length,
  parameters (beam width, score weights version, razor
  thresholds)}.
- A completion queue returns {(score, state handle)} per job.
  The host owns all path bookkeeping and the solved/unsolved
  decision — the chip never sees a filename, a payload's meaning,
  or anything but bytes and numbers.
- Transport: MMIO register file for the prototype (simplest on
  FPGA dev boards); PCIe-style DMA queues for anything serious.
  Either way the interface is a dozen registers, not a driver
  stack. Stdlib-only philosophy carries over: no firmware blobs,
  no binary-only glue.

---

## 7. The road, honestly staged

**Stage 0 — Python. Done.** The algorithm exists, all 11 bench
cases solve, v1.4 runs on a phone. This is the seed.

**Stage 1 — C core. Done.** `fastcore.c` proves the key point:
the hot paths are pure functions over byte buffers. The Python
side keeps all the judgment; the C side only counts. That
separation is *why* a hardware stage is even thinkable — you
can't put judgment in gates, but you can put counting there.

**Stage 2 — FPGA prototype.** Prototype **one unit first**: the
XCU (XOR count array) plus `HIST_FIT`. It's the highest value
per LUT in the whole engine — every XOR decision flows through
it — and it's the easiest to verify (feed it the bench's XOR
states, compare against the C core bit-for-bit). Then add the
score unit, then the transform lanes. Boards within a hobbyist
budget (hundreds, not thousands): ULX3S (ECP5, fully open
toolchain — yosys/nextpnr, no vendor license) or Arty A7 / Nexys
A7 (Artix-7, vendor toolchain, more block RAM for the quadgram
table). Either is real; neither is exotic.

**Stage 3 — ASIC. Honest numbers.** A full production tapeout at
a modern node costs millions — mask sets alone. Nobody tapes out
on a first sketch, and nobody should. The reachable path is an
MPW (multi-project wafer) shuttle — TinyTapeout, Efabless, the
open SkyWater 130nm PDK — where a tiny test chip costs hundreds
to low thousands of dollars. That gets you a real die with your
XCU on it, not a product. A product is a company, not a sketch.

No timelines are given because timelines would be invented. The
stages are ordered by cost and by what each one proves: the
algorithm (done), the separability (done), one unit in gates,
the pipeline, then — maybe, years out — a die.

---

## 8. Open questions for Curtis

Real decisions, his to make — none of these have a right answer
in this document:

1. **Fixed vs programmable peelers.** Hardwire the 14 peelers as
   fixed units (smaller, faster, frozen) or build a tiny
   "peeler ISA" so new transforms load without new silicon?
   Fixed is the honest v1; programmable is the honest v2.
2. **Beam width in hardware.** Software uses 28. Wider finds more
   but costs area linearly. 28? 64? Measured on the bench, not
   guessed.
3. **Power envelope.** Wall-powered FPGA on a bench vs the
   Termux-phone world this whole project lives in. A phone can't
   feed a hungry FPGA; the envelope decides the board before the
   design does.
4. **What "solved" means in gates.** `GOOD_ENOUGH = 0.80` is a
   software constant. In hardware it's a threshold register —
   but who sets it, and does the chip ever declare victory
   itself, or does the host always make the call?
5. **Decompression's permanent home.** gzip/zlib/bz2/lzma stay
   on the host in this sketch. Is that forever, or does inflate
   earn a unit in v2? (It's the largest single block you'd add.)
6. **The quadgram diet.** Full 49,794-entry table in SRAM vs top
   8–16k quantized. Measure the accuracy cost in Python first —
   hardware shouldn't decide what software hasn't measured.

---

*The algorithm is the seed; the processor gets built around it,
not from it. This document is the seed's shadow — drawn to scale,
but still a shadow.*
