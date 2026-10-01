#!/usr/bin/env python3
"""compare.py -- PythonX v1 vs v1.1, same payloads, same bench.

Runs both engines' beam decipher over the five known-answer cases and
prints states tried and wall time side by side. Honest numbers only:
whatever the runs actually do is what gets printed.
"""
import sys

import pythonx as v1
import pythonx11 as v11


def cases():
    out = list(v1.bench_payloads())
    out.append(("five layers: gzip, base64, xor, rot, hex",
                v11.bench_payloads()[4][1]))
    return out


def main():
    print(f"v1.1 fast core: {'ON' if v11.FAST is not None else 'OFF'}")
    print(f"{'case':44} {'v1 states':>10} {'v1 time':>8} "
          f"{'v1.1 states':>12} {'v1.1 time':>10}  verdict")
    print("-" * 104)
    for label, payload in cases():
        o1, _p1, t1, s1 = v1.decipher_beam(payload)
        o2, _p2, t2, s2 = v11.decipher_beam(payload)
        ok1 = "SOLVED" if o1 == v1.PLAIN else "best-effort"
        ok2 = "SOLVED" if o2 == v11.PLAIN else "best-effort"
        print(f"{label:44} {t1:>10} {s1:>7.2f}s {t2:>12} {s2:>9.2f}s  "
              f"v1 {ok1} | v1.1 {ok2} | states x{t1 / max(t2, 1):.1f} "
              f"time x{s1 / max(s2, 0.001):.1f}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
