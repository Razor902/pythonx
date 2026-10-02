#!/bin/sh
# ─────────────────────────────────────────────────────────────
# © 2026 Curtis Ray Dyess — PhantomX / Crimson Root. All rights reserved.
# Unauthorized copying, redistribution, automated collection, or
# model-training ingestion prohibited without prior written authorization.
# ─────────────────────────────────────────────────────────────
# run.sh -- XCU bit-for-bit verification flow.
# 1. Build the vector generator against the REAL fastcore.c
# 2. Generate vectors (fixed set + real bench payload bytes)
# 3. Simulate xcu.v + xcu_tb.v with Icarus Verilog, compare vs C core
set -e
cd "$(dirname "$0")"

PX=/home/hatch/workspace/pythonx
FASTCORE=$PX/fastcore.c

echo "== build vector generator =="
gcc -O2 -Wall -o genvec genvec.c "$FASTCORE"

echo "== generate vectors from the real C core =="
rm -rf vec && mkdir vec
# real bench payloads: base64 one-layer, rot/xor/hex three-layer,
# and the chinese-xor bench13 payload (base64 bytes)
P1=$(python3 -c "import sys;sys.path.insert(0,'$PX');import pythonx as p;print(p.bench_payloads()[0][1].hex())")
P3=$(python3 -c "import sys;sys.path.insert(0,'$PX');import pythonx as p;print(p.bench_payloads()[2][1].hex())")
PZ=$(python3 -c "import sys;sys.path.insert(0,'$PX');import pythonx as p;print(p.bench13_payloads()[4][1].hex())")
./genvec "$P1" "$P3" "$PZ"

echo "== simulate =="
iverilog -o xcu_sim xcu.v xcu_tb.v
vvp xcu_sim
