#!/bin/sh
# Build the optional compiled C core for PythonX v1.1.
# v1.1 runs fine without it (pure-Python fallback); with it, faster.
cc -O2 -shared -fPIC fastcore.c -o libpxfast.so || clang -O2 -shared -fPIC fastcore.c -o libpxfast.so
