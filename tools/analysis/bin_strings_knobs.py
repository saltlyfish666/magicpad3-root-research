# -*- coding: utf-8 -*-
"""Analyze the GhostLock exploit binary (READ-ONLY) for environment-variable knobs
and their semantics (usage strings, defaults)."""
import re
import sys

BIN = r"D:\file\文档\workbuddy\2026-10-13-23-07-58\.workbuddy\ghostlock\cve-bin-dc14-sig.extracted"

data = open(BIN, "rb").read()
# extract printable ASCII runs >= 4 chars
strings = re.findall(rb"[\x20-\x7e]{4,}", data)
strs = [s.decode("ascii", "ignore") for s in strings]

KEY = re.compile(
    r"(getenv|USEC|ATTEMPTS|EXPLOIT|KSNITCH|SLIDE|PSELECT|STACK_WRITER|GW_|ROUTE|"
    r"CFI_|FMPS|CHEAP|RETRY|LOOP|WAIT|DELAY|REPEAT|SHOT|TARGET|FORCE|BREAK|KEEPPAGE|cpu|affinity)",
    re.I,
)

print("=== total strings:", len(strs))
print("\n=== strings mentioning knobs / env vars ===")
seen = set()
for s in strs:
    if KEY.search(s) and s not in seen:
        seen.add(s)
        print(repr(s))
