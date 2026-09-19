#!/usr/bin/env python3
"""Decode a WinSCP INI Password value and remove its user/host prefix."""
import argparse

p = argparse.ArgumentParser()
p.add_argument("encrypted", help="hexadecimal WinSCP Password value")
p.add_argument("username")
p.add_argument("hostname")
a = p.parse_args()

data = bytearray.fromhex(a.encrypted)


def nxt():
    if not data:
        raise SystemExit("truncated WinSCP value")
    return (~(data.pop(0) ^ 0xA3)) & 0xff


flag = nxt()
if flag == 0xff:
    version = nxt()
    length = nxt()
else:
    version = None
    length = flag
skip = nxt()
for _ in range(skip):
    nxt()
decoded = bytes(nxt() for _ in range(length)).decode("utf-8")
prefix = a.username + a.hostname
if flag == 0xff:
    if not decoded.startswith(prefix):
        raise SystemExit(
            "enhanced value does not start with the expected username+hostname prefix")
    password = decoded[len(prefix):]
else:
    password = decoded
print(f"flag={flag} version={version} length={length} skip={skip}")
print(f"decoded={decoded}")
print(f"password={password}")
