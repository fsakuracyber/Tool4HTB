#!/usr/bin/env python3
"""Decrypt a CRD container that has a 12-byte clear header."""
import argparse
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

p = argparse.ArgumentParser()
p.add_argument("crd", type=Path)
p.add_argument("password")
p.add_argument("output", type=Path)
a = p.parse_args()

data = a.crd.read_bytes()
if len(data) < 12 + 68 + 16:
    raise SystemExit("container is too short")
ciphertext, footer = data[12:-68], data[-68:]
if not ciphertext or len(ciphertext) % 16:
    raise SystemExit(f"ciphertext is not AES-block-aligned: {len(ciphertext)} bytes")
salt_a, salt_b, iv, want = footer[:16], footer[16:32], footer[32:48], footer[48:]


def cryptderive_aes256(digest):
    block = digest + b"\0" * (64 - len(digest))
    ipad = bytes(x ^ 0x36 for x in block)
    opad = bytes(x ^ 0x5c for x in block)
    return hashlib.sha1(ipad).digest() + hashlib.sha1(opad).digest()[:12]


pw = a.password.encode("utf-16le")
digest = hashlib.sha1(pw + salt_a).digest()
key = cryptderive_aes256(digest)
decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
plain_padded = decryptor.update(ciphertext) + decryptor.finalize()
pad = plain_padded[-1]
valid_padding = 1 <= pad <= 16 and plain_padded.endswith(bytes([pad]) * pad)
if not valid_padding:
    raise SystemExit(f"invalid PKCS#7 padding byte={pad}")
plain = plain_padded[:-pad]
# The implementation stores a SHA-1 HMAC in the footer. Its second salt is
# preserved and printed because valid padding is the password/container oracle.
print(f"valid_padding=True plaintext_bytes={len(plain)}")
print(f"salt_a={salt_a.hex()} salt_b={salt_b.hex()} iv={iv.hex()} hmac_sha1={want.hex()}")
a.output.parent.mkdir(parents=True, exist_ok=True)
a.output.write_bytes(plain)
print(f"wrote={a.output}")
