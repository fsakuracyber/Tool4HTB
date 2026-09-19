#!/usr/bin/env python3
"""Probe an IPv4 address with RFC 5227-style ARP probes before assigning it."""
import argparse
import fcntl
import select
import socket
import struct
import time

p = argparse.ArgumentParser()
p.add_argument("iface")
p.add_argument("address")
p.add_argument("--timeout", type=float, default=3.0)
a = p.parse_args()

target_ip = socket.inet_aton(a.address)
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((a.iface, 0))
mac = fcntl.ioctl(s.fileno(), 0x8927,
                  struct.pack("256s", a.iface.encode()))[18:24]
frame = (b"\xff" * 6 + mac + struct.pack("!H", 0x0806) +
         struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) +
         mac + b"\0" * 4 + b"\0" * 6 + target_ip)

deadline = time.monotonic() + a.timeout
for _ in range(2):
    s.send(frame)
    time.sleep(0.2)
while time.monotonic() < deadline:
    ready, _, _ = select.select([s], [], [], max(0, deadline - time.monotonic()))
    if not ready:
        break
    packet = s.recv(2048)
    claimed = (len(packet) >= 42 and packet[28:32] == target_ip)
    competing_probe = (len(packet) >= 42 and packet[28:32] == b"\0" * 4 and
                       packet[38:42] == target_ip and packet[22:28] != mac)
    if (len(packet) >= 42 and packet[12:14] == b"\x08\x06" and
            (claimed or competing_probe)):
        print(f"duplicate={a.address} responder_mac={packet[22:28].hex(':')}")
        raise SystemExit(1)
print(f"available={a.address} iface={a.iface} probes=2")
