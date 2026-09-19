#!/usr/bin/env python3
"""Pin one DNS A record, forward an internal zone, and reject other names."""
import argparse
import socket
import struct

p = argparse.ArgumentParser()
p.add_argument("--listen-ip", required=True)
p.add_argument("--listen-port", type=int, default=5353)
p.add_argument("--upstream", required=True)
p.add_argument("--upstream-port", type=int, default=53)
p.add_argument("--zone", required=True)
p.add_argument("--pin-name", required=True)
p.add_argument("--pin-ip", required=True)
p.add_argument("--ttl", type=int, default=60)
a = p.parse_args()

zone = a.zone.rstrip(".").lower()
pin_name = a.pin_name.rstrip(".").lower()
if not zone:
    raise SystemExit("--zone must not be empty")
if pin_name != zone and not pin_name.endswith("." + zone):
    raise SystemExit("--pin-name must belong to --zone")

listen = (a.listen_ip, a.listen_port)
upstream = (a.upstream, a.upstream_port)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(listen)
print("dns_pin_internal", listen, "upstream", upstream,
      "zone", zone, "pin", f"{pin_name}={a.pin_ip}", flush=True)
while True:
    data, peer = s.recvfrom(4096)
    pos, labels = 12, []
    while pos < len(data) and data[pos]:
        n = data[pos]
        pos += 1
        labels.append(data[pos:pos+n].decode(errors="ignore"))
        pos += n
    qend = pos + 5
    name = ".".join(labels).lower()
    qtype_class = data[pos+1:pos+5]
    if name == pin_name and qtype_class == b"\x00\x01\x00\x01":
        header = data[:2] + b"\x81\x80" + data[4:6] + b"\x00\x01\x00\x00\x00\x00"
        answer = (b"\xc0\x0c\x00\x01\x00\x01" +
                  struct.pack("!IH", a.ttl, 4) + socket.inet_aton(a.pin_ip))
        reply, result = header + data[12:qend] + answer, "pinned"
    elif name == zone or name.endswith("." + zone):
        u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        u.settimeout(2)
        try:
            u.sendto(data, upstream)
            reply, result = u.recvfrom(4096)[0], "forwarded"
        except Exception:
            reply = (data[:2] + b"\x81\x83" + data[4:6] +
                     b"\x00\x00\x00\x00\x00\x00" + data[12:qend])
            result = "internal_nxdomain"
        finally:
            u.close()
    else:
        reply = (data[:2] + b"\x81\x83" + data[4:6] +
                 b"\x00\x00\x00\x00\x00\x00" + data[12:qend])
        result = "public_nxdomain"
    s.sendto(reply, peer)
    print(result, peer, name, flush=True)
