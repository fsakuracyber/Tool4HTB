#!/usr/bin/env python3
"""Poll /proc for newly-created processes without requiring root."""

import argparse
import os
from pathlib import Path
import sys
import time


def read_bytes(path):
    try:
        return path.read_bytes()
    except (FileNotFoundError, PermissionError, ProcessLookupError):
        return b""


def process_identity(entry):
    """Return (pid, starttime, ppid), parsing comm with embedded spaces safely."""
    try:
        raw_stat = (entry / "stat").read_text()
        suffix = raw_stat[raw_stat.rfind(")") + 2:].split()
        # suffix[0] is field 3 (state); starttime is field 22.
        return int(entry.name), suffix[19], suffix[1]
    except (FileNotFoundError, PermissionError, ProcessLookupError, IndexError):
        return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seconds", type=float, default=120.0)
    parser.add_argument("--interval", type=float, default=0.02)
    args = parser.parse_args()

    seen = set()
    for entry in Path("/proc").iterdir():
        if entry.name.isdigit():
            identity = process_identity(entry)
            raw = read_bytes(entry / "cmdline")
            if identity and raw:
                seen.add(identity[:2] + (raw,))
    deadline = time.monotonic() + args.seconds
    while time.monotonic() < deadline:
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit():
                continue
            identity = process_identity(entry)
            if not identity:
                continue
            pid, starttime, ppid = identity
            raw = read_bytes(entry / "cmdline")
            if not raw:
                # A fork may be observed before exec populates cmdline. Retry it.
                continue
            signature = (pid, starttime, raw)
            if signature in seen:
                continue
            # Include cmdline so a forked child seen before exec is logged again
            # when exec replaces the inherited parent argv with the target argv.
            seen.add(signature)
            command = raw.replace(b"\0", b" ").decode(errors="replace").strip()
            command = command.encode("unicode_escape").decode("ascii")
            try:
                uid = os.stat(str(entry)).st_uid
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                uid = "?"
            stamp = time.strftime("%Y-%m-%dT%H:%M:%S")
            print("{} pid={} ppid={} uid={} cmd={}".format(
                stamp, pid, ppid, uid, command
            ))
            sys.stdout.flush()
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
