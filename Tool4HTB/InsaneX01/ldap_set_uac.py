#!/usr/bin/env python3
"""Replace an LDAP userAccountControl value with pre- and post-state guards."""
import argparse

from ldap3 import ALL, MODIFY_REPLACE, NTLM, Connection, Server

p = argparse.ArgumentParser()
p.add_argument("--host", required=True)
p.add_argument("--port", type=int, default=389)
p.add_argument("--user", required=True)
p.add_argument("--hashes", required=True,
               help="LM:NT or :NT value accepted by ldap3 NTLM")
p.add_argument("--dn", required=True)
p.add_argument("--expect", required=True, type=int)
p.add_argument("--set", required=True, type=int)
a = p.parse_args()

c = Connection(Server(a.host, port=a.port, get_info=ALL), user=a.user,
               password=a.hashes, authentication=NTLM, auto_bind=True)
c.search(a.dn, "(objectClass=user)", attributes=["userAccountControl"])
if len(c.entries) != 1:
    raise SystemExit(f"expected one user, got {len(c.entries)}")
before = int(c.entries[0].userAccountControl.value)
print(f"before={before}")
if before != a.expect:
    raise SystemExit(f"guard failed: expected {a.expect}, observed {before}")
ok = c.modify(a.dn, {"userAccountControl": [(MODIFY_REPLACE, [a.set])]})
print(f"modify={ok} result={c.result}")
if not ok:
    raise SystemExit(1)
c.search(a.dn, "(objectClass=user)", attributes=["userAccountControl"])
after = int(c.entries[0].userAccountControl.value)
print(f"after={after}")
if after != a.set:
    raise SystemExit(f"post-state verification failed: expected {a.set}, observed {after}")
