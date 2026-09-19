#!/usr/bin/env python3
"""Add a user DN to an LDAP group and verify the linked member value."""
import argparse

from ldap3 import Connection, MODIFY_ADD, NTLM, SUBTREE, Server
from ldap3.utils.conv import escape_filter_chars

p = argparse.ArgumentParser()
p.add_argument("--host", required=True)
p.add_argument("--port", type=int, default=389)
p.add_argument("--user", required=True)
p.add_argument("--password", required=True)
p.add_argument("--base", required=True)
p.add_argument("--group", required=True)
p.add_argument("--user-dn", required=True)
a = p.parse_args()

conn = Connection(Server(a.host, port=a.port), user=a.user,
                  password=a.password, authentication=NTLM, auto_bind=True)
group_name = escape_filter_chars(a.group)
conn.search(a.base, f"(&(objectClass=group)(cn={group_name}))", SUBTREE,
            attributes=["distinguishedName", "member"])
if len(conn.entries) != 1:
    raise SystemExit(f"expected one group, got {len(conn.entries)}")
entry = conn.entries[0]
group_dn = entry.entry_dn
before = list(entry.member.values)
print("group_dn=", group_dn)
print("before_member=", before)
if a.user_dn not in before:
    ok = conn.modify(group_dn, {"member": [(MODIFY_ADD, [a.user_dn])]})
    print("modify=", ok, conn.result)
    if not ok:
        raise SystemExit(1)
else:
    print("modify=already_present")
conn.search(group_dn, "(objectClass=group)", attributes=["member"])
after = list(conn.entries[0].member.values)
print("after_member=", after)
if a.user_dn not in after:
    raise SystemExit("membership verification failed")
