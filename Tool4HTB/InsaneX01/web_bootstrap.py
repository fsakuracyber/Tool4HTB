#!/usr/bin/env python3
"""Register and activate an osTicket account through a Roundcube inbox."""
import argparse
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

p = argparse.ArgumentParser()
p.add_argument("--mail", required=True, help="Roundcube base URL")
p.add_argument("--ticket", required=True, help="osTicket base URL")
p.add_argument("--email", required=True)
p.add_argument("--display-name", default="Example User")
p.add_argument("--phone", default="5550100")
p.add_argument("--mail-password", required=True)
p.add_argument("--ost-password", required=True)
p.add_argument("--cookie-out", type=Path, required=True)
p.add_argument("--evidence-dir", type=Path, required=True)
a = p.parse_args()
a.evidence_dir.mkdir(parents=True, exist_ok=True)
a.cookie_out.unlink(missing_ok=True)


def endpoint_host(url, option):
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit(f"{option} must be an absolute HTTP(S) URL")
    return parsed.hostname.lower()


mail_host = endpoint_host(a.mail, "--mail")
ticket_host = endpoint_host(a.ticket, "--ticket")


def csrf(html):
    tag = BeautifulSoup(html, "html.parser").select_one(
        'input[name="__CSRFToken__"],input[name="_token"]')
    if not tag or not tag.get("value"):
        raise RuntimeError("CSRF token not found")
    return tag["value"]


# Register using the live randomized osTicket field names.
ost = requests.Session()
r = ost.get(urljoin(a.ticket, "/account.php?do=create"), timeout=30)
r.raise_for_status()
(a.evidence_dir / "account-form.html").write_text(r.text, encoding="utf-8")
soup = BeautifulSoup(r.text, "html.parser")
form = soup.select_one("form")
if not form:
    raise RuntimeError("registration form not found")
data = {"__CSRFToken__": csrf(r.text), "do": "create",
        "passwd1": a.ost_password, "passwd2": a.ost_password}
email_field = form.select_one('input[type="email"]')
name_field = form.select_one('input[type="text"]')
tel_field = form.select_one('input[type="tel"]')
if not email_field or not name_field:
    raise RuntimeError("randomized registration fields not found")
data[email_field["name"]] = a.email
data[name_field["name"]] = a.display_name
if tel_field:
    data[tel_field["name"]] = a.phone
r = ost.post(urljoin(a.ticket, form.get("action", "account.php")),
             data=data, timeout=30)
r.raise_for_status()
(a.evidence_dir / "registration-response.html").write_text(
    r.text, encoding="utf-8")
if "Thanks for registering for an account" not in r.text:
    raise RuntimeError("registration success marker absent")
print("registration=accepted")

# Authenticate to Roundcube and poll the newest messages for the confirmation URL.
mail = requests.Session()
r = mail.get(a.mail, timeout=30)
r.raise_for_status()
token = csrf(r.text)
r = mail.post(urljoin(a.mail, "/?_task=login"), data={
    "_token": token, "_task": "login", "_action": "login",
    "_timezone": "_default_", "_url": "", "_user": a.email,
    "_pass": a.mail_password,
}, allow_redirects=False, timeout=30)
if r.status_code != 302 or "roundcube_sessauth" not in mail.cookies:
    raise RuntimeError(f"Roundcube login failed: status={r.status_code}")
print(f"roundcube=authenticated host={mail_host}")

# Roundcube's remote list/show actions require the authenticated session token.
inbox = mail.get(urljoin(a.mail, r.headers["Location"]), timeout=30)
inbox.raise_for_status()
(a.evidence_dir / "roundcube-inbox.html").write_text(
    inbox.text, encoding="utf-8")
m = re.search(r'"request_token":"([^"\\]+)"', inbox.text)
if not m:
    raise RuntimeError("authenticated Roundcube request_token not found")
mail_token = m.group(1)

activation = None
for _ in range(12):
    listing = mail.get(urljoin(
        a.mail,
        f"/?_task=mail&_action=list&_refresh=1&_mbox=INBOX&_remote=1&_token={mail_token}"),
        timeout=30)
    listing.raise_for_status()
    (a.evidence_dir / "roundcube-list.json").write_text(
        listing.text, encoding="utf-8")
    uids = [int(x) for x in re.findall(
        r"add_message_row\((\d+),", listing.text)]
    for uid in sorted(uids, reverse=True):
        msg = mail.get(urljoin(
            a.mail,
            f"/?_task=mail&_action=show&_uid={uid}&_mbox=INBOX&_token={mail_token}"),
            timeout=30)
        msg.raise_for_status()
        (a.evidence_dir / f"mail-{uid}.html").write_text(
            msg.text, encoding="utf-8")
        soup = BeautifulSoup(msg.text, "html.parser")
        link = next((x.get("href") for x in soup.select("a[href]")
                     if "pwreset.php?token=" in x.get("href", "")), None)
        if link:
            activation = urljoin(a.ticket, link)
            break
    if activation:
        break
    time.sleep(5)
if not activation:
    raise RuntimeError("activation link not found in Roundcube")
print(f"activation_url={activation}")

r = ost.get(activation, allow_redirects=True, timeout=30)
r.raise_for_status()
(a.evidence_dir / "activation-response.html").write_text(
    r.text, encoding="utf-8")
if "Account Confirmed" not in r.text:
    raise RuntimeError("activation success marker absent")
print("activation=confirmed")

# Log in to osTicket and export the cookie in curl-compatible form.
r = ost.get(urljoin(a.ticket, "/login.php"), timeout=30)
r.raise_for_status()
r = ost.post(urljoin(a.ticket, "/login.php"), data={
    "__CSRFToken__": csrf(r.text), "luser": a.email,
    "lpasswd": a.ost_password,
}, allow_redirects=False, timeout=30)
if (r.status_code != 302 or
        not r.headers.get("Location", "").startswith("tickets.php")):
    raise RuntimeError(
        f"osTicket login failed: status={r.status_code} "
        f"location={r.headers.get('Location')}")
matching = [
    cookie for cookie in ost.cookies
    if cookie.name == "OSTSESSID"
    and (cookie.domain.lstrip(".").lower() == ticket_host
         or ticket_host.endswith("." + cookie.domain.lstrip(".").lower()))
]
if not matching:
    matching = [cookie for cookie in ost.cookies if cookie.name == "OSTSESSID"]
if not matching:
    raise RuntimeError("OSTSESSID not issued")
a.cookie_out.write_text(
    f"OSTSESSID={matching[-1].value}\n", encoding="utf-8")
print(f"osticket=authenticated cookie_file={a.cookie_out}")
