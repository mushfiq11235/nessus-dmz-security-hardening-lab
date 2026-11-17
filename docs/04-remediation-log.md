# 4. Remediation log

Five fixes, all on Metasploitable 2 (`10.10.20.20`). The method was the same each time: **look first** with read-only commands, **back up** the file, make the **smallest change**, restart only the affected service, and **verify from the LAN client**, outside the host. Commands are shown as run, over SSH as `msfadmin` with `sudo`.

## Fix 1: VNC with the password "password"

**Finding:** Nessus 61708, CVSS 10.0. Nessus logged in over VNC with the password `password`.

**Investigation:**
```
sudo netstat -tlnp | grep 5900
ps aux | grep -i vnc | grep -v grep
sudo ls -la /root/.vnc
grep -rIl -i vnc /etc/init.d /etc/rc.local /etc/rc2.d 2>/dev/null
```
VNC (`Xtightvnc :0`) runs **as root** on port 5900, with its password in `/root/.vnc/passwd`, and `/etc/rc.local` line 18 starts it at boot.

**Decision:** disable VNC rather than set a new password. Nothing in the lab needs it, and removing an unused root service is a better fix than a stronger password on it.

**Change:**
```
sudo cp /etc/rc.local /etc/rc.local.bak
sudo sed -i '18s/^/#/' /etc/rc.local
sudo cat -n /etc/rc.local | sed -n '17,19p'
sudo pkill Xtightvnc
sudo netstat -tlnp | grep 5900
```

**Verification (from the LAN client):** `nc -zv -w 3 10.10.20.20 5900` returns `Connection refused`.

**Rollback:** `sudo cp /etc/rc.local.bak /etc/rc.local`, then reboot or run `vncserver :0` as root.

**Evidence:** `04-fix1-rc-local-vnc-line.png`, `05-fix1-vnc-disabled-port-5900-refused.png`.

## Fix 2: Bind shell backdoor on port 1524

**Finding:** Nessus 51988, CVSS 9.8. A service on port 1524 gives a command prompt to anyone who connects.

**Proof of the problem (from the LAN client):**
```
nc -w 3 10.10.20.20 1524
id
```
The reply is `uid=0(root) gid=0(root)`: a root shell, no password.

**Investigation:**
```
sudo netstat -tlnp | grep 1524
sudo grep -n ingreslock /etc/inetd.conf
ls /etc/init.d | grep -i inet
sudo grep -rn -i ingreslock /etc/xinetd.conf /etc/xinetd.d/
ps aux | grep -i inetd | grep -v grep
```
The port is owned by **xinetd**, but the line is in `/etc/inetd.conf` (line 8: `ingreslock stream tcp nowait root /bin/bash bash -i`), and `xinetd.d` has no matching file. `ps` shows xinetd runs with `-inetd_compat`, which makes it read `/etc/inetd.conf`. So that file is the right one to edit, and `openbsd-inetd` is not running at all.

**Change:**
```
sudo cp /etc/inetd.conf /etc/inetd.conf.bak
sudo sed -i '8s/^/#/' /etc/inetd.conf
sudo sed -n '6,10p' /etc/inetd.conf
sudo /etc/init.d/xinetd restart
sudo netstat -tlnp | grep 1524
```

**Verification:** `nc -zv -w 3 10.10.20.20 1524` returns `Connection refused`.

**Rollback:** `sudo cp /etc/inetd.conf.bak /etc/inetd.conf` and restart xinetd.

**Evidence:** `06` (root shell before), `07`, `08` (xinetd and `-inetd_compat`), `09` (after).

## Fix 3: Tomcat "Ghostcat" AJP connector

**Finding:** Nessus 134862, CVSS 9.8. The AJP connector on port 8009 lets an attacker read files from the web application (Ghostcat).

**Investigation:**
```
sudo netstat -tlnp | grep -E '8009|8180'
sudo find / -name server.xml 2>/dev/null
sudo grep -n -i -B3 -A4 'ajp' /etc/tomcat5.5/server.xml
ls /etc/init.d | grep -i tomcat
```
Tomcat 5.5 runs under `jsvc`. The AJP connector is on lines 105 and 106 of `/etc/tomcat5.5/server.xml`. Ports 8009 (AJP) and 8180 (HTTP) are separate connectors.

**Change:** wrap exactly those two lines in an XML comment.
```
sudo cp /etc/tomcat5.5/server.xml /etc/tomcat5.5/server.xml.bak
sudo sed -i -e '105s/^/<!-- /' -e '106s/$/ -->/' /etc/tomcat5.5/server.xml
sudo sed -n '104,107p' /etc/tomcat5.5/server.xml
sudo /etc/init.d/tomcat5.5 restart
```

**Verification (from the LAN client):** `nc -zv -w 3 10.10.20.20 8009` returns `Connection refused`, and `nc -zv -w 3 10.10.20.20 8180` still reports `succeeded`, so Tomcat itself came back up.

**Rollback:** `sudo cp /etc/tomcat5.5/server.xml.bak /etc/tomcat5.5/server.xml`, then restart Tomcat.

**Evidence:** `10` (8009 open before), `11`, `12`, `13`.

## Fix 4: NFS exports to everyone

**Finding:** Nessus 42256, CVSS 7.5, "NFS Shares World Readable".

**Investigation:**
```
sudo cat -n /etc/exports
sudo exportfs -v
```
Line 12 reads `/ *(rw,sync,no_root_squash,no_subtree_check)`. That is the **entire filesystem**, **read-write**, to **every host**, with **`no_root_squash`** so a remote root user keeps root powers. The finding's name understates it.

**Change:**
```
sudo cp /etc/exports /etc/exports.bak
sudo sed -i '12s/^/#/' /etc/exports
sudo sed -n '11,12p' /etc/exports
sudo exportfs -ra
sudo exportfs -v
```

**Verification (from the LAN client):** `showmount -e 10.10.20.20` returns an empty export list. `exportfs -v` on the host prints nothing.

**Rollback:** `sudo cp /etc/exports.bak /etc/exports && sudo exportfs -ra`.

**Evidence:** `17-fix4-nfs-exports-before.png`, `18-fix4-nfs-export-removed.png`, `28-fix4-showmount-empty.png`.

## Fix 5: SSL v2/v3 on SMTP and PostgreSQL

**Finding:** Nessus 20007, CVSS 9.8. Port 25 (Postfix) and port 5432 (PostgreSQL 8.3) accept the broken SSL 2.0 and 3.0 protocols.

**Investigation:**
```
sudo netstat -tlnp | grep -E ':25 |:5432 '
sudo grep -rn -i '^ *ssl' /etc/postgresql/
sudo postconf -n | grep -i tls
ls /etc/init.d | grep -i -E 'postfix|postgres'
```
PostgreSQL has `ssl = true` on line 76 of `/etc/postgresql/8.3/main/postgresql.conf`. Postfix has `smtpd_use_tls = yes`.

**Decision:** the machine's OpenSSL dates from 2008 and cannot be upgraded, so the weak protocols can only be removed by turning TLS off on both services. That is acceptable here, on an isolated lab machine. In production the correct fix is to upgrade the software and keep TLS on.

**Change:**
```
sudo cp /etc/postgresql/8.3/main/postgresql.conf /etc/postgresql/8.3/main/postgresql.conf.bak
sudo cp /etc/postfix/main.cf /etc/postfix/main.cf.bak
sudo sed -i '76s/ssl = true/ssl = false/' /etc/postgresql/8.3/main/postgresql.conf
sudo /etc/init.d/postgresql-8.3 restart
sudo postconf -e 'smtpd_use_tls = no'
sudo /etc/init.d/postfix restart
sudo netstat -tlnp | grep -E ':25 |:5432 '
```
Both services are still listening afterwards: encryption was removed, not the services.

**Verification (from the LAN client):**
```
(sleep 1; printf 'EHLO test\r\n'; sleep 1; printf 'QUIT\r\n') | nc 10.10.20.20 25
```
The reply lists the server's features and has **no `250-STARTTLS` line**.

**Rollback:** restore the two `.bak` files and restart both services.

**Side effect:** with TLS off, 15 related findings disappeared as well (SWEET32, DROWN, FREAK, RC4, TLS 1.0, certificate trust, expiry, hostname and self-signed findings on port 25).

**Evidence:** `19`, `20`, `21`.

## Not fixed, on purpose

| Finding | Why |
|---|---|
| Ubuntu 8.04 end-of-life (CVSS 10.0) | The only fix is replacing the operating system |
| Tomcat 5.5 end-of-life (CVSS 10.0) | The only fix is upgrading Tomcat, which needs a newer OS |
| Weak OpenSSH/OpenSSL keys (CVSS 10.0) | Needs a patched OpenSSL, then new keys, on a release with no updates |
| FFmpeg, libass and SRT on the LAN client | Fix is only in Ubuntu Pro (`esm-apps`), which I did not enable |
| Everything rated Medium or lower that was not in the top five | Outside the scope of the top-five rule |
