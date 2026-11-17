# 6. Troubleshooting

Problems met during the project, in the order they happened.

## The port was owned by xinetd, but the config line was in inetd.conf

**Symptom:** `netstat` showed `4956/xinetd` listening on port 1524, but the backdoor line (`ingreslock ... /bin/bash bash -i`) was in `/etc/inetd.conf`, and `/etc/xinetd.d/` had no matching file.

**Cause:** xinetd was started with `-inetd_compat`, which makes it read `/etc/inetd.conf` in addition to its own configuration. `openbsd-inetd` was installed but not running.

**Fix:** edit `/etc/inetd.conf`, then restart **xinetd**, not `openbsd-inetd`. Verified from outside: the port refuses connections.

**Lesson:** find out which program owns the port before editing a config file. The obvious file can belong to a service that is not running.

## The NFS finding was much worse than its name

**Symptom:** Nessus called it "NFS Shares World Readable" (CVSS 7.5).

**Cause:** `/etc/exports` held `/ *(rw,sync,no_root_squash,no_subtree_check)`: the whole filesystem, writable, to every host, with remote root preserved.

**Fix:** comment out the line and run `exportfs -ra`. Verified with an empty `showmount -e` list.

**Lesson:** read the configuration, not only the scanner's label.

## An early test printed nothing

**Symptom:** the one-line SMTP check, `printf 'EHLO test\r\nQUIT\r\n' | nc -w 3 10.10.20.20 25`, printed nothing, although the port was open.

**Cause:** the command sent `EHLO` before the server finished its greeting, and `nc` exited early.

**Fix:** wait for the greeting: `(sleep 1; printf 'EHLO test\r\n'; sleep 1; printf 'QUIT\r\n') | nc 10.10.20.20 25`. The reply then showed the feature list with no `250-STARTTLS`.

## Package updates did not fix the FFmpeg findings

**Symptom:** `apt upgrade` installed updates (74 upgradable lines became 13), but the FFmpeg, libass and SRT package versions did not change, and the Nessus findings stayed.

**Cause:** the fixes for those packages are in Ubuntu Pro's `esm-apps` repository. `apt update` said so: "Get more security updates through Ubuntu Pro with 'esm-apps' enabled". The 12 remaining upgradable packages were held back by phased updates and were unrelated.

**Decision:** left open and documented. I did not enable Ubuntu Pro. NFS replaced this item in the top five.

## The first rescan reported two Tomcat findings as fixed

**Symptom:** in rescan 1, Tomcat end-of-life (Critical) and Tomcat default files (Medium) were missing, and the host showed far fewer informational findings. Port 8180 appeared only as "open".

**Investigation:** the only change on Tomcat was the AJP connector edit and a restart, which does not touch the HTTP connector on 8180. `curl -I http://10.10.20.20:8180/` from the LAN client returned `HTTP/1.1 200 OK` from Apache-Coyote, so Tomcat was running.

**Attempt:** rescan 2, run after Tomcat had been up and healthy for a while, showed the same gap, so it was not a startup timing problem.

**Resolution:** the two findings are counted as still open, and the report says why. The cause is unknown. I did not roll back the AJP fix to test it, because that would have undone a fix.

**Lesson:** a scanner can fail quietly. Checking the result directly, with `curl`, is what stopped me from reporting a better outcome than I could prove.

## The first scan ran for about 18 hours

**Symptom:** the pilot scan on `My Basic Network Scan` reported a duration of about 18 hours. Later runs of a new scan with the same policy took about 18 minutes.

**Cause:** not established. The VMs or the host may have paused during the pilot.

## Nessus Essentials cannot export PDF or CSV

**Symptom:** clicking Export showed "Exports are not available in Essentials".

**Fix:** use Report, "Detailed Vulnerabilities By Host", HTML, and parse it. [`tools/parse_nessus_html.py`](../tools/parse_nessus_html.py) turns the HTML into the CSV used for the comparison.

## Old SSH needs legacy algorithms

**Symptom:** a modern OpenSSH client refuses Metasploitable's host key and key exchange.

**Fix:** `ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa msfadmin@10.10.20.20`. This is for a lab machine only. The weak algorithms are themselves findings in the report.
