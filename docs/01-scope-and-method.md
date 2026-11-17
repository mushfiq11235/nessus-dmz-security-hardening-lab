# 1. Scope and method

## Objective

Find, rank and fix real vulnerabilities in the lab network from Project 1, then prove the fixes with a rescan. The output is a report a junior security or IT role would produce: scope, method, findings ranked by CVSS, the top five fixed, a rescan, and a before and after comparison.

## Scope

| Host | Role | Zone | Address | Scanned how |
|---|---|---|---|---|
| OPNsense | Firewall (LAN interface) | LAN | `10.10.10.1` | Network scan, no credentials |
| Lubuntu | LAN client and Nessus scanner | LAN | `10.10.10.170` | Scanner's own host, local checks run automatically |
| Ubuntu Server + nginx | Hardened web server (Project 1) | DMZ | `10.10.20.10` | Network scan, no credentials |
| Metasploitable 2 | Intentionally vulnerable machine | DMZ | `10.10.20.20` | Network scan, no credentials |

**Out of scope:** Kali Linux (GUEST), the WAN side, and the Windows host.

## Tool and policy

All three formal runs used the same scan, named `NEW SCAN`, so their settings are identical.

| Setting | Value |
|---|---|
| Tool | Tenable Nessus Essentials, version 10.12.6 (build R20073) |
| Plugin feed | 202611161028 (same for all three runs) |
| Scanner | Local scanner on Lubuntu, `10.10.10.170` |
| Policy | Basic Network Scan, default settings |
| Port scanner and range | `nessus_syn_scanner`, default port range |
| Safe checks | Yes |
| Credentialed checks | No (the scanner's own host is the only exception) |
| Web application tests | Disabled |
| Severity base | CVSS v3.0 |

The scanner clock is on US Eastern time (UTC-5).

## Scan runs

| Run | Start | Duration | Purpose |
|---|---|---|---|
| Pilot (`My Basic Network Scan`) | 15 Nov 2026 | about 18 hours | First trial on a different scan object. Not used for the comparison. |
| **Baseline** | 17 Nov 2026, 11:49 EST | 1075 s | Before any fix |
| Rescan 1 | 17 Nov 2026, 15:04 EST | 1061 s | After the fixes. Did not detect Tomcat on port 8180 (see [troubleshooting](06-troubleshooting.md)). |
| **Rescan 2** | 17 Nov 2026, 15:36 EST | 1062 s | After the fixes. Used for the comparison. Also did not detect Tomcat on 8180. |

The pilot ran on a separate scan object, and it classified some findings differently (for example, Ghostcat was High there and Critical in the later scans). That is one reason the comparison uses only the two runs of `NEW SCAN`. Nessus Essentials cannot export PDF or CSV, so each run was exported as an HTML "Detailed Vulnerabilities By Host" report and parsed with [`tools/parse_nessus_html.py`](../tools/parse_nessus_html.py).

## Method

1. **Baseline scan** of all four hosts before any change.
2. **Rank** every Critical to Low finding by CVSS v3 base score (v2 where v3 is absent).
3. **Choose five fixes.** The rule: the highest-CVSS findings that can realistically be fixed on that host. Findings whose only fix is an operating system replacement, a software upgrade that no longer exists, or a paid repository are recorded as accepted risk or left open, with the reason.
4. **Fix one finding at a time.** For each: look first (read-only commands), back up the file, make the smallest change, restart the service, and verify from outside the host.
5. **Rescan** with identical settings and compare findings by (host, plugin ID).

## Selection of the top five

By CVSS the top items on Metasploitable are Tomcat end-of-life (10.0), Ubuntu 8.04 end-of-life (10.0), the weak OpenSSH/OpenSSL keys (10.0) and the VNC password (10.0). The first three cannot be fixed without replacing the software or the OS, so they are accepted risks. The fixable high-CVSS findings, in order, became the five:

1. VNC "password" (10.0)
2. Bind shell backdoor (9.8)
3. Tomcat Ghostcat AJP (9.8)
4. NFS exported to everyone (7.5)
5. SSL v2/v3 on SMTP and PostgreSQL (9.8)

A sixth candidate, the FFmpeg and SRT updates on the LAN client (CVSS up to 9.8), was dropped. `apt` reports the fixes are only in Ubuntu Pro's `esm-apps` repository, and I chose not to sign up. NFS took its place in the five. The fix order above is the order they were applied.

## Containment

Metasploitable sits on the DMZ LAN Segment only. The imported VM came with a second, host-only network adapter, which was removed so the only network path goes through OPNsense (the VM settings screenshot shows a single adapter on the DMZ segment). The Project 1 rules then apply: the DMZ cannot reach the LAN or GUEST, and can reach the internet only on ports 80 and 443. The isolation was tested for this project: a ping from Metasploitable to the LAN client gets 100% packet loss (`27-isolation-metasploitable-to-lan-blocked.png`), while the LAN client can reach Metasploitable (`26-ping-lan-to-metasploitable-ok.png`). Only the ICMP path to the LAN was tested here; the full rule set and its tests are in Project 1.
