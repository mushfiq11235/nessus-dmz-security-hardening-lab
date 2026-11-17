# 3. Findings report

## Summary for a non-technical reader

1. I built a small test network and added a computer that is deliberately full of security holes, so there was something real to find.
2. A scanning tool checked four machines and found 49 problems, 12 of them rated Critical.
3. I fixed the five most serious problems that could actually be fixed, including a hidden door that gave anyone on the network full control with no password.
4. A second scan confirmed all five were gone, along with 16 related problems that depended on them. 27 problems remain, down from 49.
5. What remains needs bigger changes, such as replacing end-of-life software or paying for security updates. I recorded those as known risks, and the test machine stays isolated from the rest of the network.

## Scope and method

Four hosts, scanned with Nessus Essentials 10.12.6 (Basic Network Scan, no credentials, plugin feed 202611161028) on 17 November 2026. Full details: [scope and method](01-scope-and-method.md). Findings are ranked by CVSS v3 base score, or v2 where v3 is not available. Counts are unique findings per host, not one per port.

## Findings by host (baseline)

| Host | Critical | High | Medium | Low | Notes |
|---|---|---|---|---|---|
| `10.10.20.20` Metasploitable 2 | 8 | 2 | 19 | 7 | End-of-life OS and services, many weak defaults |
| `10.10.10.170` Lubuntu | 4 | 3 | 1 | 0 | Package and kernel advisories |
| `10.10.10.1` OPNsense | 0 | 0 | 4 | 1 | Self-signed certificate, missing HSTS |
| `10.10.20.10` Web server | 0 | 0 | 0 | 0 | Informational findings only |

The hardened web server from Project 1 came back with nothing above Informational, which supports the hardening work in that project.

## Critical and High findings

All 17 Critical and High findings from the baseline, with their final status. The five fixes are labelled Fix 1 to Fix 5.

| ID | Host | Severity | CVSS | Finding | Status |
|---|---|---|---|---|---|
| F-01 | `10.10.20.20` | Critical | 10.0 | Apache Tomcat SEoL (<= 5.5.x) (plugin 171340) | Open: not re-detected: Nessus did not fingerprint Tomcat on 8180; Tomcat still running |
| F-02 | `10.10.20.20` | Critical | 10.0 | Canonical Ubuntu Linux SEoL (8.04.x) (plugin 201352) | Open: accepted risk: Ubuntu 8.04 is end-of-life, needs OS replacement |
| F-03 | `10.10.20.20` | Critical | 10.0 | Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (plugin 32314) | Open: accepted risk: weak SSH host keys, needs patched OpenSSL and new keys |
| F-04 | `10.10.20.20` | Critical | 10.0 | Debian OpenSSH/OpenSSL Package Random Number Generator Weakness (SSL check) (plugin 32321) | Resolved: side effect of Fix 5 (TLS disabled) |
| F-05 | `10.10.20.20` | Critical | 10.0 | VNC Server 'password' Password (plugin 61708) | Fixed: Fix 1: VNC disabled |
| F-06 | `10.10.10.170` | Critical | 9.8 | Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 26.04 LTS : FFmpeg vulnerabiliti... (plugin 322791) | Open: fix needs Ubuntu Pro (esm-apps), not applied |
| F-07 | `10.10.10.170` | Critical | 9.8 | Ubuntu 26.04 LTS : Linux kernel vulnerabilities (USN-9018-1) (plugin 381339) | Open: kernel advisory, remained after apt upgrade |
| F-08 | `10.10.20.20` | Critical | 9.8 | Apache Tomcat AJP Connector Request Injection (Ghostcat) (plugin 134862) | Fixed: Fix 3: AJP connector disabled |
| F-09 | `10.10.20.20` | Critical | 9.8 | Bind Shell Backdoor Detection (plugin 51988) | Fixed: Fix 2: bind shell removed |
| F-10 | `10.10.20.20` | Critical | 9.8 | SSL Version 2 and 3 Protocol Detection (plugin 20007) | Fixed: Fix 5: TLS disabled on SMTP and PostgreSQL |
| F-11 | `10.10.10.170` | Critical | 8.8 | Ubuntu 16.04 LTS / 18.04 LTS / 20.04 LTS / 22.04 LTS / 24.04 LTS / 26.04 LT... (plugin 365762) | Open: fix needs Ubuntu Pro (esm-apps), not applied |
| F-12 | `10.10.10.170` | Critical | 8.8 | Ubuntu 26.04 LTS : FFmpeg vulnerabilities (USN-8738-1) (plugin 344612) | Open: fix needs Ubuntu Pro (esm-apps), not applied |
| F-13 | `10.10.10.170` | High | 9.1 | Ubuntu 20.04 LTS / 22.04 LTS / 24.04 LTS / 26.04 LTS : SRT vulnerabilities ... (plugin 346232) | Open: fix needs Ubuntu Pro (esm-apps), not applied |
| F-14 | `10.10.10.170` | High | 8.8 | Ubuntu 14.04 LTS / 18.04 LTS / 20.04 LTS / 24.04 LTS / 26.04 LTS : libass v... (plugin 350176) | Open: fix needs Ubuntu Pro (esm-apps), not applied |
| F-15 | `10.10.20.20` | High | 8.6 | ISC BIND Service Downgrade / Reflected DoS (plugin 136769) | Open: not in the top five |
| F-16 | `10.10.10.170` | High | 7.8 | Ubuntu 24.04 LTS / 26.04 LTS : Linux kernel vulnerabilities (USN-8959-1) (plugin 376443) | Open: kernel advisory, remained after apt upgrade |
| F-17 | `10.10.20.20` | High | 7.5 | SSL Medium Strength Cipher Suites Supported (SWEET32) (plugin 42873) | Resolved: side effect of Fix 5 (TLS disabled) |

The full list of 49 findings, including the Medium and Low ones, is in [`reports/findings-table.csv`](../reports/findings-table.csv).

## Findings that need a decision

| Finding | Status | Reasoning |
|---|---|---|
| Ubuntu 8.04 end-of-life (10.0) and Tomcat 5.5 end-of-life (10.0) | Accepted risk | No patch exists. The fix is replacing the OS and Tomcat. Contained by the DMZ rules from Project 1. |
| Weak OpenSSH/OpenSSL keys (10.0) | Accepted risk | Needs a patched OpenSSL package, then new keys, on a release with no updates. |
| FFmpeg, libass, SRT on Lubuntu (up to 9.8) | Open | The fix is in Ubuntu Pro's `esm-apps` repository. I chose not to enable it. |
| Linux kernel advisories on Lubuntu (9.8 and 7.8) | Open | They remained after `apt upgrade`. A newer kernel image was installed, but I did not record the running kernel after a reboot, so I cannot say whether a reboot clears them. |
| Tomcat end-of-life and Tomcat default files | Counted as open | Not re-detected in either rescan, but Tomcat was still running. |
| All other Medium and Low findings | Open | Outside the top-five rule. Most are SSH algorithm settings, SMB signing, BIND denial of service and HTTP methods on Metasploitable. |

## Recommended next steps

1. Replace Metasploitable's role with a patched machine if the aim is a clean report, since most of its remaining findings are structural.
2. Enable Ubuntu Pro (free for personal use) on the LAN client to clear the five package findings.
3. Reboot the LAN client after kernel updates and rescan, to settle the kernel advisories.
4. Run a credentialed scan of Metasploitable and the web server to see findings the unauthenticated scan cannot.
5. Review the services Nessus did not flag but which Metasploitable is documented to ship vulnerable (vsftpd, UnrealIRCd, distccd on ports 21, 6667 and 3632).
