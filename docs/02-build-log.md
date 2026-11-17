# 2. Build log

Each step uses the format: Step, Goal, Commands, Result, Problem and fix, Screenshot. The five fixes are logged here in short form. Full commands, evidence and rollback are in the [remediation log](04-remediation-log.md).

## Step 1: Download and verify Metasploitable 2

**Goal:** get the vulnerable VM from the official source and confirm the file is intact.

**Commands (Windows PowerShell):**
```
(Get-FileHash .\metasploitable-linux-2.0.0.zip -Algorithm SHA256).Hash.ToLower()
```

**Result:** the hash printed locally matches the SHA-256 shown on the SourceForge download page: `2ae8788e95273eee87bd379a250d86ec52f286fa7fe84773a3a8f6524085a1ff`. File size 865,084,584 bytes.

**Screenshots:** `01-metasploitable-download-sourceforge.png`, `02-metasploitable-sha256-verified.png` (Windows account name masked).

## Step 2: Put Metasploitable in the DMZ

**Goal:** the VM boots on the DMZ segment only and has a fixed address, `10.10.20.20`.

**Settings:** open `Metasploitable.vmx` in VMware, choose "I copied it" when asked, set the network adapter to LAN Segment `DMZ`, and remove the extra host-only adapter. The DMZ has no DHCP, so the address is set by hand in `/etc/network/interfaces`:

```
auto eth0
iface eth0 inet static
address 10.10.20.20
netmask 255.255.255.0
gateway 10.10.20.1
```
```
sudo /etc/init.d/networking restart
ifconfig eth0
```

**Result:** the machine answers from the LAN client, and SSH works with the legacy algorithm flags that its 2008-era OpenSSH needs:
```
ssh -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedKeyTypes=+ssh-rsa msfadmin@10.10.20.20
```

**Verification:** the VM settings show a single network adapter, on LAN Segment `DMZ`, with 512 MB of RAM. `ifconfig eth0` shows `10.10.20.20`. A ping from the LAN client succeeds with 0% loss and `ttl=63`, which shows the packets crossed the firewall (one routed hop). A ping from Metasploitable back to the LAN client gets **100% packet loss**, which is the Project 1 DMZ-to-LAN rule containing the vulnerable machine.

**Screenshots:** `24-metasploitable-vm-settings-dmz.png`, `25-metasploitable-ifconfig.png`, `26-ping-lan-to-metasploitable-ok.png`, `27-isolation-metasploitable-to-lan-blocked.png`.

## Step 3: Install Nessus Essentials on the LAN client

**Goal:** a working scanner on Lubuntu.

**Commands:**
```
cd ~/Downloads
sudo dpkg -i Nessus-*.deb
sudo systemctl enable --now nessusd
```
Then `https://localhost:8834`, choose Nessus Essentials, enter the activation code from Tenable, create an admin account, and wait for the plugins to compile (the self-signed certificate warning is expected).

**Result:** Nessus 10.12.6 running. The Lubuntu VM was given extra RAM for the scans (it showed about 8 GB, above the 3 to 4 GB in the build plan), which does not change what Nessus finds.

**Problem and fix:** the first scan, on a scan object named `My Basic Network Scan`, ran about 18 hours. A new scan object (`NEW SCAN`) with the same policy took about 18 minutes. See [scope and method](01-scope-and-method.md).

**Screenshots:** not captured (Nessus welcome page, version).

## Step 4: Baseline scan

**Goal:** record what an outsider on the LAN sees, before any change.

**Settings:** New Scan, Basic Network Scan, targets `10.10.10.1, 10.10.10.170, 10.10.20.10, 10.10.20.20`, default settings, no credentials.

**Result:** 49 unique findings rated Critical to Low. Metasploitable has 8 Critical, 2 High, 19 Medium and 7 Low. The hardened web server has none above Informational. The HTML report is saved as [`reports/baseline/baseline-scan.html`](../reports/baseline/baseline-scan.html) and parsed into a CSV.

**Screenshots:** `03-nessus-finding-vnc-61708.png` (one finding from the earlier pilot scan) and `29-nessus-scan-history.png` (the three formal runs of `NEW SCAN`). The baseline Hosts and Vulnerabilities screens were not captured; the HTML report is the evidence.

## Steps 5 to 9: The five fixes

| Step | Fix | Host | Evidence |
|---|---|---|---|
| 5 | VNC disabled (`/etc/rc.local`, line 18) | Metasploitable | `04`, `05` |
| 6 | Bind shell removed (`/etc/inetd.conf`, line 8) | Metasploitable | `06` to `09` |
| 7 | Tomcat AJP connector disabled (`server.xml`, lines 105 to 106) | Metasploitable | `10` to `13` |
| 8 | NFS export removed (`/etc/exports`, line 12) | Metasploitable | `17`, `18`, `28` |
| 9 | TLS disabled on PostgreSQL and Postfix | Metasploitable | `19` to `21` |

## Step 10: Lubuntu package updates, and the Ubuntu Pro decision

**Goal:** clear the FFmpeg, libass and SRT findings on the LAN client (three Critical, two High).

**Commands:**
```
dpkg -l | grep -E 'ffmpeg|libavcodec|libsrt' | awk '{print $2, $3}'
apt list --upgradable 2>/dev/null | wc -l
sudo apt update
sudo apt upgrade -y
```

**Result:** 74 lines from `apt list --upgradable` before (73 packages, plus a header line) and 13 after (12 packages, held back by Ubuntu's phased rollout). The upgrade also installed a newer kernel image (the output shows `initrd.img-7.0.0-43-generic` being generated). The FFmpeg and SRT package versions did not change (`libavcodec62 7:8.0.1-3ubuntu2`, `libsrt1.5-gnutls 1.5.4-3`). `apt` printed that security updates for `libsrt1.5-gnutls`, `libass9`, `libavcodec62`, `libavfilter11`, `libavutil60`, `libswscale9`, `libswresample6` and `libavformat62` are available "through Ubuntu Pro with esm-apps enabled".

**Decision:** I did not sign up for Ubuntu Pro. These five findings are left open and documented as "fix requires Ubuntu Pro, not applied". NFS replaced this item in the top five.

**Screenshots:** `14-lubuntu-packages-before.png`, `15-lubuntu-packages-after.png`, `16-lubuntu-esm-only-updates.png`.

## Step 11: Rescans

**Goal:** prove the fixes and measure the change.

**Result:** two rescans of `NEW SCAN` with unchanged settings. In both, the five fixed findings are gone and port 8180 (Tomcat) was detected as open but not identified, so its two findings are treated as still open. See [before and after](05-before-and-after.md).

**Screenshots:** `22-nessus-rescan-1-hosts.png`, `23-nessus-rescan-1-vulnerabilities.png`.

## Evidence not captured

These were done but not screenshotted: the Nessus install page and version, and the baseline and final Hosts and Vulnerabilities screens. The HTML reports, which record the Nessus version, scan dates and every finding, stand in for them.
