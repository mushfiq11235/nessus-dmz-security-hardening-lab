#!/usr/bin/env python3
"""Compare a baseline scan with a rescan and write the findings table.

Input: two CSVs produced by parse_nessus_html.py.
Output: findings-table.csv (one row per host + plugin, with a status) and a
printed before/after summary.

Findings are matched on (host, plugin_id). Counts are UNIQUE findings per host
(one per plugin), not one per port, so they differ from the Nessus screen,
which groups findings differently.

Usage:
    python3 compare_scans.py baseline.csv rescan.csv findings-table.csv
"""
import csv
import sys

SEVERITIES = ["Critical", "High", "Medium", "Low"]

# The five findings that were fixed on purpose (see docs/04-remediation-log.md).
TARGETED = {
    "61708": "Fixed - Fix 1: VNC disabled",
    "51988": "Fixed - Fix 2: bind shell removed",
    "134862": "Fixed - Fix 3: AJP connector disabled",
    "42256": "Fixed - Fix 4: NFS export removed",
    "20007": "Fixed - Fix 5: TLS disabled on SMTP and PostgreSQL",
}
# Gone from the rescan, but Tomcat was still running: Nessus did not fingerprint
# port 8180 in either rescan, so these are treated as still open.
NOT_REDETECTED = {
    ("10.10.20.20", "171340"),  # Apache Tomcat SEoL
    ("10.10.20.20", "12085"),   # Apache Tomcat Default Files
}
# Gone from the rescan and unrelated to any change made: scanner variation.
SCANNER_VARIATION = {("10.10.10.1", "33447")}
# Gone because VNC (a root X server) was disabled.
SIDE_EFFECT_VNC = {("10.10.20.20", "10407")}
# Still open: the only fix is an OS or software upgrade, or a paid repository.
ACCEPTED = {
    ("10.10.20.20", "201352"): "Open - accepted risk: Ubuntu 8.04 is end-of-life, needs OS replacement",
    ("10.10.20.20", "32314"): "Open - accepted risk: weak SSH host keys, needs patched OpenSSL and new keys",
}


def load(path):
    findings = {}
    for row in csv.DictReader(open(path, encoding="utf-8")):
        key = (row["host"], row["plugin_id"])
        entry = findings.setdefault(key, dict(row, ports=set()))
        entry["ports"].update(p for p in row["ports"].split(";") if p)
    return findings


def cvss(row):
    return row["cvss_v3"] or row["cvss_v2"] or ""


def status(key, before, after):
    host, plugin = key
    gone = key not in after
    if gone and plugin in TARGETED and host == "10.10.20.20":
        return TARGETED[plugin]
    if not gone and plugin in TARGETED and host == "10.10.20.20":
        return "NOT FIXED - still present"
    if key in NOT_REDETECTED:
        return "Open - not re-detected: Nessus did not fingerprint Tomcat on 8180; Tomcat still running"
    if key in SCANNER_VARIATION:
        return "Not reproduced - scanner variation, no change was made to this host"
    if key in SIDE_EFFECT_VNC:
        return "Resolved - side effect of Fix 1 (VNC disabled)"
    if gone and host == "10.10.20.20" and any(p.startswith(("tcp/25/", "tcp/5432/")) for p in before[key]["ports"]):
        return "Resolved - side effect of Fix 5 (TLS disabled)"
    if gone:
        return "Resolved"
    if key in ACCEPTED:
        return ACCEPTED[key]
    name = before[key]["name"]
    if host == "10.10.10.170" and any(w in name for w in ("FFmpeg", "SRT", "libass")):
        return "Open - fix needs Ubuntu Pro (esm-apps), not applied"
    if host == "10.10.10.170" and "kernel" in name:
        return "Open - kernel advisory, remained after apt upgrade"
    return "Open - not in the top five"


def main():
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    before, after = load(sys.argv[1]), load(sys.argv[2])
    rows = []
    for key, row in before.items():
        if row["severity"] == "Info":
            continue
        rows.append({
            "host": key[0],
            "plugin_id": key[1],
            "name": row["name"],
            "severity_before": row["severity"],
            "cvss": cvss(row),
            "ports": ";".join(sorted(row["ports"])),
            "severity_after": after[key]["severity"] if key in after else "gone",
            "status": status(key, before, after),
        })
    for key, row in after.items():
        if row["severity"] != "Info" and key not in before:
            rows.append({
                "host": key[0], "plugin_id": key[1], "name": row["name"],
                "severity_before": "not present", "cvss": cvss(row),
                "ports": ";".join(sorted(row["ports"])),
                "severity_after": row["severity"], "status": "New in rescan",
            })
    order = {s: i for i, s in enumerate(SEVERITIES)}
    rows.sort(key=lambda r: (order.get(r["severity_before"], 9), -float(r["cvss"] or 0), r["host"]))
    with open(sys.argv[3], "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    print("Unique findings per host (before -> after), as scanned")
    hosts = sorted({k[0] for k in list(before) + list(after)})
    for host in hosts:
        cells = []
        for sev in SEVERITIES:
            nb = sum(1 for k, v in before.items() if k[0] == host and v["severity"] == sev)
            na = sum(1 for k, v in after.items() if k[0] == host and v["severity"] == sev)
            cells.append(f"{sev[0]}: {nb} -> {na}")
        print(" ", host, "  ".join(cells))
    total_before = {s: sum(1 for v in before.values() if v["severity"] == s) for s in SEVERITIES}
    total_after = {s: sum(1 for v in after.values() if v["severity"] == s) for s in SEVERITIES}
    # Counting the two Tomcat findings as still open (see NOT_REDETECTED).
    adjusted = dict(total_after)
    for key in NOT_REDETECTED:
        if key in before and key not in after:
            adjusted[before[key]["severity"]] += 1
    print("Totals as scanned:   ", total_before, "->", total_after, " sum", sum(total_before.values()), "->", sum(total_after.values()))
    print("Totals, Tomcat open: ", total_before, "->", adjusted, " sum", sum(total_before.values()), "->", sum(adjusted.values()))
    resolved = sum(1 for r in rows if r["status"].startswith(("Fixed", "Resolved")))
    print("Resolved by the changes made:", resolved)


if __name__ == "__main__":
    main()
