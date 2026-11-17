#!/usr/bin/env python3
"""Turn a Nessus Essentials "Detailed Vulnerabilities By Host" HTML report into a CSV.

Nessus Essentials cannot export CSV or PDF (those are Pro features), but it can
export this HTML report. This script reads that HTML and writes one row per
finding per port: host, plugin_id, name, severity, risk, cvss_v3, cvss_v2,
ports, solution.

Usage:
    python3 parse_nessus_html.py report.html findings.csv

Requires: beautifulsoup4 and lxml  (pip install beautifulsoup4 lxml)
"""
import collections
import csv
import re
import sys

from bs4 import BeautifulSoup

# Nessus colours each finding header by severity.
SEVERITY_BY_COLOUR = {
    "91243E": "Critical",
    "DD4B50": "High",
    "F18C43": "Medium",
    "F8C851": "Low",
    "67ACE1": "Info",
}
HEADER = re.compile(r"^(\d+) - (.+)$")


def first_number(text):
    match = re.match(r"([\d.]+)", text)
    return match.group(1) if match else ""


def parse(path):
    soup = BeautifulSoup(open(path, encoding="utf-8").read(), "lxml")
    host = None
    rows = []
    for div in soup.find_all("div"):
        classes = div.get("class") or []
        # Host details table: carries the "IP:" row that starts a host section.
        if "table-wrapper" in classes and "details" in classes:
            ip = re.search(r"IP:\s*(\d+\.\d+\.\d+\.\d+)", div.get_text(" ", strip=True))
            if ip:
                host = ip.group(1)
            continue
        # Finding header: "<plugin id> - <name>", clickable, coloured by severity.
        if not (div.get("id", "").startswith("id") and "toggleSection" in (div.get("onclick") or "")):
            continue
        own_text = div.find(string=True, recursive=False)
        match = HEADER.match(own_text.strip()) if own_text else None
        if not match:
            continue
        colour = re.search(r"background:\s*#([0-9A-Fa-f]{6})", div.get("style") or "")
        severity = SEVERITY_BY_COLOUR.get(colour.group(1).upper(), "?") if colour else "?"
        body = soup.find(id=div["id"] + "-container")

        def field(label):
            for header in body.find_all("div", class_="details-header"):
                if header.get_text(strip=True) == label:
                    sibling = header.find_next_sibling("div")
                    return sibling.get_text(" ", strip=True) if sibling else ""
            return ""

        ports = sorted({h.get_text(strip=True) for h in body.find_all("h2") if h.get_text(strip=True)})
        rows.append({
            "host": host,
            "plugin_id": match.group(1),
            "name": match.group(2).strip(),
            "severity": severity,
            "risk": field("Risk Factor"),
            "cvss_v3": first_number(field("CVSS v3.0 Base Score")),
            "cvss_v2": first_number(field("CVSS v2.0 Base Score")),
            "ports": ";".join(ports),
            "solution": field("Solution")[:300],
        })
    return rows


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    rows = parse(sys.argv[1])
    with open(sys.argv[2], "w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)
    counts = collections.Counter((r["host"], r["severity"]) for r in rows)
    for host in sorted({r["host"] for r in rows}):
        summary = {s: counts[(host, s)] for s in ("Critical", "High", "Medium", "Low", "Info")}
        print(host, summary)
    print("rows written:", len(rows))


if __name__ == "__main__":
    main()
