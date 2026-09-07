#!/usr/bin/env python3
"""Fetch FULL EPSS daily history (2021-07-19 .. 2026-06-01) for every CVE needed
by the incident study, via 29-day backward windows (the API caps time-series at
~30 days per call). Cached to incidents/epss_cache/{cve}.json."""
import csv
import json
import os
import time
from datetime import date, timedelta

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
os.makedirs("incidents/epss_cache", exist_ok=True)

cves = set()
for r in csv.DictReader(open("data/incidents_all.csv")):
    if r["cve"]:
        cves.update(r["cve"].split(";"))
gm = json.load(open("incidents/group_cve_map.json"))
for k, v in gm.items():
    if not k.startswith("_"):
        cves.update(v["cves"])
cves = sorted(cves)
print(f"unique CVEs: {len(cves)}")

START = date(2021, 7, 19)
END = date(2026, 6, 1)

for i, cve in enumerate(cves):
    path = f"incidents/epss_cache/{cve}.json"
    series = json.load(open(path)) if os.path.exists(path) else {}
    end = END
    tries = 0
    while end >= START and tries < 80:
        if end.isoformat() in series and (end - timedelta(days=28)).isoformat() in series:
            end -= timedelta(days=29)
            continue
        try:
            r = requests.get(
                "https://api.first.org/data/v1/epss",
                params={"cve": cve, "date": end.isoformat(), "scope": "time-series"},
                timeout=30,
                verify=False,
            )
            data = r.json().get("data", [])
            if data and data[0].get("time-series"):
                for pt in data[0]["time-series"]:
                    series[pt["date"]] = float(pt["epss"])
            end -= timedelta(days=29)
            tries = 0
        except Exception as e:
            print(f"  retry {cve} @{end}: {e}")
            tries += 1
            time.sleep(2)
        time.sleep(0.25)
    json.dump(series, open(path, "w"))
    if (i + 1) % 5 == 0:
        print(f"  {i+1}/{len(cves)} cves ({len(series)} days for {cve})")
print("done")
