# Copyright (C) 2026  wmtang2
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#!/usr/bin/env python3
"""Build the incident scoring set + date-matched controls.

Scored incidents:
  tier1: VCDB/wiki incidents with explicit CVE(s), date >= 2021-07-19 (EPSS era)
  tier2: ransomware.live/ransomwatch incidents whose group has a documented
         CVE set (incidents/group_cve_map.json); stratified sample capped per
         group-year to keep controls feasible; CVE = group's max-EPSS CVE at
         incident date (among CVEs scored by EPSS at that date)

Controls: 2 per scored incident, sampled from the EPSS daily snapshot of the
incident's quarter, excluding CVEs ever in CISA KEV.

Output: incidents/score_set.csv with one row per entity:
  kind(incident/control), inc_id, source, org, date, cve, group, tier,
  cost_usd, records
"""
import csv
import gzip
import json
import random
from datetime import date

random.seed(42)
EPSS_START = date(2021, 7, 19)
WINDOW_END = date(2026, 6, 1)

kev = {v["cveID"] for v in json.load(open("data/kev.json"))["vulnerabilities"]}
group_map = {k: v["cves"] for k, v in json.load(open("incidents/group_cve_map.json")).items() if not k.startswith("_")}

# EPSS series cache helpers
import os

def load_series(cve):
    p = f"incidents/epss_cache/{cve}.json"
    return json.load(open(p)) if os.path.exists(p) else {}


def epss_at(cve, day):
    s = load_series(cve)
    if not s:
        return None
    if day in s:
        return s[day]
    prior = [d for d in s if d < day]
    return s[max(prior)] if prior else None


rows = list(csv.DictReader(open("data/incidents_all.csv")))
scored = []
inc_id = 0

# tier1: all EPSS-era
for r in rows:
    if r["tier"] != "tier1" or r["date"] < EPSS_START.isoformat() or r["date"] >= WINDOW_END.isoformat():
        continue
    cves = [c for c in r["cve"].split(";") if c]
    # primary CVE = max EPSS at incident date among CVEs scored then
    best, best_epss = None, -1
    for c in cves:
        e = epss_at(c, r["date"])
        if e is not None and e > best_epss:
            best, best_epss = c, e
    inc_id += 1
    scored.append({
        "kind": "incident", "inc_id": inc_id, "source": r["source"], "org": r["org"],
        "date": r["date"], "cve": best or cves[0], "cve_all": r["cve"], "group": "",
        "tier": "tier1", "cost_usd": r["cost_usd"], "records": r["records"],
        "tef": best_epss if best_epss >= 0 else 0.001,
        "zero_day_flag": int(best is None),
    })

# tier2: mapped groups, EPSS era; stratified cap 100 per group-year
per_gy = {}
for r in rows:
    if r["tier"] != "tier2" or not r["date"] or r["date"] < EPSS_START.isoformat() or r["date"] >= WINDOW_END.isoformat():
        continue
    g = r["group"].lower()
    if g not in group_map:
        continue
    key = (g, r["date"][:4])
    per_gy.setdefault(key, []).append(r)
tier2_sample = []
for key, lst in per_gy.items():
    random.shuffle(lst)
    tier2_sample.extend(lst[:100])
for r in tier2_sample:
    cves = group_map[r["group"].lower()]
    best, best_epss = None, -1
    for c in cves:
        e = epss_at(c, r["date"])
        if e is not None and e > best_epss:
            best, best_epss = c, e
    inc_id += 1
    scored.append({
        "kind": "incident", "inc_id": inc_id, "source": r["source"], "org": r["org"],
        "date": r["date"], "cve": best or cves[0], "cve_all": ";".join(cves), "group": r["group"],
        "tier": "tier2", "cost_usd": r["cost_usd"], "records": r["records"],
        "tef": best_epss if best_epss >= 0 else 0.001,
        "zero_day_flag": int(best is None),
    })

print(f"scored incidents: {len(scored)} (tier1={sum(1 for s in scored if s['tier']=='tier1')}, "
      f"tier2={sum(1 for s in scored if s['tier']=='tier2')}, 0-day-flag={sum(s['zero_day_flag'] for s in scored)})")

# ---- controls: 2 per incident from the quarter's EPSS snapshot
import glob as globmod
import re as re_mod

snap_files = {}
for f in globmod.glob("data/epss_snap/epss_*.csv.gz"):
    d = re_mod.search(r"epss_(\d{4}-\d{2}-\d{2})", f).group(1)
    snap_files[d] = f
snap_dates = sorted(snap_files)
print("snapshots available:", len(snap_dates))


def snap_for(day):
    prior = [d for d in snap_dates if d <= day]
    return snap_files[prior[-1]] if prior else None


snap_cache = {}
def pool_for(day):
    f = snap_for(day)
    if f is None:
        return []
    if f not in snap_cache:
        pool = []
        with gzip.open(f, "rt") as fh:
            for line in fh:
                if line.startswith("#") or line.startswith("cve"):
                    continue
                cve, s, _ = line.strip().split(",")
                if cve not in kev:
                    pool.append((cve, float(s)))
        snap_cache[f] = pool
    return snap_cache[f]


controls = []
for s in scored:
    pool = pool_for(s["date"])
    if not pool:
        continue
    for cve, epss in random.sample(pool, 2):
        controls.append({
            "kind": "control", "inc_id": s["inc_id"], "source": "epss_snapshot",
            "org": "", "date": s["date"], "cve": cve, "cve_all": cve, "group": "",
            "tier": "control", "cost_usd": "", "records": "",
            "tef": epss, "zero_day_flag": 0,
        })

allr = scored + controls
with open("incidents/score_set.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(allr[0].keys()))
    w.writeheader()
    w.writerows(allr)
print(f"controls: {len(controls)}; total score set: {len(allr)} -> incidents/score_set.csv")
uniq = sorted({r['cve'] for r in allr})
print(f"unique CVEs needing NVD: {len(uniq)}")
open("incidents/nvd_needed.txt", "w").write("\n".join(uniq))
