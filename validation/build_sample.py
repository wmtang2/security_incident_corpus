#!/usr/bin/env python3
"""Build validation sample.

positives  = CVEs with EPSS score at CUTOFF that CISA added to KEV within
             24 months after CUTOFF (primary outcome) - also flags 12-month.
negatives  = random CVEs scored by EPSS at CUTOFF, never added to KEV
             (KEV history through 2026-08-31 gives extra follow-up past
             both horizons).

Inputs (real public data):
  - data/kev.json                 CISA Known Exploited Vulnerabilities catalog
  - data/epss_2024-06-01.csv.gz   FIRST.org EPSS scores as of cutoff date
Output: data/sample.csv  (cve, exploited_24m, exploited_12m, epss, epss_percentile)
"""
import csv
import gzip
import json
import random
from datetime import date

CUTOFF = date(2024, 6, 1)
END_12M = date(2025, 6, 1)
END_24M = date(2026, 6, 1)
N_NEG = 2500
SEED = 42

kev = json.load(open("data/kev.json"))["vulnerabilities"]
kev_all = {v["cveID"] for v in kev}
added = {v["cveID"]: date.fromisoformat(v["dateAdded"]) for v in kev}

epss = {}
with gzip.open("data/epss_2024-06-01.csv.gz", "rt") as f:
    for line in f:
        if line.startswith("#") or line.startswith("cve"):
            continue
        cve, s, pct = line.strip().split(",")
        epss[cve] = (float(s), float(pct))
print(f"EPSS rows at cutoff: {len(epss)}")

cohort = set(epss)  # CVEs known/scorable at prediction time
pos_24m = sorted(c for c in cohort if c in added and CUTOFF <= added[c] < END_24M)
pos_12m = {c for c in pos_24m if added[c] < END_12M}
print(f"positives 24m: {len(pos_24m)} (of which 12m: {len(pos_12m)})")

neg_pool = sorted(c for c in cohort if c not in kev_all)
random.seed(SEED)
negatives = random.sample(neg_pool, N_NEG)

with open("data/sample.csv", "w", newline="") as f:
    w = csv.writer(f)
    w.writerow(["cve", "exploited_24m", "exploited_12m", "epss", "epss_percentile"])
    for c in pos_24m:
        w.writerow([c, 1, 1 if c in pos_12m else 0, epss[c][0], epss[c][1]])
    for c in negatives:
        w.writerow([c, 0, 0, epss[c][0], epss[c][1]])
print(f"sample: {len(pos_24m)} pos + {len(negatives)} neg")
