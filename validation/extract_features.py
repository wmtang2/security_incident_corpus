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
"""Extract model inputs from NVD 2.0 JSON records (FKIE mirror).

Mapping (documented in REPORT.md):
  TEF   <- EPSS score at cutoff (0..1)          [from sample.csv]
  LM    <- CVSS v3.x impactScore rescaled to 0..10  (max possible 6.04)
  Vuln  <- CVSS v3.x exploitabilityScore rescaled to 0..1 (max possible 3.915)
Fallbacks: cvssMetricV30 -> same fields; cvssMetricV2 -> impact/exploitability
already 0..10 (rescaled impact/10*6.04 -> same 0..10 scale via /6.04*10 = /1,
kept as separate flag cvss_version).

Output: data/features.csv
"""
import csv
import glob
import json
import os

IMPACT_MAX_V3 = 6.04
EXPL_MAX_V3 = 3.915

rows = {}
with open("data/sample.csv") as f:
    for r in csv.DictReader(f):
        rows[r["cve"]] = r

out = []
missing_cvss = 0
for cve, r in rows.items():
    path = f"data/nvd/{cve}.json"
    if not os.path.exists(path):
        continue
    d = json.load(open(path))
    published = d.get("published", "")
    metrics = d.get("metrics", {})
    base = impact = expl = None
    version = None
    for key, v in (("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0")):
        if metrics.get(key):
            # prefer NVD primary entry
            entries = metrics[key]
            entry = next(
                (e for e in entries if e.get("source") == "nvd@nist.gov"), entries[0]
            )
            base = entry["cvssData"]["baseScore"]
            impact = entry["impactScore"]
            expl = entry["exploitabilityScore"]
            version = v
            break
    if base is None and metrics.get("cvssMetricV2"):
        entry = next(
            (e for e in metrics["cvssMetricV2"] if e.get("source") == "nvd@nist.gov"),
            metrics["cvssMetricV2"][0],
        )
        base = entry["cvssData"]["baseScore"]
        impact = entry["impactScore"]  # 0..10
        expl = entry["exploitabilityScore"]  # 0..10
        version = "2.0"
    if base is None:
        missing_cvss += 1
        continue
    if version == "2.0":
        lm_010 = impact  # already 0..10
        vuln_01 = expl / 10.0
    else:
        lm_010 = impact / IMPACT_MAX_V3 * 10.0
        vuln_01 = expl / EXPL_MAX_V3
    out.append(
        {
            "cve": cve,
            "exploited_24m": r["exploited_24m"],
            "exploited_12m": r["exploited_12m"],
            "epss": r["epss"],
            "epss_percentile": r["epss_percentile"],
            "published": published,
            "cvss_version": version,
            "cvss_base": base,
            "cvss_impact": impact,
            "cvss_exploitability": expl,
            "lm_010": round(lm_010, 4),
            "vuln_01": round(vuln_01, 4),
        }
    )

with open("data/features.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)
print(f"features: {len(out)} rows, missing CVSS: {missing_cvss}")
import collections

print(collections.Counter(o["cvss_version"] for o in out))
