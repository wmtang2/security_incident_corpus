#!/usr/bin/env python3
"""Study B feature rebuild - replace technical CVSS inputs with real-world data.

  TEF   <- EPSS @2024-06-01 (unchanged; built from real exploitation telemetry)
  Vuln  <- Exploit-DB: a public exploit for this CVE existed BEFORE the cutoff
           (real attack tooling, not a technical subscore): 0.85 yes / 0.25 no
  LM    <- real-world expected loss by consequence class (CWE -> class):
             data_exposure: $4.88M  (IBM Cost of a Data Breach 2024, global avg)
             rce:           $2.73M  (Sophos State of Ransomware 2024, mean recovery
                                     cost excl. ransom; RCE is the dominant initial vector)
             other:         $0.35M  (NetDiligence Cyber Claims Study 2024 avg incident cost)
  LM is stored both as raw USD and mapped to the model universe two ways:
    lm_lin = engine's own linear $1B scale,  lm_log = repaired log scale (0..10)

Output: data/features2.csv
"""
import csv
import json
import re
from datetime import date

CUTOFF = date(2024, 6, 1)

DATA_CWE = {
    "CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-209", "CWE-212", "CWE-213",
    "CWE-311", "CWE-312", "CWE-319", "CWE-359", "CWE-532", "CWE-535", "CWE-538",
    "CWE-552", "CWE-611", "CWE-639", "CWE-922", "CWE-22", "CWE-23", "CWE-89",
    "CWE-918", "CWE-522", "CWE-256", "CWE-257", "CWE-260", "CWE-321", "CWE-325",
    "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-79",
}
RCE_CWE = {
    "CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-96", "CWE-502", "CWE-119",
    "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-134", "CWE-190",
    "CWE-191", "CWE-415", "CWE-416", "CWE-787", "CWE-843", "CWE-908", "CWE-909",
    "CWE-917",
}
CLASS_COST_USD = {"data_exposure": 4.88e6, "rce": 2.73e6, "other": 3.5e5}


def classify(cwes):
    if any(c in DATA_CWE for c in cwes):
        return "data_exposure"
    if any(c in RCE_CWE for c in cwes):
        return "rce"
    return "other"


# ---- Exploit-DB: CVE -> earliest exploit publication
cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
edb = {}
with open("data/files_exploits.csv", encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        codes = row.get("codes") or ""
        try:
            d = date.fromisoformat(row["date_published"][:10])
        except Exception:
            continue
        for m in cve_re.finditer(codes):
            cve = m.group(0)
            if cve not in edb or d < edb[cve]:
                edb[cve] = d
print(f"Exploit-DB CVEs mapped: {len(edb)}")

rows = list(csv.DictReader(open("data/features.csv")))
out = []
import collections

cls_counts = collections.Counter()
for r in rows:
    cve = r["cve"]
    d = json.load(open(f"data/nvd/{cve}.json"))
    cwes = set()
    for w in d.get("weaknesses", []):
        for desc in w.get("description", []):
            v = desc.get("value", "")
            if v.startswith("CWE-"):
                cwes.add(v)
    cls = classify(cwes)
    cls_counts[cls] += 1
    cost = CLASS_COST_USD[cls]
    has_exploit = cve in edb and edb[cve] < CUTOFF
    vuln_real = 0.85 if has_exploit else 0.25
    import math

    lm_log = 10.0 * math.log10(1.0 + cost) / math.log10(1.0 + 1e9)
    lm_lin = cost / 1e9 * 10.0  # model's linear scale
    out.append(
        {
            **r,
            "cwe_class": cls,
            "lm_class_cost_usd": cost,
            "lm_lin": round(lm_lin, 6),
            "lm_log": round(lm_log, 4),
            "exploit_exists_pre_cutoff": int(has_exploit),
            "vuln_real": vuln_real,
        }
    )

with open("data/features2.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)
print("class distribution:", dict(cls_counts))
print(f"exploit pre-cutoff: {sum(o['exploit_exists_pre_cutoff'] for o in out)}/{len(out)}")
print(f"wrote {len(out)} rows -> data/features2.csv")
