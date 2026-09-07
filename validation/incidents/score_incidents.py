#!/usr/bin/env python3
"""Score every incident (and date-matched control) through the FIXED engine.

Inputs per entity:
  TEF  = EPSS at the incident date (exact day, from full cached series).
         For incidents: primary CVE = max-EPSS CVE among the incident's CVEs
         that EPSS scored at that date; if none scored -> 0-day (TEF=0.001).
  Vuln = Exploit-DB exploit for the CVE (incidents: any of cve_all) published
         before the date -> 0.85 else 0.25.
  LM   = realized cost_usd if disclosed; else records x $165; else real-world
         class bucket from the CVE's CWE (NVD): data_exposure $4.88M /
         rce $2.73M / other $0.35M; tier2 ransomware incidents -> $2.73M.
         USD is passed raw; the fixed engine log-maps it.

Output: incidents/scored.csv
"""
import csv
import json
import os
import re
import sys
from datetime import date

sys.path.insert(0, "/workspace")
import src.backend.fst_engine as fe  # noqa: E402
import skfuzzy.control as ctrl  # noqa: E402

rules, _ = fe._get_risk_rules_and_variables()
sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))

from src.backend.database import DatabaseManager  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

ss = ScaleService(DatabaseManager("sqlite:////workspace/fst_risk_data.db"))
lm_scale = ss.get_scale_by_name("loss_magnitude")

# ---- Exploit-DB map
cve_re = re.compile(r"CVE-\d{4}-\d{4,7}")
edb = {}
with open("data/files_exploits.csv", encoding="utf-8", errors="replace") as f:
    for row in csv.DictReader(f):
        try:
            d = date.fromisoformat(row["date_published"][:10])
        except Exception:
            continue
        for m in cve_re.finditer(row.get("codes") or ""):
            edb.setdefault(m.group(0), []).append(d)


def exploit_before(cves, day):
    d0 = date.fromisoformat(day)
    return any(d < d0 for c in cves for d in edb.get(c, []))


# ---- CWE class from NVD cache
DATA_CWE = {"CWE-200", "CWE-201", "CWE-202", "CWE-203", "CWE-209", "CWE-212", "CWE-213",
            "CWE-311", "CWE-312", "CWE-319", "CWE-359", "CWE-532", "CWE-535", "CWE-538",
            "CWE-552", "CWE-611", "CWE-639", "CWE-922", "CWE-22", "CWE-23", "CWE-89",
            "CWE-918", "CWE-522", "CWE-256", "CWE-257", "CWE-260", "CWE-321", "CWE-325",
            "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-79"}
RCE_CWE = {"CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-96", "CWE-502", "CWE-119",
           "CWE-120", "CWE-121", "CWE-122", "CWE-123", "CWE-124", "CWE-134", "CWE-190",
           "CWE-191", "CWE-415", "CWE-416", "CWE-787", "CWE-843", "CWE-908", "CWE-909",
           "CWE-917"}
CLASS_COST = {"data_exposure": 4.88e6, "rce": 2.73e6, "other": 3.5e5}


def cwe_class(cve):
    p = f"data/nvd/{cve}.json"
    if not os.path.exists(p):
        return "other"
    d = json.load(open(p))
    cwes = set()
    for w in d.get("weaknesses", []):
        for desc in w.get("description", []):
            v = desc.get("value", "")
            if v.startswith("CWE-"):
                cwes.add(v)
    if cwes & DATA_CWE:
        return "data_exposure"
    if cwes & RCE_CWE:
        return "rce"
    return "other"


# ---- EPSS series
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


rows = list(csv.DictReader(open("incidents/score_set.csv")))
out = []
for i, r in enumerate(rows):
    cves = [c for c in r["cve_all"].split(";") if c]
    if r["kind"] == "incident":
        best, best_epss = None, -1.0
        for c in cves:
            e = epss_at(c, r["date"])
            if e is not None and e > best_epss:
                best, best_epss = c, e
        cve = best or cves[0]
        tef = best_epss if best_epss >= 0 else 0.001
        zday = int(best is None)
    else:
        cve = r["cve"]
        tef = float(r["tef"])
        zday = 0

    vuln = 0.85 if exploit_before(cves or [cve], r["date"]) else 0.25

    if r["cost_usd"]:
        lm_usd = float(r["cost_usd"])
        lm_src = "realized"
    elif r["records"]:
        lm_usd = float(r["records"]) * 165.0
        lm_src = "records_x_perrecord"
    elif r["tier"] == "tier2":
        lm_usd = CLASS_COST["rce"]
        lm_src = "ransomware_bucket"
    else:
        lm_usd = CLASS_COST[cwe_class(cve)]
        lm_src = "class_bucket"

    lm_u = ss.normalize_value_for_scale(lm_scale, lm_usd, "LM")
    sim.inputs({"threat_event_frequency": min(max(tef, 0.0), 1.0),
                "loss_magnitude": lm_u, "vulnerability": vuln})
    sim.compute()
    score = float(sim.output["risk"])
    out.append({**r, "cve_primary": cve, "tef_final": round(tef, 5), "zero_day": zday,
                "vuln_final": vuln, "lm_usd": round(lm_usd, 0), "lm_src": lm_src,
                "lm_universe": round(lm_u, 3), "score": round(score, 2),
                "level": fe.get_risk_interpretation(score)})
    if (i + 1) % 2000 == 0:
        print(f"  {i+1}/{len(rows)}")

with open("incidents/scored.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)
print(f"scored {len(out)} -> incidents/scored.csv")
