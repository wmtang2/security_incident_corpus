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
"""Study A - famous real-world incidents with disclosed dollar losses.

For each incident: root-cause CVE (public record); TEF = historical EPSS at the
incident-relevant date (0.001 if the CVE was not yet published/scored - a 0-day);
Vuln = Exploit-DB public exploit existing before the incident date (0.85/0.25);
LM = (a) potential class cost bucket, and (b) realized publicly reported cost,
mapped via the repaired log scale (the linear $1B scale REJECTS >$1B losses).

Controls: high-CVSS CVEs (base >= 7.5) from the cohort with no KEV exploitation,
no pre-cutoff public exploit, mid-range EPSS.

Output: results/study_a.json + printed table.
"""
import csv
import json
import math
import random
import re
import shutil
import sys
import time
from datetime import date

sys.path.insert(0, "/workspace")
import numpy as np  # noqa: E402
import requests  # noqa: E402

CASES = [
    ("Equifax", "CVE-2017-5638", date(2017, 3, 10), 1.4e9, "10-K: $1.38B + $700M settlement"),
    ("Merck (NotPetya)", "CVE-2017-0144", date(2017, 6, 27), 8.7e8, "FY2017 10-K ~$870M"),
    ("FedEx/TNT (NotPetya)", "CVE-2017-0144", date(2017, 6, 27), 4.0e8, "FY2018 ~$400M"),
    ("Maersk (NotPetya)", "CVE-2017-0144", date(2017, 6, 27), 3.0e8, "Q2-17 ~$250-300M"),
    ("NHS (WannaCry)", "CVE-2017-0144", date(2017, 5, 12), 1.2e8, "UK DoH est. £92M"),
    ("Rackspace (ProxyNotShell)", "CVE-2022-41082", date(2022, 12, 2), 1.2e7, "10-Q ~$12M (approx)"),
    ("Accellion FTA victims", "CVE-2021-27101", date(2020, 12, 20), 8.1e6, "2023 settlement $8.1M"),
    ("MOVEit/Cl0p", "CVE-2023-34362", date(2023, 5, 31), 4.2e6, "Progress 10-Q direct costs (conservative)"),
    ("GoAnywhere/Cl0p", "CVE-2023-0669", date(2023, 2, 1), 4.2e6, "no disclosed $; placeholder bucket"),
]
EPSS_DATE = {
    "CVE-2017-5638": "2021-07-19",  # earliest EPSS snapshot (post-incident, caveat)
    "CVE-2017-0144": "2021-07-19",
    "CVE-2022-41082": "2022-12-01",  # incident window
    "CVE-2021-27101": "2021-07-19",  # earliest snapshot (post-incident, caveat)
    "CVE-2023-34362": "2023-05-15",  # pre-disclosure: expect none (0-day)
    "CVE-2023-0669": "2023-01-25",  # pre-disclosure: expect none (0-day)
}
CLASS_COST_USD = {"data_exposure": 4.88e6, "rce": 2.73e6, "other": 3.5e5}
CVE_CLASS = {"CVE-2017-5638": "rce", "CVE-2017-0144": "rce", "CVE-2022-41082": "rce",
             "CVE-2021-27101": "data_exposure", "CVE-2023-34362": "data_exposure",
             "CVE-2023-0669": "rce"}

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


def exploit_before(cve, day):
    return any(d < day for d in edb.get(cve, []))


import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

FALLBACK_DATES = ["2021-08-02", "2021-09-01", "2022-01-01"]


def epss_at(cve, day):
    for d in [day] + FALLBACK_DATES:
        try:
            r = requests.get("https://api.first.org/data/v1/epss",
                             params={"cve": cve, "date": d}, timeout=20, verify=False)
            data = r.json().get("data", [])
            if data:
                if d != day:
                    print(f"  note: {cve} EPSS unavailable @{day}, using @{d}")
                return float(data[0]["epss"])
        except Exception as e:
            print(f"  EPSS fetch failed {cve}@{d}: {e}")
            break
    return None

# ---- engine setup (same as run_model2)
SANE_DB = "/workspace/validation/model_sane.db"
shutil.copy("/workspace/fst_risk_data.test_copy.db", SANE_DB)
import src.backend.database as dbmod  # noqa: E402
from src.backend.database import DatabaseManager  # noqa: E402

dbmod._db_manager = DatabaseManager(f"sqlite:///{SANE_DB}")
import src.backend.fst_engine as fe  # noqa: E402
import skfuzzy.control as ctrl  # noqa: E402
import skfuzzy as fuzz  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

fe._scale_service = ScaleService(dbmod._db_manager)
fe.reset_rules_cache()
rules, _ = fe._get_risk_rules_and_variables()
sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))

tef_fb = ctrl.Antecedent(np.arange(0, 1.01, 0.01), "threat_event_frequency")
tef_fb["low"] = fuzz.trimf(tef_fb.universe, [0, 0, 0.4])
tef_fb["medium"] = fuzz.trimf(tef_fb.universe, [0.2, 0.5, 0.8])
tef_fb["high"] = fuzz.trimf(tef_fb.universe, [0.6, 1, 1])
lm_fb = ctrl.Antecedent(np.arange(0, 10.1, 0.1), "loss_magnitude")
v_fb = ctrl.Antecedent(np.arange(0, 10.1, 0.1), "vulnerability")
for var in (lm_fb, v_fb):
    var["low"] = fuzz.trimf(var.universe, [0, 0, 4])
    var["medium"] = fuzz.trimf(var.universe, [2, 5, 8])
    var["high"] = fuzz.trimf(var.universe, [6, 10, 10])
risk_fb = ctrl.Consequent(np.arange(0, 101, 1.0), "risk")
risk_fb["low"] = fuzz.trimf(risk_fb.universe, [0, 0, 30])
risk_fb["medium"] = fuzz.trimf(risk_fb.universe, [20, 40, 60])
risk_fb["high"] = fuzz.trimf(risk_fb.universe, [50, 70, 90])
risk_fb["critical"] = fuzz.trimf(risk_fb.universe, [80, 100, 100])
import sqlite3

conn = sqlite3.connect(SANE_DB)
vals = {vid: (s, l) for vid, s, l in conn.execute(
    "SELECT v.id, s.name, v.label FROM ordinal_values v JOIN ordinal_scales s ON v.scale_id=s.id")}
combos = set()
for ant, cons in conn.execute("SELECT antecedents_by_value_id, consequent FROM fuzzy_rules"):
    d = json.loads(ant)
    lb = {k: vals[v][1] for k, v in d.items()}
    combos.add((lb["threat_event_frequency"], lb["loss_magnitude"], lb["vulnerability"], cons.split(":")[1]))
fb_sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(
    [ctrl.Rule(tef_fb[t] & lm_fb[l] & v_fb[v], risk_fb[c]) for (t, l, v, c) in combos]))


def log_map(usd):
    return min(10.0 * math.log10(1.0 + usd) / math.log10(1.0 + 1e9), 10.0)


def score_both(tef, lm_u, vuln01):
    sim.inputs({"threat_event_frequency": tef, "loss_magnitude": lm_u, "vulnerability": vuln01})
    sim.compute()
    s1 = float(sim.output["risk"])
    fb_sim.inputs({"threat_event_frequency": tef, "loss_magnitude": lm_u,
                   "vulnerability": min(max(vuln01 * 10, 0), 10)})
    fb_sim.compute()
    return s1, float(fb_sim.output["risk"])


def level(score):
    mfs = {"low": (0, 0, 30), "medium": (20, 40, 60), "high": (50, 70, 90), "critical": (80, 100, 100)}
    def mu(x, abc):
        a, b, c = abc
        return max(0.0, min((x - a) / (b - a + 1e-30), (c - x) / (c - b + 1e-30), 1.0))
    return max(mfs, key=lambda k: mu(score, mfs[k]))


# ---- cases
case_rows = []
for name, cve, idate, cost, src in CASES:
    tef = epss_at(cve, EPSS_DATE[cve])
    time.sleep(0.4)
    tef_used = tef if tef is not None else 0.001
    vuln = 0.85 if exploit_before(cve, idate) else 0.25
    lm_pot = log_map(CLASS_COST_USD[CVE_CLASS[cve]])
    lm_real = log_map(cost)
    s_pot = score_both(tef_used, lm_pot, vuln)
    s_real = score_both(tef_used, lm_real, vuln)
    case_rows.append({
        "incident": name, "cve": cve, "date": str(idate), "cost_usd": cost, "source": src,
        "epss_used": tef_used, "epss_note": "none (0-day)" if tef is None else f"@{EPSS_DATE[cve]}",
        "exploit_public_before": vuln == 0.85,
        "sane_potential": round(s_pot[0], 2), "fb_potential": round(s_pot[1], 2),
        "sane_realized": round(s_real[0], 2), "fb_realized": round(s_real[1], 2),
        "fb_realized_level": level(s_real[1]),
    })
    print(f"{name:28s} TEF={tef_used:.3f} vuln={vuln}  sane(realized LM)={s_real[0]:6.2f}  "
          f"fb(realized LM)={s_real[1]:6.2f} [{level(s_real[1])}]")

# ---- controls
rows = list(csv.DictReader(open("data/results2.csv")))
pool = [r for r in rows
        if r["exploited_24m"] == "0" and float(r["cvss_base"]) >= 7.5
        and r["exploit_exists_pre_cutoff"] == "0" and 0.005 < float(r["epss"]) < 0.2]
random.seed(7)
controls = random.sample(pool, 10)
ctrl_rows = []
for r in controls:
    lm_pot = log_map(float(r["lm_class_cost_usd"]))
    s = score_both(float(r["epss"]), lm_pot, 0.25)
    ctrl_rows.append({"cve": r["cve"], "cvss_base": r["cvss_base"], "epss": r["epss"],
                      "sane_potential": round(s[0], 2), "fb_potential": round(s[1], 2),
                      "fb_level": level(s[1])})
    print(f"control {r['cve']} cvss={r['cvss_base']} epss={float(r['epss']):.3f} -> fb {s[1]:.2f} [{level(s[1])}]")

# ---- summary stats
from scipy import stats as st

case_scores = [c["fb_potential"] for c in case_rows]
ctrl_scores = [c["fb_potential"] for c in ctrl_rows]
u = st.mannwhitneyu(case_scores, ctrl_scores, alternative="greater")
spear = st.spearmanr([math.log10(c["cost_usd"]) for c in case_rows],
                     [c["fb_realized"] for c in case_rows])
out = {
    "cases": case_rows,
    "controls": ctrl_rows,
    "case_vs_control_mwu_p": float(u.pvalue),
    "case_median_fb_potential": float(np.median(case_scores)),
    "control_median_fb_potential": float(np.median(ctrl_scores)),
    "spearman_logcost_vs_fb_realized": float(spear.statistic),
    "spearman_p": float(spear.pvalue),
}
json.dump(out, open("results/study_a.json", "w"), indent=2)
print(f"\ncase median (potential LM) = {out['case_median_fb_potential']}, "
      f"control median = {out['control_median_fb_potential']}, MWU p={u.pvalue:.4f}")
print(f"Spearman(log realized cost, fb realized-LM score) = {spear.statistic:.3f} (p={spear.pvalue:.4f})")

