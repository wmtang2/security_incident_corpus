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
"""Run the FSTTool risk engine (its real code, pointed at the sane DB
configuration found in fst_risk_data.test_copy.db / db_backups) over every
CVE in the feature set, plus two sensitivity variants:

  fst_score        primary: engine's calculate_risk() with
                   TEF=EPSS@cutoff, LM=CVSSv3 impactScore/6.04*10, Vuln=exploitability/3.915
  fst_score_lmbase S1: same but LM = CVSS baseScore (0-10)
  fst_score_fallback S2: README-documented hardcoded membership functions
                   with the same rule base

Also demonstrates the state of the SHIPPED database (fst_risk_data.db in the
repo root), whose membership functions are degenerate (LM MFs ~1e-18, risk
MFs [1,1,1]).

Output: data/results.csv, results/broken_db_demo.json
"""
import csv
import json
import shutil
import sys
import time

sys.path.insert(0, "/workspace")

SANE_DB = "/workspace/validation/model_sane.db"
shutil.copy("/workspace/fst_risk_data.test_copy.db", SANE_DB)

import src.backend.database as dbmod  # noqa: E402
from src.backend.database import DatabaseManager  # noqa: E402

mgr = DatabaseManager(f"sqlite:///{SANE_DB}")
dbmod._db_manager = mgr  # singleton used by RulesManager

import src.backend.fst_engine as fe  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

fe._scale_service = ScaleService(mgr)  # engine builds its own DatabaseManager otherwise
fe.reset_rules_cache()

# ---- broken shipped-DB demo (root fst_risk_data.db)
broken_demo = {}
default_mgr = DatabaseManager("sqlite:////workspace/fst_risk_data.db")
_orig_service = fe._scale_service
fe._scale_service = ScaleService(default_mgr)
fe.reset_rules_cache()
try:
    for tef, lm, vuln in [(0.9, 9.0, 0.9), (0.5, 5.0, 0.5), (0.01, 0.5, 0.05)]:
        try:
            r = fe.calculate_risk_with_interpretation(
                threat_event_frequency=tef, loss_magnitude=lm, vulnerability=vuln
            )
            broken_demo[f"{tef}/{lm}/{vuln}"] = {
                "score": r["score"],
                "level": r["interpretation"],
            }
        except Exception as e:
            broken_demo[f"{tef}/{lm}/{vuln}"] = {"error": f"{type(e).__name__}: {e}"}
finally:
    fe._scale_service = _orig_service
    fe.reset_rules_cache()
json.dump(broken_demo, open("results/broken_db_demo.json", "w"), indent=2)
print("broken shipped-DB demo:", json.dumps(broken_demo))

# ---- rules + persistent simulation
rules, variables = fe._get_risk_rules_and_variables()
print(f"loaded {len(rules)} rules")
import skfuzzy.control as ctrl  # noqa: E402

system = ctrl.ControlSystem(rules)
sim = ctrl.ControlSystemSimulation(system)

# equivalence check: engine's calculate_risk vs persistent sim
import random

random.seed(0)
max_diff = 0.0
for _ in range(8):
    t, l, v = random.random(), random.uniform(0, 10), random.random()
    a = fe.calculate_risk(threat_event_frequency=t, loss_magnitude=l, vulnerability=v)
    sim.inputs({"threat_event_frequency": t, "loss_magnitude": l, "vulnerability": v})
    sim.compute()
    max_diff = max(max_diff, abs(a - float(sim.output["risk"])))
print(f"equivalence check: max diff = {max_diff:.2e}")
assert max_diff < 1e-6


def score_sane(tef, lm010, vuln01):
    sim.inputs(
        {"threat_event_frequency": tef, "loss_magnitude": lm010, "vulnerability": vuln01}
    )
    sim.compute()
    return float(sim.output["risk"])

# ---- fallback (README-documented) membership functions, same rule base
import numpy as np  # noqa: E402
import skfuzzy as fuzz  # noqa: E402

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
vals = {
    vid: (s, l)
    for vid, s, l in conn.execute(
        "SELECT v.id, s.name, v.label FROM ordinal_values v "
        "JOIN ordinal_scales s ON v.scale_id=s.id"
    )
}
combos = set()
for ant, cons in conn.execute(
    "SELECT antecedents_by_value_id, consequent FROM fuzzy_rules"
):
    d = json.loads(ant)
    labels = {k: vals[v][1] for k, v in d.items()}
    combos.add(
        (
            labels["threat_event_frequency"],
            labels["loss_magnitude"],
            labels["vulnerability"],
            cons.split(":")[1],
        )
    )
print(f"decoded {len(combos)} unique rule combos from DB")
fb_rules = [ctrl.Rule(tef_fb[t] & lm_fb[l] & v_fb[v], risk_fb[c]) for (t, l, v, c) in combos]
fb_system = ctrl.ControlSystem(fb_rules)
fb_sim = ctrl.ControlSystemSimulation(fb_system)


def score_fallback(tef, lm010, vuln01):
    fb_sim.inputs(
        {
            "threat_event_frequency": tef,
            "loss_magnitude": lm010,
            "vulnerability": min(max(vuln01 * 10.0, 0.0), 10.0),
        }
    )
    fb_sim.compute()
    return float(fb_sim.output["risk"])


# ---- batch scoring
rows = list(csv.DictReader(open("data/features.csv")))
print(f"scoring {len(rows)} CVEs ...")
t0 = time.time()
out_rows = []
for i, r in enumerate(rows):
    epss = float(r["epss"])
    lm = float(r["lm_010"])
    vuln = float(r["vuln_01"])
    base = float(r["cvss_base"])
    s_main = score_sane(epss, lm, vuln)
    s_lmbase = score_sane(epss, min(max(base, 0.0), 10.0), vuln)
    s_fb = score_fallback(epss, lm, vuln)
    out_rows.append(
        {
            **r,
            "fst_score": round(s_main, 4),
            "fst_level": fe.get_risk_interpretation(s_main),
            "fst_score_lmbase": round(s_lmbase, 4),
            "fst_score_fallback": round(s_fb, 4),
        }
    )
    if (i + 1) % 250 == 0:
        print(f"  {i+1}/{len(rows)} ({(time.time()-t0)/(i+1)*1000:.0f} ms/row)")

with open("data/results.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
    w.writeheader()
    w.writerows(out_rows)
print(f"done in {time.time()-t0:.0f}s -> data/results.csv")

