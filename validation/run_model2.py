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
"""Study B - re-run the FST engine with real-world-data inputs.

Variants (all use TEF=EPSS@2024-06-01, Vuln=Exploit-DB evidence):
  fst_real_lin   sane DB config, LM passed as raw USD (engine's linear $1B scale)
  fst_real_log   sane DB config, LM pre-mapped via repaired log scale (0-10)
  fst_fb_real_lin  fallback README membership functions, LM linear
  fst_fb_real_log  fallback README membership functions, LM log

Output: data/results2.csv (old + new columns side by side)
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
dbmod._db_manager = mgr

import src.backend.fst_engine as fe  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

fe._scale_service = ScaleService(mgr)
fe.reset_rules_cache()

import skfuzzy.control as ctrl  # noqa: E402

rules, variables = fe._get_risk_rules_and_variables()
sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))

# equivalence spot-check vs engine's public API
a = fe.calculate_risk(threat_event_frequency=0.5, loss_magnitude=5.0, vulnerability=0.5)
sim.inputs({"threat_event_frequency": 0.5, "loss_magnitude": 5.0, "vulnerability": 0.5})
sim.compute()
assert abs(a - sim.output["risk"]) < 1e-9


def score_sane_universe(tef, lm_universe, vuln01):
    """Score with LM already on the 0-10 universe."""
    sim.inputs(
        {"threat_event_frequency": tef, "loss_magnitude": lm_universe, "vulnerability": vuln01}
    )
    sim.compute()
    return float(sim.output["risk"])


# fallback (README) system
import numpy as np  # noqa: E402
import skfuzzy as fuzz  # noqa: E402
import sqlite3

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

conn = sqlite3.connect(SANE_DB)
vals = {
    vid: (s, l)
    for vid, s, l in conn.execute(
        "SELECT v.id, s.name, v.label FROM ordinal_values v JOIN ordinal_scales s ON v.scale_id=s.id"
    )
}
combos = set()
for ant, cons in conn.execute("SELECT antecedents_by_value_id, consequent FROM fuzzy_rules"):
    d = json.loads(ant)
    labels = {k: vals[v][1] for k, v in d.items()}
    combos.add((labels["threat_event_frequency"], labels["loss_magnitude"], labels["vulnerability"], cons.split(":")[1]))
fb_sim = ctrl.ControlSystemSimulation(
    ctrl.ControlSystem([ctrl.Rule(tef_fb[t] & lm_fb[l] & v_fb[v], risk_fb[c]) for (t, l, v, c) in combos])
)


def score_fb(tef, lm010, vuln01):
    fb_sim.inputs(
        {"threat_event_frequency": tef, "loss_magnitude": lm010, "vulnerability": min(max(vuln01 * 10, 0), 10)}
    )
    fb_sim.compute()
    return float(fb_sim.output["risk"])


rows = list(csv.DictReader(open("data/features2.csv")))
print(f"scoring {len(rows)} CVEs (real-data inputs) ...")
t0 = time.time()
out = []
for i, r in enumerate(rows):
    epss = float(r["epss"])
    lm_lin = float(r["lm_lin"])
    lm_log = float(r["lm_log"])
    vuln = float(r["vuln_real"])
    out.append(
        {
            **r,
            "fst_real_lin": round(score_sane_universe(epss, lm_lin, vuln), 4),
            "fst_real_log": round(score_sane_universe(epss, lm_log, vuln), 4),
            "fst_fb_real_lin": round(score_fb(epss, lm_lin, vuln), 4),
            "fst_fb_real_log": round(score_fb(epss, lm_log, vuln), 4),
        }
    )
    if (i + 1) % 500 == 0:
        print(f"  {i+1}/{len(rows)} ({(time.time()-t0)/(i+1)*1000:.0f} ms/row)")

with open("data/results2.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)
print(f"done in {time.time()-t0:.0f}s -> data/results2.csv")
