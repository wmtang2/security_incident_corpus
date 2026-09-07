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
"""Re-run the cohort validation against the FIXED configuration (fixed root DB).

Variants:
  fixed_cvss  TEF=EPSS, LM=CVSS impact rescaled 0-10, Vuln=CVSS exploitability/3.915
  fixed_real  TEF=EPSS, LM=real-world class cost in USD (engine log-maps it),
              Vuln=Exploit-DB evidence (0.85/0.25)

Output: data/results3.csv
"""
import csv
import sys
import time

sys.path.insert(0, "/workspace")

import src.backend.fst_engine as fe  # noqa: E402

rules, variables = fe._get_risk_rules_and_variables()
print(f"loaded {len(rules)} rules from FIXED db")
import skfuzzy.control as ctrl  # noqa: E402

sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))

# equivalence check vs public API on fixed DB
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


def score(tef, lm_u, vuln01):
    sim.inputs({"threat_event_frequency": tef, "loss_magnitude": lm_u, "vulnerability": vuln01})
    sim.compute()
    return float(sim.output["risk"])


# LM real-USD -> universe via the engine's own (now log) normalization
from src.backend.database import DatabaseManager
from src.backend.services.scale_service import ScaleService

ss = ScaleService(DatabaseManager("sqlite:////workspace/fst_risk_data.db"))
lm_scale = ss.get_scale_by_name("loss_magnitude")
print(f"LM scale: real [{lm_scale.real_world_min}, {lm_scale.real_world_max}] "
      f"{lm_scale.real_world_unit}, mapping={lm_scale.real_world_mapping}")


def lm_usd_to_universe(usd):
    return ss.normalize_value_for_scale(lm_scale, float(usd), "LM")


rows = list(csv.DictReader(open("data/features2.csv")))
print(f"scoring {len(rows)} CVEs against FIXED config ...")
t0 = time.time()
out = []
for i, r in enumerate(rows):
    epss = float(r["epss"])
    lm_cvss = float(r["lm_010"])
    vuln_cvss = float(r["vuln_01"])
    lm_real_u = lm_usd_to_universe(float(r["lm_class_cost_usd"]))
    vuln_real = float(r["vuln_real"])
    s_cvss = score(epss, lm_cvss, vuln_cvss)
    s_real = score(epss, lm_real_u, vuln_real)
    out.append({
        **r,
        "lm_real_universe": round(lm_real_u, 4),
        "fixed_cvss": round(s_cvss, 4),
        "fixed_cvss_level": fe.get_risk_interpretation(s_cvss),
        "fixed_real": round(s_real, 4),
        "fixed_real_level": fe.get_risk_interpretation(s_real),
    })
    if (i + 1) % 500 == 0:
        print(f"  {i+1}/{len(rows)} ({(time.time()-t0)/(i+1)*1000:.0f} ms/row)")

with open("data/results3.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out[0].keys()))
    w.writeheader()
    w.writerows(out)
print(f"done in {time.time()-t0:.0f}s -> data/results3.csv")
