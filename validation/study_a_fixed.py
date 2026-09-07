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
"""Study A re-run against the FIXED configuration, using the engine's public API
with RAW real-world inputs (realized USD losses - the engine log-maps them).

Also re-checks Study C: coverage of the 9,706 realized losses under the fixed
log-scaled LM axis (via the engine's own normalization code path).
"""
import csv
import json
import re
import sys
from datetime import date

sys.path.insert(0, "/workspace")
import numpy as np  # noqa: E402

import src.backend.fst_engine as fe  # noqa: E402
from src.backend.database import DatabaseManager  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

# engine now uses the FIXED root DB by default
ss = ScaleService(DatabaseManager("sqlite:////workspace/fst_risk_data.db"))
lm_scale = ss.get_scale_by_name("loss_magnitude")

# ---- Study A cases (TEF evidence as measured before; LM = raw realized USD)
CASES = [
    ("Equifax", 0.941, 0.85, 1.4e9),
    ("Merck (NotPetya)", 0.959, 0.85, 8.7e8),
    ("FedEx/TNT (NotPetya)", 0.959, 0.85, 4.0e8),
    ("Maersk (NotPetya)", 0.959, 0.85, 3.0e8),
    ("NHS (WannaCry)", 0.959, 0.85, 1.2e8),
    ("Rackspace (ProxyNotShell)", 0.317, 0.25, 1.2e7),
    ("Accellion FTA victims", 0.006, 0.25, 8.1e6),
    ("MOVEit/Cl0p (0-day)", 0.001, 0.25, 4.2e6),
    ("GoAnywhere/Cl0p (0-day)", 0.001, 0.25, 4.2e6),
]
case_out = []
for name, tef, vuln, cost in CASES:
    r = fe.calculate_risk_with_interpretation(
        threat_event_frequency=tef, loss_magnitude=cost, vulnerability=vuln
    )
    case_out.append({"incident": name, "cost_usd": cost, "tef": tef, "vuln": vuln,
                     "score": round(r["score"], 2), "level": r["interpretation"]})
    print(f"{name:28s} cost=${cost/1e6:8.1f}M -> {r['score']:6.2f} [{r['interpretation']}]")

# controls (same as Study A): potential LM = class bucket USD
rows = list(csv.DictReader(open("data/results3.csv")))
controls = [r for r in rows if r["cve"] in {
    "CVE-2021-23682", "CVE-2004-2016", "CVE-1999-0583", "CVE-2007-5527", "CVE-2021-46010",
    "CVE-2021-35336", "CVE-2021-30232", "CVE-2019-16993", "CVE-2021-27177", "CVE-2001-0191"}]
ctrl_out = []
for r in controls:
    res = fe.calculate_risk_with_interpretation(
        threat_event_frequency=float(r["epss"]),
        loss_magnitude=float(r["lm_class_cost_usd"]),
        vulnerability=0.25,
    )
    ctrl_out.append({"cve": r["cve"], "cvss_base": r["cvss_base"],
                     "score": round(res["score"], 2), "level": res["interpretation"]})
    print(f"control {r['cve']:18s} cvss={r['cvss_base']:4s} -> {res['score']:6.2f} [{res['interpretation']}]")

from scipy import stats as st

u = st.mannwhitneyu([c["score"] for c in case_out], [c["score"] for c in ctrl_out],
                    alternative="greater")
print(f"cases vs controls: median {np.median([c['score'] for c in case_out]):.1f} vs "
      f"{np.median([c['score'] for c in ctrl_out]):.1f}, MWU p={u.pvalue:.2e}")

# ---- Study C re-check: realized losses through the FIXED scale
z = np.load("results/losses.npz")
all_loss = np.concatenate([z["hhs"], z["wa"], z["prc"]])
u_vals = ss.normalize_array_for_scale(lm_scale, all_loss, "LM")
MFS = {"low": (0, 0, 4), "medium": (2, 5, 8), "high": (6, 10, 10)}


def mu(x, abc):
    a, b, c = abc
    return max(0.0, min((x - a) / (b - a + 1e-30), (c - x) / (c - b + 1e-30), 1.0))


def band(x):
    return max(MFS, key=lambda k: mu(x, MFS[k]))


bands = [band(v) for v in u_vals]
share = {b: float(np.mean([x == b for x in bands])) for b in MFS}
study_c_fixed = {
    "median_universe": float(np.median(u_vals)),
    "band_share": share,
    "over_range_rejected": 0,  # nothing rejected: max $78.6B < $1e12
    "max_loss_usd": float(all_loss.max()),
    "max_loss_universe": float(u_vals.max()),
}
print("fixed-scale coverage of 9,706 real losses:", json.dumps(study_c_fixed, indent=1))

json.dump({"cases": case_out, "controls": ctrl_out,
           "case_control_mwu_p": float(u.pvalue), "study_c_fixed": study_c_fixed},
          open("results/study_a_c_fixed.json", "w"), indent=2)
