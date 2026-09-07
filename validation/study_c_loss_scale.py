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
"""Study C - validate the model's Loss Magnitude scale against REALIZED losses.

Real incident data:
  - HHS OCR breach portal (7.8k US healthcare breaches, 2009-2026, individuals affected)
  - Washington AG breach notifications (1,649 breaches, all industries, 2016-2026)
  - Privacy Rights Clearinghouse chronology, cleaned (295 incidents, research dataset)

USD conversion (public per-record cost estimates, with sensitivity):
  - healthcare: $408/record (IBM Cost of a Data Breach, healthcare per-record figure)
  - general:    $165/record (IBM Cost of a Data Breach 2023, global per-record avg)
  - sensitivity bounds: $100 and $500/record for all sources

The model's LM scale: real-world range $0..$1e9, universe [0,10], LINEAR.
Membership functions (sane DB): low[0,0,4], medium[2,5,8], high[6,10,10]
(i.e. in dollars: low $0-400M, medium $200M-800M, high $600M-1B).
"""
import csv
import json
import math
import sys

import numpy as np

sys.path.insert(0, "/workspace")

PER_RECORD = {"hhs": 408.0, "wa": 165.0, "prc": 165.0}
SENS = [100.0, 500.0]


def load_hhs():
    out = []
    with open("data/hhs_breach_clean.csv", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                n = float(r["Individuals Affected"])
            except (ValueError, KeyError, TypeError):
                continue
            if n > 0:
                out.append(n)
    return np.array(out)


def load_wa():
    d = json.load(open("data/wa_breaches.json"))
    out = []
    for r in d:
        try:
            n = float(r["washingtoniansaffected"])
        except (ValueError, KeyError, TypeError):
            continue
        if n > 0:
            out.append(n)
    return np.array(out)


def load_prc():
    import pandas as pd

    df = pd.read_excel("data/prc_cyber_loss.xlsx")
    v = pd.to_numeric(df["Records_Affected"], errors="coerce").dropna()
    return v[v > 0].to_numpy()


hhs_n, wa_n, prc_n = load_hhs(), load_wa(), load_prc()
print(f"incidents with records>0: HHS={len(hhs_n)}, WA={len(wa_n)}, PRC={len(prc_n)}")

losses = {
    "hhs": hhs_n * PER_RECORD["hhs"],
    "wa": wa_n * PER_RECORD["wa"],
    "prc": prc_n * PER_RECORD["prc"],
}
all_loss = np.concatenate(list(losses.values()))
all_loss_sens = {
    "low_per_record_100": np.concatenate([hhs_n * 100, wa_n * 100, prc_n * 100]),
    "high_per_record_500": np.concatenate([hhs_n * 500, wa_n * 500, prc_n * 500]),
}

# ---- model LM scale mapping (as implemented in ScaleService._real_to_universe)
def lm_universe_linear(usd):
    return np.clip(usd / 1e9 * 10.0, 0, 10)  # linear real [0,1e9] -> universe [0,10]


def trimf_mu(x, abc):
    a, b, c = abc
    if a == b == c:
        return 1.0 if x == a else 0.0
    return float(np.clip(np.minimum((x - a) / (b - a + 1e-30), (c - x) / (c - b + 1e-30)), 0, 1))


MFS = {"low": (0, 0, 4), "medium": (2, 5, 8), "high": (6, 10, 10)}


def max_membership(u):
    return max(trimf_mu(u, abc) for abc in MFS.values())


res = {
    "n_incidents": {k: len(v) for k, v in losses.items()},
    "per_record_usd": PER_RECORD,
    "loss_stats_usd": {},
    "model_scale": {},
}

for k, v in losses.items():
    res["loss_stats_usd"][k] = {
        "median": float(np.median(v)),
        "p90": float(np.percentile(v, 90)),
        "p99": float(np.percentile(v, 99)),
        "max": float(v.max()),
    }

u = lm_universe_linear(all_loss)
maxmu = np.array([max_membership(x) for x in u])
res["model_scale"]["linear_universe"] = {
    "median_universe": float(np.median(u)),
    "p99_universe": float(np.percentile(u, 99)),
    "frac_max_membership_lt_0.05": float((maxmu < 0.05).mean()),
    "frac_classified_low_dominant": float(
        np.mean([trimf_mu(x, MFS["low"]) >= max(trimf_mu(x, MFS["medium"]), trimf_mu(x, MFS["high"])) for x in u])
    ),
}
for k, v in all_loss_sens.items():
    us = lm_universe_linear(v)
    mm = np.array([max_membership(x) for x in us])
    res["model_scale"][k] = {
        "median_universe": float(np.median(us)),
        "frac_max_membership_lt_0.05": float((mm < 0.05).mean()),
    }

# over-$1B losses are OUT OF RANGE for the model
res["model_scale"]["n_over_1B"] = int((all_loss > 1e9).sum())
res["model_scale"]["frac_over_1B"] = float((all_loss > 1e9).mean())

# ---- demonstrate through the real engine code path: normalize a $1.4B loss (Equifax)
from src.backend.database import DatabaseManager
from src.backend.services.scale_service import ScaleService

ss = ScaleService(DatabaseManager("sqlite:////workspace/validation/model_sane.db"))
lm_scale = ss.get_scale_by_name("loss_magnitude")
demo = {}
for label, usd in [("Equifax $1.4B", 1.4e9), ("Merck $0.87B", 8.7e8), ("median breach", float(np.median(all_loss)))]:
    try:
        demo[label] = {"universe": float(ss.normalize_value_for_scale(lm_scale, usd, "LM"))}
    except Exception as e:
        demo[label] = {"error": f"{type(e).__name__}: {str(e)[:120]}"}
res["engine_normalization_demo"] = demo

# ---- empirical repair: log-scale mapping into the same [0,10] universe
def lm_universe_log(usd):
    return 10.0 * np.log10(1.0 + usd) / np.log10(1.0 + 1e9)


ulog = lm_universe_log(all_loss)
res["log_repair"] = {
    "median_universe": float(np.median(ulog)),
    "band_share": {
        band: float(np.mean([trimf_mu(x, MFS[band]) >= max(trimf_mu(x, MFS[o]) for o in MFS if o != band) for x in ulog]))
        for band in MFS
    },
    "examples": {lbl: round(float(lm_universe_log(np.array([v]))[0]), 2)
                 for lbl, v in [("$100k", 1e5), ("$1M", 1e6), ("$4.88M", 4.88e6), ("$50M", 5e7), ("$400M", 4e8), ("$1B", 1e9)]},
}

json.dump(res, open("results/study_c.json", "w"), indent=2)
# save loss arrays for plotting
np.savez("results/losses.npz", hhs=losses["hhs"], wa=losses["wa"], prc=losses["prc"])
print(json.dumps(res, indent=2))
