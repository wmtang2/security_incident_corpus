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
"""Empirical validation analysis of the FST risk model against real-world
exploitation outcomes (CISA KEV within 24 months of prediction date).

Metrics:
  - ROC AUC with bootstrap 95% CI (FST vs EPSS vs CVSS baselines)
  - Average precision (PR AUC)
  - Mann-Whitney U test (exploited vs not-exploited score distributions)
  - Spearman rank correlation FST vs EPSS
  - Exploitation rate per linguistic risk level (low/medium/high/critical)
    with Wilson 95% CIs + chi-square trend
  - Decile calibration table
Outputs: results/metrics.json + PNG plots.
"""
import csv
import json

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score, roc_auc_score

rng = np.random.default_rng(42)
N_BOOT = 2000

rows = list(csv.DictReader(open("data/results.csv")))
print(f"analyzing {len(rows)} rows")


def col(name):
    return np.array([float(r[name]) for r in rows])


Y24 = col("exploited_24m").astype(int)
Y12 = col("exploited_12m").astype(int)
SCORES = {
    "fst_score": col("fst_score"),
    "fst_score_lmbase": col("fst_score_lmbase"),
    "fst_score_fallback": col("fst_score_fallback"),
    "epss": col("epss"),
    "cvss_base": col("cvss_base"),
    "epss_percentile": col("epss_percentile"),
}


def boot_auc(y, s, n=N_BOOT):
    aucs = []
    n_rows = len(y)
    for _ in range(n):
        idx = rng.integers(0, n_rows, n_rows)
        if y[idx].sum() in (0, len(idx)):
            continue
        aucs.append(roc_auc_score(y[idx], s[idx]))
    return float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))


def boot_auc_diff(y, s1, s2, n=N_BOOT):
    diffs = []
    n_rows = len(y)
    for _ in range(n):
        idx = rng.integers(0, n_rows, n_rows)
        if y[idx].sum() in (0, len(idx)):
            continue
        diffs.append(roc_auc_score(y[idx], s1[idx]) - roc_auc_score(y[idx], s2[idx]))
    diffs = np.array(diffs)
    p = 2 * min((diffs <= 0).mean(), (diffs >= 0).mean())
    return float(np.percentile(diffs, 2.5)), float(np.percentile(diffs, 97.5)), float(min(p, 1.0))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    denom = 1 + z**2 / n
    centre = (p + z**2 / (2 * n)) / denom
    half = z * np.sqrt(p * (1 - p) / n + z**2 / (4 * n**2)) / denom
    return float(p), float(max(0, centre - half)), float(min(1, centre + half))


def score_metrics(y, s):
    auc = roc_auc_score(y, s)
    lo, hi = boot_auc(y, s)
    ap = average_precision_score(y, s)
    u = stats.mannwhitneyu(s[y == 1], s[y == 0], alternative="greater")
    return {
        "auc": round(float(auc), 4),
        "auc_ci": [round(lo, 4), round(hi, 4)],
        "avg_precision": round(float(ap), 4),
        "mannwhitney_p": float(u.pvalue),
    }


out = {"n_rows": len(rows), "n_pos_24m": int(Y24.sum()), "n_pos_12m": int(Y12.sum())}

for outcome_name, y in (("24m", Y24), ("12m", Y12)):
    res = {}
    for sname, s in SCORES.items():
        res[sname] = score_metrics(y, s)
    res["spearman_fst_vs_epss"] = float(
        stats.spearmanr(SCORES["fst_score"], SCORES["epss"]).statistic
    )
    for sname in ("epss", "cvss_base"):
        lo, hi, p = boot_auc_diff(y, SCORES["fst_score"], SCORES[sname])
        res[f"auc_diff_fst_minus_{sname}"] = {
            "ci": [round(lo, 4), round(hi, 4)],
            "p": round(p, 5),
        }
    for sname in ("epss", "cvss_base", "fst_score"):
        lo, hi, p = boot_auc_diff(y, SCORES["fst_score_fallback"], SCORES[sname])
        res[f"auc_diff_fallback_minus_{sname}"] = {
            "ci": [round(lo, 4), round(hi, 4)],
            "p": round(p, 5),
        }
    out[f"outcome_{outcome_name}"] = res

# score resolution / ties
out["score_resolution"] = {
    s: {"unique": int(len(set(np.round(v, 4)))), "n": len(v)} for s, v in SCORES.items()
}

# ---- linguistic level calibration (primary outcome)
LEVELS = ["low", "medium", "high", "critical"]
level_idx = np.array([LEVELS.index(r["fst_level"]) for r in rows])
level_table = []
for i, lev in enumerate(LEVELS):
    mask = level_idx == i
    n = int(mask.sum())
    k = int(Y24[mask].sum())
    p, lo, hi = wilson(k, n)
    level_table.append(
        {"level": lev, "n": n, "events": k, "rate": round(p, 4), "ci": [round(lo, 4), round(hi, 4)]}
    )
out["level_calibration_24m"] = level_table
# chi-square trend across levels
tab = np.array([[row["events"], row["n"] - row["events"]] for row in level_table if row["n"] > 0])
if len(tab) > 1:
    chi2, p, *_ = stats.chi2_contingency(tab.T)[:2]
    out["level_chi2"] = {"chi2": float(chi2), "p": float(p)}
    out["level_spearman"] = float(stats.spearmanr(level_idx, Y24).statistic)

# ---- decile calibration
order = np.argsort(SCORES["fst_score"])
dec = np.array_split(order, 10)
dec_table = []
for i, d in enumerate(dec):
    dec_table.append(
        {
            "decile": i + 1,
            "score_min": round(float(SCORES["fst_score"][d].min()), 2),
            "score_max": round(float(SCORES["fst_score"][d].max()), 2),
            "n": len(d),
            "observed_rate": round(float(Y24[d].mean()), 4),
        }
    )
out["decile_calibration_24m"] = dec_table

json.dump(out, open("results/metrics.json", "w"), indent=2)
print(json.dumps(out, indent=2)[:3000])
