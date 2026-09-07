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
"""Plots for the fixed-configuration re-validation."""
import csv
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

rows = list(csv.DictReader(open("data/results3.csv")))
old1 = {r["cve"]: r for r in csv.DictReader(open("data/results.csv"))}
for r in rows:
    r["fst_cvss_brokencfg"] = old1[r["cve"]]["fst_score"]
y = np.array([int(r["exploited_24m"]) for r in rows])


def col(n):
    return np.array([float(r[n]) for r in rows])


# ROC: fixed vs broken vs baselines
fig, ax = plt.subplots(figsize=(6.5, 6))
for s, name, color, ls in [
    (col("fixed_cvss"), f"FST FIXED config, CVSS inputs (AUC={roc_auc_score(y, col('fixed_cvss')):.3f})", "tab:green", "-"),
    (col("fixed_real"), f"FST FIXED config, real inputs (AUC={roc_auc_score(y, col('fixed_real')):.3f})", "tab:olive", "-"),
    (col("fst_cvss_brokencfg"), f"FST broken/old DB config (AUC={roc_auc_score(y, col('fst_cvss_brokencfg')):.3f})", "tab:red", "--"),
    (col("epss"), f"EPSS alone (AUC={roc_auc_score(y, col('epss')):.3f})", "tab:blue", "-"),
    (col("cvss_base"), f"CVSS base (AUC={roc_auc_score(y, col('cvss_base')):.3f})", "tab:gray", "--"),
]:
    fpr, tpr, _ = roc_curve(y, s)
    ax.plot(fpr, tpr, label=name, color=color, ls=ls, lw=2)
ax.plot([0, 1], [0, 1], "k--", lw=1)
ax.set_xlabel("False positive rate")
ax.set_ylabel("True positive rate")
ax.set_title("Fixed configuration vs broken configuration vs baselines")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig("results/roc_fixed.png", dpi=140)
plt.close(fig)

# Level calibration: fixed config (both input sets)
m = json.load(open("results/study_fixed.json"))
fig, ax = plt.subplots(figsize=(7, 4.5))
for key, name, color, off in [
    ("level_calibration_fixed_cvss_24m", "fixed config, CVSS inputs", "tab:green", -0.12),
    ("level_calibration_fixed_real_24m", "fixed config, real inputs", "tab:olive", 0.12),
]:
    tab = m[key]
    xs = np.arange(len(tab)) + off
    rates = [r["rate"] for r in tab]
    lo = [r["rate"] - r["ci"][0] for r in tab]
    hi = [r["ci"][1] - r["rate"] for r in tab]
    ax.errorbar(xs, rates, yerr=[lo, hi], fmt="o-", capsize=5, lw=2, color=color, label=name)
    for x, r in zip(xs, tab):
        ax.annotate(f"n={r['n']}", (x, r["rate"]), textcoords="offset points", xytext=(0, 9), ha="center", fontsize=7)
ax.set_xticks(range(4), ["low", "medium", "high", "critical"])
ax.set_ylabel("Observed exploitation rate (24m)")
ax.set_title("Calibration of linguistic levels — FIXED configuration")
ax.legend(fontsize=8)
ax.set_ylim(bottom=0)
fig.tight_layout()
fig.savefig("results/level_rates_fixed.png", dpi=140)
plt.close(fig)
print("plots3 written")
