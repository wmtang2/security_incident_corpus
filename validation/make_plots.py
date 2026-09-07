#!/usr/bin/env python3
"""Plots for the validation report."""
import csv
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from sklearn.metrics import roc_auc_score, roc_curve

rows = list(csv.DictReader(open("data/results.csv")))
y = np.array([int(r["exploited_24m"]) for r in rows])


def col(name):
    return np.array([float(r[name]) for r in rows])


fst, epss, cvss = col("fst_score"), col("epss"), col("cvss_base")
metrics = json.load(open("results/metrics.json"))

# ROC
fig, ax = plt.subplots(figsize=(6, 6))
for s, name, color in [
    (fst, f"FST model (AUC={roc_auc_score(y, fst):.3f})", "tab:red"),
    (epss, f"EPSS alone (AUC={roc_auc_score(y, epss):.3f})", "tab:blue"),
    (cvss, f"CVSS base (AUC={roc_auc_score(y, cvss):.3f})", "tab:gray"),
]:
    fpr, tpr, _ = roc_curve(y, s)
    ax.plot(fpr, tpr, label=name, color=color, lw=2)
ax.plot([0, 1], [0, 1], "k--", lw=1)
ax.set_xlabel("False positive rate")
ax.set_ylabel("True positive rate")
ax.set_title("Discrimination: KEV exploitation within 24 months")
ax.legend(loc="lower right")
fig.tight_layout()
fig.savefig("results/roc_curves.png", dpi=140)
plt.close(fig)

# Level rates
lev = metrics["level_calibration_24m"]
fig, ax = plt.subplots(figsize=(6, 4))
xs = np.arange(len(lev))
rates = [r["rate"] for r in lev]
lo = [r["rate"] - r["ci"][0] for r in lev]
hi = [r["ci"][1] - r["rate"] for r in lev]
ax.errorbar(xs, rates, yerr=[lo, hi], fmt="o-", capsize=5, lw=2, color="tab:red")
for x, r in zip(xs, lev):
    ax.annotate(f"n={r['n']}", (x, r["rate"]), textcoords="offset points", xytext=(0, 10), ha="center", fontsize=8)
ax.set_xticks(xs, [r["level"] for r in lev])
ax.set_ylabel("Observed exploitation rate (24m)")
ax.set_title("Calibration by FST linguistic risk level")
ax.set_ylim(bottom=0)
fig.tight_layout()
fig.savefig("results/level_rates.png", dpi=140)
plt.close(fig)

# Decile calibration
dec = metrics["decile_calibration_24m"]
fig, ax = plt.subplots(figsize=(6, 4))
mids = [(d["score_min"] + d["score_max"]) / 2 for d in dec]
rates = [d["observed_rate"] for d in dec]
ax.plot(mids, rates, "o-", color="tab:red", lw=2)
ax.set_xlabel("FST risk score (decile midpoint)")
ax.set_ylabel("Observed exploitation rate (24m)")
ax.set_title("Calibration by FST score decile")
fig.tight_layout()
fig.savefig("results/calibration_deciles.png", dpi=140)
plt.close(fig)

# Score distributions
fig, ax = plt.subplots(figsize=(7, 4))
bins = np.linspace(0, 100, 51)
ax.hist(fst[y == 0], bins=bins, density=True, alpha=0.6, label=f"not exploited (n={(y==0).sum()})", color="tab:blue")
ax.hist(fst[y == 1], bins=bins, density=True, alpha=0.6, label=f"exploited <=24m (n={(y==1).sum()})", color="tab:red")
ax.set_xlabel("FST risk score")
ax.set_ylabel("Density")
ax.set_title("FST score distribution by realized outcome")
ax.legend()
fig.tight_layout()
fig.savefig("results/score_distributions.png", dpi=140)
plt.close(fig)
print("plots written")
