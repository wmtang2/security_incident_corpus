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
"""Plots for the real-world-data redo (Studies A/B/C)."""
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

# ---- Study C: realized loss distribution vs model LM bands
z = np.load("results/losses.npz")
all_loss = np.concatenate([z["hhs"], z["wa"], z["prc"]])
fig, ax = plt.subplots(figsize=(8, 4.5))
bins = np.logspace(3, 10.5, 46)
ax.hist(all_loss, bins=bins, color="tab:blue", alpha=0.75, edgecolor="white")
ax.set_xscale("log")
# model's linear-band dollar edges: low[0,.4B] med[.2B,.8B] high[.6B,1B]
for x, lab in [(2e8, "medium starts\n$200M"), (6e8, "high starts\n$600M"), (1e9, "scale max $1B\n(>$1B rejected)")]:
    ax.axvline(x, color="tab:red", ls="--", lw=1.5)
    ax.text(x, ax.get_ylim()[1] * 0.55, lab, rotation=90, va="top", ha="right", fontsize=8, color="tab:red")
med = np.median(all_loss)
ax.axvline(med, color="black", lw=1.5)
ax.text(med, ax.get_ylim()[1] * 0.75, f"median realized loss\n≈ ${med/1e6:.1f}M", rotation=90, va="top", ha="right", fontsize=8)
ax.set_xlabel("Realized loss per incident (USD, log scale)")
ax.set_ylabel("# incidents")
ax.set_title("9,706 real breaches (HHS OCR + WA AG + PRC) vs the model's LM bands")
fig.tight_layout()
fig.savefig("results/loss_distribution_vs_scale.png", dpi=140)
plt.close(fig)

# ---- Study B: ROC comparison
import csv

from sklearn.metrics import roc_auc_score, roc_curve

rows = list(csv.DictReader(open("data/results2.csv")))
old = {r["cve"]: r for r in csv.DictReader(open("data/results.csv"))}
for r in rows:
    o = old.get(r["cve"], {})
    r["fst_score_fallback"] = o.get("fst_score_fallback", "")
rows = [r for r in rows if r.get("fst_score_fallback") not in (None, "")]
y = np.array([int(r["exploited_24m"]) for r in rows])


def col(n):
    return np.array([float(r[n]) for r in rows])


fig, ax = plt.subplots(figsize=(6, 6))
for s, name, color, ls in [
    (col("fst_fb_real_log"), f"FST + real inputs (AUC={roc_auc_score(y, col('fst_fb_real_log')):.3f})", "tab:red", "-"),
    (col("fst_real_log"), f"FST DB-config + real inputs (AUC={roc_auc_score(y, col('fst_real_log')):.3f})", "tab:orange", "-"),
    (col("fst_score_fallback"), f"FST + CVSS inputs, fallback MFs (AUC={roc_auc_score(y, col('fst_score_fallback')):.3f})", "tab:purple", "--"),
    (col("epss"), f"EPSS alone (AUC={roc_auc_score(y, col('epss')):.3f})", "tab:blue", "-"),
    (col("cvss_base"), f"CVSS base (AUC={roc_auc_score(y, col('cvss_base')):.3f})", "tab:gray", "--"),
]:
    fpr, tpr, _ = roc_curve(y, s)
    ax.plot(fpr, tpr, label=name, color=color, ls=ls, lw=2)
ax.plot([0, 1], [0, 1], "k--", lw=1)
ax.set_xlabel("False positive rate")
ax.set_ylabel("True positive rate")
ax.set_title("Discrimination with real-world inputs (KEV ≤24m)")
ax.legend(loc="lower right", fontsize=8)
fig.tight_layout()
fig.savefig("results/roc_realdata.png", dpi=140)
plt.close(fig)

# ---- Study A: incidents vs controls
sa = json.load(open("results/study_a.json"))
fig, ax = plt.subplots(figsize=(8.5, 4))
names = [c["incident"] for c in sa["cases"]] + [c["cve"].replace("CVE-", "") for c in sa["controls"]]
scores = [c["fb_realized"] for c in sa["cases"]] + [c["fb_potential"] for c in sa["controls"]]
colors = ["tab:red"] * len(sa["cases"]) + ["tab:blue"] * len(sa["controls"])
ax.barh(range(len(names)), scores, color=colors, alpha=0.8)
ax.set_yticks(range(len(names)), names, fontsize=8)
ax.invert_yaxis()
ax.axvline(80, color="k", ls="--", lw=1)
ax.text(80.5, len(names) - 1, "critical ≥85 boundary ≈", fontsize=8, rotation=90, va="bottom")
ax.set_xlabel("FST fallback-config score (real-data inputs)")
ax.set_title("Famous incidents (real $ losses) vs high-CVSS non-incident controls")
fig.tight_layout()
fig.savefig("results/incidents_vs_controls.png", dpi=140)
plt.close(fig)
print("plots2 written")
