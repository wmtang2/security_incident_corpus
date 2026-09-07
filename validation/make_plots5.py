#!/usr/bin/env python3
"""Plots for the scenario-level calibration (Part V)."""
import csv
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

rows = list(csv.DictReader(open("results/scenario_table.csv")))
for r in rows:
    r["expected_perorg_loss_usd"] = float(r["freq_per_org_yr"]) * float(r["model_vuln"]) * float(r["model_lm_usd"])
    r["score"] = float(r["score"])

# 1. FST score vs per-org expected annual loss (FAIR quantity)
fig, ax = plt.subplots(figsize=(7.5, 5))
x = [float(r["expected_perorg_loss_usd"]) for r in rows]
y = [float(r["score"]) for r in rows]
lab = [f"{r['sector'][:12]}/{r['scenario']}" for r in rows]
sc = ax.scatter(x, y, c=np.log10(np.maximum(x, 1)), cmap="viridis", s=60)
ax.set_xscale("log")
for xi, yi, li in zip(x, y, lab):
    ax.annotate(li, (xi, yi), fontsize=7, xytext=(4, 3), textcoords="offset points")
ax.set_xlabel("Per-org expected annual loss (USD, log) = TEF×Vuln×LM")
ax.set_ylabel("FST risk score")
ax.set_title("FST score vs FAIR expected annual loss (real registry data)")
ax.set_ylim(0, 100)
plt.colorbar(sc, label="log10(loss)")
fig.tight_layout()
fig.savefig("results/scenario_fair_reconciliation.png", dpi=140)
plt.close(fig)

# 2. TEF sweep for ransomware (environment-conditional likelihood)
st = json.load(open("results/study_scenarios.json"))
tef_pts = [0.01, 0.05, 0.1, 0.25, 0.5, 0.9]
# recompute quickly via the engine
import sys

sys.path.insert(0, "/workspace")
import src.backend.fst_engine as fe

scores = []
for t in tef_pts:
    r = fe.calculate_risk_with_interpretation(threat_event_frequency=t, loss_magnitude=2.73e6, vulnerability=0.85)
    scores.append(r["score"])
fig, ax = plt.subplots(figsize=(6.5, 4.5))
ax.plot(tef_pts, scores, "o-", color="tab:red", lw=2)
ax.axvspan(0, 0.25, color="gray", alpha=0.15)
ax.text(0.12, 92, "poor resolution band:", fontsize=8, ha="center")
ax.text(0.12, 86, "all 'medium'", fontsize=8, ha="center")
ax.set_xlabel("Environment-conditional TEF (input)")
ax.set_ylabel("FST risk score")
ax.set_title("Score vs likelihood input (ransomware scenario)\nno universal likelihood - input is environment-dependent")
ax.set_ylim(0, 100)
fig.tight_layout()
fig.savefig("results/scenario_tef_sweep.png", dpi=140)
plt.close(fig)

# 3. Scenario scores by sector heat-ish bar
fig, ax = plt.subplots(figsize=(9, 5))
sectors = sorted(set(r["sector"] for r in rows))
scen_set = ["web_exploit", "insider_leak", "accidental_loss"]
mat = np.full((len(scen_set), len(sectors)), np.nan)
for r in rows:
    if r["scenario"] in scen_set:
        mat[scen_set.index(r["scenario"]), sectors.index(r["sector"])] = float(r["score"])
im = ax.imshow(mat, cmap="RdYlGn_r", vmin=20, vmax=80)
ax.set_xticks(range(len(sectors)), [s[:10] for s in sectors], rotation=45, ha="right", fontsize=8)
ax.set_yticks(range(len(scen_set)), scen_set, fontsize=9)
ax.set_title("Scenario risk scores by sector (real breach-type data)")
plt.colorbar(im, label="FST score")
fig.tight_layout()
fig.savefig("results/scenario_by_sector.png", dpi=140)
plt.close(fig)
print("plots5 written")