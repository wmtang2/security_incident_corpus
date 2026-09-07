#!/usr/bin/env python3
"""Predictive-power graph: FST-predicted ALE vs realized (observed) loss data.

Observed ALE (per-org, per year) = real frequency x real median loss, from the
breach registries (HHS OCR, WA AG) + published anchors (ransomware.live / Sophos).

Predicted ALE from FST: the model's score is mapped to dollars with a
leave-one-out calibrated regression log10(observed ALE) ~ score, then plotted
against observed ALE. This is the honest in-field calibration: model score ->
predicted dollars, benchmarked against what actually happened.

Also reports: score vs observed ALE Spearman; ratio predicted/observed per
scenario; and flags the rare-event floor (score floored at 40 medium).
"""
import csv
import json
import sys

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
from scipy import stats

sys.path.insert(0, "/workspace")

rows = list(csv.DictReader(open("results/scenario_table.csv")))
for r in rows:
    r["expected_perorg_loss_usd"] = (
        float(r["freq_per_org_yr"]) * float(r["model_vuln"]) * float(r["model_lm_usd"])
    )
    r["observed_ale_usd"] = float(r["freq_per_org_yr"]) * float(r["model_lm_usd"])
    r["score"] = float(r["score"])

# points with an observed ALE (per-org realized loss)
pts = [r for r in rows if r["observed_ale_usd"] > 0]
scores = np.array([r["score"] for r in pts])
obs_log = np.log10(np.maximum(np.array([r["observed_ale_usd"] for r in pts]), 1e-6))

# leave-one-out calibrated predicted ALE: log10(pred) = a(-i) + b(-i)*score_i
pred_log = np.zeros(len(pts))
for i in range(len(pts)):
    tr = np.delete(np.arange(len(pts)), i)
    slope, intercept, *_ = stats.linregress(scores[tr], obs_log[tr])
    pred_log[i] = intercept + slope * scores[i]
pred_ale = 10.0 ** pred_log
obs_ale = 10.0 ** obs_log

# in-sample fit
sl, ic, rr, pp, se = stats.linregress(scores, obs_log)
r2 = rr**2
rho, rho_p = stats.spearmanr(scores, obs_log)
ratio = pred_ale / obs_ale

print("FST score -> ALE calibration (n=%d):" % len(pts))
print(f"  Spearman(score, log10 observed ALE) = {rho:.3f} (p={rho_p:.2e})")
print(f"  OLS fit R2 = {r2:.3f}")
print(f"  LOO predicted-vs-observed: median ratio = {np.median(ratio):.2f}x, "
      f"geomean ratio = {10**np.mean(np.log10(ratio)):.2f}x")
for i, r in enumerate(sorted(range(len(pts)), key=lambda i: pts[i]["score"])):
    p = pts[i]
    print(f"    {p['sector'][:14]:14s} {p['scenario'][:18]:18s} score={p['score']:5.1f} "
          f"obs=${p['observed_ale_usd']:>12,.0f} pred=${pred_ale[i]:>12,.0f} "
          f"ratio={ratio[i]:.1f}x")

# ---- figure: predicted ALE vs observed ALE (the requested graph)
fig, ax = plt.subplots(figsize=(7.5, 6))
im = ax.scatter(obs_ale, pred_ale, c=scores, cmap="RdYlGn_r", s=90, edgecolor="k", lw=0.5)
lims = [10**np.floor(np.log10(min(obs_ale.min(), pred_ale.min()))) * 0.1,
        10**np.ceil(np.log10(max(obs_ale.max(), pred_ale.max())))]
ax.plot(lims, lims, "k--", lw=1.5, label="perfect calibration (pred = obs)")
# LOO fit line
xx = np.logspace(np.log10(lims[0]), np.log10(lims[1]), 100)
ax.fill_between(xx, xx / 3, xx * 3, color="gray", alpha=0.12, label="within 3x")
for r, i in zip(pts, range(len(pts))):
    ax.annotate(f"{r['sector'][:12]}/{r['scenario']}", (obs_ale[i], pred_ale[i]),
                fontsize=6.5, xytext=(4, 3), textcoords="offset points")
ax.set_xscale("log"); ax.set_yscale("log")
ax.set_xlabel("Observed per-org annualized loss (USD/yr) - real breach data")
ax.set_ylabel("FST predicted ALE (USD/yr, LOO-calibrated from score)")
ax.set_title(f"FST predictive power: predicted ALE vs real loss data\n"
             f"(Spearman {rho:.2f}, R2={r2:.2f}, n={len(pts)}; dashed grey = within 3x)")
cb = plt.colorbar(im, label="FST score")
fig.tight_layout()
fig.savefig("results/ale_predicted_vs_observed.png", dpi=150)
plt.close(fig)

# ---- figure 2: score vs observed ALE (regression view)
fig, ax = plt.subplots(figsize=(7.5, 5))
ax.scatter(scores, obs_ale, c=np.log10(obs_ale), cmap="viridis", s=80, edgecolor="k", lw=0.5)
xs = np.linspace(scores.min(), scores.max(), 100)
ax.plot(xs, 10 ** (ic + sl * xs), "r-", lw=2, label=f"fit: log10(ALE)={ic:.1f}+{sl:.3f}·score (R2={r2:.2f})")
for r, i in zip(pts, range(len(pts))):
    ax.annotate(f"{r['sector'][:12]}/{r['scenario']}", (scores[i], obs_ale[i]),
                fontsize=6.5, xytext=(4, 3), textcoords="offset points")
ax.set_yscale("log")
ax.set_xlabel("FST risk score")
ax.set_ylabel("Observed per-org annualized loss (USD/yr, log)")
ax.set_title(f"FST score vs realized annualized loss (Spearman {rho:.2f}, p={rho_p:.1e})")
ax.legend(loc="lower right")
fig.tight_layout()
fig.savefig("results/ale_score_vs_observed.png", dpi=150)
plt.close(fig)

json.dump({
    "n": len(pts),
    "spearman_score_vs_log_obs_ale": float(rho), "p": float(rho_p),
    "r2": float(r2), "slope": float(sl), "intercept": float(ic),
    "loo_median_ratio": float(np.median(ratio)),
    "loo_geomean_ratio": float(10 ** np.mean(np.log10(ratio))),
    "min_observed_ale": float(obs_ale.min()), "max_observed_ale": float(obs_ale.max()),
    "points": [{"sector": r["sector"], "scenario": r["scenario"], "score": r["score"],
                "observed_ale_usd": float(r["observed_ale_usd"]),
                "predicted_ale_usd": float(pred_ale[i])}
               for r, i in zip(pts, range(len(pts)))],
}, open("results/ale_calibration.json", "w"), indent=2)
print("wrote results/ale_calibration.json + ale_predicted_vs_observed.png "
      "+ ale_score_vs_observed.png")