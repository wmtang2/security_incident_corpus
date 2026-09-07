#!/usr/bin/env python3
"""Plots for the expanded incident study."""
import csv
import json

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

rows = list(csv.DictReader(open("incidents/scored.csv")))
inc = [r for r in rows if r["kind"] == "incident"]
ctl = [r for r in rows if r["kind"] == "control"]

# score distributions
fig, ax = plt.subplots(figsize=(7.5, 4.5))
bins = np.linspace(0, 100, 51)
ax.hist([float(r["score"]) for r in ctl], bins=bins, density=True, alpha=0.6,
        label=f"date-matched controls (n={len(ctl)})", color="tab:blue")
ax.hist([float(r["score"]) for r in inc], bins=bins, density=True, alpha=0.6,
        label=f"real incidents (n={len(inc)})", color="tab:red")
ax.set_xlabel("FST score (fixed config)")
ax.set_ylabel("Density")
ax.set_title("Real security incidents vs comparable non-exploited CVEs")
ax.legend()
fig.tight_layout()
fig.savefig("results/incidents_vs_controls_expanded.png", dpi=140)
plt.close(fig)

# level shares
fig, ax = plt.subplots(figsize=(7, 4))
levels = ["low", "medium", "high", "critical"]
xi = [sum(1 for r in inc if r["level"] == l) / len(inc) for l in levels]
xc = [sum(1 for r in ctl if r["level"] == l) / len(ctl) for l in levels]
x = np.arange(4)
ax.bar(x - 0.2, xi, width=0.4, label="real incidents", color="tab:red", alpha=0.85)
ax.bar(x + 0.2, xc, width=0.4, label="controls", color="tab:blue", alpha=0.85)
for i, v in enumerate(xi):
    ax.text(i - 0.2, v + 0.01, f"{v:.0%}", ha="center", fontsize=9)
for i, v in enumerate(xc):
    ax.text(i + 0.2, v + 0.01, f"{v:.0%}", ha="center", fontsize=9)
ax.set_xticks(x, levels)
ax.set_ylabel("Share of group")
ax.set_title("Where do real incidents land on the model's risk levels?")
ax.legend()
fig.tight_layout()
fig.savefig("results/incident_level_shares.png", dpi=140)
plt.close(fig)

# incidents per month in window, colored by median score
win = [r for r in inc if "2024-06-01" <= r["date"] < "2026-06-01"]
by_month = {}
for r in win:
    by_month.setdefault(r["date"][:7], []).append(float(r["score"]))
months = sorted(by_month)
counts = [len(by_month[m]) for m in months]
meds = [float(np.median(by_month[m])) for m in months]
fig, ax1 = plt.subplots(figsize=(8.5, 4))
ax1.bar(range(len(months)), counts, color="tab:blue", alpha=0.7)
ax1.set_ylabel("# incidents in catalog", color="tab:blue")
ax2 = ax1.twinx()
ax2.plot(range(len(months)), meds, "o-", color="tab:red", lw=2)
ax2.set_ylabel("median FST score", color="tab:red")
ax2.set_ylim(0, 100)
ax1.set_xticks(range(len(months)), [m[2:] for m in months], rotation=60, fontsize=8)
ax1.set_title("Scored incidents per month (24-month outcome window)")
fig.tight_layout()
fig.savefig("results/incidents_per_month.png", dpi=140)
plt.close(fig)
print("plots4 written")
