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
"""Analyze the expanded incident study: do real incidents score high?

Comparisons:
  1. incidents vs date-matched controls (Mann-Whitney, AUC, level purity)
  2. tier1 (explicit CVE) vs tier2 (group-attributed) breakdowns
  3. 0-day share (CVE not EPSS-scored at incident date)
  4. score vs realized cost where disclosed (Spearman)
  5. monthly coverage of the window
"""
import csv
import json
from collections import Counter, defaultdict

import numpy as np
from scipy import stats

rows = list(csv.DictReader(open("incidents/scored.csv")))
inc = [r for r in rows if r["kind"] == "incident"]
ctl = [r for r in rows if r["kind"] == "control"]
print(f"incidents={len(inc)} controls={len(ctl)}")


def s(rs):
    return np.array([float(r["score"]) for r in rs])


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return float(p), float(max(0, c - h)), float(min(1, c + h))


out = {"n_incidents": len(inc), "n_controls": len(ctl)}

# 1. overall comparison
si, sc = s(inc), s(ctl)
u = stats.mannwhitneyu(si, sc, alternative="greater")
out["overall"] = {
    "incident_median": float(np.median(si)),
    "control_median": float(np.median(sc)),
    "mannwhitney_p": float(u.pvalue),
    "auc_incident_vs_control": float(u.statistic / (len(si) * len(sc))),
}
# level purity
for lev in ("low", "medium", "high", "critical"):
    ni = sum(1 for r in inc if r["level"] == lev)
    nc = sum(1 for r in ctl if r["level"] == lev)
    out.setdefault("level_shares", {})[lev] = {
        "incidents": {"n": ni, "share": round(ni / len(inc), 4)},
        "controls": {"n": nc, "share": round(nc / len(ctl), 4)},
    }

# 2. by tier
for tier in ("tier1", "tier2"):
    sub = [r for r in inc if r["tier"] == tier]
    if not sub:
        continue
    ss_, sc_ = s(sub), sc
    u2 = stats.mannwhitneyu(ss_, sc_, alternative="greater")
    out[tier] = {
        "n": len(sub),
        "median": float(np.median(ss_)),
        "auc_vs_controls": float(u2.statistic / (len(ss_) * len(sc_))),
        "p": float(u2.pvalue),
        "pct_high_or_critical": float(np.mean([x >= 55 for x in ss_])),
    }

# controls pct high+
out["control_pct_high_or_critical"] = float(np.mean([x >= 55 for x in sc]))

# 3. 0-day share
out["zero_day_share"] = float(np.mean([int(r["zero_day"]) for r in inc]))
out["zero_day_by_tier"] = {
    t: float(np.mean([int(r["zero_day"]) for r in inc if r["tier"] == t]))
    for t in ("tier1", "tier2")
}

# 4. score vs realized cost
with_cost = [r for r in inc if r["lm_src"] == "realized"]
if len(with_cost) >= 5:
    sp = stats.spearmanr([float(r["score"]) for r in with_cost],
                         [np.log10(float(r["lm_usd"])) for r in with_cost])
    out["realized_cost"] = {"n": len(with_cost), "spearman": float(sp.statistic),
                            "p": float(sp.pvalue)}
else:
    out["realized_cost"] = {"n": len(with_cost)}

# 5. monthly coverage in the 24m window
win = [r for r in inc if "2024-06-01" <= r["date"] < "2026-06-01"]
out["window_incidents"] = len(win)
out["window_by_tier"] = dict(Counter(r["tier"] for r in win))
out["window_median_score"] = float(np.median(s(win))) if win else None

# score bands vs incident odds (paired per quarter): odds ratio high+ vs controls
a = sum(1 for r in inc if float(r["score"]) >= 55)
b = len(inc) - a
c = sum(1 for r in ctl if float(r["score"]) >= 55)
d = len(ctl) - c
orv = (a * d) / max(b * c, 1)
out["odds_ratio_high_plus"] = float(orv)

json.dump(out, open("results/study_incidents.json", "w"), indent=2)
print(json.dumps(out, indent=2))
