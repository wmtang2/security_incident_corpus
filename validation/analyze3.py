#!/usr/bin/env python3
"""Analysis of the FIXED configuration vs everything measured before."""
import csv
import json

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score, roc_auc_score

rng = np.random.default_rng(42)
N_BOOT = 2000

rows = list(csv.DictReader(open("data/results3.csv")))
old2 = {r["cve"]: r for r in csv.DictReader(open("data/results2.csv"))}
old1 = {r["cve"]: r for r in csv.DictReader(open("data/results.csv"))}
for r in rows:
    r["fst_cvss_fallback"] = old1[r["cve"]]["fst_score_fallback"]      # Part I best
    r["fst_cvss_brokencfg"] = old1[r["cve"]]["fst_score"]              # Part I DB config
    r["fst_fb_real_log"] = old2[r["cve"]]["fst_fb_real_log"]           # Part II best real
print(f"analyzing {len(rows)} rows")


def col(name):
    return np.array([float(r[name]) for r in rows])


Y24 = col("exploited_24m").astype(int)
Y12 = col("exploited_12m").astype(int)
SCORES = {
    "fixed_cvss": col("fixed_cvss"),
    "fixed_real": col("fixed_real"),
    "fst_cvss_fallback": col("fst_cvss_fallback"),
    "fst_cvss_brokencfg": col("fst_cvss_brokencfg"),
    "fst_fb_real_log": col("fst_fb_real_log"),
    "epss": col("epss"),
    "cvss_base": col("cvss_base"),
}


def boot_auc(y, s, n=N_BOOT):
    aucs = []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if y[idx].sum() in (0, len(idx)):
            continue
        aucs.append(roc_auc_score(y[idx], s[idx]))
    return float(np.percentile(aucs, 2.5)), float(np.percentile(aucs, 97.5))


def boot_diff(y, s1, s2, n=N_BOOT):
    d = []
    for _ in range(n):
        idx = rng.integers(0, len(y), len(y))
        if y[idx].sum() in (0, len(idx)):
            continue
        d.append(roc_auc_score(y[idx], s1[idx]) - roc_auc_score(y[idx], s2[idx]))
    d = np.array(d)
    p = 2 * min((d <= 0).mean(), (d >= 0).mean())
    return float(np.percentile(d, 2.5)), float(np.percentile(d, 97.5)), float(min(p, 1.0))


def wilson(k, n, z=1.96):
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = k / n
    den = 1 + z * z / n
    c = (p + z * z / (2 * n)) / den
    h = z * np.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return float(p), float(max(0, c - h)), float(min(1, c + h))


out = {}
for name, y in (("24m", Y24), ("12m", Y12)):
    res = {}
    for sname, s in SCORES.items():
        lo, hi = boot_auc(y, s)
        u = stats.mannwhitneyu(s[y == 1], s[y == 0], alternative="greater")
        res[sname] = {
            "auc": round(float(roc_auc_score(y, s)), 4),
            "auc_ci": [round(lo, 4), round(hi, 4)],
            "avg_precision": round(float(average_precision_score(y, s)), 4),
            "mannwhitney_p": float(u.pvalue),
        }
    for label, a, b in [
        ("fixed_cvss_minus_cvss_base", "fixed_cvss", "cvss_base"),
        ("fixed_cvss_minus_brokencfg", "fixed_cvss", "fst_cvss_brokencfg"),
        ("fixed_cvss_minus_epss", "fixed_cvss", "epss"),
        ("fixed_real_minus_cvss_base", "fixed_real", "cvss_base"),
        ("fixed_real_minus_epss", "fixed_real", "epss"),
        ("fixed_real_minus_brokencfg", "fixed_real", "fst_cvss_brokencfg"),
    ]:
        lo, hi, p = boot_diff(y, SCORES[a], SCORES[b])
        res[label] = {"ci": [round(lo, 4), round(hi, 4)], "p": round(p, 5)}
    out[name] = res

# level calibration of fixed config (levels computed by the engine itself)
for variant, y in (("fixed_cvss", Y24), ("fixed_real", Y24)):
    lvl_col = variant + "_level"
    tab = []
    for lev in ("low", "medium", "high", "critical"):
        mask = [r[lvl_col] == lev for r in rows]
        n = sum(mask)
        k = sum(1 for m, yy in zip(mask, y) if m and yy == 1)
        p, lo, hi = wilson(k, n)
        tab.append({"level": lev, "n": n, "events": k, "rate": round(p, 4), "ci": [round(lo, 4), round(hi, 4)]})
    out[f"level_calibration_{variant}_24m"] = tab

out["unique_scores"] = {s: int(len(set(np.round(v, 4)))) for s, v in SCORES.items()}
json.dump(out, open("results/study_fixed.json", "w"), indent=2)
print(json.dumps(out, indent=2)[:3500])
