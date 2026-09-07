#!/usr/bin/env python3
"""Study B analysis - did real-world inputs beat the technical CVSS inputs?"""
import csv
import json

import numpy as np
from scipy import stats
from sklearn.metrics import average_precision_score, roc_auc_score

rng = np.random.default_rng(42)
N_BOOT = 2000

rows = list(csv.DictReader(open("data/results2.csv")))
# merge CVSS-based scores from the first study by CVE
old = {r["cve"]: r for r in csv.DictReader(open("data/results.csv"))}
for r in rows:
    o = old.get(r["cve"], {})
    for k in ("fst_score", "fst_score_fallback", "fst_level"):
        r[k] = o.get(k, "")
rows = [r for r in rows if r["fst_score"] != ""]
print(f"analyzing {len(rows)} rows")


def col(name):
    return np.array([float(r[name]) for r in rows])


Y24 = col("exploited_24m").astype(int)
Y12 = col("exploited_12m").astype(int)

SCORES = {
    # old (technical CVSS-derived inputs)
    "fst_cvss_sane": col("fst_score"),
    "fst_cvss_fallback": col("fst_score_fallback"),
    # new (real-world inputs)
    "fst_real_lin": col("fst_real_lin"),
    "fst_real_log": col("fst_real_log"),
    "fst_fb_real_lin": col("fst_fb_real_lin"),
    "fst_fb_real_log": col("fst_fb_real_log"),
    # baselines
    "epss": col("epss"),
    "cvss_base": col("cvss_base"),
    "exploitdb_binary": col("exploit_exists_pre_cutoff"),
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
        ("real_log_minus_cvss_sane", "fst_real_log", "fst_cvss_sane"),
        ("fb_real_log_minus_fb_cvss", "fst_fb_real_log", "fst_cvss_fallback"),
        ("fb_real_log_minus_epss", "fst_fb_real_log", "epss"),
        ("real_log_minus_real_lin", "fst_real_log", "fst_real_lin"),
        ("fb_real_log_minus_cvss_base", "fst_fb_real_log", "cvss_base"),
    ]:
        lo, hi, p = boot_diff(y, SCORES[a], SCORES[b])
        res[label] = {"ci": [round(lo, 4), round(hi, 4)], "p": round(p, 5)}
    out[name] = res

# level calibration for the recommended variant (fallback MFs + real log LM)
LEVEL_MFS = {"low": (0, 0, 30), "medium": (20, 40, 60), "high": (50, 70, 90), "critical": (80, 100, 100)}


def level_of(score):
    def mu(x, abc):
        a, b, c = abc
        return float(np.clip(min((x - a) / (b - a + 1e-30), (c - x) / (c - b + 1e-30)), 0, 1))

    return max(LEVEL_MFS, key=lambda k: mu(score, LEVEL_MFS[k]))


for variant in ("fst_real_log", "fst_fb_real_log"):
    levels = [level_of(s) for s in SCORES[variant]]
    tab = []
    for lev in ("low", "medium", "high", "critical"):
        n = sum(1 for l in levels if l == lev)
        k = sum(1 for l, yy in zip(levels, Y24) if l == lev and yy == 1)
        p, lo, hi = wilson(k, n)
        tab.append({"level": lev, "n": n, "events": k, "rate": round(p, 4), "ci": [round(lo, 4), round(hi, 4)]})
    out[f"level_calibration_{variant}"] = tab

out["unique_scores"] = {s: int(len(set(np.round(v, 4)))) for s, v in SCORES.items()}
json.dump(out, open("results/study_b.json", "w"), indent=2)
print(json.dumps(out, indent=2)[:4000])
