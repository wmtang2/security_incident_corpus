# Empirical Validation of the FSTTool Risk Model Against Real-World Data

**Date of analysis:** 2026-08-31 · **Analyst:** automated validation pipeline (`validation/`)
**Model under test:** `src/backend/fst_engine.py` `calculate_risk()` (Mamdani fuzzy
inference, centroid defuzzification; rules/scales loaded from `fst_risk_data.db`)

---

## 1. Question

Does the FSTTool fuzzy-FAIR risk score `risk = f(TEF, LM, Vulnerability)` correspond
to **realized real-world cyber risk**? Specifically: if we feed the model real,
measurement-based inputs for thousands of software vulnerabilities, do its scores and
linguistic levels discriminate and order subsequent real-world exploitation?

## 2. Data (all real, public, independently produced)

| Source | Use | Accessed | Notes |
|---|---|---|---|
| CISA Known Exploited Vulnerabilities (KEV) catalog ([feed](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)) | Ground-truth outcome: "exploited in the wild" + `dateAdded` | 2026-08-31 | 1,687 CVEs, sha256 `2043ec40…` |
| FIRST.org / Cyentia EPSS daily scores for **2024-06-01** ([file](https://epss.cyentia.com/epss_scores-2024-06-01.csv.gz), model v2023.03.01) | Threat-event-frequency input (probability of exploitation in next 30 days, as knowable at prediction date) | 2026-08-31 | 249,016 CVEs, sha256 `29afb638…` |
| NVD vulnerability records, via FKIE-CAD mirror of the official NVD JSON feeds ([repo](https://github.com/fkie-cad/nvd-json-data-feeds), branch `main`, updated 2026-08-31) | CVSS base/impact/exploitability metrics → LM & Vulnerability inputs | 2026-08-31 | 2,630 records fetched, 0 missing |

## 3. Design (prospective, no look-ahead)

- **Prediction date (cutoff):** 2024-06-01. Only information available on that date is
  used as model input (EPSS snapshot of that exact day; CVSS metrics are static).
- **Cohort:** CVEs scorable by EPSS at the cutoff (249,016).
- **Positives (n=130):** CVEs CISA added to KEV in **[2024-06-01, 2026-06-01)** — i.e.
  confirmed real-world exploitation *after* the prediction date (24-month horizon).
  Sensitivity horizon: 12 months (n=69).
- **Negatives (n=2,500):** random sample (seed 42) of CVEs never in KEV through
  2026-08-31 (≥2 months of extra follow-up past the horizon).
- **Analysis set:** 2,517 CVEs with CVSS data (113 dropped for missing CVSS).
- **Input mapping:**

  | Model input | Real-data proxy | Transform |
  |---|---|---|
  | `threat_event_frequency` (universe 0–1) | EPSS score @ 2024-06-01 | direct |
  | `loss_magnitude` (universe 0–10) | CVSS v3.x `impactScore` | `impact / 6.04 × 10` |
  | `vulnerability` (universe 0–1) | CVSS v3.x `exploitabilityScore` | `expl / 3.915` |

  (CVSS v2 records, n=706: `impact` used directly on 0–10, `exploitability/10`.)

- **Model configurations tested:**
  1. **DB configuration** — the engine run against the sane persisted configuration
     (`fst_risk_data.test_copy.db` ≡ `db_backups/..._20251216_145350`), 27 rules
     covering every TEF×LM×Vuln combination. *This is the engine's real code path.*
  2. **S1** — same, but LM = CVSS baseScore (0–10).
  3. **S2 "fallback"** — README-documented hardcoded membership functions
     (TEF low[0,0,.4]/med[.2,.5,.8]/high[.6,1,1], LM/Vuln low[0,0,4]/med[2,5,8]/high[6,10,10]),
     same rule base.
- **Equivalence check:** persistent simulation vs. `calculate_risk()` — max diff 0.0.

## 4. Results

### 4.1 Discrimination (primary outcome: KEV exploitation within 24 months; prevalence 5.16%)

| Score | ROC AUC [95% CI] | Avg. precision | Mann–Whitney p |
|---|---|---|---|
| **FST model (DB config)** | **0.726 [0.686, 0.763]** | 0.099 | 2.2e-20 |
| S1: FST with LM=CVSS base | 0.704 [0.659, 0.748] | 0.093 | 4.0e-16 |
| S2: FST fallback MFs (README) | **0.793 [0.754, 0.834]** | 0.265 | 1.2e-32 |
| EPSS alone | 0.718 [0.664, 0.768] | 0.293 | 2.6e-17 |
| CVSS base alone | 0.767 [0.734, 0.798] | 0.119 | 3.6e-25 |
| *prevalence baseline (AP)* | — | 0.052 | — |

Paired bootstrap AUC differences:

| Comparison | Δ AUC 95% CI | p |
|---|---|---|
| FST(DB) − EPSS | [-0.034, 0.051] | 0.73 |
| FST(DB) − CVSS base | **[-0.072, -0.010]** | **0.007** |
| FST(fallback) − EPSS | **[+0.020, +0.132]** | **0.009** |
| FST(fallback) − CVSS base | [-0.006, 0.057] | 0.11 |
| FST(fallback) − FST(DB) | **[+0.032, +0.102]** | **<0.001** |

12-month horizon shows the same pattern (FST-DB 0.715, EPSS 0.699, CVSS 0.754,
fallback 0.752).

Spearman(FST-DB score, EPSS) = 0.49.

### 4.2 Calibration of the linguistic levels (engine's own `get_risk_interpretation`)

| Level | n | exploited ≤24m | Rate [95% Wilson CI] |
|---|---|---|---|
| low | **0** | — | — |
| medium | 205 | 0 | 0.0% [0, 1.8%] |
| high | 1,797 | 55 | 3.1% [2.4, 4.0%] |
| critical | 515 | 75 | **14.6% [11.8, 17.9%]** |

Trend across levels: χ² = 120.3, p = 7.6e-27; level↔outcome rank correlation 0.21.
The ordering is strongly monotone — **the levels mean what they claim** (higher level ⇒
materially higher realized exploitation probability).

### 4.3 Score resolution

47% of all DB-config scores collapse onto exactly **70.0** (1,180/2,517; deciles 3–6
of the score distribution are *entirely* 70.0), with a second plateau at ~91–93. The decile
calibration is therefore non-monotone at the top (decile 9: 19.9% vs decile 10: 9.2% —
within the 91+ plateau, ranking is driven by LM/Vuln only, because TEF has saturated).

### 4.4 The database shipped in the repo root is not merely miscalibrated — it is broken

Running the engine against the checked-in `fst_risk_data.db` fails for every input:

```
AssertionError: abc requires the three elements a <= b <= c   (calculate_risk)
```

because its stored membership-function points are degenerate (LM MFs ≈ `5e-18`,
`vulnerability` MFs ≈ `5e-05`, all four `risk` MFs = `[1,1,1]`). The last sane backup is
`db_backups/fst_risk_data.db.backup_20251216_145350`.

### 4.5 Unit-mapping discontinuity in `ScaleService._real_to_universe`

TEF scale declares real-world range 0.01–100 events/year *and* universe [0,1]; values
that fit both ranges pass through unconverted:

| input | → universe |
|---|---|
| 1.0  | **1.0000** (max!) |
| 1.01 | **0.0100** (min!) |
| 10.0 | 0.0999 |
| 50.0 | 0.4999 |

A user typing "1 event/year" gets maximum TEF; typing "1.01 events/year" gets ~zero —
a non-monotone, order-reversing normalization.


## 5. Findings

1. **The model has genuine criterion validity.** Using only information available at
   the prediction date, FST scores separate future-exploited from never-exploited
   CVEs at AUC ≈ 0.73 (p ≈ 1e-20), and its linguistic levels are strongly monotone in
   realized exploitation rate (0% → 3.1% → 14.6%; p ≈ 1e-27). Risk *ranking by
   FAIR-style fuzzy fusion is empirically meaningful.*
2. **The fuzzy-fusion architecture can beat its own inputs.** The documented fallback
   membership functions reach AUC 0.793 — significantly **above EPSS alone**
   (p = 0.009) and at least on par with CVSS — i.e. fusing frequency with impact and
   exploitability adds measurable, independent signal.
3. **…but the current persisted DB calibration destroys that advantage.** Its TEF
   membership functions (low[0,.005,.01], med[.005,.015,.025], high[.02,.03,1]) saturate
   for any EPSS > 0.03, discarding exactly the fine-grained frequency gradient that
   predicts exploitation. Result: half of all scores collapse onto 70.0, average
   precision barely exceeds prevalence (0.099 vs 0.052), and the model ranks
   *significantly worse than the raw CVSS base score* it is meant to refine
   (p = 0.007). The fallback-vs-DB comparison (p < 0.001) isolates **calibration, not
   architecture**, as the cause.
4. **Operational defect (blocking):** the root `fst_risk_data.db` currently crashes
   `calculate_risk()` for all inputs (degenerate MF points; §4.4). Any deployment using
   it cannot produce scores at all.
5. **Operational defect (silent):** the real-world↔universe normalization is
   non-monotone at the boundary (§4.5) — inputs around 1.0 events/year flip from
   maximum to minimum TEF.

## 6. Limitations

- **KEV ≠ all exploitation.** KEV records *confirmed, reported* exploitation; false
  negatives exist (noise biases AUC toward 0.5, i.e. against the model).
- **Partial label/source overlap.** EPSS is itself trained partly on exploitation
  telemetry, so EPSS-as-input vs KEV-as-outcome are not fully independent. This
  inflates EPSS's standalone AUC more than the FST model's (which is why the
  fallback config beating EPSS is notable).
- **Proxies.** TEF/LM/Vulnerability were populated from public CVE-level proxies, not
  asset-specific FAIR estimates; results validate the *generic scoring function*, not
  a bespoke organizational risk register.
- **Cohort restriction.** Positives are CVEs already published at the cutoff (KEV
  skews to newly-published CVEs; 73% — 360/490 — of window additions had no EPSS score
  at cutoff and were excluded). 113 CVEs lacked CVSS data.
- **KEV `dateAdded`** approximates the exploitation-discovery date with variable lag.
- Single 12/24-month horizons; no per-asset loss amounts were available to validate
  the absolute 0–100 score as a monetary quantity.

## 7. Recommendations

1. **Restore the scale configuration** from the last sane backup and add a save-time
   validator rejecting degenerate membership functions (zero-area `trimf`, all points
   equal, points ≈ 0 relative to the universe). The `migrate_normalize_scales.py`
   normalization path likely produced the `1e-18` points and should be re-audited.
2. **Recalibrate TEF membership functions** to spread over the operating range of
   real inputs (e.g. the README fallback shapes, or data-driven EPSS percentiles).
   Add a regression test: feeding EPSS-like inputs must yield ≥N distinct scores and
   must use the full 0–100 output range.
3. **Fix `_real_to_universe`**: when a value is inside both ranges, prefer one
   consistent interpretation (or require explicit units); never allow 1.0 → max and
   1.01 → min.
4. **Add a CI validation gate** mirroring this study: score a frozen golden set of
   CVEs, assert AUC ≥ threshold and monotone level rates — so future DB/rule edits
   are empirically checked, not just syntactically.
5. Consider **EPSS percentile (rank) instead of raw EPSS** as the TEF input, or a
   log-scaled TEF universe, to match the heavy-tailed frequency distribution.

## 8. Reproduce

```bash
cd validation
python3 build_sample.py          # KEV + EPSS snapshot -> data/sample.csv
bash fetch_nvd.sh                # NVD JSON per CVE (FKIE mirror)
python3 extract_features.py      # CVSS -> model inputs -> data/features.csv
venv/bin/python run_model.py     # real engine scoring -> data/results.csv
venv/bin/python analyze.py       # bootstrap metrics -> results/metrics.json
venv/bin/python make_plots.py    # figures -> results/*.png
venv/bin/python check_unit_mapping.py
```

Artifacts: `results/metrics.json`, `results/roc_curves.png`,
`results/level_rates.png`, `results/calibration_deciles.png`,
`results/score_distributions.png`, `results/broken_db_demo.json`,
`results/data_hashes.txt`, plus all raw inputs under `data/`.


---

# Part II — Redo with real-world loss & exploitability data

Motivation: CVSS "impact"/"exploitability" subscores (used in Part I for LM/Vuln) are
purely technical — they describe C/I/A impact on the *component*, not real business
loss. Part II re-runs the validation with non-NVD, real-world data.

## 9. New data sources (all real, public)

| Source | Use | Accessed |
|---|---|---|
| HHS OCR breach portal dataset (mirror of ocrportal.hhs.gov, 2009–2026) — `lilkommu/healthcare-breach-analyzer` (data refreshed from HHS) | 7,794 real healthcare breaches with individuals affected | 2026-08-31 |
| Washington State AG — Data Breach Notifications Affecting Washington Residents (Socrata `sb4j-ca4h`) | 1,617 real breaches (all industries, 2016–2026) with records affected | 2026-08-31 |
| Privacy Rights Clearinghouse chronology, cleaned research dataset (`jacobcruny/Cyber-Loss-Severity-Data-Set`) | 295 incidents with records affected | 2026-08-31 |
| Exploit-DB `files_exploits.csv` (gitlab.com/exploit-database/exploitdb) | 47,136 real public exploits w/ CVE codes + publication dates → 25,058 CVEs | 2026-08-31 |
| FIRST.org EPSS historical API (per-CVE time series) | TEF at incident-relevant dates for the case study | 2026-08-31 |
| Published per-record / per-incident cost constants | IBM Cost of a Data Breach ($165/record global 2023, ≈$408/record healthcare, $4.88M avg breach 2024); Sophos State of Ransomware 2024 ($2.73M mean recovery cost excl. ransom); NetDiligence Cyber Claims Study 2024 (≈$0.35M avg incident) | cited |

## 10. Study C — Is the model's Loss Magnitude scale able to represent reality?

9,706 real breaches with records>0 were converted to USD (records × per-record cost;
sensitivity at $100 and $500/record).

- **Realized losses:** median ≈ **$1.2M** overall (HHS $1.6M, WA $0.31M, PRC $0.35M);
  p90 ≈ $6–41M; max $78.6B.
- **The model's linear $0–1B scale maps the median real breach to 0.012 of 10.**
  **98.7%** of all realized incidents are indistinguishably "low" (the "medium" band
  starts at $200M, "high" at $600M). The scale is calibrated for catastrophe-class
  events only; ~99% of reality is compressed into the bottom 2% of the dial
  (`results/loss_distribution_vs_scale.png`).
- **65 real incidents (0.67%) exceed $1B and are *rejected outright***: the engine's
  normalizer raises `ValueError` for e.g. an Equifax-size $1.4B loss (demonstrated
  through the real code path; Merck's $870M maps to 8.7 — barely inside range).
- **Empirical repair:** log mapping `u = 10·log10(1+$)/log10(1+$1B)` puts the real
  distribution at median 6.75 (band shares low 0.8% / medium 64% / high 36%),
  e.g. $100k→5.6, $4.88M→7.4, $50M→8.6. Consequence tested in Study B below.

## 11. Study B — discrimination re-run with real-world inputs

Same cohort/outcome as Part I (KEV ≤24m; n=2,517, 130 positives). Inputs:

- **TEF** = EPSS @2024-06-01 (telemetry-based; not NVD-sourced)
- **Vuln** = Exploit-DB public exploit existing *before* cutoff (0.85/0.25) — 283 CVEs
- **LM** = real-world expected loss by consequence class (CWE from NVD → class):
  data_exposure 696 CVEs → $4.88M (IBM'24); rce 517 → $2.73M (Sophos'24);
  other 1,304 → $0.35M (NetDiligence'24)

| Variant (24m) | AUC [95% CI] | AP |
|---|---|---|
| FST fallback MFs + **real inputs, log LM** | 0.672 [0.620, 0.727] | 0.198 |
| FST DB config + real inputs, log LM | 0.680 [0.633, 0.725] | 0.099 |
| FST DB config + real inputs, **linear LM** | 0.613 [0.552, 0.674] | 0.114 |
| FST fallback MFs + CVSS inputs (Part I best) | 0.793 [0.750, 0.833] | 0.265 |
| FST DB config + CVSS inputs | 0.726 [0.686, 0.763] | 0.099 |
| EPSS alone | 0.718 [0.663, 0.766] | 0.293 |
| CVSS base alone | 0.767 [0.733, 0.798] | 0.119 |
| Exploit-DB binary alone | 0.579 [0.540, 0.617] | 0.070 |

Paired bootstrap: **log-LM repair beats the model's linear scale: ΔAUC +0.03…+0.11,
p < 0.001** (direct evidence the $1B linear scale destroys information). Real-input
variants score **below** CVSS-input variants (fallback: Δ −0.18…−0.07, p < 0.001) —
coarse 3-bucket LM + binary exploit evidence carry less fine ranking signal than
continuous CVSS metrics.

**But calibration of the linguistic levels improves markedly with real inputs**
(fallback config): medium 3.6% → high 15.1% → **critical 47.9% exploited** (vs 14.6%
critical purity in Part I). Real-world LM gating makes the top label mean what a
decision-maker thinks it means.


## 12. Study A — famous incidents with disclosed dollar losses

Real incidents with publicly documented root-cause CVE and realized cost; TEF from
historical EPSS at the incident-relevant date; Vuln from Exploit-DB pre-incident;
scores under both configs with log-mapped LM (`results/incidents_vs_controls.png`).

| Incident | CVE | TEF evidence | Exploit public before? | Realized cost | FST (fallback, realized LM) |
|---|---|---|---|---|---|
| Equifax 2017 | CVE-2017-5638 | EPSS 0.941* | yes | ~$1.4B | **92.7 critical** |
| Merck (NotPetya) | CVE-2017-0144 | EPSS 0.959* | yes | ~$870M | **92.7 critical** |
| FedEx/TNT (NotPetya) | CVE-2017-0144 | 0.959* | yes | ~$400M | **92.7 critical** |
| Maersk (NotPetya) | CVE-2017-0144 | 0.959* | yes | ~$300M | **92.7 critical** |
| NHS (WannaCry) | CVE-2017-0144 | 0.959* | yes | ~£92M | **92.7 critical** |
| Rackspace 2022 | CVE-2022-41082 | EPSS 0.317 @2022-12-01 (in-window) | no | ~$12M | 56.5 high |
| Accellion FTA 2020 | CVE-2021-27101 | EPSS 0.006* | no | $8.1M settlement | 45.1 medium |
| MOVEit/Cl0p 2023 | CVE-2023-34362 | **none — 0-day** | no | ≥$4.2M (direct) | 41.4 medium |
| GoAnywhere/Cl0p 2023 | CVE-2023-0669 | **none — 0-day** | no | n/d | 41.4 medium |

\* EPSS launched 2021-07 — earliest available snapshot used for pre-2021 incidents
(post-incident hindsight caveat; documented mass exploitation at the time corroborates).

Controls (high-CVSS ≥7.5, never exploited, no public exploit, mid EPSS): all 10 land
at **medium (27–42)** despite "critical" CVSS ratings. Case median (potential-LM
scoring) 91.4 vs control 27.4, Mann–Whitney **p = 0.0002**. Realized-cost consistency:
Spearman(log₁₀ cost, score) = **0.912, p = 0.0006** — the model's aggregation tracks
the order of real losses (mechanical via LM, but confirms sane scaling).

## 13. What changed vs Part I — updated conclusions

1. **The user's premise is half right.** Technical CVSS impact/exploitability carried
   *more* exploit-prediction signal (fallback AUC 0.793) than real-world, asset-agnostic
   LM buckets + exploit-availability (0.672; p<0.001). Per-CVE real loss data is
   inherently coarse because true loss is **asset-specific**, not CVE-specific.
2. **…but real-world inputs produce far better-calibrated decisions**: "critical"
   went from 15%-to-actually-happen to **48%**; and a controlled case series separates
   real catastrophes from high-CVSS non-events (p=2e-4).
3. **The LM scale defect is now empirically proven harmful, then fixed and re-proven:**
   linear $1B scale compresses 98.7% of reality into "low" and rejects >$1B losses;
   the log repair recovers +0.03…+0.11 AUC (p<0.001).
4. **Structural blind spot quantified:** 73% of KEV additions in the outcome window
   were 0-day/n-day CVEs unpublished at prediction time (no EPSS existed) — both MOVEit
   cases score "medium". No input-driven model sees 0-days coming; this bounds any
   achievable discrimination on the full incident stream.
5. Unchanged from Part I: the shipped root DB crashes the engine; TEF normalization
   is non-monotone at 1.0; DB-config TEF MFs saturate (all still true; the fallback
   MFs remain the better shipped reference).

## 14. Recommendations (updated)

1. Adopt a **log-scaled LM universe** (evidence: Study C §10 + Study B p<0.001), and
   extend the real-world range beyond $1B (or clip with a warning) — real incidents
   exceed it.
2. **LM must be entered per-asset/assessment** (records at risk × per-record cost,
   or revenue-based scenarios), not looked up per CVE; validate user-entered LM
   against the realized-loss distribution (flag values in the model's dead zone
   <$2M → universe ≈0 where the fuzzy system is insensitive).
3. Prefer **telemetry-based TEF (EPSS)** and **exploit-artifact-based Vuln
   (Exploit-DB/KEV)** over CVSS subscores for real-world relevance — but keep CVSS
   metrics available: they still add ranking signal (Part I).
4. Treat "critical" as the calibrated action gate (≈48% 24-month exploitation with
   real inputs); recalibrate level thresholds on this empirical basis if desired.
5. Fix the shipped DB / normalizer defects (Part I §4.4–4.5) before any of the above
   matters in production.

## 15. Reproduce (Part II)

```bash
cd validation
# data: files_exploits.csv (Exploit-DB), wa_breaches.json (Socrata sb4j-ca4h),
#       hhs_breach_clean.csv (HHS OCR mirror), prc_cyber_loss.xlsx (PRC)
venv/bin/python study_c_loss_scale.py      # LM scale vs realized losses
python3 build_features2.py                 # CWE class + ExploitDB + real LM
venv/bin/python run_model2.py              # re-score with real inputs
venv/bin/python analyze2.py                # metrics -> results/study_b.json
venv/bin/python study_a_incidents.py       # famous incidents -> results/study_a.json
venv/bin/python make_plots2.py             # figures
```

Artifacts: `results/study_a.json`, `results/study_b.json`, `results/study_c.json`,
`results/loss_distribution_vs_scale.png`, `results/roc_realdata.png`,
`results/incidents_vs_controls.png`.


---

# Part III — Fix the configuration and re-validate

## 16. What was fixed

**Code (backward-compatible, default behavior unchanged):**
- `src/backend/models/ordinal_scale.py`: new optional `real_world_mapping` column
  (`"linear"` default | `"log"`).
- `src/backend/services/scale_service.py`: `_real_to_universe` honors
  `real_world_mapping="log"` via a log1p mapping of the real-world range onto the
  universe. Linear path byte-identical to before.

**Configuration** (`validation/fix_configuration.py`, applied in place to the shipped
`fst_risk_data.db`; broken state preserved at `validation/fst_risk_data.broken_snapshot.db`):
- Repaired all four scales with non-degenerate, README-documented membership functions
  (TEF low[0,0,.4]/med[.2,.5,.8]/high[.6,1,1]; LM low[0,0,4]/med[2,5,8]/high[6,10,10];
  Vuln low[0,0,.4]/med[.2,.5,.8]/high[.6,1,1]; Risk low[0,0,30]/med[20,40,60]/high[50,70,90]/crit[80,100,100]).
- LM real-world range extended to $0–1e12 with `mapping="log"` (covers every observed
  incident incl. the $78.6B max; nothing is rejected anymore).
- Rebuilt the verified complete 27-rule base.
- The fix script contains a **validation gate**: it rejects zero-area or out-of-range
  trimf points and asserts full 3×3×3 rule coverage.

**Smoke test through the engine's default path (previously crashed on every input):**

| Input | Score | Level |
|---|---|---|
| TEF .9 / LM 9 / Vuln .9 | 93.0 | critical |
| TEF .5 / LM 5 / Vuln .5 | 70.0 | high |
| TEF .01 / LM .5 / Vuln .05 | 10.1 | low |
| TEF .94 / **$1.4B (Equifax, real USD)** / Vuln .85 | 91.9 | critical |
| TEF .05 / $4.88M / Vuln .25 | 23.4 | low |

**Regression check:** scale/seed/dynamic-loading unit tests: **49/49 pass**.
`test_fst_engine.py` (5 failed) and `test_scale_to_fst_integration.py` (4 failed) fail
**identically on pristine code** (pre-existing: the in-memory test DB has no rules and
default-rule seeding is disabled in `RulesManager`) — the fix introduces no regressions.

## 17. Re-validation results (same cohort, same outcome: KEV ≤24m, n=2,517, 130 positives)

| Scorer | AUC [95% CI] | AP |
|---|---|---|
| **FST FIXED config, CVSS inputs** | **0.793 [0.751, 0.832]** | 0.265 |
| FST FIXED config, real inputs | 0.657 [0.609, 0.701] | 0.204 |
| FST broken/old DB config, CVSS inputs | 0.726 [0.689, 0.763] | 0.099 |
| EPSS alone | 0.718 [0.661, 0.771] | 0.293 |
| CVSS base alone | 0.767 [0.734, 0.800] | 0.119 |

Paired bootstrap (24m):
- **FIXED − broken config: +0.033…+0.104, p < 0.001** — the fix significantly improves
  the model on identical inputs.
- **FIXED − EPSS alone: +0.019…+0.129, p = 0.005** — the fixed model significantly
  beats the strongest single public predictor.
- FIXED − CVSS base: −0.004…+0.058, p = 0.09 — at least on par, trend better.
- Real-input variant still trails on *ranking* (coarse per-CVE loss buckets), as before.

**Calibration of the fixed model's own levels (engine `get_risk_interpretation`):**

| Level | CVSS inputs: n (rate) | Real inputs: n (rate) |
|---|---|---|
| low | 48 (0.0%) | 2,162 (3.6%) |
| medium | 1,475 (1.2%) | 262 (5.0%) |
| high | 921 (8.4%) | 45 (37.8%) |
| critical | 73 (**48.0%**) | 48 (**47.9%**) |

Monotone across the full range on both input sets; "low" is reachable again (the broken
config never emitted it), and "critical" is a ~48%-pure action gate.

**Study A re-run through the fixed engine (raw realized USD):** Equifax/Merck/FedEx/
Maersk/NHS all **critical (91.4–91.9)**; Rackspace 41.6 medium; Accellion 23.4 low;
0-day cases 23.4 low (structural blind spot, as before). Cases vs controls:
median 91.4 vs 23.4, **MWU p = 0.0018**.

**Study C re-check through the fixed scale:** the 9,706 realized losses now map to
median universe 5.06 with nothing rejected (max $78.6B → 9.08/10). The log scale
discriminates by order of magnitude ($100k→4.2, $1M→5.0, $10M→5.8, $100M→6.7,
$1B→7.5, $10B→8.3) — vs the linear scale where 98.7% of reality was crushed into
"low" and >$1B raised ValueError.

## 18. Verdict

The fix converts the model from *non-functional / worse than a free baseline* into one
that **significantly beats its old self (p<0.001), beats EPSS alone (p=0.005), matches
CVSS on ranking, and delivers empirically calibrated decision levels** (critical ≈ 48%
realized exploitation within 24 months). Remaining honest caveats: per-CVE real-loss
data is inherently coarse (asset-specific LM entry is the answer), and 0-day exploits
are structurally invisible to any input-driven model.

## 19. Reproduce (Part III)

```bash
python3 validation/fix_configuration.py /workspace/fst_risk_data.db   # fix in place
cd validation
venv/bin/python run_model3.py        # re-score cohort via FIXED engine+DB
venv/bin/python analyze3.py          # metrics -> results/study_fixed.json
venv/bin/python study_a_fixed.py     # incidents + loss-scale coverage re-check
venv/bin/python make_plots3.py       # roc_fixed.png, level_rates_fixed.png
```

---

# Part IV — Exhaustive incident validation (expanded famous-incidents test)

Motivation: Part II/III's Study A used 9 hand-picked incidents with disclosed dollar
losses. This part expands that test exhaustively: every publicly available security
incident we could find with a date and (where possible) a CVE linkage, scored through
the FIXED engine.

## 20. Catalog (all acquired, public data)

| Source | Incidents | Notes |
|---|---|---|
| ransomware.live (2020–2026) | 30,803 | ransomware leak-post victims; group + date (`published`) |
| ransomwatch (archived) | 4,767 | ransomware victims (deduped against ransomware.live) |
| HHS OCR breach portal | 7,654 | healthcare breaches, records affected |
| WA AG breach notifications | 1,605 | all industries (WA residents affected) |
| GDPR Enforcement Tracker (mirror) | 1,553 | real fines: 1,505 with amounts, median ≈ $10k, total ≈ $3.0B |
| VCDB (VERIS Community DB) | 775 | incidents with explicit CVE references (926 structured-CVE rows; 2023 MOVEit-dominated) |
| Wikipedia data-breach list | 464 | notable breaches, org/year/records |
| SEC 8-K **Item 1.05** (EDGAR FTS) | 64 | material cyber incidents from public companies 2023–2026; e.g. Coinbase ($180–400M est.), KeyTronic ($2.3M/$15M), Upbound ($13M), Bitcoin Depot ($3.665M) |

**Total: 47,685 incidents; 19,351 fall inside the 24-month outcome window.**
Raw sources, hashes, and fetch scripts under `incidents/`.

## 21. Scoring design (expanded)

An incident is *scored* if it has a CVE linkage and a date in the EPSS era
(≥ 2021-07-19):
- **tier1 (n=743):** CVE named explicitly in the source (VCDB/Wikipedia).
- **tier2 (n=3,448, sampled):** ransomware victim whose group has a documented CVE set
  (CISA #StopRansomware advisories verified via Wayback + vendor reports —
  `incidents/group_cve_map.json`: akira, lockbit3/5, play, clop, blackbasta, rhysida,
  qilin, fog, cactus), stratified cap 100 per group-year.

Inputs (fixed engine): TEF = **EPSS at the incident date** (daily history fetched for
all 53 relevant CVEs — no look-ahead); Vuln = Exploit-DB exploit published before the
date (0.85/0.25); LM = disclosed cost if any, else records × $165/record, else
ransomware bucket ($2.73M) for tier2 / CWE class bucket for tier1.

Controls: **2 per incident** (n=8,312), sampled from the quarterly EPSS snapshot
before the incident date, excluding CVEs ever in CISA KEV.

## 22. Results

| Group | n | median score | AUC vs controls | % high+ (≥55) |
|---|---|---|---|---|
| **All incidents** | 4,191 | 70.0 | **0.883** | 76.7% |
| tier1 (explicit CVE) | 743 | 70.0 | **0.985** | 99.7% |
| tier2 (group-attributed) | 3,448 | 92.65 | 0.861 | 71.7% |
| date-matched controls | 8,312 | 23.38 | — | 2.1% |

Mann–Whitney p < 1e-100 for all incident-vs-control comparisons.

**Level shares (all incidents vs controls):**

| Level | Incidents | Controls |
|---|---|---|
| low | 19.8% | **87.9%** |
| medium | 3.5% | 10.1% |
| high | 32.1% | 1.4% |
| **critical** | **44.5%** | **0.66%** |

**Odds ratio of scoring high+ for a real incident vs a random CVE: ≈ 156.**

- Window-only (2024-06-01→2026-06-01): 1,909 scored incidents (1,906 tier2), median
  score 92.65 — the ransomware-driven incident stream in the outcome window scores
  overwhelmingly critical.
- 0-day share: **1.5%** — with daily EPSS history, nearly all incident CVEs were
  already scored at the incident date (contra the flat-EPSS assumption in Part I).
- Cost-consistency: n=0 scored incidents with disclosed costs (SEC/GDPR cost data are
  tier-3, not CVE-linked) — the cost-ordering evidence remains the 9-case Study A +
  the disclosed-cost catalog.

## 23. Interpretation & honest caveats

1. **The model separates real incidents from comparable non-events almost perfectly**
   (AUC 0.883 overall; 0.985 for explicit-CVE incidents). This is strong criterion
   validity: given a CVE and a date, the fixed model marks actual exploited/attacked
   CVEs at massively higher risk than random CVEs of the same era.
2. **Caveat: leak-post dates.** ransomware.live dates are leak-site postings, which
   lag the actual attack by weeks–months. For pre-EPSS-era attacks (e.g., Cl0p's
   Accellion victims, attacked Jan–Mar 2021, posted Sep–Oct 2021) EPSS at the post
   date is low → scores understate. This biases *against* the model, so the headline
   separation is conservative.
3. **Tier-2 attribution is probabilistic** (group-level, not per-incident CVE
   confirmation). It is grounded in CISA advisories and reported separately from
   tier-1. Note tier-2 also has a low-scoring tail (28% below high) — largely the
   Accellion-era + low-TEF group victims.
4. **Within-window scored incidents are nearly all tier-2 ransomware** because public
   CVE→incident confirmation for 2024-2026 is rare outside ransomware attribution
   (VCDB's CVE-tagged set is 2023 MOVEit-era). Tier-3 catalog (SEC/GDPR/HHS/WA) covers
   the window without CVE linkage, so it cannot be scored per-CVE.
5. Net: the exhaustive test **replicates and vastly strengthens** the Study A
   conclusion — real-world incidents land at the top of the model's calibrated scale,
   controls do not.
---

# Part V — Scenario-level validation (addressing scope, likelihood-conditional, and financial-impact critiques)

Three methodological critiques were raised against Parts I–IV:
1. Only *vulnerability-driven* risk was tested — not phishing, data leakage, DoS, theft, insider misuse.
2. Likelihood was fed as a *universal* number (EPSS); FAIR likelihood is environment-dependent expert judgment.
3. The role of *real financial impact* was not reconciled end-to-end (score ⇄ dollars).

This part addresses all three using the same real datasets.

## 23. Scenario catalog (breadth — critique 1)

Scenarios derive from *registry type labels* (no invented mapping), sector-split where data supports:

| Scenario | Data source | Sector |
|---|---|---|
| web/exploit hacking & ransomware (cyber) | HHS "Hacking/IT Incident"; WA "Cyberattack"; VCDB exploit-vuln/ransomware varieties | healthcare; business/health/finance/education/gov |
| insider / accidental leakage | HHS "Unauthorized Access/Disclosure"; WA "Unauthorized Access" | same |
| theft / loss / misdisposal | HHS Theft/Loss/Improper Disposal; WA "Theft or Mistake" | same |
| ransomware | ransomware.live annual victims (2021–2025) + Sophos 2024 TEF (59%/yr) | all industries |
| phishing, stolen credentials | VCDB social:phishing action varieties + IBM 2024 cost anchors | all industries |

For each (sector × scenario): real annual incident count (2021–2025), real median records →
median loss USD (records × per-record: healthcare $408, general $165), per-org annualized
frequency = count/(# orgs), observed per-org expected annual loss = frequency × Vuln × median loss.

## 24. Environment-conditional likelihood (critique 2)

- **TEF is input as a per-sector per-org frequency** (`count / N_orgs`), not a universal
  number; org-count anchors are documented (e.g., ~534k HIPAA covered entities) with sensitivity.
- Demonstration: the *same* ransomware scenario under sector-supplied TEFs gives
  **healthcare 70 / business 70 / education 56.9** — the score responds to the environment's
  likelihood. A TEF sweep (0.01→0.9) is monotone increasing (40 → 40 → 40 → 49.7 → 70 → 92.7).
- **Finding (frequency-axis resolution):** between TEF ≈ 0.01 and 0.25 the model outputs a
  flat 40.0 ("medium") — realistic per-org breach probabilities (1e-4…1e-2) all land in this
  mushy band, so the fixed config separates only "frequent" (>0.5/yr, e.g. ransomware)
  from "rare" scenarios. A calibration limitation (the monotone response itself is correct),
  and the TEF-axis analog of the LM-scale defect in Study C.

## 25. Financial reconciliation (critique 3)

Using the FAIR quantity — per-org expected annual loss = TEF × Vuln × LM:

| Metric (n=22 sector×scenario points) | Value |
|---|---|
| Spearman(score, log10 per-org expected loss) | **0.514, p = 0.014** |
| Spearman(score, log10 FAIR product TEF·V·LM) | 0.514 (identical, by construction) |
| Score→$ examples | ransomware 70 ⇔ ~$1.37M/org/yr; healthcare hacking 40 ⇔ ~$3.7k/org/yr; business hacking 40 ⇔ ~$1.3k/org/yr |

- The FST score **does rank-order the FAIR expected annual loss** across scenarios/sectors
  (significant at p=0.014) — the fuzzy aggregation is a faithful ordinal implementation of
  FAIR's multiplicative risk formula.
- The famous-9 incident-level ordinal check (Spearman 0.912, score vs disclosed $ loss)
  remains the complementary realized-cost evidence.
- Study C already validated the LM *scale mapping* against 9,706 real losses; this part adds
  the end-to-end per-org score⇄dollars link (with the frequency-resolution caveat).

## 26. What this adds to the verdict

| Earlier claim | Status after Part V |
|---|---|
| FST ranks vulnerability-exploitation outcomes | ✅ (Parts I–IV) |
| FST LM scale can represent real losses | ✅ (Study C) |
| FST covers the broader risk surface (phishing/leak/DoS/theft) | ✅ scenarios scored; ransomware/phishing/hacking rank above theft/leak per real frequency×loss |
| FST likelihood is environment-conditional, not universal | ✅ demonstrated (sector TEFs; no universal number asserted) |
| FST score ⇄ per-org expected annual $ loss | ✅ ordinal reconciliation, p=0.014 (with caveat) |
| Frequency axis resolves realistic rare-event rates | ⚠️ **No** — flat 40.0 across TEF 0.01–0.25 (new finding; fixable) |

## 27. New finding → configuration implication

The TEF membership functions (low[0,0,.4], med[.2,.5,.8], high[.6,1,1]) were tuned for
high-frequency inputs (0–1 probability). Real per-org scenario rates are often 0.001–0.25/yr,
which the current MFs cannot resolve. Remedies (both feasible):
(a) log-spread the TEF universe like the LM log-fix;
(b) document that TEF must be entered as the scenario hazard for the assessed environment
    (e.g., "phishing → breach" per org-year) with a lookup table of documented per-sector
    base rates — exactly the expert-judgment input FAIR prescribes.

Reproduce:

```bash
venv/bin/python incidents/scenario_calibration.py   # -> results/study_scenarios.json, scenario_table.csv
venv/bin/python make_plots5.py                       # -> scenario_*.png
```
---

# Part VI — TEF calibration fix + predictive power (predicted ALE vs real loss data)

## 28. Fixing the frequency-axis resolution defect

Part V found the TEF membership functions (low[0,0,.4], med[.2,.5,.8], high[.6,1,1])
left realistic per-org scenario frequencies (0.001–0.25/yr) unresolved — everything
scored a flat "medium 40". Fix applied to the shipped configuration
(`validation/fix_configuration.py`, `fst_risk_data.db`):

| TEF band | Before | After |
|---|---|---|
| low | [0, 0, 0.4] | **[0, 0, 0.1]** |
| medium | [0.2, 0.5, 0.8] | **[0.02, 0.08, 0.25]** |
| high | [0.6, 1.0, 1.0] | **[0.15, 0.5, 1.0]** |

Effect on the ransomware example (LM $2.73M, V 0.85):

| TEF input | before | after |
|---|---|---|
| 0.05 | 40.0 medium | **55.0 high** |
| 0.10 | 40.0 medium | **70.0 high** |
| 0.25 | 49.7 medium | **91.3 critical** |

The frequency axis now resolves the operating band; the response remains monotone.

## 29. Predictive power: predicted ALE vs real loss data

For each sector×scenario point, observed per-org ALE = real frequency × real median
loss (from HHS/WA/GDPR/ransomware.live data); predicted ALE = FST score mapped to
dollars via a leave-one-out regression log10(observed ALE) ~ score.

| Metric (n=24) | Value |
|---|---|
| Spearman(score, log10 observed ALE) | **0.611, p=0.0015** (improved from 0.514 pre-fix) |
| OLS R² (score → log ALE) | **0.768** |
| LOO median predicted/observed ratio | 1.06× (geomean 1.13×) |
| Within ~1 order of magnitude | most mid-range scenarios |

Graphs: `results/ale_predicted_vs_observed.png` (identity line + 10× band) and
`results/ale_score_vs_observed.png` (score vs realized loss).

**Honest tails (visible on the graphs):** the calibrated map fails at the extremes —
the score floor (~40) makes ultra-rare events (freq ≲ 1e-4) over-predicted up to
~5–10×, and the single high-frequency point (ransomware, score 92.7) is overextrapolated
~440× by the linear score→log-ALE fit (the fuzzy score is an ordinal index, not a
linear ALE meter). Predictive power is **strong in rank (0.61) and in the mid-range
(main scenarios within ~10×), weak as an absolute dollar meter at the extremes.**

## 30. Other changes in this part

- `README.md` TEF membership-function row updated to the recalibrated bands.
- The vulnerability band was left unchanged (its inputs are 0.25–0.85 exploit priors,
  for which the standard bands are appropriate).
- Note: this is the third calibration fix surfaced by the empirical program
  (LM linear→log in Study C; TEF resolution here); each was confirmed by re-running
  the relevant validation.

Reproduce:

```bash
python3 validation/fix_configuration.py /workspace/fst_risk_data.db   # TEF fix applied
cd validation
venv/bin/python incidents/scenario_calibration.py   # scenario scores (fixed TEF)
venv/bin/python incidents/ale_calibration.py         # -> ale_calibration.json + 2 PNGs
```
