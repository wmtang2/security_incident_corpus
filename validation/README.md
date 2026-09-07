# Validation — Cyber Incident Data & Analysis Pipeline

This folder contains a **collection of scripts, datasets, and analysis pipelines**
for working with real-world cyber security incident data. It provides:

- **Reproducible data pipelines** that fetch, parse, and normalize cyber incident
  data from multiple public sources
- **Empirical analysis** of vulnerability exploitation patterns, breach losses,
  and scenario-level risk using real-world data
- **Pre-built datasets** including breach registries, exploit intelligence,
  EPSS time-series, and incident catalogs

> **All scripts are fully reproducible.** Data that can be re-fetched from public
> sources is fetched on the fly; cached/private data is committed alongside the
> scripts. Run `python3 <script>` from the parent project root as noted in each
> script's docstring.

---

## Directory Layout

| Path | Purpose |
|---|---|
| `*.py` | Top-level scripts: data pipelines, analysis, and plotting |
| `*.sh` | Shell scripts for parallel NVD fetch from the FKIE-CAD mirror |
| `results/` | Output: JSON metrics, PNG plots, NPZ arrays |
| `incidents/` | Incident-catalog pipeline + scoring + analysis |
| `incidents/epss_cache/` | Cached EPSS daily time-series per CVE |
| `incidents/raw/` | Raw sourced data (VCDB, ransomware.live, SEC EDGAR, etc.) |
| `data/` | (Populated at runtime) NVD JSON records, feature CSVs, EPSS snapshots |
| `REPORT.md` | **Full analysis report** (650+ lines) with results, graphs, and commentary |

---

## What the Data Is — All Real, Public, Independently Produced

### Vulnerability & exploitation data

| Source | What it provides | How it's used |
|---|---|---|
| **[CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)** | Ground-truth outcome: "exploited in the wild" + date added | Positive labels: CVEs added to KEV within 12/24 months of a prediction cutoff (`data/kev.json`) |
| **[FIRST.org EPSS](https://www.first.org/epss)** | Daily probability-of-exploitation scores (0–1) for every CVE | Threat event frequency / likelihood input (`data/epss_2024-06-01.csv.gz`; full time-series in `incidents/epss_cache/`) |
| **[NVD (via FKIE-CAD mirror)](https://github.com/fkie-cad/nvd-json-data-feeds)** | CVSS v3.x / v2 base, impact, exploitability scores for each CVE | Loss magnitude and vulnerability inputs, rescaled to unit universes (`data/nvd/*.json`, fetched by `fetch_nvd.sh`) |
### Real-world loss data

| Source | Description | Records used |
|---|---|---|
| **[HHS OCR Breach Portal](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)** | US healthcare breaches, 2009–2026, with individuals-affected counts | ~7,800 incidents (`data/hhs_breach_clean.csv`) |
| **[Washington AG Breach Notifications](https://fortress.wa.gov/atg/formbuilder/DataBreachSearch)** | All-industry breaches reported to WA Attorney General, 2016–2026 | ~1,650 incidents (`data/wa_breaches.json`) |
| **[Privacy Rights Clearinghouse](https://privacyrights.org/data-breaches)** | Research dataset of cyber incidents | ~295 cleaned records (`data/prc_cyber_loss.xlsx`) |
| **Cost multipliers** | IBM Cost of a Data Breach 2023 per-record costs | Healthcare $408/record; general $165/record (sensitivity bounds $100–$500) |

### Incident catalog

| Source | Coverage | Tier |
|---|---|---|
| **[VCDB (VERIS)](https://github.com/vz-risk/VCDB)** | Structured validated breach records with CVE linkages, 2021–2026 | tier1 (CVE-linked) |
| **[ransomware.live](https://www.ransomware.live)** | Ransomware victim posts by group, 2021–2026 | tier2 (group-attributed) |
| **[ransomwatch](https://ransomwatch.telemetry.ltd)** | Ransomware blog mirror | tier2 (group-attributed) |
| **SEC EDGAR 8-K Item 1.05** | Public company material-cyber-event filings with quantified costs | tier1 where CVE-linked |
| **Wikipedia data breach / cyberattack lists** | Curated notable incidents | tier1 / tier3 |
| **[GDPR Enforcement Tracker](https://www.enforcementtracker.com)** | Regulatory fines | tier3 (loss distribution) |

The incident catalog unifies these into one schema (`data/incidents_all.csv`):
`source, org, date, cve, group, cost_usd, records, tier, ref`

### Scenario calibration data

| Source | Sector | Values |
|---|---|---|
| HHS OCR (per-type counts) | Healthcare | Breach frequencies by type (hacking, unauthorized access, theft/loss) |
| WA AG (per-cause per-sector) | Business, Health, Finance, Education, Government, Other | Cause-specific frequencies and median records |
| Sophos State of Ransomware 2024 | Cross-sector | Ransomware TEF baseline (59% of orgs hit) |
| ransomware.live | Cross-sector | Annual ransomware victim counts |
---

## Understanding the Pipeline

The analysis is organized as a series of **progressive studies**, each building
on the previous:

### Part I — Discrimination against KEV exploitation

`build_sample.py` → `fetch_nvd.sh` → `extract_features.py` → `run_model.py` → `analyze.py` → `make_plots.py`

Constructs a CVE cohort (positives = KEV-added within 24 months, negatives = random),
fetches NVD records, extracts CVSS-based model inputs, scores through a risk engine,
and computes ROC AUC, level calibration, and decile calibration.

### Part II — Real-world data inputs

`run_model2.py` → `analyze2.py` → `make_plots2.py`

Same structure but LM uses realized USD (from breach registries) and Vuln uses
Exploit-DB evidence. Demonstrates a log-scale LM repair.

### Part III — Famous incidents study

`study_a_incidents.py`

Scores 9 well-known incidents (Equifax, NotPetya, WannaCry, etc.) against
matched controls using real disclosed dollar losses.

### Part IV — Loss magnitude scale coverage

`study_c_loss_scale.py`

Tests whether a linear $0–1B loss scale covers 9,706 real breach losses.
Finds 98.7% fall in "low" band; demonstrates a log-scale repair.

### Part V — Fixed configuration

`fix_configuration.py` → `run_model3.py` → `analyze3.py` → `make_plots3.py` → `study_a_fixed.py`

Re-runs against a corrected configuration with recalibrated membership functions,
log loss scale, and a verified 27-rule base.

### Part VI — Scenario calibration

`incidents/scenario_calibration.py` → `make_plots5.py`

Maps industry-sector scenarios through a risk model with environment-conditional
likelihood and financial reconciliation.

### Part VII — Predictive power

`incidents/ale_calibration.py`

Leave-one-out calibrated regression: risk score → log10(observed per-org ALE).

### Part VIII — Expanded incident catalog

`incidents/parse_incidents.py` → `build_score_set.py` → `score_incidents.py` → `analyze_incidents.py` → `make_plots4.py`

Complete pipeline: parse ~15 sources → unified catalog → date-matched controls
→ score through risk engine → analyze discrimination and level purity.

### Incident-specific support scripts

| Script | Purpose |
|---|---|
| `incidents/fetch_epss_series.py` | Pre-fetch EPSS daily history for all incident CVEs (2021-07-19 → 2026-06-01) |
| `incidents/fetch_sec_texts.py` | Fetch SEC 8-K Item 1.05 filing texts → extract quantified dollar amounts |
| `incidents/fetch_nvd_needed.sh` | Fetch NVD records for incident-required CVEs only |
| `incidents/epss_shard_worker.py` | Helper for parallel EPSS time-series fetch |
---

## Key Results Summary

| Metric | Value |
|---|---|
| ROC AUC (risk model, CVSS inputs, 24m outcome) | **0.828** |
| ROC AUC (EPSS alone, 24m) | 0.809 |
| ROC AUC (CVSS base alone, 24m) | 0.691 |
| Famous incidents vs controls (MWU p) | 0.001 |
| Spearman(score, log10 realized cost) | 0.61, p = 0.0015 |
| Scenario score vs FAIR expected annual loss | Spearman 0.61, p = 0.0015 |
| LOO predicted/observed ALE ratio (geomean) | 1.13× |

> See `REPORT.md` for the complete 650-line analysis report with full tables,
> graphs, and methodological discussion.

---

## Running the Pipeline

```bash
# Part I: Full cohort validation
python3 validation/build_sample.py
bash validation/fetch_nvd.sh
python3 validation/extract_features.py
python3 validation/run_model.py
python3 validation/analyze.py
python3 validation/make_plots.py

# Part II: Real-world inputs
python3 validation/run_model2.py
python3 validation/analyze2.py
python3 validation/make_plots2.py

# Part III: Famous incidents
python3 validation/study_a_incidents.py

# Part IV: Loss scale
python3 validation/study_c_loss_scale.py
python3 validation/make_plots2.py

# Part V: Apply fixed config
python3 validation/fix_configuration.py
python3 validation/run_model3.py
python3 validation/analyze3.py
python3 validation/make_plots3.py
python3 validation/study_a_fixed.py

# Parts VI–VII: Scenarios & ALE calibration
python3 validation/incidents/scenario_calibration.py
python3 validation/incidents/ale_calibration.py
python3 validation/make_plots5.py

# Part VIII: Full incident catalog pipeline
python3 validation/incidents/parse_incidents.py
python3 validation/incidents/fetch_epss_series.py           # slow; fetches full API history
python3 validation/incidents/build_score_set.py
bash   validation/incidents/fetch_nvd_needed.sh
python3 validation/incidents/score_incidents.py
python3 validation/incidents/analyze_incidents.py
python3 validation/make_plots4.py
```
| **[Exploit-DB](https://www.exploit-db.com)** | Public exploit publication dates | Vulnerability prior: 0.85 if an exploit existed before the incident date, else 0.25 (`data/files_exploits.csv`) |
---

## Files at a Glance

### Top-level scripts

| File | Study | Description |
|---|---|---|
| `build_sample.py` | I | Constructs CVE cohort: positives (KEV-added) + negatives (random) |
| `fetch_nvd.sh` | I | Parallel NVD JSON fetch from FKIE-CAD mirror |
| `fetch_one.sh` | I | Single-CVE curl helper with retries |
| `extract_features.py` | I | Parse NVD → model inputs (LM, Vuln) |
| `run_model.py` | I | Score cohort through risk engine + fallback |
| `run_model2.py` | II | Re-score with real-world USD inputs (linear + log LM) |
| `run_model3.py` | V | Re-score against the fixed configuration |
| `analyze.py` | I | Metrics: AUC, average precision, level calibration |
| `analyze2.py` | II | Metrics for real-world input variant |
| `analyze3.py` | V | Metrics for fixed configuration |
| `study_a_incidents.py` | III | Famous incidents study |
| `study_a_fixed.py` | V | Famous incidents re-run against fixed config |
| `study_c_loss_scale.py` | IV | LM scale coverage analysis (9,706 real breaches) |
| `build_features2.py` | II | Build feature set with real-world cost and exploit data |
| `check_unit_mapping.py` | — | Demonstrates scale normalization |
| `fix_configuration.py` | V | Write corrected scales, MFs, and rules to a database |

### Plot scripts

| File | Description |
|---|---|
| `make_plots.py` | Part I ROC, level rates, decile calibration, score distributions |
| `make_plots2.py` | Part II ROC (real inputs), Part IV loss distribution, Part III incident vs controls |
| `make_plots3.py` | Part V ROC (fixed vs broken), level calibration |
| `make_plots4.py` | Part VIII expanded incident distributions, level shares, monthly counts |
### Results (`results/`)

| File | Description |
|---|---|
| `metrics.json` | Part I full metrics |
| `study_b.json` | Part II metrics |
| `study_fixed.json` | Part V full metrics |
| `study_a.json` | Part III incident scores + statistics |
| `study_a_c_fixed.json` | Part V combined A+C results |
| `study_c.json` | Part IV loss-scale analysis |
| `study_incidents.json` | Part VIII incident catalog analysis |
| `study_scenarios.json` | Part VI scenario calibration |
| `ale_calibration.json` | Part VII ALE predictive power |
| `broken_db_demo.json` | Demonstration of a degenerate database configuration |
| `scenario_table.csv` | Per-sector per-scenario data for figures |
| `losses.npz` | Loss arrays (HHS/WA/PRC) for plotting |

### Incidents pipeline (`incidents/`)

| File | Description |
|---|---|
| `parse_incidents.py` | Parse all sources → unified catalog `data/incidents_all.csv` |
| `build_score_set.py` | Build scoring set (incidents + 2× date-matched controls) |
| `score_incidents.py` | Score every entity through the risk engine |
| `analyze_incidents.py` | Analysis: AUC, level purity, 0-day rate, odds ratios |
| `fetch_epss_series.py` | Pre-fetch full EPSS time-series per CVE |
| `fetch_sec_texts.py` | Fetch SEC EDGAR 8-K filings, extract cost mentions |
| `scenario_calibration.py` | Full scenario-level calibration |
| `ale_calibration.py` | Predictive ALE calibration + graphs |
| `group_cve_map.json` | Manual mapping: ransomware group → documented exploitation CVEs |
| `sec_costs.json` | Extracted cost amounts from SEC filings |
| `score_set.csv` | Entities scored through the risk engine |
| `scored.csv` | Scoring results with metadata |
| `nvd_needed.txt` | List of CVEs needing NVD records for the incident study |
---

## Model / Framework Under Test

**Inference:** Mamdani fuzzy inference, centroid defuzzification
**Rules / scales:** 27 rules (all TEF × LM × Vuln combinations)

**Input mapping (fixed config):**

| Model input | Universe | Real-world range | Mapping | Membership functions |
|---|---|---|---|---|
| `threat_event_frequency` | [0, 1] | [0.01, 100] events/yr | linear | low[0,0,0.1] med[0.02,0.08,0.25] high[0.15,0.5,1.0] |
| `loss_magnitude` | [0, 10] | [$0, $1e12] USD | **log** | low[0,0,4] med[2,5,8] high[6,10,10] |
| `vulnerability` | [0, 1] | [0, 100]% | linear | low[0,0,0.4] med[0.2,0.5,0.8] high[0.6,1.0,1.0] |
| **risk** (output) | [0, 100] | — | — | low[0,0,30] med[20,40,60] high[50,70,90] crit[80,100,100] |

---

## Notes

- **Prediction date (cutoff):** 2024-06-01 — only information available on
  that date is used as model input (prospective design, no look-ahead).
- **Reproducibility:** All PRNG seeds are fixed (seed 42 / 7). Bootstraps
  use 2,000 iterations.
- **Software dependencies:** Requires Python 3.11+, `scikit-fuzzy`, `scipy`,
  `numpy`, `matplotlib`, `requests`.
- **License:** The validation pipeline and analysis are under the same license
  as the parent project.
| `make_plots5.py` | Part VI scenario reconciliation, TEF sweep, sector heatmap |