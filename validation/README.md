# Cyber Security Incident Dataset

This folder is a **curated dataset** of cyber security incident information,
assembled from public sources for research and analysis purposes.

**What's here:**
- ~1,400 scored real-world incidents with CVE linkages, EPSS exploitation
  likelihoods, loss estimates, and risk scores
- ~8,300 date-matched controls (non-exploited CVEs) for comparison
- 9,700+ breach loss records from US healthcare, Washington State, and
  Privacy Rights Clearinghouse
- EPSS daily time-series (2021–2026) for thousands of CVEs
- Ransomware group → CVE mapping grounded in CISA advisories
- Pre-computed analysis results, metrics, and visualizations

---

## Dataset Contents

### Committed data files

| File | Size | Description |
|---|---|---|
| `incidents/scored.csv` | ~1.8 MB | 1,364 incidents + 8,312 controls, each scored through a risk model |
| `incidents/score_set.csv` | ~1.1 MB | Pre-scoring entity set (incidents + controls with raw inputs) |
| `incidents/sec_costs.json` | ~17 KB | Quantified cost mentions from SEC 8-K Item 1.05 filings |
| `incidents/group_cve_map.json` | ~5 KB | Ransomware group → exploited CVEs (CISA-sourced) |
| `incidents/nvd_needed.txt` | ~118 KB | CVEs needing NVD records for the incident study |
| `results/scenario_table.csv` | ~3 KB | Per-sector per-scenario risk data |
| `results/losses.npz` | ~78 KB | Loss arrays (HHS/WA/PRC) for plotting |
| `results/study_*.json` | 1–12 KB each | Pre-computed analysis results |
| `results/*.png` | 30–150 KB each | Pre-computed visualizations |
| `REPORT.md` | ~40 KB | Full analysis report |

### Schema: `incidents/scored.csv`

| Column | Description |
|---|---|
| `kind` | `incident` or `control` |
| `inc_id` | Unique incident identifier |
| `source` | Origin (vcdb, ransomwatch, sec_edgar, wikipedia, etc.) |
| `org` | Affected organization name |
| `date` | Incident date (ISO 8601) |
| `cve` | Primary CVE identifier |
| `cve_all` | All CVEs associated with the incident (semicolon-separated) |
| `group` | Ransomware group name (for tier2 incidents) |
| `tier` | `tier1` (CVE-linked), `tier2` (group-attributed), `tier3` (no CVE) |
| `cost_usd` | Disclosed dollar loss (if available) |
| `records` | Number of records affected (if available) |
| `tef` | EPSS exploitation probability at incident date |
| `zero_day_flag` | 1 if no EPSS score existed at incident date (0-day) |
| `cve_primary` | The CVE used for scoring (max-EPSS among cve_all) |
| `tef_final` | Final threat event frequency used |
| `zero_day` | Binary: was this a 0-day? |
| `vuln_final` | Vulnerability prior (0.85 exploit existed, 0.25 otherwise) |
| `lm_usd` | Loss magnitude in USD (disclosed, records×$165, or class bucket) |
| `lm_src` | Source of loss magnitude (realized, records_x_perrecord, class_bucket) |
| `lm_universe` | Loss magnitude normalized to [0, 10] universe |
| `score` | Risk score (0–100) |
| `level` | Linguistic risk level (low/medium/high/critical) |

### Schema: `results/scenario_table.csv`

| Column | Description |
|---|---|
| `sector` | Industry sector (healthcare, business, finance, etc.) |
| `scenario` | Breach type (hacking_incident, ransomware, phishing, etc.) |
| `n` | Number of observed incidents |
| `freq_per_org_yr` | Annualized frequency per organization |
| `median_records` | Median records affected |
| `median_loss_usd` | Median loss in USD |
| `annualized_loss_usd` | Annualized loss (freq × median loss) |
| `score` | Risk score |
| `level` | Risk level |

---

## Data Sources

All data is drawn from public, independently produced sources:

| Source | Data Provided |
|---|---|
| **[CISA KEV](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)** | Known exploited vulnerabilities catalog |
| **[FIRST.org EPSS](https://www.first.org/epss)** | Daily probability-of-exploitation scores for all CVEs |
| **[NVD (FKIE-CAD mirror)](https://github.com/fkie-cad/nvd-json-data-feeds)** | CVSS scores, CWEs, and vulnerability metadata |
| **[Exploit-DB](https://www.exploit-db.com)** | Public exploit publication dates (extraction script only; data not redistributed) |
| **[HHS OCR Breach Portal](https://ocrportal.hhs.gov/ocr/breach/breach_report.jsf)** | US healthcare breach records (7,800+ incidents) |
| **[WA AG Breach Notifications](https://fortress.wa.gov/atg/formbuilder/DataBreachSearch)** | Washington State breach notifications (1,650+ incidents) |
| **[Privacy Rights Clearinghouse](https://privacyrights.org/data-breaches)** | Research breach database |
| **[VCDB](https://github.com/vz-risk/VCDB)** | VERIS Community Database — structured breach records |
| **[ransomware.live](https://www.ransomware.live)** | Ransomware victim posts (extraction script only; data not redistributed) |
| **[ransomwatch](https://ransomwatch.telemetry.ltd)** | Ransomware blog mirror |
| **SEC EDGAR** | Public company 8-K Item 1.05 cyber-event filings |
| **Wikipedia** | Data breach and cyberattack lists |
| **[GDPR Enforcement Tracker](https://www.enforcementtracker.com)** | Regulatory fines |
| **Sophos State of Ransomware 2024** | Ransomware victimization rates (cited constants only; no bulk data) |
---

## Maintenance Scripts

The scripts in this folder are tools for **extending and maintaining
the dataset** by fetching fresh data from public sources and reprocessing it.
They are organized as a staged pipeline:

| Stage | Scripts | What it does |
|---|---|---|
| **Fetch** | `build_sample.py`, `fetch_nvd.sh` + `fetch_one.sh`, `incidents/fetch_epss_series.py`, `incidents/fetch_sec_texts.py` | Download or build CVEs / NVD records / EPSS time-series / SEC texts |
| **Parse** | `incidents/parse_incidents.py`, `extract_features.py`, `build_features2.py` | Normalize raw sources into unified catalog / feature tables |
| **Score** | `run_model.py`, `run_model2.py`, `run_model3.py`, `incidents/build_score_set.py`, `incidents/score_incidents.py` | Attach scores and labels to catalog entities |
| **Analyze** | `analyze.py`, `analyze2.py`, `analyze3.py`, `incidents/analyze_incidents.py`, `study_a_incidents.py`, `study_a_fixed.py`, `study_c_loss_scale.py`, `incidents/scenario_calibration.py`, `incidents/ale_calibration.py` | Compute metrics, studies, and calibrations on the dataset |
| **Plot** | `make_plots.py` … `make_plots5.py` | Generate visualizations of the dataset and results |
| **Configure** | `fix_configuration.py`, `check_unit_mapping.py` | Manage the scale/rule configuration used by scoring |
---

## Usage

This dataset can be used for:

- **Risk model validation** — compare predicted exploitation against known-exploited CVEs
- **Incident analysis** — study the characteristics of real-world cyber incidents
- **Scenario analysis** — examine breach frequencies and losses by sector and type
- **Loss modeling** — analyze breach loss distributions from registry data
- **Vulnerability research** — study EPSS time-series, exploit publication patterns,
  and CVE exploitation timelines

The pre-computed results in `results/` and the analysis in `REPORT.md` are one
example of what can be done with this data. The scripts are provided so you can
reproduce, extend, or adapt the dataset to your own purposes.

### Dependencies

Python 3.11+, `scikit-fuzzy`, `scipy`, `numpy`, `matplotlib`, `requests`.

### Reproducibility

All PRNG seeds are fixed (seed 42 / 7). Bootstraps use 2,000 iterations.

## License & Attribution

This dataset aggregates data from multiple public sources. Each source retains
its own license and attribution requirements. **You must comply with the terms
of each source when using or redistributing this dataset.**

### Public Domain (US Government)

| Source | License | Attribution |
|---|---|---|
| **CISA KEV** | US Government work — public domain (17 U.S.C. § 105) | No attribution required |
| **HHS OCR Breach Portal** | US Government work — public domain | No attribution required |
| **SEC EDGAR** | US Government work — public domain | No attribution required |
| **NVD (via FKIE-CAD mirror)** | NVD Terms of Use — public service | "This product uses the NVD API but is not endorsed or certified by the NVD" |

### Open Licenses (Copyleft)

| Source | License | Attribution |
|---|---|---|
| **VCDB (VERIS)** | **CC BY-SA 4.0** | Attribute to Verizon Risk Team; share-alike required |
| **Wikipedia** | **CC BY-SA 4.0** | Attribute to Wikipedia contributors; share-alike required |
| **ransomwatch** | **Unlicense** | No attribution required |

### Non-Commercial Licenses

| Source | License | Attribution |
|---|---|---|
| **Privacy Rights Clearinghouse** | **CC BY-NC-SA 4.0** | Attribute to Privacy Rights Clearinghouse; non-commercial use only; share-alike required |
| **GDPR Enforcement Tracker** | **CC BY-NC-SA 4.0** | Attribute to CMS; non-commercial use only; share-alike required |

### Restricted Sources (Extraction Scripts Only)

The following sources prohibit redistribution of their data. The extraction
scripts are provided so you can download the data yourself for your own use:

| Source | Terms | Notes |
|---|---|---|
| **ransomware.live** | All rights reserved; commercial use prohibited without permission | Data not included in this dataset; use `incidents/parse_incidents.py` to fetch |
| **Sophos State of Ransomware 2024** | © Sophos Ltd. All rights reserved | Cited constants only ($2.73M mean recovery cost, 59% victimization rate); no bulk data |
| **Exploit-DB** | Terms of Service apply | Data not included; use `build_features2.py` to fetch |

### This Project

**Scripts and code** in this repository (all `.py`, `.sh`, and other script files)
are licensed under the **GNU General Public License v3.0** (GPL-3.0), as
provided in the top-level `LICENSE` file.

**Dataset files** (CSV, JSON, text files containing incident data, results, and
other compiled data) remain subject to the licenses of their original sources
as described in the tables above. The compilation may be used under the terms
of the respective source licenses; no additional restriction is asserted over
the data itself.

This is a **security incident corpus** — a curated, validated collection of
publicly available IT security incident data. It is **not** a software product
and is provided for research and analysis purposes only.
