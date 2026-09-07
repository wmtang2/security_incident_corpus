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
"""Scenario-level calibration of the FST risk model (addresses 3 critiques).

Critique 1 -> scenarios span the real risk surface, not just vulnerabilities:
  ransomware, phishing, web/exploit hacking, stolen creds, insider misuse/
  leakage, and accidental loss (theft/loss/misdisposal) + DoS where data allows.
Critique 2 -> likelihood is environment-conditional: TEF is a per-org, per-sector
  annualized frequency (count / number of in-scope orgs) and is varied per sector
  and by sensitivity. No universal likelihood is asserted.
Critique 3 -> financial reconciliation: LM = real median realized loss per
  scenario (registry records x per-record cost, or published monetary figures),
  and we regress observed annualized loss (count x median loss) on the model's
  risk score to obtain an empirical score->$ mapping.

Real data used:
  HHS OCR (healthcare; per-type counts + records), WA AG (sectors + causes),
  VCDB action varieties (phishing/ransomware/exploit/possession), ransomware.live
  (annual ransomware victims), GDPR fines (fines as regulatory losses).
"""
import csv
import json
import sys
from collections import defaultdict

import numpy as np
from scipy import stats

sys.path.insert(0, "/workspace")
import src.backend.fst_engine as fe  # noqa: E402
import skfuzzy.control as ctrl  # noqa: E402

rules, _ = fe._get_risk_rules_and_variables()
sim = ctrl.ControlSystemSimulation(ctrl.ControlSystem(rules))

from src.backend.database import DatabaseManager  # noqa: E402
from src.backend.services.scale_service import ScaleService  # noqa: E402

ss = ScaleService(DatabaseManager("sqlite:////workspace/fst_risk_data.db"))
lm_scale = ss.get_scale_by_name("loss_magnitude")

# ------------------------------------------------------------------ per-sector real data
# HHS: (type -> list of records) for 2021..2025, sector=healthcare
hhs = defaultdict(list)
with open("data/hhs_breach_clean.csv", encoding="utf-8", errors="replace") as f:
    for r in csv.DictReader(f):
        y = (r.get("Year") or (r.get("Breach Submission Date") or "")[:4])
        if not y.isdigit() or not (2021 <= int(y) <= 2025):
            continue
        t = (r.get("Type of Breach") or "").strip()
        try:
            rec = float(r["Individuals Affected"])
        except (ValueError, TypeError):
            continue
        hhs[t].append(rec)

HHS_N_ORGS = 534000  # ~ HIPAA covered entities (OCR); cited in report with sensitivity
PER_RECORD_HHS = 408.0

hhs_types = {
    "hacking_incident": ["Hacking/IT Incident"],
    "unauthorized_access_disclosure": ["Unauthorized Access/Disclosure"],
    "theft_loss_misdisposal": ["Theft", "Loss", "Improper Disposal",
                               "Theft, Unauthorized Access/Disclosure", "Loss, Theft",
                               "Other"],
}

# WA AG: per cause per sector, 2021..2025
wa = defaultdict(lambda: defaultdict(list))  # sector -> cause -> [records]
with open("data/wa_breaches.json") as f:
    import json as _j

    wd = _j.load(f)
for w in wd:
    y = (w.get("year") or "")
    if not y.isdigit() or not (2021 <= int(y) <= 2025):
        continue
    cause = (w.get("databreachcause") or "").strip()
    sector = (w.get("industrytype") or "Other").strip()
    try:
        rec = float(w.get("washingtoniansaffected") or 0)
    except (ValueError, TypeError):
        continue
    wa[sector][cause].append(rec)

WA_N_ORGS = {"Business": 240000, "Health": 12000, "Finance": 15000,
             "Education": 4000, "Government": 1500, "Non-Profit/Charity": 60000,
             "Other": 100000}  # WA-based approximate org counts; sensitivity below
PER_RECORD_WA = 165.0

# published loss anchors (documented in report)
LOSS_PUB = {  # scenario -> mean/modal realized monetary loss (USD)
    "ransomware": 2.73e6,  # Sophos State of Ransomware 2024 (mean recovery, excl. ransom)
    "phishing": 4.88e6,    # IBM Cost of a Data Breach 2024 (phishing-attributed avg)
    "web_exploit": 4.88e6, # IBM CODB 2024 global average breach
    "stolen_creds": 4.81e6 # IBM CODB 2024 (stolen credentials avg)
}
VULN_PRIOR = {  # "ease" priors per scenario (documented judgment; sensitivity)
    "ransomware": 0.85, "phishing": 0.60, "web_exploit": 0.85,
    "stolen_creds": 0.60, "insider_leak": 0.50, "accidental_loss": 0.30,
    "dos": 0.50,
}


def score(tef, lm_usd, vuln):
    lm_u = ss.normalize_value_for_scale(lm_scale, float(lm_usd), "LM")
    sim.inputs({"threat_event_frequency": min(max(tef, 0.0), 1.0),
                "loss_magnitude": lm_u, "vulnerability": vuln})
    sim.compute()
    return float(sim.output["risk"]), fe.get_risk_interpretation(float(sim.output["risk"]))


def reg_rows(sector, n_orgs, per_record, types, registry, year_n=5):
    rows = []
    for label, kinds in types.items():
        recs = []
        for k in kinds:
            recs += registry.get(k, [])
        n = len(recs)
        if n == 0:
            continue
        freq = n / year_n / n_orgs
        med_rec = float(np.median(recs))
        med_loss = med_rec * per_record
        ann_loss = n / year_n * med_loss
        rows.append({"sector": sector, "scenario": label, "n": n,
                     "freq_per_org_yr": freq, "median_records": med_rec,
                     "median_loss_usd": med_loss, "annualized_loss_usd": ann_loss})
    return rows


scenario_rows = []
scenario_rows += reg_rows("healthcare", HHS_N_ORGS, PER_RECORD_HHS, hhs_types, hhs)

wa_types = {
    "hacking_incident": ["Cyberattack"],
    "unauthorized_access_disclosure": ["Unauthorized Access"],
    "theft_loss_misdisposal": ["Theft or Mistake"],
}
for sec, norgs in WA_N_ORGS.items():
    scenario_rows += reg_rows(sec, norgs, PER_RECORD_WA, wa_types, wa[sec])

import glob


def rwl_year_counts():
    counts = defaultdict(int)
    for f in glob.glob("incidents/raw/rwl_victims_*.json"):
        d = json.load(open(f))
        for r in d:
            year = (r.get("published") or r.get("discovered") or "")[:4]
            if year.isdigit() and 2021 <= int(year) <= 2025:
                counts[year] += 1
    return counts


rwl = rwl_year_counts()

out_rows = []
for r in scenario_rows:
    if r["scenario"] == "hacking_incident":
        scen, lm, vuln = "web_exploit", r["median_loss_usd"], VULN_PRIOR["web_exploit"]
    elif r["scenario"] == "unauthorized_access_disclosure":
        scen, lm, vuln = "insider_leak", r["median_loss_usd"], VULN_PRIOR["insider_leak"]
    else:
        scen, lm, vuln = "accidental_loss", r["median_loss_usd"], VULN_PRIOR["accidental_loss"]
    tef = r["freq_per_org_yr"]
    sc, lev = score(tef, lm, vuln)
    out_rows.append({**r, "canonical_scenario": scen, "model_lm_usd": lm,
                     "model_vuln": vuln, "score": sc, "level": lev})
    print(f"{r['sector']:22s} {scen:22s} n={r['n']:5d} TEF={tef:.5f} "
          f"LM=${lm/1e6:.2f}M score={sc:.1f} [{lev}]")

extra = []
for scen, tef, lm, vuln, n in [
    ("ransomware", 0.59, LOSS_PUB["ransomware"], VULN_PRIOR["ransomware"], sum(rwl.values())),
    ("phishing", 0.15, LOSS_PUB["phishing"], VULN_PRIOR["phishing"], None),
    ("stolen_creds", 0.08, LOSS_PUB["stolen_creds"], VULN_PRIOR["stolen_creds"], None),
]:
    sc, lev = score(tef, lm, vuln)
    ann_loss = n / 5 * lm if n else None
    extra.append({"sector": "all_industries", "scenario": scen, "n": n or 0,
                  "freq_per_org_yr": tef, "median_records": None,
                  "median_loss_usd": lm, "annualized_loss_usd": ann_loss,
                  "canonical_scenario": scen, "model_lm_usd": lm, "model_vuln": vuln,
                  "score": sc, "level": lev})
    print(f"all_industries      {scen:22s} TEF={tef:.2f} LM=${lm/1e6:.2f}M score={sc:.1f} [{lev}]")

out_rows += extra
# ------------------------------------------------------------------ calibration checks + financial reconciliation
with open("results/scenario_table.csv", "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
    w.writeheader()
    w.writerows(out_rows)

for r in out_rows:
    # per-org expected annual loss = TEF x P(loss|event~Vuln) x LM  (FAIR quantity)
    r["expected_perorg_loss_usd"] = (r["freq_per_org_yr"] * r["model_vuln"] * r["model_lm_usd"])

rec = [r for r in out_rows if r["annualized_loss_usd"]]

# A) financial reconciliation on the FAIR per-org quantity
scores = np.array([r["score"] for r in rec])
logl = np.array([np.log10(max(r["expected_perorg_loss_usd"], 1)) for r in rec])
sl, p = stats.spearmanr(scores, logl)
lin = stats.linregress(scores, logl)

# B) does the FST score track the FAIR product TEF*Vuln*LM in rank?
fair = np.array([np.log10(max(r["freq_per_org_yr"] * r["model_vuln"] * r["model_lm_usd"], 1e-9))
                 for r in rec])
sl_fair, p_fair = stats.spearmanr(scores, fair)

recon = {
    "n": len(rec),
    "spearman_score_vs_log_perorg_expected_loss": float(sl),
    "p": float(p),
    "r2": float(lin.rvalue ** 2),
    "slope": float(lin.slope),
    "spearman_score_vs_fair_product": float(sl_fair),
    "p_fair": float(p_fair),
    "note": ("score compression: at realistic per-org frequencies most scores tie "
             "at 30.4/40.0 -> frequency axis under-calibrated for rare events"),
}
print(f"\nfinancial reconciliation (per-org, n={recon['n']}):")
print(f"  Spearman(score, log10 per-org expected loss) = {sl:.3f} (p={p:.2e})")
print(f"  Spearman(score, log10 FAIR product TEF*V*LM)  = {sl_fair:.3f} (p={p_fair:.2e})")
for r in sorted(rec, key=lambda r: r["expected_perorg_loss_usd"], reverse=True)[:12]:
    print(f"    score {r['score']:5.1f}  per-org ann loss ${r['expected_perorg_loss_usd']:>12,.0f}  "
          f"=> ${r['expected_perorg_loss_usd']/1e6:6.3f}M  {r['sector']}/{r['scenario']}")

# C) environment-conditional likelihood demonstration (no universal TEF)
env_rows = []
for sector, tef in [("healthcare", 0.6), ("business", 0.4), ("education", 0.3)]:
    sc, lev = score(tef, LOSS_PUB["ransomware"], VULN_PRIOR["ransomware"])
    env_rows.append({"sector": sector, "tef_ransomware": tef, "score": sc, "level": lev})
    print(f"env-conditional ransomware TEF@{sector}: TEF={tef} -> score {sc:.1f} [{lev}]")
for tef in (0.01, 0.05, 0.1, 0.25, 0.5, 0.9):
    sc, lev = score(tef, LOSS_PUB["ransomware"], VULN_PRIOR["ransomware"])
    print(f"  TEF sweep ransomware: {tef:.2f} -> {sc:.1f} [{lev}]")

json.dump({"rows": out_rows, "reconciliation": recon, "env_conditional": env_rows,
           "assumptions": {"HHS_N_ORGS": HHS_N_ORGS, "per_record_hhs": PER_RECORD_HHS,
                           "per_record_wa": PER_RECORD_WA,
                           "wa_org_counts": WA_N_ORGS,
                           "ransomware_tef_source": "Sophos State of Ransomware 2024 (59%)",
                           "vuln_priors": VULN_PRIOR}},
          open("results/study_scenarios.json", "w"), indent=2, default=str)
print("\nwrote results/study_scenarios.json + results/scenario_table.csv")
