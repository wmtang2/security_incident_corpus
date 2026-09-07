#!/usr/bin/env python3
"""Parse all acquired incident sources into one exhaustive catalog.

Unified schema (validation/data/incidents_all.csv):
  source, org, date, date_precision, cve, group, cost_usd, records, tier, ref

Tiers:
  tier1 = CVE explicitly named in the source record (hard linkage)
  tier2 = ransomware incident attributed to a group with documented exploited CVEs
  tier3 = no CVE linkage (catalog only; used for loss distributions)

Sources: VCDB, ransomware.live, ransomwatch, SEC EDGAR 8-K Item 1.05,
GDPR Enforcement Tracker (mirror), Wikipedia lists, HHS OCR, WA AG, PRC.
"""
import csv
import glob
import json
import re
from datetime import date

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}")
RAW = "incidents/raw"
OUT = "data/incidents_all.csv"

rows = []


def add(source, org, dt, prec, cve, group, cost, records, tier, ref):
    if not org:
        return
    rows.append({
        "source": source, "org": org.strip()[:200], "date": dt,
        "date_precision": prec, "cve": cve or "", "group": group or "",
        "cost_usd": cost if cost else "", "records": records if records else "",
        "tier": tier, "ref": (ref or "")[:300],
    })


# ---------------- VCDB (tier1: structured CVE fields)
for f in glob.glob(f"{RAW}/vcdb/data/json/validated/*.json"):
    txt = open(f, encoding="utf-8", errors="replace").read()
    m = CVE_RE.findall(txt)
    if not m:
        continue
    d = json.loads(txt)
    act = d.get("action", {})
    cve_field = (act.get("hacking", {}) or {}).get("cve") or (act.get("malware", {}) or {}).get("cve")
    cves = CVE_RE.findall(cve_field or "") or m
    tl = d.get("timeline", {}).get("incident", {})
    y, mo, da = tl.get("year"), tl.get("month"), tl.get("day")
    if not y:
        continue
    prec = "day" if da else ("month" if mo else "year")
    dt = f"{y:04d}-{mo or 7:02d}-{da or 15:02d}"
    org = (d.get("victim", {}) or {}).get("victim_id") or "unknown"
    # records / cost if present
    records = None
    for dd in d.get("attribute", {}).get("confidentiality", {}).get("data", []):
        if isinstance(dd.get("amount"), (int, float)):
            records = (records or 0) + dd["amount"]
    cost = None
    imp = d.get("impact", {}) or {}
    if isinstance(imp.get("overall_amount"), (int, float)):
        cost = imp["overall_amount"]
    add("vcdb", org, dt, prec, ";".join(sorted(set(cves))), "", cost, records, "tier1",
        (d.get("reference") or "")[:200])

# ---------------- ransomware.live (tier2: group attribution)
for f in glob.glob(f"{RAW}/rwl_victims_*.json"):
    try:
        d = json.load(open(f))
    except Exception:
        continue
    if not isinstance(d, list):
        continue
    for r in d:
        dt = (r.get("published") or r.get("discovered") or "")[:10]
        if not dt:
            continue
        org = r.get("post_title") or r.get("website") or ""
        add("ransomware.live", org, dt, "day", "", r.get("group_name") or "",
            None, None, "tier2", r.get("post_url") or "")

# ---------------- ransomwatch (tier2; dedupe later)
try:
    d = json.load(open(f"{RAW}/ransomwatch_posts.json"))
    for r in d:
        dt = (r.get("discovered") or "")[:10]
        if not dt:
            continue
        add("ransomwatch", r.get("post_title") or "", dt, "day", "",
            r.get("group_name") or "", None, None, "tier2", "")
except Exception as e:
    print("ransomwatch parse failed:", e)

# ---------------- GDPR fines (tier3, real monetary losses)
try:
    with open(f"{RAW}/gdpr_fines.csv", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            dt = r.get("Date", "")[:10]
            fine = r.get("Fine_cleaned") or ""
            try:
                cost = float(fine) * 1.08  # EUR -> USD approx
            except ValueError:
                cost = None
            add("gdpr_fines", r.get("Controller", ""), dt, "day", "", "", cost,
                None, "tier3", r.get("Source", ""))
except Exception as e:
    print("gdpr parse failed:", e)

print(f"parsed so far: {len(rows)}")
import collections
print(collections.Counter(r["source"] for r in rows))

# ---------------- SEC 8-K Item 1.05 material cyber incidents (tier3)
seen_cik_date = set()
for f in ("sec_item105.json", "sec_item105_b.json"):
    try:
        d = json.load(open(f"{RAW}/{f}"))
    except Exception:
        continue
    for h in d.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        names = s.get("display_names") or []
        org = names[0].split("  ")[0] if names else ""
        dt = (s.get("period_ending") or s.get("file_date") or "")[:10]
        key = (org, dt)
        if key in seen_cik_date:
            continue
        seen_cik_date.add(key)
        acc = h.get("_id", "").split(":")[0].replace("-", "")
        cik = (s.get("ciks") or [""])[0].lstrip("0")
        doc = h.get("_id", "").split(":")[-1]
        ref = f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc}/{doc}" if acc else ""
        add("sec_8k_item105", org, dt, "day", "", "", None, None, "tier3", ref)

# ---------------- Wikipedia lists (tier1 if CVE mentioned else tier3)
def parse_wiki(fname, source):
    try:
        d = json.load(open(f"{RAW}/{fname}"))
        text = d["parse"]["wikitext"]
    except Exception as e:
        print(f"wiki {source} parse failed:", e)
        return
    # table rows look like: | org || year || records || ... (varies); extract per line-block
    cur = []
    for line in text.splitlines():
        if line.startswith("|-"):
            if cur:
                handle_wiki_row(cur, source)
            cur = []
        elif line.startswith("|") and not line.startswith("|}") and not line.startswith("|+"):
            cur.append(line)
    if cur:
        handle_wiki_row(cur, source)


CELL_RE = re.compile(r"\[\[(?:[^\]|]*\|)?([^\]|]+)\]\]|\{\{[^}]*\}\}")


def handle_wiki_row(lines, source):
    cells = []
    for ln in lines:
        ln = ln.lstrip("|!").strip()
        for part in re.split(r"\|\|", ln):
            part = CELL_RE.sub(lambda m: m.group(1) or "", part).strip()
            part = re.sub(r"'''", "", part)
            if part:
                cells.append(part)
    if len(cells) < 2:
        return
    joined = " | ".join(cells)
    cves = ";".join(sorted(set(CVE_RE.findall(joined))))
    year_m = re.search(r"\b(19|20)\d{2}\b", joined)
    org = cells[0][:120]
    if org.lower() in ("entity", "organisation", "organization", "company", "name", "year"):
        return
    records = None
    cost = None
    for c in cells:
        cm = re.match(r"^([\d,.]+)\s*(million|billion)?$", c.replace(" records", "").strip(), re.I)
        if cm and records is None:
            try:
                v = float(cm.group(1).replace(",", ""))
                mult = {"million": 1e6, "billion": 1e9}.get((cm.group(2) or "").lower(), 1)
                if v * mult >= 10:
                    records = int(v * mult)
            except ValueError:
                pass
        dm = re.search(r"\$\s*([\d,.]+)\s*(million|billion)", c, re.I)
        if dm and cost is None:
            try:
                v = float(dm.group(1).replace(",", ""))
                cost = v * (1e9 if dm.group(2).lower() == "billion" else 1e6)
            except ValueError:
                pass
    dt = f"{year_m.group(0)}-07-01" if year_m else ""
    tier = "tier1" if cves else "tier3"
    add(source, org, dt, "year", cves, "", cost, records, tier, "wikipedia")


parse_wiki("wiki_breaches.json", "wiki_data_breaches")
parse_wiki("wiki_cyberattacks.json", "wiki_cyberattacks")

# ---------------- HHS OCR + WA AG + PRC (tier3, records-based losses)
try:
    with open("data/hhs_breach_clean.csv", encoding="utf-8", errors="replace") as f:
        for r in csv.DictReader(f):
            try:
                n = float(r["Individuals Affected"])
            except (ValueError, KeyError):
                continue
            if n <= 0:
                continue
            dt = (r.get("Breach Submission Date") or "")[:10]
            add("hhs_ocr", r.get("Name of Covered Entity", ""), dt, "day", "", "",
                None, int(n), "tier3", "")
except Exception as e:
    print("hhs parse failed:", e)

try:
    d = json.load(open("data/wa_breaches.json"))
    for r in d:
        try:
            n = float(r["washingtoniansaffected"])
        except (ValueError, KeyError):
            continue
        if n <= 0:
            continue
        dt = (r.get("datestart") or r.get("dateaware") or "")[:10]
        add("wa_ag", r.get("name", ""), dt, "day", "", "", None, int(n), "tier3", "")
except Exception as e:
    print("wa parse failed:", e)

# ---------------- dedupe (org-month-source-family) and write
def norm(org):
    return re.sub(r"[^a-z0-9]", "", org.lower())[:40]


seen = {}
for r in rows:
    key = (norm(r["org"]), r["date"][:7], "tier2" if r["tier"] == "tier2" else r["source"])
    if key not in seen:
        seen[key] = r
    else:
        # prefer records with more info (cve > records > cost)
        cur, new = seen[key], r
        def score(x):
            return bool(x["cve"]) * 4 + bool(x["records"]) * 2 + bool(x["cost_usd"])
        if score(new) > score(cur):
            seen[key] = new

final = sorted(seen.values(), key=lambda r: r["date"])
with open(OUT, "w", newline="") as f:
    w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
    w.writeheader()
    w.writerows(final)

import collections

print(f"total incidents written: {len(final)} -> {OUT}")
print("by source:", collections.Counter(r["source"] for r in final).most_common())
print("by tier:", collections.Counter(r["tier"] for r in final))
print("tier1 (CVE-linked):", sum(1 for r in final if r["tier"] == "tier1"))

