#!/usr/bin/env python3
"""Fetch SEC 8-K Item 1.05 filing texts and extract quantified impact mentions
(dollar amounts near cyber keywords) -> incidents/sec_costs.json"""
import json
import re
import time

import urllib3
import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
HDR = {"User-Agent": "FSTValidation research contact@example.com"}

rows = []
seen = set()
for f in ("incidents/raw/sec_item105.json", "incidents/raw/sec_item105_b.json"):
    try:
        d = json.load(open(f))
    except Exception:
        continue
    for h in d.get("hits", {}).get("hits", []):
        s = h.get("_source", {})
        acc = h.get("_id", "").split(":")[0]
        doc = h.get("_id", "").split(":")[-1]
        cik = (s.get("ciks") or [""])[0].lstrip("0")
        if (acc, doc) in seen:
            continue
        seen.add((acc, doc))
        rows.append({
            "org": (s.get("display_names") or [""])[0].split("  ")[0],
            "file_date": s.get("file_date", ""),
            "url": f"https://www.sec.gov/Archives/edgar/data/{cik}/{acc.replace('-', '')}/{doc}",
        })
print(f"filings to fetch: {len(rows)}")

AMOUNT = re.compile(
    r"([\$]\s*[\d,.]+\s*(?:million|billion))|([\d,.]+\s*(?:million|billion)\s*(?:dollars|USD))",
    re.I,
)
CYBER = re.compile(r"cyber|incident|ransom|breach|unauthorized", re.I)

out = []
for i, r in enumerate(rows):
    try:
        t = requests.get(r["url"], headers=HDR, timeout=30, verify=False).text
    except Exception as e:
        print("fetch fail", r["url"], e)
        continue
    text = re.sub(r"<[^>]+>", " ", t)
    text = re.sub(r"\s+", " ", text)
    amounts = []
    for m in AMOUNT.finditer(text):
        span = text[max(0, m.start() - 200): m.end() + 200]
        if CYBER.search(span):
            amounts.append(m.group(0))
    r["amount_mentions"] = amounts[:10]
    out.append(r)
    time.sleep(0.25)
    if (i + 1) % 20 == 0:
        print(f"  {i+1}/{len(rows)}")

json.dump(out, open("incidents/sec_costs.json", "w"), indent=1)
with_amt = sum(1 for r in out if r["amount_mentions"])
print(f"done: {len(out)} filings, {with_amt} with quantified amounts near cyber context")
