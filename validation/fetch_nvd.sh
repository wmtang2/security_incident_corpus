#!/bin/bash
# Fetch NVD 2.0 JSON records for sampled CVEs from the FKIE-CAD daily mirror
# of the official NVD JSON feeds (github.com/fkie-cad/nvd-json-data-feeds).
# Layout: CVE-<year>/CVE-<year>-<seq100>xx/CVE-<year>-<seq>.json
set -u
cd "$(dirname "$0")"
mkdir -p data/nvd
BASE=https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main

tail -n +2 data/sample.csv | cut -d, -f1 | while read -r cve; do
  [ -s "data/nvd/$cve.json" ] && continue
  year=$(echo "$cve" | cut -d- -f2)
  seq=$(echo "$cve" | cut -d- -f3)
  hundred=$(echo "$seq" | sed -E 's/^(.*)[0-9]{2}$/\1/')
  [ -z "$hundred" ] && hundred=0
  printf '%s %s %sxx\n' "$cve" "$year" "$hundred"
done > /tmp/fetch_list.txt
echo "to fetch: $(wc -l < /tmp/fetch_list.txt)"

rm -f data/nvd_missing.txt
cat /tmp/fetch_list.txt | xargs -P 8 -n 3 ./fetch_one.sh _ "$BASE" "$PWD/data/nvd" 2>/dev/null || true

echo "pass done. fetched: $(ls data/nvd | wc -l), missing: $(wc -l < data/nvd_missing.txt 2>/dev/null || echo 0)"
