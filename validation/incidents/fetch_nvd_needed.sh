#!/bin/bash
cd /workspace/validation
mkdir -p data/nvd
BASE=https://raw.githubusercontent.com/fkie-cad/nvd-json-data-feeds/main
while read -r cve; do
  [ -s "data/nvd/$cve.json" ] && continue
  year=$(echo "$cve" | cut -d- -f2)
  seq=$(echo "$cve" | cut -d- -f3)
  hundred=$(echo "$seq" | sed -E 's/^(.*)[0-9]{2}$/\1/')
  [ -z "$hundred" ] && hundred=0
  printf '%s %s %sxx\n' "$cve" "$year" "$hundred"
done < incidents/nvd_needed.txt > /tmp/fetch_needed.txt
echo "to fetch: $(wc -l < /tmp/fetch_needed.txt)"
cat /tmp/fetch_needed.txt | xargs -P 8 -n 3 ./fetch_one.sh _ "$BASE" "$PWD/data/nvd" 2>/dev/null || true
echo "done. total nvd cache: $(ls data/nvd | wc -l)"
