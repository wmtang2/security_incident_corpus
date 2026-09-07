#!/bin/bash
# invoked via: xargs -n 3 ./fetch_one.sh _ BASE OUTDIR  (cve year sub appended)
base=$2; outdir=$3; cve=$4; year=$5; sub=$6
out="$outdir/$cve.json"
for i in 1 2 3 4; do
  code=$(curl -sL -m 45 --retry 0 -o "$out" -w "%{http_code}" "$base/CVE-$year/CVE-$year-$sub/$cve.json")
  if [ "$code" = "200" ] && [ -s "$out" ]; then exit 0; fi
  rm -f "$out"
  sleep $((i*2))
done
echo "$cve" >> "$outdir/../nvd_missing.txt"
exit 1
