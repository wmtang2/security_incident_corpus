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
