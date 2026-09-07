import json, os, sys, time
from datetime import date, timedelta
import urllib3, requests
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
shard_file = sys.argv[1]
cves = [c for c in open(shard_file).read().split() if c]
START, END = date(2021, 7, 19), date(2026, 6, 1)
for cve in cves:
    path = f'incidents/epss_cache/{cve}.json'
    series = json.load(open(path)) if os.path.exists(path) else {}
    end = END
    tries = 0
    while end >= START and tries < 90:
        if end.isoformat() in series and (end - timedelta(days=28)).isoformat() in series:
            end -= timedelta(days=29)
            continue
        try:
            r = requests.get('https://api.first.org/data/v1/epss',
                             params={'cve': cve, 'date': end.isoformat(), 'scope': 'time-series'},
                             timeout=30, verify=False)
            data = r.json().get('data', [])
            if data and data[0].get('time-series'):
                for pt in data[0]['time-series']:
                    series[pt['date']] = float(pt['epss'])
            end -= timedelta(days=29)
            tries = 0
        except Exception as e:
            tries += 1
            time.sleep(2)
        time.sleep(0.2)
    json.dump(series, open(path, 'w'))
    print(f'{shard_file}: {cve} -> {len(series)} days', flush=True)
print(shard_file, 'DONE', flush=True)
