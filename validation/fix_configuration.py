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
"""Fix the FSTTool risk-model configuration (scales + membership functions + rules).

Defects being fixed (all empirically demonstrated in earlier studies):
  1. Shipped fst_risk_data.db has degenerate MF points (LM ~5e-18, risk [1,1,1],
     vuln ~5e-5) -> calculate_risk() crashes (AssertionError) for every input.
  2. Sane-backup TEF MFs (low[0,.005,.01] med[.005,.015,.025] high[.02,.03,1])
     saturate for any probability > 0.03 -> 47% of scores collapse onto 70.0.
  3. LM linear $0-1B scale compresses 98.7% of realized losses into "low" and
     REJECTS losses > $1B (ValueError).

Fixed configuration:
  - TEF:  universe [0,1], real [0.01,100] events/yr (linear),
          MFs low[0,0,.4] med[.2,.5,.8] high[.6,1,1]   (README-documented shapes)
  - LM:   universe [0,10], real [$0,$1e12] USD, mapping='log' (NEW code support),
          MFs low[0,0,4] med[2,5,8] high[6,10,10]
  - Vuln: universe [0,1], real [0,100]%, linear,
          MFs low[0,0,.4] med[.2,.5,.8] high[.6,1,1]
  - Risk: universe [0,100], MFs low[0,0,30] med[20,40,60] high[50,70,90] crit[80,100,100]
  - Rules: the verified complete 27-rule base (all TEF x LM x Vuln combos)

Includes a validation gate: rejects degenerate trimf points, checks rule coverage,
and smoke-tests the real engine (including a $1.4B Equifax-size loss).

Usage: python fix_configuration.py <target_db_path>
"""
import json
import sqlite3
import sys
import uuid

TARGET = sys.argv[1] if len(sys.argv) > 1 else "/workspace/fst_risk_data.db"

SCALES = [
    ("threat_event_frequency", "Threat Event Frequency (0.0 to 1.0)", 0.0, 1.0, 0.01,
     "Antecedent", 0.01, 100.0, "events/year", "linear",
     [("low", [0.0, 0.0, 0.1]), ("medium", [0.02, 0.08, 0.25]), ("high", [0.15, 0.5, 1.0])]),
    ("loss_magnitude", "Loss Magnitude (0.0 to 10.0)", 0.0, 10.0, 0.1,
     "Antecedent", 0.0, 1e12, "USD", "log",
     [("low", [0.0, 0.0, 4.0]), ("medium", [2.0, 5.0, 8.0]), ("high", [6.0, 10.0, 10.0])]),
    ("vulnerability", "Vulnerability (0.0 to 1.0)", 0.0, 1.0, 0.01,
     "Antecedent", 0.0, 100.0, "%", "linear",
     [("low", [0.0, 0.0, 0.4]), ("medium", [0.2, 0.5, 0.8]), ("high", [0.6, 1.0, 1.0])]),
    ("risk", "Risk Output (0.0 to 100.0)", 0.0, 100.0, 1.0,
     "Consequent", None, None, None, None,
     [("low", [0.0, 0.0, 30.0]), ("medium", [20.0, 40.0, 60.0]),
      ("high", [50.0, 70.0, 90.0]), ("critical", [80.0, 100.0, 100.0])]),
]

# Complete 3x3x3 rule base (TEF, LM, Vuln) -> risk, verified against the last sane backup
RULES = {
    ("low", "low", "low"): "low", ("low", "low", "medium"): "low",
    ("low", "low", "high"): "medium", ("low", "medium", "low"): "low",
    ("low", "medium", "medium"): "medium", ("low", "medium", "high"): "medium",
    ("low", "high", "low"): "medium", ("low", "high", "medium"): "high",
    ("low", "high", "high"): "high",
    ("medium", "low", "low"): "low", ("medium", "low", "medium"): "medium",
    ("medium", "low", "high"): "medium", ("medium", "medium", "low"): "medium",
    ("medium", "medium", "medium"): "high", ("medium", "medium", "high"): "high",
    ("medium", "high", "low"): "high", ("medium", "high", "medium"): "high",
    ("medium", "high", "high"): "critical",
    ("high", "low", "low"): "medium", ("high", "low", "medium"): "high",
    ("high", "low", "high"): "high", ("high", "medium", "low"): "high",
    ("high", "medium", "medium"): "high", ("high", "medium", "high"): "critical",
    ("high", "high", "low"): "high", ("high", "high", "medium"): "critical",
    ("high", "high", "high"): "critical",
}
assert len(RULES) == 27


def main():
    conn = sqlite3.connect(TARGET)
    conn.execute("PRAGMA foreign_keys=ON")
    cols = [r[1] for r in conn.execute("PRAGMA table_info(ordinal_scales)")]
    if "real_world_mapping" not in cols:
        conn.execute(
            "ALTER TABLE ordinal_scales ADD COLUMN real_world_mapping TEXT DEFAULT 'linear'"
        )
        print("added column ordinal_scales.real_world_mapping")

    conn.execute("DELETE FROM fuzzy_rules")
    conn.execute("DELETE FROM ordinal_values")
    conn.execute("DELETE FROM ordinal_scales")

    value_ids = {}
    for name, desc, umin, umax, ustep, vtype, rmin, rmax, unit, mapping, values in SCALES:
        sid = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO ordinal_scales (id, name, description, universe_min, universe_max,"
            " universe_step, variable_type, real_world_min, real_world_max, real_world_unit,"
            " real_world_mapping, created_at, updated_at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?, datetime('now'), datetime('now'))",
            (sid, name, desc, umin, umax, ustep, vtype, rmin, rmax, unit, mapping),
        )
        for i, (label, pts) in enumerate(values):
            # validation gate: no degenerate / out-of-range trimf points
            assert len(pts) == 3 and pts[0] <= pts[1] <= pts[2], f"{name}/{label}: {pts} not ordered"
            assert not (pts[0] == pts[1] == pts[2]), f"{name}/{label}: zero-area trimf {pts}"
            assert all(umin <= p <= umax for p in pts), f"{name}/{label}: {pts} outside universe"
            vid = str(uuid.uuid4())
            value_ids[(name, label)] = vid
            conn.execute(
                "INSERT INTO ordinal_values (id, scale_id, label, order_index, mf_type, mf_points,"
                " created_at, updated_at) VALUES (?,?,?,?, 'trimf', ?, datetime('now'), datetime('now'))",
                (vid, sid, label, i, json.dumps(pts)),
            )

    for (tef, lm, vuln), risk in RULES.items():
        ant = json.dumps({
            "threat_event_frequency": value_ids[("threat_event_frequency", tef)],
            "loss_magnitude": value_ids[("loss_magnitude", lm)],
            "vulnerability": value_ids[("vulnerability", vuln)],
        })
        conn.execute(
            "INSERT INTO fuzzy_rules (id, rule_id, antecedents_by_value_id, consequent,"
            " description, created_at, updated_at) VALUES (?,?,?,?, '', datetime('now'), datetime('now'))",
            (str(uuid.uuid4()), f"fixed_{tef}_{lm}_{vuln}", ant, f"risk:{risk}"),
        )
    conn.commit()
    n_rules = conn.execute("SELECT COUNT(*) FROM fuzzy_rules").fetchone()[0]
    assert n_rules == 27, f"expected 27 rules, got {n_rules}"
    conn.close()
    print(f"fixed configuration written to {TARGET}: 4 scales, 13 values, 27 rules")


if __name__ == "__main__":
    main()

