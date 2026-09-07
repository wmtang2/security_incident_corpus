#!/usr/bin/env python3
"""Demonstrate the ScaleService._real_to_universe dual-range discontinuity:
values that fall inside BOTH the real-world range and the universe range are
passed through unchanged, while values above the universe are linearly mapped
from the real-world range. Around the boundary this is non-monotone.
"""
import sys

sys.path.insert(0, "/workspace")
from src.backend.database import DatabaseManager
from src.backend.services.scale_service import ScaleService

mgr = DatabaseManager("sqlite:////workspace/validation/model_sane.db")
ss = ScaleService(mgr)
tef = ss.get_scale_by_name("threat_event_frequency")
print(f"TEF scale: universe=[{tef.universe_min},{tef.universe_max}] "
      f"real=[{tef.real_world_min},{tef.real_world_max}] {tef.real_world_unit}")
for v in [0.9, 0.99, 1.0, 1.01, 1.5, 2.0, 10.0, 50.0]:
    n = ss.normalize_value_for_scale(tef, v, "TEF")
    print(f"  input {v:>6} -> universe {n:.4f}")
