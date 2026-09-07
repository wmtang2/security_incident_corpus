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
