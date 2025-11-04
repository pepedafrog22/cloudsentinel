
from __future__ import annotations
import json
from pathlib import Path
from typing import Any,Dict


# Step 1 — JSON loader
# ---------------------
# Purpose: read the snapshot file created by collect_iam.py and return it as a dict.
# Design: minimal, raise on common errors so callers fail fast with clear messages.


def load_json(path: str) -> Dict[str,Any]