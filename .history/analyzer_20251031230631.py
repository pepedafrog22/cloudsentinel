
from __future__ import annotations
import json
from pathlib import Path
from typing import Any,Dict


# Step 1 — JSON loader
# ---------------------
# Purpose: read the snapshot file created by collect_iam.py and return it as a dict.
# Design: minimal, raise on common errors so callers fail fast with clear messages.


def load_json(path: str) -> Dict[str,Any]:
    """Load and parse a JSON file from disk.


Args:
path: Filesystem path to the JSON snapshot (e.g., "data/iam_snapshot.json").


Returns:
A Python dict representing the JSON content.


Raises:
FileNotFoundError: If the path does not exist.
json.JSONDecodeError: If the file is not valid JSON.
"""

    return json.loads(Path(path).read_text())

