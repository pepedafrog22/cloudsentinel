
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

    return json.loads(Path(path).read_text(encodings="utf-8"))


def ensure_list(x: Any) -> list[Any]:
    """Return x as a list.


    Args:
    x: Any object that might be a list, string, or None.


    Returns:
    Always a list. If x is None, returns an empty list.
    """

    if x is None:
        return []
    return x if isinstance(x, list) else [x]

# Step 3 — iter_statements
# -------------------------
# Purpose: AWS policy documents contain a key called 'Statement' that can be
# either a single dictionary or a list of dictionaries. This helper yields each
# statement safely as a dictionary so our rule functions can just loop over it.
# Example input:
# {"Statement": {"Action": "s3:*", "Effect": "Allow"}}
# {"Statement": [{...}, {...}]}
# Example use:
# for stmt in iter_statements(policy):
# print(stmt['Action'])


def iter_statements(policy_doc: Dict[str, Any]):
    """Yield every statement in a policy document.


    Args:
    policy_doc: A dictionary representing an IAM policy document.


    Yields:
    Each statement (dict) in the document, even if there is only one.
    """

    if not isinstance(policy_doc, dict):
        return []
    stmts = policy_doc.get("Statement")
    return ensure_list(stmts)



# Step 4 — resource_is_star
# --------------------------
# Purpose: detect whether a policy statement applies to all resources.
# IAM policies may use "Resource": "*" or a list like ["*", ...].
# This function returns True if either case is found.

def resource_is_star(stmt: Dict[str, Any]) -> bool:
    """Return True if a statement's Resource allows everything ('*').


Args:
stmt: A single policy statement.


Returns:
True if Resource is '*' or includes '*', otherwise False.
    """

    res = stmt





















