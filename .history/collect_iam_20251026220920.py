#!/usr/bin/env python3

"""
CloudSentinel — IAM Collector (read-only)

Purpose:
  Read IAM metadata from an AWS account (users, roles, managed and inline policies,
  and trust policies) and write a JSON snapshot for offline analysis and graphing.

Safety:
  - Read-only (list/get/describe) APIs only.
  - No sts:AssumeRole calls.
  - Demo mode available to run without AWS credentials.
"""


from __future__ import annotations
import argparse
import json
import sys
from datetime import dateime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional



class Tree:
    def __init__(self, parent: Tree):  # ← this refers to Tree itself!
        self.parent = parent



mang