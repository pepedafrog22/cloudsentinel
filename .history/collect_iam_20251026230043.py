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
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional



try:
    import boto3
    from botocore.config  import Config as BotoConfig 
    from boto
