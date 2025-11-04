# CloudSentinel
 
CloudSentinel is a lightweight, demo-friendly tool that helps defenders spot risky AWS IAM configurations and surface escalation-ready role chains. It has three parts:

Collector (collect_iam.py) — pulls IAM roles, trust policies, and managed/inline policy documents via boto3

Analyzer (analyzer.py) — runs simple rules (R1–R3) over policies and trust docs to produce findings

ASCII Reporter (report_ascii.py) — renders an easy-to-read table and “Top Exploitable Chains”

A single CLI wrapper, cloudsentinel.py, orchestrates those parts or lets you run each stage standalone.

 This is a prototype for blue-team demos and education. It’s intentionally conservative and not a substitute for full IAM analysis. Validate results before acting.

Features (what it catches today)

R1 – PassRole misuse
iam:PassRole on Resource: * (inline or managed policy)

R2 – Service wildcards
Admin-like service:* on Resource: * for key services (iam, sts, ec2, s3, lambda) with severity weighting (IAM/STS → HIGH, others → MEDIUM)

R3 – Broad/unsafe trust
Role trust policy allows Principal: "*", or an entire account :root without conditions

Escalation-ready detection
If a role has PassRole and a launcher capability (e.g., ec2:RunInstances, lambda:CreateFunction, ecs:RunTask, or the service:* wildcard), it’s flagged with a suggested exploit path.


HOW TO RUN:

1) Clone the repo:

git clone https://github.com/<your_username>/<repo_name>.git
cd <repo_name>


2) Create a python virtual environment (recommended):
python3 -m venv .venv
source .venv/bin/activate     # Windows: .venv\Scripts\activate


3) Install requirements:

pip install -r requirements.txt


Run in demo mode:

python cloudsentinel.py cloudsentinel --demo demo/sample_account.json --report-out out/report.txt


To run in live mode, you need to configure an AWS profile with valid AWS credentials:

1) make sure the AWS CLI is installed:
aws --version

If the AWS CLI is not installed, follow the steps here: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html

2) Configure an AWS profile:
aws configure --profile <profile name>

3) run in live mode:
python cloudsentinel.py cloudsentinel --profile example_profile --report-out out/report.txt

if you want the output of the JSON data that was created:
python cloudsentinel.py cloudsentinel --profile example_profile \
  --snapshot-out data/iam_snapshot.json --findings-out demo/findings.json --report-out out/report.txt








