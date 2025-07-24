# AWSCAN
usage:
"pip install -e . "
then run this command "awscan --help"

# AWS Cloud Security Posture Management tool

## Overview

This project is an automated security assessment tool that evaluates AWS environments against the Center for Internet Security (CIS) AWS Foundations Benchmark. It helps identify security misconfigurations and compliance issues in your AWS account by performing checks across multiple AWS services including IAM, S3, and EC2.

## Features

- **Multi-Service Assessment**: Detects and audits enabled AWS services (IAM, S3, EC2)
- **Automated Discovery**: Automatically discovers which services are active in your AWS account
- **Concurrent Processing**: Uses multi-threading to run checks efficiently
- **Comprehensive Checks**: Implements key CIS benchmark controls for AWS services
- **Remediation Guidance**: Provides actionable remediation steps for failed checks
- **Flexible Output**: Supports different output formats (JSON, table)

## Implemented CIS Benchmark Checks

### IAM Checks
### S3 Checks
### EC2 Checks
### EFS Checks
### RDS Checks
### Monitoring Checks
### Logging Checks

## Requirements
- Node.js 21 or newer
- Python 3.6 or higher
- AWS Account with the minimum IAM permissions required to run the scan (see “Required AWS Permissions” below).
- The following Python packages:
  - boto3
  - click

## Installation


1. Clone the repository:
   ```bash
   git clone https://github.com/YoussefSahnoun/AWSCAN.git
   cd AWSCAN
   ```

2. Create and activate a virtual environment (optional but recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install the package in development mode:
   ```bash
   pip install -e .
   ```



## Usage

### Running the cli version

```bash
awscan --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --session-token YOUR_SESSION_TOKEN --region us-east-1 --output json
```
### Running the gui version (for Linux OS)
```bash
cd webinterface
chmod +x build.sh
./build.sh
```
### Running the gui version (for Windows OS)
```powershell
cd webinterface
.\build.ps1
```


### Command-line Options

| Option | Description |
|--------|-------------|
| `--access-key` | Your AWS access key |
| `--secret-key` | Your AWS secret key |
| `--session-token` | Your AWS session token (if using temporary credentials) |
| `--region` | AWS region to use for the assessment |
| `--output` | Output format for results (`json` or `table`) |

## Required AWS Permissions

To run all checks, the tool requires the following minimum AWS permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:GetAccountSummary",
                "iam:GetAccountPasswordPolicy",
                "iam:ListUsers",
                "iam:ListAccessKeys",
                "iam:GetAccessKeyLastUsed",
                "iam:GetLoginProfile",
                "iam:ListMFADevices",
                "s3:ListAllMyBuckets",
                "s3:GetBucketEncryption",
                "s3:GetPublicAccessBlock",
                "ec2:DescribeInstances",
                "ec2:DescribeVpcs",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeInstanceAttribute"
            ],
            "Resource": "*"
        }
    ]
}
```

## How It Works

1. The tool validates your AWS credentials
2. It discovers which AWS services are enabled in your account
3. For each enabled service, it runs the relevant CIS benchmark checks
4. Results are consolidated and output in your chosen format

## Important Notice
-This is a proof‑of‑concept and does not yet implement the full CIS AWS Foundations Benchmark.

