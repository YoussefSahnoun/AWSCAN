# CIS_Benchmark
usage:
"pip install -e . "
then run this command "cis-audit --help"

# AWS CIS Benchmark Automation Tool

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

## Project Structure

```
CIS_Benchmark/
├── Cli/
│   ├── __init__.py
│   └── main.py              # Command-line interface entry point
├── Core/
│   ├── Checks/
│   │   ├── __init__.py
│   │   ├── ec2_audit.py     # EC2-specific checks
│   │   ├── iam_audit.py     # IAM-specific checks
│   │   └── s3_audit.py      # S3-specific checks
│   ├── __init__.py
│   ├── auth.py              # AWS authentication handling
│   └── orchestrator.py      # Orchestrates the scanning process
└── setup.py                 # Package installation configuration
```

## Requirements

- Python 3.6 or higher
- AWS Account with appropriate read-only permissions
- The following Python packages:
  - boto3
  - click

## Installation

### Option 1: Install from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/YoussefSahnoun/CIS_Benchmark.git
   cd CIS_Benchmark
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

### Option 2: Install via pip

```bash
pip install git+https://github.com/YoussefSahnoun/CIS_Benchmark.git
```

## Usage

### Running the tool

If you're running from the cloned repository without installing:
```bash
python Cli/main.py --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --session-token YOUR_SESSION_TOKEN --region us-east-1 --output json
```

If you installed the package using either of the installation methods above:
```bash
cis-audit --access-key YOUR_ACCESS_KEY --secret-key YOUR_SECRET_KEY --session-token YOUR_SESSION_TOKEN --region us-east-1 --output json
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

## Development

### Adding New Checks

To add a new check:

1. Add your check function to the appropriate service file in `Core/Checks/`
2. Follow the existing pattern for check functions
3. Make sure your function returns findings in the standard format

### Running Tests

```bash
# To be implemented
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request
