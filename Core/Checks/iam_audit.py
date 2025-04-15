import boto3
from botocore.exceptions import ClientError
from collections import defaultdict

def check_cis_1_1(session):
    # CIS 1.1: Avoid use of the root account
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_summary()
        if response['SummaryMap'].get('AccountUsage', 0) > 0:
            findings.append({
                'check_id': 'CIS-1.1',
                'status': 'FAIL',
                'resource': 'RootAccount',
                'evidence': 'Root account has been used',
                'remediation': 'Avoid using the root account. Create IAM users instead.'
            })
        else:
            findings.append({
                'check_id': 'CIS-1.1',
                'status': 'PASS',
                'resource': 'RootAccount',
                'evidence': 'Root account not used',
                'remediation': None
            })
    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.1',
            'status': 'ERROR',
            'resource': 'RootAccount',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure proper IAM permissions to access get_account_summary.'
        })

    return findings


def check_cis_1_2(session):
    # CIS 1.2: Ensure multi-factor authentication (MFA) is enabled for the root account
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_summary()
        mfa_enabled = response['SummaryMap'].get('AccountMFAEnabled', 0)

        if mfa_enabled:
            findings.append({
                'check_id': 'CIS-1.2',
                'status': 'PASS',
                'resource': 'RootAccount',
                'evidence': 'MFA enabled for root account',
                'remediation': None
            })
        else:
            findings.append({
                'check_id': 'CIS-1.2',
                'status': 'FAIL',
                'resource': 'RootAccount',
                'evidence': 'MFA not enabled for root account',
                'remediation': (
                    "Enable MFA for the root account in the AWS console "
                    "under IAM > Dashboard > Activate MFA on your root account."
                )
            })

    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.2',
            'status': 'ERROR',
            'resource': 'RootAccount',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure permission to access IAM get_account_summary.'
        })

    return findings


def generate_report(findings):
    print("S3 CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-"*40)


def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_1_1(session))
    all_findings.extend(check_cis_1_2(session))

    generate_report(all_findings)
