import boto3
from botocore.exceptions import ClientError
import datetime

def check_cis_1_1(session):
    # CIS 1.1: Avoid use of the root account
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_summary()
        if response['SummaryMap'].get('AccountUsage', 0) > 0:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.1',
                'status':     'FAIL',
                'resource':   'RootAccount',
                'evidence':   'Root account has been used',
                'remediation':'Avoid using the root account. Create IAM users instead.'
            })
        else:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.1',
                'status':     'PASS',
                'resource':   'RootAccount',
                'evidence':   'Root account not used',
                'remediation': None
            })
    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.1',
            'status':     'ERROR',
            'resource':   'RootAccount',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure proper IAM permissions to access get_account_summary.'
        })

    return findings


def check_cis_1_2(session):
    # CIS 1.2: Ensure MFA is enabled for the root account
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_summary()
        mfa_enabled = response['SummaryMap'].get('AccountMFAEnabled', 0)

        if mfa_enabled:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.2',
                'status':     'PASS',
                'resource':   'RootAccount',
                'evidence':   'MFA enabled for root account',
                'remediation': None
            })
        else:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.2',
                'status':     'FAIL',
                'resource':   'RootAccount',
                'evidence':   'MFA not enabled for root account',
                'remediation': (
                    "Enable MFA for the root account in the AWS console "
                    "under IAM > Dashboard > Activate MFA on your root account."
                )
            })

    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.2',
            'status':     'ERROR',
            'resource':   'RootAccount',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure permission to access IAM get_account_summary.'
        })

    return findings


def check_cis_1_8(session):
    # CIS 1.8: Ensure IAM password policy requires minimum length of 14 or greater
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_password_policy()
        min_length = response['PasswordPolicy'].get('MinimumPasswordLength', 0)

        if min_length >= 14:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.8',
                'status':     'PASS',
                'resource':   'PasswordPolicy',
                'evidence':   f'Minimum password length is {min_length}',
                'remediation': None
            })
        else:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.8',
                'status':     'FAIL',
                'resource':   'PasswordPolicy',
                'evidence':   f'Minimum password length is {min_length}',
                'remediation': (
                    "Set the minimum password length to at least 14 characters.\n"
                    "Console: IAM > Account Settings > Set minimum password length.\n"
                    "CLI: aws iam update-account-password-policy --minimum-password-length 14"
                )
            })

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.8',
            'status':     'FAIL',
            'resource':   'PasswordPolicy',
            'evidence':   'No password policy found',
            'remediation': (
                "Create a password policy with a minimum password length of 14.\n"
                "CLI: aws iam update-account-password-policy --minimum-password-length 14"
            )
        })
    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.8',
            'status':     'ERROR',
            'resource':   'PasswordPolicy',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure permission to access IAM get_account_password_policy.'
        })

    return findings


def check_cis_1_9(session):
    # CIS 1.9: Ensure IAM password policy prevents password reuse (24 or more)
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_password_policy()
        reuse_prevention = response['PasswordPolicy'].get('PasswordReusePrevention', 0)

        if reuse_prevention >= 24:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.9',
                'status':     'PASS',
                'resource':   'PasswordPolicy',
                'evidence':   f'Password reuse prevention is set to {reuse_prevention}',
                'remediation': None
            })
        else:
            findings.append({
                'service':    'iam',
                'check_id':   'CIS-1.9',
                'status':     'FAIL',
                'resource':   'PasswordPolicy',
                'evidence':   f'Password reuse prevention is set to {reuse_prevention}',
                'remediation': (
                    "Set password reuse prevention to at least 24.\n"
                    "CLI: aws iam update-account-password-policy --password-reuse-prevention 24"
                )
            })

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.9',
            'status':     'FAIL',
            'resource':   'PasswordPolicy',
            'evidence':   'No password policy found',
            'remediation': (
                "Create a password policy with password reuse prevention set to at least 24.\n"
                "CLI: aws iam update-account-password-policy --password-reuse-prevention 24"
            )
        })
    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.9',
            'status':     'ERROR',
            'resource':   'PasswordPolicy',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure permission to access IAM get_account_password_policy.'
        })

    return findings


def check_cis_1_10(session):
    # CIS 1.10: Ensure MFA is enabled for all IAM users that have a console password
    findings = []
    iam = session.client('iam')

    try:
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Check console access
                try:
                    iam.get_login_profile(UserName=username)
                    has_console_password = True
                except ClientError as e:
                    has_console_password = False if e.response['Error']['Code']=='NoSuchEntity' else False

                if has_console_password:
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings.append({
                            'service':    'iam',
                            'check_id':   'CIS-1.10',
                            'status':     'FAIL',
                            'resource':   username,
                            'evidence':   f'User {username} has a console password but no MFA device enabled',
                            'remediation': (
                                'Enable MFA for users with console passwords. '
                                'Go to IAM > Users > Security credentials tab > Manage MFA Device.'
                            )
                        })
                    else:
                        findings.append({
                            'service':    'iam',
                            'check_id':   'CIS-1.10',
                            'status':     'PASS',
                            'resource':   username,
                            'evidence':   f'User {username} has MFA enabled',
                            'remediation': None
                        })
    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.10',
            'status':     'ERROR',
            'resource':   'IAM Users',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure proper IAM permissions to list users, login profiles, and MFA devices.'
        })

    return findings


def check_cis_1_12(session):
    # CIS 1.12: Ensure credentials unused for 45 days or more are disabled
    findings = []
    iam = session.client('iam')
    now = datetime.datetime.utcnow()

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            user_findings = []

            # Console password last used
            pwd_last = user.get('PasswordLastUsed')
            if pwd_last:
                days = (now - pwd_last.replace(tzinfo=None)).days
                if days > 45:
                    user_findings.append({
                        'service':    'iam',
                        'check_id':   'CIS-1.12',
                        'status':     'FAIL',
                        'resource':   username,
                        'evidence':   f'Console password not used for {days} days',
                        'remediation':'Disable the console password for users inactive >45 days.'
                    })

            # Access keys
            for key in iam.list_access_keys(UserName=username)['AccessKeyMetadata']:
                key_id   = key['AccessKeyId']
                created  = key['CreateDate']
                age_days = (now - created.replace(tzinfo=None)).days
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id)['AccessKeyLastUsed'].get('LastUsedDate')
                if last_used:
                    days = (now - last_used.replace(tzinfo=None)).days
                    if days > 45:
                        user_findings.append({
                            'service':    'iam',
                            'check_id':   'CIS-1.12',
                            'status':     'FAIL',
                            'resource':   f"{username} (AccessKey {key_id})",
                            'evidence':   f'Access key not used for {days} days',
                            'remediation':'Deactivate or delete access keys inactive >45 days.'
                        })
                else:
                    if age_days > 45:
                        user_findings.append({
                            'service':    'iam',
                            'check_id':   'CIS-1.12',
                            'status':     'FAIL',
                            'resource':   f"{username} (AccessKey {key_id})",
                            'evidence':   f'Access key created {age_days} days ago and never used',
                            'remediation':'Deactivate or delete unused access keys older than 45 days.'
                        })

            if user_findings:
                findings.extend(user_findings)
            else:
                findings.append({
                    'service':    'iam',
                    'check_id':   'CIS-1.12',
                    'status':     'PASS',
                    'resource':   username,
                    'evidence':   'No unused credentials found older than 45 days',
                    'remediation': None
                })

    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.12',
            'status':     'ERROR',
            'resource':   'IAM Users',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure proper IAM permissions to list users and access keys.'
        })

    return findings


def check_cis_1_13(session):
    # CIS 1.13: Ensure there is only one active access key per IAM user
    findings = []
    iam = session.client('iam')

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            active_keys = [k for k in iam.list_access_keys(UserName=username)['AccessKeyMetadata'] if k['Status']=='Active']

            if len(active_keys) > 1:
                findings.append({
                    'service':    'iam',
                    'check_id':   'CIS-1.13',
                    'status':     'FAIL',
                    'resource':   username,
                    'evidence':   f'User has {len(active_keys)} active access keys.',
                    'remediation':'Ensure only one active access key per user.'
                })
            elif len(active_keys) == 0:
                findings.append({
                    'service':    'iam',
                    'check_id':   'CIS-1.13',
                    'status':     'FAIL',
                    'resource':   username,
                    'evidence':   'User has no active access keys.',
                    'remediation':'Ensure each user has at least one active access key.'
                })
            else:
                findings.append({
                    'service':    'iam',
                    'check_id':   'CIS-1.13',
                    'status':     'PASS',
                    'resource':   username,
                    'evidence':   'User has only one active access key.',
                    'remediation': None
                })

    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.13',
            'status':     'ERROR',
            'resource':   'IAM Users',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure proper IAM permissions to list users and access keys.'
        })

    return findings


def check_cis_1_14(session):
    # CIS 1.14: Ensure access keys are rotated every 90 days or less
    findings = []
    iam = session.client('iam')
    now = datetime.datetime.utcnow()

    try:
        users = iam.list_users()['Users']
        for user in users:
            username = user['UserName']
            rotated = True

            for key in iam.list_access_keys(UserName=username)['AccessKeyMetadata']:
                age = (now - key['CreateDate'].replace(tzinfo=None)).days
                if age > 90:
                    findings.append({
                        'service':    'iam',
                        'check_id':   'CIS-1.14',
                        'status':     'FAIL',
                        'resource':   f"{username} (AccessKey {key['AccessKeyId']})",
                        'evidence':   f'Access key {key["AccessKeyId"]} is {age} days old.',
                        'remediation':'Rotate keys older than 90 days by creating new and deactivating old.'
                    })
                    rotated = False

            if rotated:
                findings.append({
                    'service':    'iam',
                    'check_id':   'CIS-1.14',
                    'status':     'PASS',
                    'resource':   username,
                    'evidence':   'All access keys are within the 90-day rotation period.',
                    'remediation': None
                })

    except ClientError as e:
        findings.append({
            'service':    'iam',
            'check_id':   'CIS-1.14',
            'status':     'ERROR',
            'resource':   'IAM Users',
            'evidence':   f"Access denied or other error: {e}",
            'remediation':'Ensure proper IAM permissions to list users and access keys.'
        })

    return findings


def generate_report(findings):
    print("IAM CIS Benchmark Results:")
    for f in findings:
        print(f)
        print("-" * 40)


def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_1_1(session))
    all_findings.extend(check_cis_1_2(session))
    all_findings.extend(check_cis_1_8(session))
    all_findings.extend(check_cis_1_9(session))
    all_findings.extend(check_cis_1_10(session))
    all_findings.extend(check_cis_1_12(session))
    all_findings.extend(check_cis_1_13(session))
    all_findings.extend(check_cis_1_14(session))
    generate_report(all_findings)
    return all_findings
