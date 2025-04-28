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

def check_cis_1_8(session):
    # CIS 1.8: Ensure IAM password policy requires minimum length of 14 or greater
    findings = []
    iam = session.client('iam')

    try:
        response = iam.get_account_password_policy()
        min_length = response['PasswordPolicy'].get('MinimumPasswordLength', 0)

        if min_length >= 14:
            findings.append({
                'check_id': 'CIS-1.8',
                'status': 'PASS',
                'resource': 'PasswordPolicy',
                'evidence': f'Minimum password length is {min_length}',
                'remediation': None
            })
        else:
            findings.append({
                'check_id': 'CIS-1.8',
                'status': 'FAIL',
                'resource': 'PasswordPolicy',
                'evidence': f'Minimum password length is {min_length}',
                'remediation': (
                    "Set the minimum password length to at least 14 characters.\n"
                    "Console: IAM > Account Settings > Set minimum password length.\n"
                    "CLI: aws iam update-account-password-policy --minimum-password-length 14"
                )
            })

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            'check_id': 'CIS-1.8',
            'status': 'FAIL',
            'resource': 'PasswordPolicy',
            'evidence': 'No password policy found',
            'remediation': (
                "Create a password policy with a minimum password length of 14.\n"
                "CLI: aws iam update-account-password-policy --minimum-password-length 14"
            )
        })
    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.8',
            'status': 'ERROR',
            'resource': 'PasswordPolicy',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure permission to access IAM get_account_password_policy.'
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
                'check_id': 'CIS-1.9',
                'status': 'PASS',
                'resource': 'PasswordPolicy',
                'evidence': f'Password reuse prevention is set to {reuse_prevention}',
                'remediation': None
            })
        else:
            findings.append({
                'check_id': 'CIS-1.9',
                'status': 'FAIL',
                'resource': 'PasswordPolicy',
                'evidence': f'Password reuse prevention is set to {reuse_prevention}',
                'remediation': (
                    "Set password reuse prevention to at least 24.\n"
                    "CLI: aws iam update-account-password-policy --password-reuse-prevention 24"
                )
            })

    except iam.exceptions.NoSuchEntityException:
        findings.append({
            'check_id': 'CIS-1.9',
            'status': 'FAIL',
            'resource': 'PasswordPolicy',
            'evidence': 'No password policy found',
            'remediation': (
                "Create a password policy with password reuse prevention set to at least 24.\n"
                "CLI: aws iam update-account-password-policy --password-reuse-prevention 24"
            )
        })
    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.9',
            'status': 'ERROR',
            'resource': 'PasswordPolicy',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure permission to access IAM get_account_password_policy.'
        })

    return findings

def check_cis_1_10(session):
    # CIS 1.10: Ensure MFA is enabled for all IAM users that have a console password
    findings = []
    iam = session.client('iam')

    try:
        # Get the list of IAM users
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']

                # Check if user has a login profile (i.e., console access)
                try:
                    iam.get_login_profile(UserName=username)
                    has_console_password = True
                except ClientError as e:
                    if e.response['Error']['Code'] == 'NoSuchEntity':
                        has_console_password = False
                    else:
                        raise

                if has_console_password:
                    # Check if MFA devices are associated with the user
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    if not mfa_devices:
                        findings.append({
                            'check_id': 'CIS-1.10',
                            'status': 'FAIL',
                            'resource': username,
                            'evidence': f'User {username} has a console password but no MFA device enabled',
                            'remediation': (
                                'Enable MFA for users with console passwords. '
                                'Go to IAM > Users > Security credentials tab > Manage MFA Device.'
                            )
                        })
                    else:
                        findings.append({
                            'check_id': 'CIS-1.10',
                            'status': 'PASS',
                            'resource': username,
                            'evidence': f'User {username} has MFA enabled',
                            'remediation': None
                        })

    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.10',
            'status': 'ERROR',
            'resource': 'IAM Users',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure proper IAM permissions to list users, login profiles, and MFA devices.'
        })

    return findings

import datetime

def check_cis_1_12(session):
    # CIS 1.12: Ensure credentials unused for 45 days or more are disabled
    findings = []
    iam = session.client('iam')
    now = datetime.datetime.utcnow()

    try:
        # Get all IAM users (without pagination, suitable for fewer than 100 users)
        users_response = iam.list_users()
        users = users_response['Users']

        for user in users:
            username = user['UserName']
            user_findings = []

            # Check Console Password last used (if available)
            password_last_used = user.get('PasswordLastUsed')
            if password_last_used:
                days_since_last_password_use = (now - password_last_used.replace(tzinfo=None)).days
                if days_since_last_password_use > 45:
                    user_findings.append({
                        'check_id': 'CIS-1.12',
                        'status': 'FAIL',
                        'resource': username,
                        'evidence': f'Console password not used for {days_since_last_password_use} days',
                        'remediation': (
                            'Disable the console password for users not using it for over 45 days. '
                            'IAM > Users > Security Credentials > Console Password > Disable.'
                        )
                    })

            # Check Access Keys (if available)
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            for key in access_keys:
                access_key_id = key['AccessKeyId']
                key_create_date = key['CreateDate']
                key_age_days = (now - key_create_date.replace(tzinfo=None)).days

                # Get last used information for the key
                last_used_info = iam.get_access_key_last_used(AccessKeyId=access_key_id)
                last_used_date = last_used_info['AccessKeyLastUsed'].get('LastUsedDate')

                if last_used_date:
                    days_since_last_use = (now - last_used_date.replace(tzinfo=None)).days
                    if days_since_last_use > 45:
                        user_findings.append({
                            'check_id': 'CIS-1.12',
                            'status': 'FAIL',
                            'resource': f"{username} (AccessKey {access_key_id})",
                            'evidence': f'Access key not used for {days_since_last_use} days',
                            'remediation': (
                                'Deactivate or delete access keys unused for over 45 days. '
                                'IAM > Users > Security Credentials > Access Keys.'
                            )
                        })
                else:
                    # If key has never been used
                    if key_age_days > 45:
                        user_findings.append({
                            'check_id': 'CIS-1.12',
                            'status': 'FAIL',
                            'resource': f"{username} (AccessKey {access_key_id})",
                            'evidence': f'Access key created {key_age_days} days ago and never used',
                            'remediation': (
                                'Deactivate or delete unused access keys older than 45 days. '
                                'IAM > Users > Security Credentials > Access Keys.'
                            )
                        })

            # If findings are found for the user, add them
            if user_findings:
                findings.extend(user_findings)
            else:
                findings.append({
                    'check_id': 'CIS-1.12',
                    'status': 'PASS',
                    'resource': username,
                    'evidence': 'No unused credentials found older than 45 days',
                    'remediation': None
                })

    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.12',
            'status': 'ERROR',
            'resource': 'IAM Users',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure proper IAM permissions to list users, access keys, and get usage data.'
        })

    return findings


def check_cis_1_13(session):
    # CIS 1.13: Ensure there is only one active access key for any single IAM user
    findings = []
    iam = session.client('iam')

    try:
        # List IAM users directly
        response = iam.list_users()
        
        for user in response['Users']:
            username = user['UserName']
            user_findings = []

            # List access keys for the user
            access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
            
            # Check if user has more than one active access key
            active_keys = [key for key in access_keys if key['Status'] == 'Active']
            
            if len(active_keys) > 1:
                user_findings.append({
                    'check_id': 'CIS-1.13',
                    'status': 'FAIL',
                    'resource': username,
                    'evidence': f'User has {len(active_keys)} active access keys.',
                    'remediation': (
                        'Ensure there is only one active access key for this user. '
                        'Select the active access key that is less than 90 days old, '
                        'and deactivate the other keys. '
                        'IAM > Users > Security Credentials > Access Keys.'
                    )
                })
            elif len(active_keys) == 0:
                user_findings.append({
                    'check_id': 'CIS-1.13',
                    'status': 'FAIL',
                    'resource': username,
                    'evidence': 'User has no active access keys.',
                    'remediation': (
                        'Ensure the user has at least one active access key to access AWS programmatically. '
                        'IAM > Users > Security Credentials > Access Keys.'
                    )
                })

            if not user_findings:
                findings.append({
                    'check_id': 'CIS-1.13',
                    'status': 'PASS',
                    'resource': username,
                    'evidence': 'User has only one active access key.',
                    'remediation': None
                })
            else:
                findings.extend(user_findings)

    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.13',
            'status': 'ERROR',
            'resource': 'IAM Users',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure proper IAM permissions to list users and access keys.'
        })

    return findings

def check_cis_1_14(session):
    # CIS 1.14: Ensure access keys are rotated every 90 days or less
    findings = []
    iam = session.client('iam')
    now = datetime.datetime.utcnow()

    try:
        # Get all IAM users (with pagination to handle large numbers)
        paginator = iam.get_paginator('list_users')
        for page in paginator.paginate():
            for user in page['Users']:
                username = user['UserName']
                user_findings = []

                # Check Access Keys (if available)
                access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                for key in access_keys:
                    access_key_id = key['AccessKeyId']
                    key_create_date = key['CreateDate']
                    key_age_days = (now - key_create_date.replace(tzinfo=None)).days

                    if key_age_days > 90:
                        user_findings.append({
                            'check_id': 'CIS-1.14',
                            'status': 'FAIL',
                            'resource': f"{username} (AccessKey {access_key_id})",
                            'evidence': f'Access key created {key_age_days} days ago, which exceeds the 90-day rotation period.',
                            'remediation': (
                                'Rotate the access key by creating a new key and deactivating the old one. '
                                'IAM > Users > Security Credentials > Access Keys.'
                            )
                        })

                # If findings are found for the user, add them
                if user_findings:
                    findings.extend(user_findings)
                else:
                    findings.append({
                        'check_id': 'CIS-1.14',
                        'status': 'PASS',
                        'resource': username,
                        'evidence': 'All access keys are within the 90-day rotation period.',
                        'remediation': None
                    })

    except ClientError as e:
        findings.append({
            'check_id': 'CIS-1.14',
            'status': 'ERROR',
            'resource': 'IAM Users',
            'evidence': f"Access denied or other error: {e}",
            'remediation': 'Ensure proper IAM permissions to list users, access keys, and get creation data.'
        })

    return findings


def generate_report(findings):
    print("IAM CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-"*40)


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



"""

### Instead of manually adding every new check to run_audit, we'll automatically detect all check_cis_* functions and run them dynamically
import inspect
import sys

def run_audit(session):
    all_findings = []

    # Get all functions defined in the current module
    current_module = sys.modules[__name__]

    for name, func in inspect.getmembers(current_module, inspect.isfunction):
        if name.startswith('check_cis_'):
            findings = func(session)
            all_findings.extend(findings)

    generate_report(all_findings)

"""



