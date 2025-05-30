import boto3
import json
from botocore.exceptions import ClientError
from collections import defaultdict

SERVICE_NAME = 's3'

def get_s3_buckets(session):
    # List all buckets
    s3 = session.client(SERVICE_NAME)
    try:
        response = s3.list_buckets()
        return response.get('Buckets', [])
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return []


def check_cis_2_1_1(session, buckets):
    # CIS 2.1.1: Ensure S3 buckets have encryption enabled
    findings = []
    s3 = session.client(SERVICE_NAME)
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
            findings.append({
                'service': SERVICE_NAME,
                'check_id': 'CIS-2.1.1',
                'status': 'PASS',
                'resource': bucket_name,
                'evidence': 'Encryption enabled',
                'remediation': None
            })
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.1',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No bucket encryption configured',
                    'remediation': (
                        "Enable default encryption:\n"
                        f"aws s3api put-bucket-encryption --bucket {bucket_name} "
                        "--server-side-encryption-configuration '{\"Rules\":["
                        "{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
                    )
                })
            else:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.1',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied: {e}",
                    'remediation': 'Add s3:GetEncryptionConfiguration permission'
                })
    return findings


def check_cis_2_1_3(session, buckets):
    # CIS 2.1.3: Ensure S3 buckets block public access
    findings = []
    s3 = session.client(SERVICE_NAME)
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            resp = s3.get_public_access_block(Bucket=bucket_name)
            config = resp.get('PublicAccessBlockConfiguration', {})
            if all([
                config.get('BlockPublicAcls'),
                config.get('IgnorePublicAcls'),
                config.get('BlockPublicPolicy'),
                config.get('RestrictPublicBuckets')
            ]):
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.3',
                    'status': 'PASS',
                    'resource': bucket_name,
                    'evidence': 'Public access fully blocked',
                    'remediation': None
                })
            else:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.3',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'Incomplete public access restrictions',
                    'remediation': (
                        "Enable full public access blocking:\n"
                        f"aws s3api put-public-access-block --bucket {bucket_name} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    )
                })
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NoSuchPublicAccessBlockConfiguration':
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.3',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No public access block configuration',
                    'remediation': 'Create public access block configuration as shown above'
                })
            else:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.3',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied: {e}",
                    'remediation': 'Add s3:GetPublicAccessBlock permission'
                })
    return findings


def check_cis_2_1_2(session, buckets):
    # CIS 2.1.2: Ensure S3 Bucket Policy denies non-HTTPS requests
    findings = []
    s3 = session.client(SERVICE_NAME)
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            resp = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(resp.get('Policy', '{}'))
            statements = policy.get('Statement', [])
            deny_found = False
            for stmt in statements:
                if stmt.get('Effect') == 'Deny':
                    cond = stmt.get('Condition', {})
                    bool_cond = cond.get('Bool', {})
                    if bool_cond.get('aws:SecureTransport') == 'false':
                        deny_found = True
            if deny_found:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.2',
                    'status': 'PASS',
                    'resource': bucket_name,
                    'evidence': 'Bucket policy denies non-HTTPS access',
                    'remediation': None
                })
            else:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.2',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No Deny statement for non-HTTPS access found',
                    'remediation': (
                        f"Apply bucket policy to deny HTTP access:\n"  
                        "{\"Effect\": \"Deny\",}\n"  
                        "{\"Principal\": \"*\",}\n"  
                        f"{{\"Resource\": \"arn:aws:s3:::{bucket_name}/*\"}},\n"  
                        "{\"Condition\": {\"Bool\": {\"aws:SecureTransport\": \"false\"}}}")
                    })
                        
        except ClientError as e:
            code = e.response['Error']['Code']
            if code == 'NoSuchBucketPolicy':
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.2',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No bucket policy configured',
                    'remediation': 'Create a policy that denies access when aws:SecureTransport is false'
                })
            else:
                findings.append({
                    'service': SERVICE_NAME,
                    'check_id': 'CIS-2.1.2',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied or error: {e}",
                    'remediation': 'Add s3:GetBucketPolicy permission'
                })
    return findings


def generate_report(findings):
    print("S3 CIS Benchmark Results:")
    for finding in findings:
        print(json.dumps(finding, indent=2))
        print("-" * 40)


def run_audit(session):
    buckets = get_s3_buckets(session)
    if not buckets:
        print("No S3 buckets found")
        return []

    all_findings = []
    all_findings.extend(check_cis_2_1_1(session, buckets))
    all_findings.extend(check_cis_2_1_3(session, buckets))
    all_findings.extend(check_cis_2_1_2(session, buckets))

    generate_report(all_findings)
    return all_findings

# Example usage:
# from auth import get_aws_session
# session = get_aws_session(access_key, secret_key)
# run_s3_audit(session)