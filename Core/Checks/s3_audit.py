import boto3
import json
from botocore.exceptions import ClientError
from collections import defaultdict

def get_s3_buckets(session):
    #list all buckets
    s3 = session.client('s3')
    try:
        response = s3.list_buckets()
        return response['Buckets']
    except ClientError as e:
        print(f"Error listing buckets: {e}")
        return []


def check_cis_2_1_1(session, buckets):
    #CIS 2.1.1: Ensure S3 buckets have encryption enabled
    findings = []
    s3 = session.client('s3')
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
            findings.append({
                'check_id': 'CIS-2.1.1',
                'status': 'PASS',
                'resource': bucket_name,
                'evidence': 'Encryption enabled',
                'remediation': None
            })
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                findings.append({
                    'check_id': 'CIS-2.1.1',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No bucket encryption configured',
                    'remediation': (
                        "Enable default encryption:\n"
                        "aws s3api put-bucket-encryption --bucket {bucket} "
                        "--server-side-encryption-configuration '{\"Rules\":["
                        "{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"AES256\"}}]}'"
                    ).format(bucket=bucket_name)
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.1.1',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied: {e}",
                    'remediation': "Add s3:GetEncryptionConfiguration permission"
                })
    return findings

def check_cis_2_1_3(session, buckets):
    #CIS 2.1.3: Ensure S3 buckets block public access
    findings = []
    s3 = session.client('s3')
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            response = s3.get_public_access_block(Bucket=bucket_name)
            config = response['PublicAccessBlockConfiguration']
            
            if all([config['BlockPublicAcls'], 
                    config['IgnorePublicAcls'],
                    config['BlockPublicPolicy'],
                    config['RestrictPublicBuckets']]):
                findings.append({
                    'check_id': 'CIS-2.1.3',
                    'status': 'PASS',
                    'resource': bucket_name,
                    'evidence': 'Public access fully blocked',
                    'remediation': None
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.1.3',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'Incomplete public access restrictions',
                    'remediation': (
                        "Enable full public access blocking:\n"
                        "aws s3api put-public-access-block --bucket {bucket} "
                        "--public-access-block-configuration "
                        "BlockPublicAcls=true,IgnorePublicAcls=true,"
                        "BlockPublicPolicy=true,RestrictPublicBuckets=true"
                    ).format(bucket=bucket_name)
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                findings.append({
                    'check_id': 'CIS-2.1.3',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No public access block configuration',
                    'remediation': "Create public access block configuration as shown above"
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.1.3',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied: {e}",
                    'remediation': "Add s3:GetPublicAccessBlock permission"
                })
    return findings

def check_cis_2_1_2(session, buckets):
    # CIS 2.1.2: Ensure S3 Bucket Policy is set to deny HTTP requests
    findings = []
    s3 = session.client('s3')
    
    for bucket in buckets:
        bucket_name = bucket['Name']
        try:
            response = s3.get_bucket_policy(Bucket=bucket_name)
            policy = json.loads(response['Policy'])
            statements = policy.get("Statement", [])
            deny_http_found = False
            
            for statement in statements:
                effect = statement.get("Effect", "")
                condition = statement.get("Condition", {})
                
                if effect == "Deny":
                    if "Bool" in condition and condition["Bool"].get("aws:SecureTransport") == "false":
                        deny_http_found = True
                    elif "NumericLessThan" in condition and condition["NumericLessThan"].get("s3:TlsVersion", 1.2) < 1.2:
                        deny_http_found = True

            if deny_http_found:
                findings.append({
                    'check_id': 'CIS-2.1.2',
                    'status': 'PASS',
                    'resource': bucket_name,
                    'evidence': 'Bucket policy denies non-HTTPS access',
                    'remediation': None
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.1.2',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No Deny statement for non-HTTPS access found',
                    'remediation': (
                        "Apply a bucket policy to deny unencrypted (HTTP) access:\n"
                        '{\n'
                        '  "Effect": "Deny",\n'
                        '  "Principal": "*",\n'
                        '  "Action": "s3:*",\n'
                        '  "Resource": "arn:aws:s3:::{bucket}/*",\n'
                        '  "Condition": {\n'
                        '    "Bool": {\n'
                        '      "aws:SecureTransport": "false"\n'
                        '    }\n'
                        '  }\n'
                        '}\n'
                    ).format(bucket=bucket_name)
                })
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                findings.append({
                    'check_id': 'CIS-2.1.2',
                    'status': 'FAIL',
                    'resource': bucket_name,
                    'evidence': 'No bucket policy configured',
                    'remediation': "Create a policy that denies access when aws:SecureTransport is false"
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.1.2',
                    'status': 'ERROR',
                    'resource': bucket_name,
                    'evidence': f"Access denied or error: {e}",
                    'remediation': "Add s3:GetBucketPolicy permission"
                })
    
    return findings


def generate_report(findings):
    print("S3 CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-"*40)

def run_audit(session):
    #run all cis benchmarks
    buckets = get_s3_buckets(session)
    
    if not buckets:
        print("No S3 buckets found")
        return
    
    all_findings = []
    all_findings.extend(check_cis_2_1_1(session, buckets))
    all_findings.extend(check_cis_2_1_3(session, buckets))
    all_findings.extend(check_cis_2_1_2(session, buckets))
    
    generate_report(all_findings)
    

# Example usage:
# from auth import get_aws_session
# session = get_aws_session(access_key, secret_key)
# run_s3_audit(session)