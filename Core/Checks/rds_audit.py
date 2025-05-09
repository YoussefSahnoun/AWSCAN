import boto3
from botocore.exceptions import ClientError

def get_all_regions(session):
    ec2 = session.client('ec2')
    try:
        response = ec2.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except ClientError as e:
        print(f"Error getting regions: {e}")
        return []

def get_rds_instances(session, region):
    rds = session.client('rds', region_name=region)
    try:
        response = rds.describe_db_instances()
        return response.get('DBInstances', [])
    except ClientError as e:
        print(f"Error listing RDS instances in {region}: {e}")
        return []

def check_cis_2_2_1(session):
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        db_instances = get_rds_instances(session, region)
        for db in db_instances:
            db_id = db['DBInstanceIdentifier']
            encrypted = db.get('StorageEncrypted', False)
            if encrypted:
                findings.append({
                    'check_id': 'CIS-2.2.1',
                    'status': 'PASS',
                    'resource': f"{db_id} ({region})",
                    'evidence': 'Storage encryption is enabled',
                    'remediation': None,
                    'service': 'rds'
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.2.1',
                    'status': 'FAIL',
                    'resource': f"{db_id} ({region})",
                    'evidence': 'Storage encryption is NOT enabled',
                    'remediation': (
                        "Create a snapshot of the unencrypted RDS instance and restore it with encryption:\n"
                        "1. aws rds create-db-snapshot --region {region} --db-snapshot-identifier {db_id}-snapshot --db-instance-identifier {db_id}\n"
                        "2. aws kms list-aliases --region {region}  # Find KMS key\n"
                        "3. aws rds copy-db-snapshot --region {region} --source-db-snapshot-identifier {db_id}-snapshot "
                        "--target-db-snapshot-identifier {db_id}-snapshot-encrypted --kms-key-id <kms-key-id>\n"
                        "4. aws rds restore-db-instance-from-db-snapshot --region {region} "
                        "--db-instance-identifier {db_id}-encrypted --db-snapshot-identifier {db_id}-snapshot-encrypted\n"
                    ).format(db_id=db_id, region=region),
                    'service': 'rds'
                })

    return findings

def check_cis_2_2_2(session):
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        db_instances = get_rds_instances(session, region)
        for instance in db_instances:
            instance_id = instance['DBInstanceIdentifier']
            try:
                auto_upgrade_enabled = instance.get('AutoMinorVersionUpgrade', False)
                if auto_upgrade_enabled:
                    findings.append({
                        'check_id': 'CIS-2.2.2',
                        'status': 'PASS',
                        'resource': f"{instance_id} ({region})",
                        'evidence': 'Auto Minor Version Upgrade is enabled',
                        'remediation': None,
                        'service': 'rds'
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-2.2.2',
                        'status': 'FAIL',
                        'resource': f"{instance_id} ({region})",
                        'evidence': 'Auto Minor Version Upgrade is disabled',
                        'remediation': (
                            "Enable Auto Minor Version Upgrade using the AWS Console or CLI:\n"
                            "CLI example:\n"
                            "aws rds modify-db-instance --region {region} --db-instance-identifier {instance} "
                            "--auto-minor-version-upgrade --apply-immediately"
                        ).format(instance=instance_id, region=region),
                        'service': 'rds'
                    })
            except ClientError as e:
                findings.append({
                    'check_id': 'CIS-2.2.2',
                    'status': 'ERROR',
                    'resource': f"{instance_id} ({region})",
                    'evidence': f"Access denied or error: {e}",
                    'remediation': "Ensure the IAM role has rds:DescribeDBInstances permission",
                    'service': 'rds'
                })

    return findings

def check_cis_2_2_3(session):
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        db_instances = get_rds_instances(session, region)
        for db in db_instances:
            db_id = db['DBInstanceIdentifier']
            publicly_accessible = db.get('PubliclyAccessible', False)

            if publicly_accessible:
                findings.append({
                    'check_id': 'CIS-2.2.3',
                    'status': 'FAIL',
                    'resource': f"{db_id} ({region})",
                    'evidence': 'RDS instance is publicly accessible',
                    'remediation': (
                        "Disable public access for the RDS instance:\n"
                        f"1. aws rds modify-db-instance --region {region} "
                        f"--db-instance-identifier {db_id} --no-publicly-accessible --apply-immediately\n\n"
                        "If the RDS instance is in a public subnet, consider modifying its subnet configuration and route table:\n"
                        "- Ensure no route in the subnet's route table allows 0.0.0.0/0 via an Internet Gateway (igw-xxxxxxxx).\n"
                        "- Move the instance to private subnets if needed."
                    ),
                    'service': 'rds'
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.2.3',
                    'status': 'PASS',
                    'resource': f"{db_id} ({region})",
                    'evidence': 'RDS instance is not publicly accessible',
                    'remediation': None,
                    'service': 'rds'
                })

    return findings

def generate_report(findings):
    print("RDS CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-" * 40)
def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_2_2_1(session))
    all_findings.extend(check_cis_2_2_2(session))
    all_findings.extend(check_cis_2_2_3(session))
    generate_report(all_findings)
    return all_findings
