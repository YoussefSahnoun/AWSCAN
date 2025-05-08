# efs_audit.py
import boto3

def get_all_regions(session):
    ec2 = session.client('ec2')
    regions_info = ec2.describe_regions(AllRegions=True)
    return [region['RegionName'] for region in regions_info['Regions'] if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']]

def get_efs_file_systems(session, region):
    client = session.client('efs', region_name=region)
    try:
        response = client.describe_file_systems()
        return response.get('FileSystems', [])
    except Exception as e:
        print(f"[ERROR] Could not retrieve EFS file systems in {region}: {e}")
        return []

def check_cis_2_3_1(session):
    # CIS 2.3.1: Ensure that encryption is enabled for EFS file systems
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        efs_filesystems = get_efs_file_systems(session, region)

        for fs in efs_filesystems:
            fs_id = fs['FileSystemId']
            encrypted = fs.get('Encrypted', False)

            if encrypted:
                findings.append({
                    'check_id': 'CIS-2.3.1',
                    'status': 'PASS',
                    'resource': f"{fs_id} ({region})",
                    'evidence': 'Encryption at rest is enabled',
                    'remediation': None
                })
            else:
                findings.append({
                    'check_id': 'CIS-2.3.1',
                    'status': 'FAIL',
                    'resource': f"{fs_id} ({region})",
                    'evidence': 'Encryption at rest is NOT enabled',
                    'remediation': (
                        "Create a new EFS file system with encryption enabled and migrate data as needed:\n"
                        f"1. aws efs create-file-system --region {region} --performance-mode generalPurpose --encrypted\n"
                        f"2. Use AWS DataSync or other tools to move data from {fs_id} to the new encrypted file system."
                    )
                })

    return findings

def generate_report(findings):
    print("EFS CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-" * 40)

def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_2_3_1(session))
    generate_report(all_findings)