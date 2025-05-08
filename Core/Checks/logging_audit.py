import boto3

def get_all_regions(session):
    ec2 = session.client('ec2')
    regions_info = ec2.describe_regions(AllRegions=True)
    return [region['RegionName'] for region in regions_info['Regions'] if region['OptInStatus'] in ['opt-in-not-required', 'opted-in']]

def check_cis_3_1(session):
    # CIS 3.1: Ensure CloudTrail is enabled in all regions
    findings = []
    regions = get_all_regions(session)
    checked_trails = set()

    for region in regions:
        client = session.client('cloudtrail', region_name=region)
        try:
            response = client.describe_trails()
            trails = response.get('trailList', [])

            if not trails:
                findings.append({
                    'check_id': 'CIS-3.1',
                    'status': 'FAIL',
                    'resource': f"{region}",
                    'evidence': 'No CloudTrail trails configured in this region',
                    'remediation': (
                        "Create a multi-region trail:\n"
                        f"aws cloudtrail create-trail --name <trail-name> --bucket-name <s3-bucket> --is-multi-region-trail"
                    )
                })
                continue

            for trail in trails:
                name = trail.get('Name')
                if name in checked_trails:
                    continue  # Skip already checked multi-region trail
                checked_trails.add(name)

                is_multi_region = trail.get('IsMultiRegionTrail', False)

                # Check if logging is enabled
                status = client.get_trail_status(Name=name)
                is_logging = status.get('IsLogging', False)

                # Check for management events only
                selectors_response = client.get_event_selectors(TrailName=name)
                advanced_selectors = selectors_response.get('AdvancedEventSelectors', [])
                management_only = any(
                    selector.get('FieldSelectors') and
                    all(fs.get('Field') == 'eventCategory' and 'Management' in fs.get('Equals', [])
                        for fs in selector.get('FieldSelectors'))
                    for selector in advanced_selectors
                )

                if is_multi_region and is_logging and management_only:
                    findings.append({
                        'check_id': 'CIS-3.1',
                        'status': 'PASS',
                        'resource': f"{name} ({region})",
                        'evidence': 'Multi-region CloudTrail enabled with management-only logging',
                        'remediation': None
                    })
                else:
                    remediation_steps = []
                    if not is_multi_region:
                        remediation_steps.append(
                            f"aws cloudtrail update-trail --name {name} --is-multi-region-trail"
                        )
                    if not is_logging:
                        remediation_steps.append(
                            f"aws cloudtrail start-logging --name {name}"
                        )
                    if not management_only:
                        remediation_steps.append(
                            f"Update trail {name} to log only Management events using AdvancedEventSelectors"
                        )
                    findings.append({
                        'check_id': 'CIS-3.1',
                        'status': 'FAIL',
                        'resource': f"{name} ({region})",
                        'evidence': (
                            f"MultiRegion: {is_multi_region}, "
                            f"IsLogging: {is_logging}, "
                            f"ManagementOnly: {management_only}"
                        ),
                        'remediation': "\n".join(remediation_steps)
                    })

        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.1',
                'status': 'ERROR',
                'resource': region,
                'evidence': str(e),
                'remediation': 'Ensure CloudTrail is accessible and permissions are correctly set'
            })

    return findings

def check_cis_3_2(session):
    # CIS 3.2: Ensure CloudTrail log file validation is enabled
    findings = []
    regions = get_all_regions(session)
    checked_trails = set()

    for region in regions:
        client = session.client('cloudtrail', region_name=region)
        try:
            response = client.describe_trails()
            trails = response.get('trailList', [])

            if not trails:
                continue  # No trails in this region

            for trail in trails:
                name = trail.get('Name')
                if name in checked_trails:
                    continue  # Already checked this trail
                checked_trails.add(name)

                log_validation_enabled = trail.get('LogFileValidationEnabled', False)

                if log_validation_enabled:
                    findings.append({
                        'check_id': 'CIS-3.2',
                        'status': 'PASS',
                        'resource': f"{name} ({region})",
                        'evidence': 'Log file validation is enabled',
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.2',
                        'status': 'FAIL',
                        'resource': f"{name} ({region})",
                        'evidence': 'Log file validation is NOT enabled',
                        'remediation': (
                            f"Enable log file validation:\n"
                            f"aws cloudtrail update-trail --name {name} --enable-log-file-validation"
                        )
                    })

        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.2',
                'status': 'ERROR',
                'resource': region,
                'evidence': str(e),
                'remediation': 'Check CloudTrail access and permissions'
            })

    return findings

def check_cis_3_3(session):
    # CIS 3.3: Ensure AWS Config is enabled in all regions
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        client = session.client('config', region_name=region)

        try:
            recorders = client.describe_configuration_recorders().get('ConfigurationRecorders', [])
            statuses = client.describe_configuration_recorder_status().get('ConfigurationRecordersStatus', [])
            delivery_channels = client.describe_delivery_channels().get('DeliveryChannels', [])

            if not recorders or not statuses or not delivery_channels:
                findings.append({
                    'check_id': 'CIS-3.3',
                    'status': 'FAIL',
                    'resource': f"AWS Config ({region})",
                    'evidence': 'AWS Config is not fully configured (missing recorder, status, or delivery channel)',
                    'remediation': (
                        "1. Ensure you have created a suitable IAM role, S3 bucket, and SNS topic.\n"
                        "2. Run the following:\n"
                        "aws configservice put-configuration-recorder --configuration-recorder "
                        "--name <config-recorder-name> --roleARN arn:aws:iam::<account-id>:role/<iam-role> "
                        "--recording-group allSupported=true,includeGlobalResourceTypes=true\n"
                        "3. Create a delivery channel JSON file and run:\n"
                        "aws configservice put-delivery-channel --delivery-channel file://<delivery-channel-file>.json\n"
                        "4. Start the recorder:\n"
                        "aws configservice start-configuration-recorder --configuration-recorder-name <config-recorder-name>"
                    )
                })
                continue

            status = statuses[0]
            is_recording = status.get('recording', False)

            if is_recording:
                findings.append({
                    'check_id': 'CIS-3.3',
                    'status': 'PASS',
                    'resource': f"AWS Config ({region})",
                    'evidence': 'AWS Config is enabled and recording',
                    'remediation': None
                })
            else:
                findings.append({
                    'check_id': 'CIS-3.3',
                    'status': 'FAIL',
                    'resource': f"AWS Config ({region})",
                    'evidence': 'Configuration recorder exists but is not recording',
                    'remediation': (
                        "Start the recorder using:\n"
                        "aws configservice start-configuration-recorder --configuration-recorder-name <config-recorder-name>"
                    )
                })
        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.3',
                'status': 'FAIL',
                'resource': f"AWS Config ({region})",
                'evidence': f'Error checking AWS Config: {e}',
                'remediation': 'Verify AWS Config is available and properly set up in this region.'
            })

    return findings

def check_cis_3_4(session):
    # CIS 3.4: Ensure that server access logging is enabled on the CloudTrail S3 bucket
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            s3_client = session.client('s3')

            trails = cloudtrail_client.describe_trails()['trailList']
            for trail in trails:
                bucket_name = trail.get('S3BucketName')
                if not bucket_name:
                    findings.append({
                        'check_id': 'CIS-3.4',
                        'status': 'FAIL',
                        'resource': f"CloudTrail (Region: {region})",
                        'evidence': 'No S3 bucket associated with this trail',
                        'remediation': (
                            "Ensure CloudTrail is configured with an S3 bucket.\n"
                            "You can find the bucket using:\n"
                            "aws cloudtrail describe-trails --region <region-name> --query trailList[*].S3BucketName"
                        )
                    })
                    continue

                logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)

                if 'LoggingEnabled' in logging_status:
                    findings.append({
                        'check_id': 'CIS-3.4',
                        'status': 'PASS',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Server access logging is enabled',
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.4',
                        'status': 'FAIL',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Server access logging is not enabled',
                        'remediation': (
                            "1. Create a JSON file with the following content:\n"
                            '{\n'
                            '  "LoggingEnabled": {\n'
                            '    "TargetBucket": "<target-bucket>",\n'
                            '    "TargetPrefix": "<log-prefix>",\n'
                            '    "TargetGrants": [\n'
                            '      {\n'
                            '        "Grantee": {\n'
                            '          "Type": "AmazonCustomerByEmail",\n'
                            '          "EmailAddress": "<email>"\n'
                            '        },\n'
                            '        "Permission": "FULL_CONTROL"\n'
                            '      }\n'
                            '    ]\n'
                            '  }\n'
                            '}\n'
                            "2. Run:\n"
                            "aws s3api put-bucket-logging --bucket <bucket-name> --bucket-logging-status file://<filename>.json"
                        )
                    })
        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.4',
                'status': 'FAIL',
                'resource': f"CloudTrail (Region: {region})",
                'evidence': f"Error checking server access logging: {str(e)}",
                'remediation': 'Verify CloudTrail and S3 permissions and configuration in this region.'
            })

    return findings

def generate_report(findings):
    print("CloudTrail CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-" * 40)

def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_3_1(session))
    all_findings.extend(check_cis_3_2(session))
    all_findings.extend(check_cis_3_3(session))
    all_findings.extend(check_cis_3_4(session))
    generate_report(all_findings)
