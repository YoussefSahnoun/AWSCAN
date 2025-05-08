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

def check_cis_3_5(session):
    # CIS 3.5: Ensure CloudTrail logs are encrypted at rest using KMS CMKs
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            trails = cloudtrail_client.describe_trails()['trailList']

            for trail in trails:
                trail_name = trail.get('Name', 'Unknown')
                kms_key_id = trail.get('KmsKeyId')

                if kms_key_id:
                    findings.append({
                        'check_id': 'CIS-3.5',
                        'status': 'PASS',
                        'resource': f"CloudTrail: {trail_name} (Region: {region})",
                        'evidence': f"Trail is encrypted with KMS CMK: {kms_key_id}",
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.5',
                        'status': 'FAIL',
                        'resource': f"CloudTrail: {trail_name} (Region: {region})",
                        'evidence': 'Trail is not encrypted with a KMS Customer Master Key (CMK)',
                        'remediation': (
                            "1. Choose or create a KMS CMK.\n"
                            "2. Run the following command to enable KMS encryption on the trail:\n"
                            "aws cloudtrail update-trail --name <trail-name> --kms-id <kms-key-id>\n"
                            "3. Optionally, attach a key policy to the KMS key if required:\n"
                            "aws kms put-key-policy --key-id <kms-key-id> --policy <policy-document>"
                        )
                    })
        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.5',
                'status': 'FAIL',
                'resource': f"CloudTrail (Region: {region})",
                'evidence': f"Error checking KMS encryption: {str(e)}",
                'remediation': (
                    "Ensure CloudTrail is available and that you have the necessary IAM permissions to describe trails."
                )
            })

    return findings

def check_cis_3_6(session):
    # CIS 3.6: Ensure rotation for customer-created symmetric CMKs is enabled
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            kms_client = session.client('kms', region_name=region)
            paginator = kms_client.get_paginator('list_keys')
            for page in paginator.paginate():
                for key in page['Keys']:
                    key_id = key['KeyId']
                    key_metadata = kms_client.describe_key(KeyId=key_id)['KeyMetadata']

                    # Skip AWS-managed keys and asymmetric keys
                    if key_metadata['KeyManager'] != 'CUSTOMER' or key_metadata['KeySpec'].startswith('RSA') or key_metadata['KeySpec'].startswith('ECC'):
                        continue

                    rotation_enabled = kms_client.get_key_rotation_status(KeyId=key_id)['KeyRotationEnabled']

                    if rotation_enabled:
                        findings.append({
                            'check_id': 'CIS-3.6',
                            'status': 'PASS',
                            'resource': f"KMS Key ID: {key_id} (Region: {region})",
                            'evidence': 'Key rotation is enabled',
                            'remediation': None
                        })
                    else:
                        findings.append({
                            'check_id': 'CIS-3.6',
                            'status': 'FAIL',
                            'resource': f"KMS Key ID: {key_id} (Region: {region})",
                            'evidence': 'Key rotation is not enabled',
                            'remediation': (
                                "Enable key rotation for this customer-managed symmetric KMS key using:\n"
                                "aws kms enable-key-rotation --key-id <kms-key-id>"
                            )
                        })
        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.6',
                'status': 'FAIL',
                'resource': f"KMS (Region: {region})",
                'evidence': f"Error checking key rotation: {str(e)}",
                'remediation': 'Verify KMS permissions and configuration in this region.'
            })

    return findings

def check_cis_3_7(session):
    # CIS 3.7: Ensure VPC flow logging is enabled in all VPCs
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            ec2_client = session.client('ec2', region_name=region)
            logs_client = session.client('logs', region_name=region)

            vpcs = ec2_client.describe_vpcs()['Vpcs']

            for vpc in vpcs:
                vpc_id = vpc['VpcId']
                flow_logs = ec2_client.describe_flow_logs(
                    Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                )['FlowLogs']

                if any(log['TrafficType'] == 'REJECT' for log in flow_logs):
                    findings.append({
                        'check_id': 'CIS-3.7',
                        'status': 'PASS',
                        'resource': f"VPC ID: {vpc_id} (Region: {region})",
                        'evidence': 'Flow logging for REJECT traffic is enabled',
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.7',
                        'status': 'FAIL',
                        'resource': f"VPC ID: {vpc_id} (Region: {region})",
                        'evidence': 'No VPC flow log with traffic type REJECT',
                        'remediation': (
                            "Enable VPC flow logging for REJECT traffic:\n"
                            "1. Create IAM role and policy (see CIS 3.7 remediation steps).\n"
                            "2. Run:\n"
                            "aws ec2 create-flow-logs --resource-type VPC "
                            "--resource-ids <vpc-id> --traffic-type REJECT "
                            "--log-group-name <log-group-name> "
                            "--deliver-logs-permission-arn <iam-role-arn>"
                        )
                    })
        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.7',
                'status': 'FAIL',
                'resource': f"VPCs (Region: {region})",
                'evidence': f"Error checking VPC flow logs: {str(e)}",
                'remediation': 'Verify EC2 permissions and VPC configuration in this region.'
            })

    return findings

def check_cis_3_8(session):
    # CIS 3.8: Ensure object-level logging for write events is enabled for S3 buckets
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            s3_client = session.client('s3', region_name=region)

            # List all S3 buckets
            buckets_response = s3_client.list_buckets()
            buckets = buckets_response.get('Buckets', [])

            # List all trails in the region
            trails = cloudtrail_client.describe_trails()['trailList']

            if not trails:
                findings.append({
                    'check_id': 'CIS-3.8',
                    'status': 'FAIL',
                    'resource': f'All buckets in {region}',
                    'evidence': 'No CloudTrail trail found in region.',
                    'remediation': 'Create a CloudTrail trail in the region and enable object-level logging.'
                })
                continue

            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_arn = f"arn:aws:s3:::{bucket_name}/"
                write_logging_enabled = False

                for trail in trails:
                    trail_name = trail['Name']
                    try:
                        selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                        for selector in selectors.get('EventSelectors', []):
                            if selector.get('ReadWriteType') in ['WriteOnly', 'All'] and selector.get('IncludeManagementEvents'):
                                for resource in selector.get('DataResources', []):
                                    if resource.get('Type') == 'AWS::S3::Object':
                                        for value in resource.get('Values', []):
                                            if value == bucket_arn or value == "arn:aws:s3":
                                                write_logging_enabled = True
                    except Exception as e:
                        continue  # Skip error for this trail

                if write_logging_enabled:
                    findings.append({
                        'check_id': 'CIS-3.8',
                        'status': 'PASS',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Object-level write events are being logged in CloudTrail',
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.8',
                        'status': 'FAIL',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Object-level write events are not logged',
                        'remediation': (
                            "Enable object-level write logging in CloudTrail:\n"
                            "aws cloudtrail put-event-selectors --region <region> --trail-name <trail-name> "
                            "--event-selectors '[{\"ReadWriteType\": \"WriteOnly\", "
                            "\"IncludeManagementEvents\": true, \"DataResources\": [{\"Type\": \"AWS::S3::Object\", "
                            "\"Values\": [\"arn:aws:s3:::<bucket-name>/\"]}]}]'"
                        )
                    })

        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.8',
                'status': 'FAIL',
                'resource': f"S3 Buckets in {region}",
                'evidence': f"Error checking CloudTrail settings: {str(e)}",
                'remediation': 'Verify CloudTrail permissions and region availability.'
            })

    return findings

def check_cis_3_9(session):
    # CIS 3.9: Ensure object-level logging for read events is enabled for S3 buckets
    findings = []
    regions = get_all_regions(session)

    for region in regions:
        try:
            cloudtrail_client = session.client('cloudtrail', region_name=region)
            s3_client = session.client('s3', region_name=region)

            # List all S3 buckets
            buckets_response = s3_client.list_buckets()
            buckets = buckets_response.get('Buckets', [])

            # List all trails in the region
            trails = cloudtrail_client.describe_trails()['trailList']

            if not trails:
                findings.append({
                    'check_id': 'CIS-3.9',
                    'status': 'FAIL',
                    'resource': f'All buckets in {region}',
                    'evidence': 'No CloudTrail trail found in region.',
                    'remediation': 'Create a CloudTrail trail in the region and enable object-level logging for read events.'
                })
                continue

            for bucket in buckets:
                bucket_name = bucket['Name']
                bucket_arn = f"arn:aws:s3:::{bucket_name}/"
                read_logging_enabled = False

                for trail in trails:
                    trail_name = trail['Name']
                    try:
                        selectors = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                        for selector in selectors.get('EventSelectors', []):
                            if selector.get('ReadWriteType') in ['ReadOnly', 'All'] and selector.get('IncludeManagementEvents'):
                                for resource in selector.get('DataResources', []):
                                    if resource.get('Type') == 'AWS::S3::Object':
                                        for value in resource.get('Values', []):
                                            if value == bucket_arn or value == "arn:aws:s3":
                                                read_logging_enabled = True
                    except Exception as e:
                        continue  # Skip error for this trail

                if read_logging_enabled:
                    findings.append({
                        'check_id': 'CIS-3.9',
                        'status': 'PASS',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Object-level read events are being logged in CloudTrail',
                        'remediation': None
                    })
                else:
                    findings.append({
                        'check_id': 'CIS-3.9',
                        'status': 'FAIL',
                        'resource': f"S3 Bucket: {bucket_name} (Region: {region})",
                        'evidence': 'Object-level read events are not logged',
                        'remediation': (
                            "Enable object-level read logging in CloudTrail:\n"
                            "aws cloudtrail put-event-selectors --region <region> --trail-name <trail-name> "
                            "--event-selectors '[{\"ReadWriteType\": \"ReadOnly\", "
                            "\"IncludeManagementEvents\": true, \"DataResources\": [{\"Type\": \"AWS::S3::Object\", "
                            "\"Values\": [\"arn:aws:s3:::<bucket-name>/\"]}]}]'"
                        )
                    })

        except Exception as e:
            findings.append({
                'check_id': 'CIS-3.9',
                'status': 'FAIL',
                'resource': f"S3 Buckets in {region}",
                'evidence': f"Error checking CloudTrail settings: {str(e)}",
                'remediation': 'Verify CloudTrail permissions and region availability.'
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
    all_findings.extend(check_cis_3_5(session))
    all_findings.extend(check_cis_3_6(session))
    all_findings.extend(check_cis_3_7(session))
    all_findings.extend(check_cis_3_8(session))
    all_findings.extend(check_cis_3_9(session))
    generate_report(all_findings)
