import boto3
import base64
import json
from botocore.exceptions import ClientError


def get_ec2_instances(session):
    """List all EC2 instances in the account."""
    ec2 = session.client('ec2')
    try:
        response = ec2.describe_instances()
        instances = []
        for reservation in response.get('Reservations', []):
            for instance in reservation.get('Instances', []):
                instances.append(instance)
        
        return instances
    except ClientError as e:
        print(f"Error listing EC2 instances: {e}")
        return []


def check_cis_2_13(session):
    """
    CIS 2.13: Ensure Secrets and Sensitive Data are not stored directly in EC2 User Data
    
    This check examines the user data of each EC2 instance to look for potential secrets
    or sensitive information.
    """
    findings = []
    ec2 = session.client('ec2')
    
    # Keywords that might indicate sensitive data
    sensitive_keywords = [
        'password', 'passwd', 'secret', 'key', 'token', 'credential', 
        'api_key', 'apikey', 'access_key', 'accesskey', 'aws_access_key_id',
        'aws_secret_access_key', 'private_key', 'ssh_key'
    ]
    
    try:
        # Get all instances
        instances = get_ec2_instances(session)
        
        # If there are no instances, return a note
        if not instances:
            findings.append({
                'check_id': 'CIS-2.13',
                'status': 'PASS',
                'service': 'ec2',
                'resource': 'No EC2 Instances',
                'evidence': 'No EC2 instances found to check',
                'remediation': None
            })
            return findings
        
        # Check each instance for user data
        for instance in instances:
            instance_id = instance['InstanceId']
            
            try:
                # Get user data for this instance
                response = ec2.describe_instance_attribute(
                    InstanceId=instance_id,
                    Attribute='userData'
                )
                
                user_data_b64 = response.get('UserData', {}).get('Value')
                
                # If no user data exists, mark as passing
                if not user_data_b64:
                    findings.append({
                        'check_id': 'CIS-2.13',
                        'status': 'PASS',
                        'service': 'ec2',
                        'resource': instance_id,
                        'evidence': 'No user data found',
                        'remediation': None
                    })
                    continue
                
                # Decode base64 user data
                try:
                    user_data = base64.b64decode(user_data_b64).decode('utf-8')
                    
                    # Check for sensitive keywords
                    has_sensitive_data = False
                    matching_keywords = []
                    
                    for keyword in sensitive_keywords:
                        if keyword.lower() in user_data.lower():
                            has_sensitive_data = True
                            matching_keywords.append(keyword)
                    
                    if has_sensitive_data:
                        findings.append({
                            'check_id': 'CIS-2.13',
                            'status': 'FAIL',
                            'service': 'ec2',
                            'resource': instance_id,
                            'evidence': f"User data contains potential sensitive information: {', '.join(matching_keywords)}",
                            'remediation': (
                                "1. Launch a new EC2 instance without sensitive data in user data\n"
                                "2. Use AWS Secrets Manager or Parameter Store for secrets\n"
                                "3. If scripts need secrets, let them retrieve from secure sources at runtime"
                            )
                        })
                    else:
                        findings.append({
                            'check_id': 'CIS-2.13',
                            'status': 'PASS',
                            'service': 'ec2',
                            'resource': instance_id,
                            'evidence': 'No sensitive data detected in user data',
                            'remediation': None
                        })
                except Exception as e:
                    findings.append({
                        'check_id': 'CIS-2.13',
                        'status': 'ERROR',
                        'service': 'ec2',
                        'resource': instance_id,
                        'evidence': f"Unable to decode user data: {e}",
                        'remediation': "Verify the user data encoding format"
                    })
                    
            except ClientError as e:
                findings.append({
                    'check_id': 'CIS-2.13',
                    'status': 'ERROR',
                    'service': 'ec2',
                    'resource': instance_id,
                    'evidence': f"Error accessing user data: {e}",
                    'remediation': "Ensure IAM permissions include ec2:DescribeInstanceAttribute"
                })
    
    except ClientError as e:
        findings.append({
            'check_id': 'CIS-2.13',
            'status': 'ERROR',
            'service': 'ec2',
            'resource': 'EC2Service',
            'evidence': f"Access denied or service error: {e}",
            'remediation': "Verify IAM permissions include ec2:DescribeInstances and ec2:DescribeInstanceAttribute"
        })
        
    return findings


def check_cis_2_7(session):
    """
    CIS 2.7: Ensure Default EC2 Security groups are not being used.
    
    This check verifies that no EC2 instances are using the default security group.
    """
    findings = []
    ec2 = session.client('ec2')
    
    try:
        # Get all VPCs to identify their default security groups
        response = ec2.describe_vpcs()
        default_sg_instances = {}
        
        # For each VPC, find its default security group
        for vpc in response.get('Vpcs', []):
            vpc_id = vpc['VpcId']
            
            # Find the default security group for this VPC
            sg_response = ec2.describe_security_groups(
                Filters=[
                    {
                        'Name': 'vpc-id',
                        'Values': [vpc_id]
                    },
                    {
                        'Name': 'group-name',
                        'Values': ['default']
                    }
                ]
            )
            
            if not sg_response.get('SecurityGroups'):
                continue
                
            # Get the default security group ID
            default_sg_id = sg_response['SecurityGroups'][0]['GroupId']
            
            # Find instances using this security group
            instance_response = ec2.describe_instances(
                Filters=[
                    {
                        'Name': 'instance.group-id',
                        'Values': [default_sg_id]
                    }
                ]
            )
            
            # Add any instances using the default SG to our tracking dict
            instances_using_default_sg = []
            for reservation in instance_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances_using_default_sg.append(instance['InstanceId'])
            
            if instances_using_default_sg:
                default_sg_instances[vpc_id] = {
                    'security_group_id': default_sg_id,
                    'instances': instances_using_default_sg
                }
        
        # If no default security groups with instances found
        if not default_sg_instances:
            findings.append({
                'check_id': 'CIS-2.7',
                'status': 'PASS',
                'service': 'ec2',
                'resource': 'ALL_VPCS',
                'evidence': 'No instances are using default security groups',
                'remediation': None
            })
        else:
            # For each VPC with instances using default security group
            for vpc_id, sg_data in default_sg_instances.items():
                findings.append({
                    'check_id': 'CIS-2.7',
                    'status': 'FAIL',
                    'service': 'ec2',
                    'resource': f"{vpc_id}:{sg_data['security_group_id']}",
                    'evidence': f"{len(sg_data['instances'])} instances using default security group: {', '.join(sg_data['instances'][:5])}{'...' if len(sg_data['instances']) > 5 else ''}",
                    'remediation': (
                        "1. Create a custom security group with required rules\n"
                        "2. Attach the custom security group to the instances\n"
                        "3. Remove the default security group from the instances"
                    )
                })
                
    except ClientError as e:
        findings.append({
            'check_id': 'CIS-2.7',
            'status': 'ERROR',
            'service': 'ec2',
            'resource': 'EC2Service',
            'evidence': f"Access denied or service error: {e}",
            'remediation': "Verify IAM permissions include ec2:DescribeVpcs, ec2:DescribeSecurityGroups, and ec2:DescribeInstances"
        })
    
    return findings


def generate_report(findings):
    """Generate a report of the EC2 CIS benchmark results."""
    print("EC2 CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-" * 40)


def run_audit(session):
    """Run all EC2 CIS benchmarks and return the findings."""
    all_findings = []
    
    # CIS 2.13: Secrets in EC2 User Data
    all_findings.extend(check_cis_2_13(session))
    
    # CIS 2.7: Default security groups
    all_findings.extend(check_cis_2_7(session))
    
    # Generate report for terminal output
    generate_report(all_findings)
    
    # Return findings for integration with main program
    return all_findings