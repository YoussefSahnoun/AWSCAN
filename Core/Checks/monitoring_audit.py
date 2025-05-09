import boto3
from botocore.exceptions import ClientError

def check_cis_4_1(session):
    # CIS 4.1: Ensure unauthorized API calls are monitored
    findings = []
    logs = session.client('logs')
    
    try:
        paginator = logs.get_paginator('describe_metric_filters')
        response_iterator = paginator.paginate()
        
        unauthorized_patterns = [
            '\"errorCode\"=\"*UnauthorizedOperation*\"',
            '\"errorCode\"=\"AccessDenied*\"'
        ]
        
        found = False
        
        for page in response_iterator:
            for metric_filter in page.get('metricFilters', []):
                pattern = metric_filter.get('filterPattern', '')
                if any(p in pattern for p in unauthorized_patterns):
                    findings.append({
                        'service':   'monitoring',
                        'check_id':  'CIS-4.1',
                        'status':    'PASS',
                        'resource':  metric_filter.get('logGroupName'),
                        'evidence':  f'Metric filter pattern: {pattern}',
                        'remediation': None
                    })
                    found = True
                    break  # One valid match is enough to consider PASS
            if found:
                break

        if not found:
            findings.append({
                'service':   'monitoring',
                'check_id':  'CIS-4.1',
                'status':    'FAIL',
                'resource':  'CloudWatch Logs',
                'evidence':  'No metric filter found for unauthorized API calls',
                'remediation': (
                    "Create a metric filter in CloudWatch Logs:\n"
                    "aws logs put-metric-filter --log-group-name <log-group-name> "
                    "--filter-name 'UnauthorizedAPICalls' "
                    "--metric-transformations "
                    "metricName='UnauthorizedAPICalls',metricNamespace='CISBenchmark',metricValue='1' "
                    "--filter-pattern '{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }'"
                )
            })

    except ClientError as e:
        findings.append({
            'service':   'monitoring',
            'check_id':  'CIS-4.1',
            'status':    'ERROR',
            'resource':  'CloudWatch Logs',
            'evidence':  f"Error accessing CloudWatch Logs: {e}",
            'remediation': "Add logs:DescribeMetricFilters permission"
        })

    return findings

def generate_report(findings):
    print("Monitoring CIS Benchmark Results:")
    for finding in findings:
        print(finding)
        print("-" * 40)

def run_audit(session):
    all_findings = []
    all_findings.extend(check_cis_4_1(session))
    generate_report(all_findings)
    return all_findings

# Example usage:
# from auth import get_aws_session
# session = get_aws_session(access_key, secret_key)
# run_audit(session)
