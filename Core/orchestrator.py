from .auth import *
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import importlib
import json  # Optional: for pretty printing

# Mandatory services are audited regardless of resource presence
MANDATORY_SERVICES = ['iam']  # IAM will always be audited

# Conditional services are only audited if resources exist
CONDITIONAL_SERVICES = {
    's3': ('s3', 'list_buckets', 'Buckets'),
    'ec2': ('ec2', 'describe_instances', 'Reservations'),
}

# Map of service names to their respective audit modules
AUDIT_MODULES = {
    's3': 's3_audit',
    'iam': 'iam_audit',       # ADDED IAM MODULE
    # 'ec2': 'ec2_audit',     # To be added later
}

def discover_enabled_services(session):
    enabled = set(MANDATORY_SERVICES)

    def check_service(service):
        client = session.client(service)  # ou une autre région valide
        method = getattr(client, CONDITIONAL_SERVICES[service][1])
        try:
            response = method()
            if response.get(CONDITIONAL_SERVICES[service][2]):
                return service
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error checking {service}: {e}")
        return None

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_service, s): s for s in CONDITIONAL_SERVICES}
        for future in futures:
            if result := future.result():
                enabled.add(result)

    return sorted(enabled)

def run_audit(service, session):
    try:
        module_name = f'Core.Checks.{AUDIT_MODULES[service]}'
        module = importlib.import_module(module_name)
        return module.run_audit(session)
    except Exception as e:
        return [{
            'check_id': 'ORCHESTRATION-ERROR',
            'status': 'ERROR',
            'service': service,
            'evidence': f"Failed to run audit: {str(e)}"
        }]

def organize_results(all_results):
    report = defaultdict(list)
    for service_results in all_results:
        if service_results:
            for finding in service_results:
                report[finding['service']].append(finding)
    return report

def thread_audits(enabled_services,session):
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(run_audit, s, session) for s in enabled_services if s in AUDIT_MODULES]
        all_results = [f.result() for f in futures]
    return all_results

