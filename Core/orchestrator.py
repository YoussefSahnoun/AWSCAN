from auth import *
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict
import importlib



MANDATORY_SERVICES = ['iam'] #for now iam is the only mandatory we'll work on , mandatory means we have to benchmark directly without checking instances
#for other services that need to be instanced we have to run a check to collect these services:
CONDITIONAL_SERVICES = {  # we'll start with s3 and ec2 for now 
    's3': ('s3', 'list_buckets', 'Buckets'),
    'ec2': ('ec2', 'describe_instances', 'Reservations'),
}
AUDIT_MODULES = {
    's3': 's3_audit', #deja mawjoud
    #'iam': 'iam_audit',---->to be added
    #'ec2': 'ec2_audit',---->to be added
    
}


def discover_enabled_services(session):
    #mandatory goes directly into enabled services
    enabled = set(MANDATORY_SERVICES)
    #nested function to be called only when necessary 
    def check_service(service):
        client = session.client(service)
        method = getattr(client, CONDITIONAL_SERVICES[service][1]) # traja3 client.list_buckets mathalan fel s3 
        try:
            response = method()
            if response.get(CONDITIONAL_SERVICES[service][2]):#traja3 lbuckets ken mawjoud , wken mch mawjoudin matraja3 chay (bch manaamlouch audit ken mafamech buckets w kif kif lel ec2 )
                return service
        except ClientError as e:
            if e.response['Error']['Code'] != 'AccessDenied':
                print(f"Error checking {service}: {e}")
        return None
    #Thread usage to search for services in parallel
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_service, s): s 
                 for s in CONDITIONAL_SERVICES.keys()}#el keys houwa l services li hajetna bihom 
        for future in futures:
            if result := future.result(): # equivalent lel result = future.result() w ken fama result nzidouh lel set enabled eli bch naamlou aaleha el audit 
                enabled.add(result)

    return sorted(enabled)


def run_audit(service, session):
    #function to dynamically import modules for audit 
	try:
		module_name = f'Checks.{AUDIT_MODULES[service]}'
		module = importlib.import_module(module_name)
		return module.run_audit(session)
	except Exception as e:
		return [{
        	'check_id': 'ORCHESTRATION-ERROR',
        	'status': 'ERROR',
        	'service': service,
        	'evidence': f"Failed to run audit: {str(e)}"
		}]
#to be implemented later 
def organize_results(all_results):
	report = defaultdict(list)
	for service_results in all_results:
		if service_results:
			for finding in service_results:
				report[finding['service']].append(finding)
	return report
def main():
	access_key=input('Enter your access key: ')
	secret_key=input('Enter your secret key: ')
	session_token=input('Enter your session_token: ')
	validate,response,session=validate_creds(access_key,secret_key,session_token)
	print(response)
	print("Discovering enabled services...")
	enabled_services = discover_enabled_services(session)
	print(f"Found {len(enabled_services)} services: {', '.join(enabled_services)}")
	print("\nRunning CIS benchmarks...")
	with ThreadPoolExecutor(max_workers=5) as executor:
	    futures = [executor.submit(run_audit, s, session) 
	             for s in enabled_services if s in AUDIT_MODULES]
	    all_results = [f.result() for f in futures]
	#consolidated = organize_results(all_results)
	#print(consolidated)

if __name__ == "__main__":
    main()


