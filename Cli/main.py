
import json
import click
from concurrent.futures import ThreadPoolExecutor

from Core import orchestrator

@click.command()
@click.option('--access-key', prompt='Enter your access key', help='Your AWS access key.')
@click.option('--secret-key', prompt='Enter your secret key', hide_input=True, help='Your AWS secret key.')
@click.option('--session-token', prompt='Enter your session token', hide_input=True, help='Your AWS session token.')
@click.option('--region', prompt='Enter your region', help='AWS region to use.')
@click.option('--output', type=click.Choice(['json', 'table'], case_sensitive=False), default='json',help='Output format for the results (json or table).')

def main(access_key, secret_key, session_token, region, output):
    validate, response, session = orchestrator.validate_creds(access_key, secret_key, session_token, region)
    click.echo(response)
    
    click.echo("Discovering enabled services...")
    enabled_services = orchestrator.discover_enabled_services(session)
    click.echo(f"Found {len(enabled_services)} services: {', '.join(enabled_services)}")
    
    click.echo("\nRunning CIS benchmarks...")
    all_results=orchestrator.thread_audits(enabled_services,session)
    click.echo(all_results)
    consolidated = orchestrator.organize_results(all_results)
    
    
                
if __name__ == '__main__':
    main()
