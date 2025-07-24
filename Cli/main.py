
import json
import click
from concurrent.futures import ThreadPoolExecutor
from tabulate import tabulate

from Core.banner import print_banner
from Core import orchestrator

# print banner & description before any prompts
print_banner()

@click.command()
@click.option('--access-key', prompt='Enter your access key', help='Your AWS access key.')
@click.option('--secret-key', prompt='Enter your secret key', hide_input=True, help='Your AWS secret key.')
@click.option('--session-token', prompt='Enter your session token', hide_input=True, help='Your AWS session token.')
@click.option('--region', prompt='Enter your region', help='AWS region to use.')
@click.option(
    '--output',
    type=click.Choice(['table', 'json'], case_sensitive=False),
    default='table',
    help='Output format for the results (table or json).'
)
def main(access_key, secret_key, session_token, region, output):
    # 1) Validate & discover
    validate, response, session = orchestrator.validate_creds(
        access_key, secret_key, session_token, region
    )
    click.echo(response)
    click.echo("Discovering enabled services...")
    enabled_services = orchestrator.discover_enabled_services(session)
    click.echo(f"Found {len(enabled_services)} services: {', '.join(enabled_services)}\n")

    # 2) Run audits
    click.echo("Running CIS benchmarks…")
    all_results = orchestrator.thread_audits(enabled_services, session)
    consolidated = orchestrator.organize_results(all_results)

    # 3) Render output
    if output.lower() == 'json':
        # pretty-print JSON
        click.echo(json.dumps(consolidated, indent=2))
    else:
        # console table per service
        for service, findings in consolidated.items():
            click.echo(click.style(f"\n=== {service.upper()} ===", fg="yellow", bold=True))
            # define your table columns:
            headers = ['check_id', 'status', 'resource', 'evidence', 'remediation']
            rows = [
                [f.get(h, '') or '' for h in headers]
                for f in findings
            ]
            click.echo(tabulate(rows, headers=headers, tablefmt='grid'))

if __name__ == '__main__':
    main()
