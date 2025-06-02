# Core/banner.py
import pyfiglet
import click

def print_banner():
    # ASCII logo
    ascii_art = pyfiglet.figlet_format("awscan", font="slant")
    click.echo(click.style(ascii_art, fg="cyan", bold=True))
    
    # Tool description
    click.echo(click.style(
        "awscan — AWS configuration audit tool",
        fg="bright_white",
        italic=True
    ))
    click.echo()