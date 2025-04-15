from setuptools import setup, find_packages

setup(
    name="cis_audit_tool",
    version="0.1.0",
    packages=find_packages(),  # This finds packages in folders with __init__.py
    install_requires=[
        "click",
        "boto3"
    ],
    entry_points={
        "console_scripts": [
            "cis-audit=Cli.main:main",  # This installs a CLI command named `cis-audit`
        ],
    },
)