# -*- coding: utf-8 -*-
from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

long_description = ""
# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='scandb',
    version='1.0.0',
    author='Christoph Bless',
    author_email='bitbucket@cbless.de',
    url='https://bitbucket.org/cbless/scandb',
    license=' GPLv3',
    description=("Scripts to import nmap and nessus scan results into a SQLite database, analyze the overall results and generate reports or target lists."),
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=[
        'scandb',
        'scandb.report',
        'scandb.importer',
        'scandb.services',
        'scandb.statistics',
        'scandb.models',
        'scandb.vulns'
    ],
    install_requires=[
        'argparse',
        'termcolor',
        'python-libnmap',
        'python-libnessus',
        'SQLAlchemy',
        'sqlalchemy-views',
        'docxtpl'
    ],
    entry_points = {
        "console_scripts": [
            "scandb-vulns = scandb.vulns.cli:vulns_cli",
            "scandb-services = scandb.services.cli:services_cli",
            "scandb-statistics = scandb.statistics.cli:statistics_cli",
            "scandb-importer = scandb.importer.cli:importer_cli",
            "scandb-compare = scandb.compare:compare_cli",
            "scandb-report = scandb.report.cli:report_cli"
        ]
    }
)

