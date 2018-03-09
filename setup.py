# -*- coding: utf-8 -*-
from setuptools import setup
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()
setup(
    name='scandb',
    version='0.2.0',
    author='Christoph Bless',
    author_email='bitbucket@cbless.de',
    url='https://bitbucket.org/cbless/scandb',
    license=' GPLv3',
    description=('TODO'),
    long_description=long_description,
    packages=['scandb'],
    install_requires=[
        'argparse',
        'termcolor',
        'python-libnmap',
        'python-libnessus',
        'peewee'
    ],
    entry_points = {
        "console_scripts": [
            "nmap2scandb = scandb.nmap:nmap2scandb",
            "nessus2scandb = scandb.nessus:nessus2scandb"
        ]
    }
)

