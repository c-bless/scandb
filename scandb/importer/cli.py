from __future__ import print_function
import argparse
import os
from scandb.models.db import init_db
from scandb.importer.nmap import import_nmap_file
from scandb.importer.nessus import import_nessus_file

def importer_cli():
    """
    Entry point for the console script scandb-importer. This script allows to import either a single nessus|nmap XML-file or
    several nessus|nmap XML-files within a given directory.
    :return:
    """
    parser = argparse.ArgumentParser(description="I will import Nmap and Nessus scans into a SQLite database.")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*",
                        help="The nessus and/or nmap file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, default=None,
                        help="Directory name with nessus and/or nmap files")
    args = parser.parse_args()

    db = args.db
    filename = args.file
    dir = args.dir

    # initialize the database
    database = init_db(db)

    if filename is None and dir is None:
        # either a filename or a directory must be specified
        parser.print_usage()
        return

    if filename is not None:
        # import a single nessus/nmap XML-file
        for file in filename:
            if file.endswith('.nessus'):
                import_nessus_file(file)
            if file.endswith('.xml'):
                import_nmap_file(file)
    if dir is not None:
        # import several nessus/nmap files within a directory
        for filename in os.listdir(dir):
            if filename.endswith('.nessus'):
                fullname = os.path.join(dir, filename)
                import_nessus_file(fullname)
            if filename.endswith('.xml'):
                fullname = os.path.join(dir, filename)
                import_nmap_file(fullname)

    database.close()
