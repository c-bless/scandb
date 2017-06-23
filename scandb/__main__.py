import argparse
import os
from scandb.importer import import_nmap_file


def nmap2db():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*", help="The nmap XML file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, help="Directory name with the nmap XML files to import")
    args = parser.parse_args()

    db = args.db
    files = args.file
    dir = args.dir

    if files is None and dir is None:
        parser.print_usage()
        return

    if files is not None:
        for file in files:
            import_nmap_file(db, file)
    if dir is not None:
        for filename in os.listdir(dir):
            if not filename.endswith('.xml'): continue
            fullname = os.path.join(dir, filename)
            import_nmap_file(db, fullname)


def nessus2db():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*",
                        help="The nessus file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, default=None,
                        help="Directory name with the nessus files to import")
    args = parser.parse_args()

    db = args.db
    files = args.file
    dir = args.dir

    if files is None and dir is None:
        parser.print_usage()
        return

    if files is not None:
        for file in files:
            pass
            #import_nmap_file(db, file)
    if dir is not None:
        for filename in os.listdir(dir):
            if not filename.endswith('.nessus'): continue
            fullname = os.path.join(dir, filename)
            pass
            #import_nmap_file(db, fullname)