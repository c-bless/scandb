import argparse
import os
import peewee
from libnessus.parser import NessusParser
from termcolor import colored
from scandb.util import host_to_tupel, get_ports, hash_file
from scandb.models import Scan, Host, Port, init_db


def import_nessus_file(infile):
    print colored("[*] Importing file: {0}".format(infile), 'green')
    try:
        report = NessusParser.parse_fromfile(infile)
        sha512 = hash_file(infile)
    except Exception as e:
        print colored("[-] File cannot be imported : {0}".format(infile), 'red')

    try:
        scan = Scan(file_hash=sha512, name=report.name, type='nessus', start=report.started, end=report.endtime,
                    elapsed=report.elapsed, hosts_total=report.hosts_total)
        scan.save()
    except peewee.IntegrityError as e:
        print colored("[-] File already imported: {0}".format(infile), 'red')
        return

    for h in report.hosts:
        host = Host(address=h.ip, hostname=h.name, scan=scan)
        print "{0} cve count {1}".format(h.ip, h.get_summary_total_cves)
        host.save()

    #   print colored("importing host: {0}".format(host.address), 'blue')
    #    insert_nmap_host(conn, host, scan_id=scan_id)
    #    conn.commit()

    print colored("[*] File imported.")



def nessus2scandb():
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

    database = init_db(db)

    if files is None and dir is None:
        parser.print_usage()
        return

    if files is not None:
        for file in files:
            pass
            import_nessus_file(file)
    if dir is not None:
        for filename in os.listdir(dir):
            if not filename.endswith('.nessus'): continue
            fullname = os.path.join(dir, filename)
            pass
            import_nessus_file(fullname)

    database.close()