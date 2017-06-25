import argparse
import os
import peewee
from libnmap.parser import NmapParser
from termcolor import colored
from scandb.util import host_to_tupel, get_ports, hash_file
from scandb.models import Scan, Host, Port, init_db


def import_nmap_file(infile):
    print colored("[*] Importing file: {0}".format(infile), 'green')
    try:
        report = NmapParser.parse_fromfile(infile)
        sha512 = hash_file(infile)
    except Exception as e:
        print colored("[-] File cannot be imported : {0}".format(infile), 'red')

    try:
        scan = Scan(file_hash=sha512, name=report.commandline, type='nmap', start=report.started, end=report.endtime,
                    elapsed=report.elapsed, hosts_total=report.hosts_total, hosts_up=report.hosts_up,
                    hosts_down=report.hosts_down)
        scan.save()
    except peewee.IntegrityError as e:
        print colored("[-] File already imported: {0}".format(infile), 'red')
        return

    for h in report.hosts:
        address, hostname, os, osgen, status = host_to_tupel(h)
        host = Host(address=address, hostname=hostname, os=os, os_gen=osgen, status=status, scan=scan)
        host.save()
        ports = get_ports(h)
        for p, proto, servicename, state, banner in ports:
            port = Port(host=host, address=address, port=p, protocol=proto, service=servicename, banner=banner,
                        status=state)
            port.save()

    print colored("[*] File imported. ")


def nmap2scandb():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*", help="The nmap XML file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, help="Directory name with the nmap XML files to import")
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
            import_nmap_file(file)
    if dir is not None:
        for filename in os.listdir(dir):
            if not filename.endswith('.xml'): continue
            fullname = os.path.join(dir, filename)
            import_nmap_file(fullname)

    database.close()
