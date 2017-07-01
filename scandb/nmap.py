import argparse
import os
import peewee
from libnmap.parser import NmapParser
from termcolor import colored
from scandb.util import host_to_tupel, get_ports, hash_file
from scandb.models import Scan, Host, Port, init_db


def import_nmap_file(infile):
    """
    This function is responsable for importing the given file.  For each file a SHA-512 hash is calculated to ensure
    that the file is only imported once.

    :param infile: nmap XML-file to import
    :return:
    """
    print colored("[*] Importing file: {0}".format(infile), 'green')
    try:
        report = NmapParser.parse_fromfile(infile) # read and parse the nmap XML file
        # calculate a SHA-512 hash. This is used to ensure that the file will not be imported more than once.
        sha512 = hash_file(infile)
    except Exception as e:
        # Invalid file format
        print colored("[-] File cannot be imported : {0}".format(infile), 'red')

    try:
        # create the database entry for the scan.
        scan = Scan(file_hash=sha512, name=report.commandline, type='nmap', start=report.started, end=report.endtime,
                    elapsed=report.elapsed, hosts_total=report.hosts_total, hosts_up=report.hosts_up,
                    hosts_down=report.hosts_down)
        scan.save()
    except peewee.IntegrityError as e:
        # This error is throw when the SHA-512 hash is already present in the database. Therefore the file cannot be
        # imported again.
        print colored("[-] File already imported: {0}".format(infile), 'red')
        return

    # import all hosts and ports present in the report
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
    """
    Entry point for the console script nmap2scandb. This script allows to import either a single nmap XML-file or
    several nmap XML-files in a given directory.
    :return:
    """
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*", help="The nmap XML file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, help="Directory name with the nmap XML files to import")
    args = parser.parse_args()

    db = args.db
    filename = args.file
    dir = args.dir

    # initialize the database
    database = init_db(db)

    if filename is None and dir is None:
        # either a filename or a directoy must be specified
        parser.print_usage()
        return

    if filename is not None:
        # import a single nmap XML-file
        for file in filename:
            import_nmap_file(file)
    if dir is not None:
        # import several nmap XML-files within a directory
        for filename in os.listdir(dir):
            if not filename.endswith('.xml'): continue
            fullname = os.path.join(dir, filename)
            import_nmap_file(fullname)

    database.close()
