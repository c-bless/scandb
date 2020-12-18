import argparse
import os
import peewee
from libnmap.parser import NmapParser
from termcolor import colored

from scandb.importer.util import hash_file
from scandb.importer.util import host_to_tupel, get_ports
from scandb.models.db import Scan, Host, Port, init_db


def import_nmap_file(infile):
    """
    This function is responsible for importing the given file.  For each file a SHA-512 hash is calculated to ensure
    that the file is only imported once.

    :param infile: nmap XML-file to import
    :return:
    """
    sha512 = ""
    print(colored("[*] Importing file: {0}".format(infile), 'green'))
    try:
        report = NmapParser.parse_fromfile(infile) # read and parse the nmap XML file
        # calculate a SHA-512 hash. This is used to ensure that the file will not be imported more than once.
        sha512 = hash_file(infile)

        # create the database entry for the scan.
        scan = Scan(file_hash=sha512, name=report.commandline, type='nmap', start=report.started, end=report.endtime,
                    elapsed=report.elapsed, hosts_total=report.hosts_total, hosts_up=report.hosts_up,
                    hosts_down=report.hosts_down)
        scan.save()
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

        print(colored("[*] File imported. ",'green'))

    except peewee.IntegrityError as e:
        # This error is throw when the SHA-512 hash is already present in the database. Therefore the file cannot be
        # imported again.
        print(colored("[-] File already imported: {0}".format(infile), 'red'))
    except Exception as e:
        # Invalid file format
        print(colored("[-] File cannot be imported : {0}".format(infile), 'red'))

