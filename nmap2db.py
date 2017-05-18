#!/usr/bin/env python

import os
import sqlite3
from libnmap.parser import NmapParser
from termcolor import colored


create_db = """

CREATE TABLE IF NOT EXISTS scan (
    id INTEGER PRIMARY KEY,
    commandline TEXT,
    hosts_total INTEGER,
    hosts_up INTEGER,
    hosts_down INTEGER
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    address TEXT,
    hostname TEXT,
    os TEXT,
    status TEXT,
    scan_id INTEGER
);

CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY,
    address TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    banner TEXT,
    status TEXT,
    scan_id INTEGER
);

CREATE TABLE IF NOT EXISTS port_list (
    id INTEGER PRIMARY KEY,
    address TEXT,
    tcp TEXT,
    udp TEXT,
    scan_id INTEGER
);
"""


def get_open_ports(host, protocol='tcp'):
    ports = []
    for port, proto in host.get_open_ports():
        if protocol == proto:
            ports.append(port)
    return ports


def get_ports(host):
    """
    This function generates a list of open ports. Each entry is a tuple which contains the port, protocol, servicename,
    state and a banner string.

    :param host: The NmapHost object
    :type host libnmap.objects.host.NmapHost

    :return: list of tuples
    """
    ports = []
    for port, proto in host.get_ports():
        if host.get_service(port, proto) is not None:
            service = host.get_service(port, proto)
            servicename = service.service
            state = service.state
            banner = service.banner
            ports.append((port, proto, servicename, state, banner))
    return ports


def get_hostname(host):
    """
    This function get the hostname of the given host.

    :param host: The NmapHost object
    :type host: libnmap.objects.host.NmapHost

    :return: hostname
    :rtype: str
    """
    hostname = ""
    for name in host.hostnames:
        if name == "localhost" and hostname != "":
            continue
        hostname = name
    return hostname


def get_best_os_match(host):
    os_matches = host.os_match_probabilities()
    os = ""
    if len(os_matches) > 0:
        os = os_matches[0].name
    return os


def host_to_tupel(host):
    hostname = get_hostname(host)
    os = get_best_os_match(host)
    return host.address, hostname, os, host.status


def insert(conn, host, scan_id=-1):
    cursor = conn.cursor()

    insert_host_cmd = "INSERT INTO hosts (address, hostname, os, status, scan_id) VALUES (?,?,?,?,?);"
    address, hostname, os, status = host_to_tupel(host)
    values = address, hostname, os, status, scan_id
    cursor.execute(insert_host_cmd, values)

    insert_port_cmd = "INSERT INTO ports (address, port, protocol, service, banner, status,scan_id) VALUES " \
                      "(?,?,?,?,?,?,?);"
    ports = get_ports(host)
    for port, proto, servicename, state, banner in ports:
        port_values = (host.address, port, proto, servicename, state, banner,scan_id)
        cursor.execute(insert_port_cmd, port_values)

    insert_port_list_cmd = "INSERT INTO port_list (address, tcp, udp,scan_id) VALUES (?,?,?,?);"
    tcp_ports = get_open_ports(host, protocol="tcp")
    udp_ports = get_open_ports(host, protocol="udp")

    tcp = ",".join(str(x) for x in tcp_ports)
    udp = ",".join(str(x) for x in udp_ports)
    if len(tcp) > 0 or len(udp) > 0:
        cursor.execute(insert_port_list_cmd, (host.address, tcp, udp,scan_id))



def import_file(db, infile):
    conn = sqlite3.connect(db)
    cursor = conn.cursor()
    cursor.executescript(create_db)

    print colored("Importing file: {0}".format(infile), 'green')
    try:
        report = NmapParser.parse_fromfile(infile)
        report_cmd = "INSERT INTO scan (commandline, hosts_total, hosts_up, hosts_down) VALUES (?,?,?,?);"
        report_values = (report.commandline, report.hosts_total, report.hosts_up, report.hosts_down)
        cursor.execute(report_cmd, report_values)
        scan_id = cursor.lastrowid
        for host in report.hosts:
            print colored("importing host: {0}".format(host.address), 'blue')
            insert(conn, host, scan_id=scan_id)
            conn.commit()
    except Exception as e:
        print colored(e.message, 'red')

    conn.close()


def main(db, files, dir):
    if files is not None:
        for file in files:
            import_file(db, file)
    if dir is not None:
        for filename in os.listdir(dir):
            if not filename.endswith('.xml'): continue
            fullname = os.path.join(dir, filename)
            import_file(db, fullname)

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="nmap.sqlite")
    parser.add_argument("--file", metavar="FILE", type=str, default=None, nargs="*", help="The nmap XML file(s)")
    parser.add_argument("--dir", metavar="DIR", type=str, help="Directory name with the nmap XML files to import")
    args = parser.parse_args()

    main(args.db, args.file, args.dir)


