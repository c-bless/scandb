
import sqlite3
from scandb.util import host_to_tupel, get_ports

create_db_script = """
CREATE TABLE IF NOT EXISTS scans (
    scanid INTEGER PRIMARY KEY,
    type TEXT,
    commandline TEXT,
    start INTEGER,
    end INTEGER,
    elapsed INTEGER,
    hosts_total INTEGER,
    hosts_up INTEGER,
    hosts_down INTEGER
);


CREATE TABLE IF NOT EXISTS hosts (
    hostid INTEGER PRIMARY KEY,
    address TEXT,
    hostname TEXT,
    os TEXT,
    os_gen TEXT,
    status TEXT,
    scan_id INTEGER,
        FOREIGN KEY (scan_id) REFERENCES scans(scanid)
);

CREATE TABLE IF NOT EXISTS ports (
    portid INTEGER PRIMARY KEY,
    hostid INTEGER,
    address TEXT,
    port INTEGER,
    protocol TEXT,
    service TEXT,
    banner TEXT,
    status TEXT,
    scan_id INTEGER,
        FOREIGN KEY (scan_id) REFERENCES scans(scanid)
);

CREATE TABLE IF NOT EXISTS vulns (
    vulnid INTEGER PRIMARY KEY,
	name TEXT
);
"""


def init_db(db_name):
    conn = sqlite3.connect(db_name)
    cursor = conn.cursor()
    cursor.executescript(create_db_script)
    return conn


def insert_nmap_scan(conn, report):
    cursor = conn.cursor()
    insert_scan_cmd = "INSERT INTO scans (commandline, type, start, end, elapsed, hosts_total, hosts_up, hosts_down" \
                      ") VALUES (?,?,?,?,?,?,?, ?);"
    report_values = (report.commandline, 'nmap', report.started, report.endtime, report.elapsed, report.hosts_total,
                     report.hosts_up, report.hosts_down)
    cursor.execute(insert_scan_cmd, report_values)
    scan_id = cursor.lastrowid
    return scan_id


def insert_nmap_host(conn, host, scan_id):
    cursor = conn.cursor()
    insert_host_cmd = "INSERT INTO hosts (address, hostname, os, status, scan_id) VALUES (?,?,?,?,?);"
    address, hostname, os, status = host_to_tupel(host)
    values = address, hostname, os, status, scan_id
    cursor.execute(insert_host_cmd, values)
    host_id = cursor.lastrowid

    insert_port_cmd = "INSERT INTO ports (hostid, address, port, protocol, service, banner, status,scan_id) VALUES " \
                      "(?,?,?,?,?,?,?,?);"
    ports = get_ports(host)
    for port, proto, servicename, state, banner in ports:
        port_values = (host_id, host.address, port, proto, servicename, banner, state, scan_id)
        cursor.execute(insert_port_cmd, port_values)

