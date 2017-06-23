from libnmap.parser import NmapParser
from termcolor import colored
from scandb.db import init_db, insert_nmap_scan, insert_nmap_host


def import_nmap_file(db, infile):
    conn = init_db(db)

    print colored("Importing file: {0}".format(infile), 'green')
    try:
        report = NmapParser.parse_fromfile(infile)
    except Exception as e:
        print colored(e.message, 'red')

    scan_id = insert_nmap_scan(conn, report)

    for host in report.hosts:
        print colored("importing host: {0}".format(host.address), 'blue')
        insert_nmap_host(conn, host, scan_id=scan_id)
        conn.commit()

    conn.close()




