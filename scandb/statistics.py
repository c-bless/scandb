import argparse
import sqlite3


def get_scan_stats(db):
    """
    This function creates a list with statistics for each scan that has been imported by scandb-importer.

    :param db: sqlite database created by scandb-importer
    :return: list with statistics for each scan
    """
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT id,start,end,elapsed,hosts_total,hosts_up,hosts_down,name FROM scan")
    rows = cur.fetchall()
    conn.close()
    return rows


def handle_scan_stats(db, outfile, write_file = False, delimeter= ";"):
    results_csv = []
    results_cli = []
    fmt = '{0:^10}{1:^15}{2:^15}{3:^12}{4:^12}{5:^12}{6:^15}{7}'
    results_cli.append(fmt.format("scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down",
                                  "Parameters"))
    results_csv.append(delimeter.join(["scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down",
                                      "Parameters"]))

    stats = get_scan_stats(db)
    for s in stats:
        id, start, end, elapsed, total, up, down, params = (s)
        # on Nessus scans hosts up and hosts down are 'None'
        # convert numbers and None to strings to ensure that they don't case exceptions when used in format() or join()
        id = str(id); up = str(up); down = str(down); total = str(total)
        results_cli.append(fmt.format(id, start, end, elapsed, total, up, down, params))
        results_csv.append(delimeter.join([id, start, end, elapsed, total, up, down, params]))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-scan-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))


def get_vuln_stats(db):
    """
    This function creates a list with a number of vulnerabilities per host and severity. The static is created across
    all imported Nessus scans but each Nessus Plugin-ID is only counted once per host.

    :param db: sqlite database created by scandb-importer
    :return: list with number of vulnerabilities per host
    """
    sql = "SELECT address,\
    COUNT(CASE WHEN severity = 4 THEN 1 END) as CRITICAL, \
    COUNT(CASE WHEN severity = 3 THEN 1 END) as HIGH,\
    COUNT(CASE WHEN severity = 2 THEN 1 END) as MEDIUM,\
    COUNT(CASE WHEN severity = 1 THEN 1 END) as LOW,\
    COUNT(CASE WHEN severity = 0 THEN 1 END) as INFO\
    from \
    ( select distinct address, plugin, severity   from host h left join vuln v on h.id = v.host_id )\
    GROUP by address\
    order by CRITICAL DESC, HIGH DESC, MEDIUM DESC, LOW DESC, INFO DESC;"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows


def handle_vuln_stats(db, outfile, write_file = False, delimeter=";"):
    results_csv = []
    results_cli = []
    fmt = '{0:>20}{1:>15}{2:>15}{3:>15}{4:>15}{5:>15}'
    results_cli.append(fmt.format("Address", "Critical", "High", "Medium", "Low", "Info"))
    results_csv.append(delimeter.join(["Address", "Critical", "High", "Medium", "Low", "Info"]))

    stats = get_vuln_stats(db)

    for s in stats:
        address, c, h, m, l, i = (s)
        # convert counter values to strings to ensure that they don't case exceptions when used in format() or join()
        c = str(c); h = str(h); m = str(m); l = str(l); i = str(i)
        results_cli.append(fmt.format(address, c, h, m, l, i))
        results_csv.append(delimeter.join([address, c, h, m, l, i]))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-vuln-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))


def get_port_stats(db):
    """
    This function creates a list with a number of open TCP- and UDP-Ports per host. The static is created across
    all imported Nmap scans (only ports with status 'open' are counted).

    :param db: sqlite database created by scandb-importer
    :return: list with number of TCP- and UDP-Ports per host
    """
    sql = "select address,\
    COUNT(CASE WHEN protocol = 'tcp' THEN 1 END) as TCP,\
    COUNT(CASE WHEN protocol = 'udp' THEN 1 END) as UDP\
    from (select DISTINCT address, port, protocol from port where status = 'open')\
    GROUP by address"
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(sql)
    rows = cur.fetchall()
    conn.close()
    return rows


def handle_port_stats(db, outfile, write_file = False, delimeter=";"):
    results_csv = []
    results_cli = []
    fmt = '{0:>20}{1:>15}{2:>15}'
    results_cli.append(fmt.format("Address", "TCP", "UDP"))
    results_csv.append(delimeter.join(["Address", "TCP", "UDP"]))

    stats = get_port_stats(db)
    for s in stats:
        address, tcp, udp = (s)
        # convert counter values to strings to ensure that they don't case exceptions when used in format() or join()
        tcp = str(tcp); udp = str(udp)
        results_cli.append(fmt.format(address, tcp, udp))
        results_csv.append(delimeter.join([address, tcp, udp]))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-port-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))


host_port_list = """
    select address , group_concat(distinct port), protocol from port where protocol = 'tcp' and status='open' group by address
    union
    select address , group_concat(distinct port), protocol from port where protocol = 'udp' and status='open' group by address;"""


def gen_host_port_list(db,outfile):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(host_port_list)
    rows = cur.fetchall()
    filename = "{0}-hostportlist.csv".format(outfile)
    with open(filename,'w') as f:
        for r in rows:
            f.write(";".join(r))
            f.write("\n")
    print ("Results written to : {0}".format(filename))
    conn.close()


def statistics_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("-s", "--scan-statistics", required=False, action='store_true', default=False,
                        help="Print statistics for each scan")
    parser.add_argument("-v", "--vuln-statistics", required=False, action='store_true', default=False,
                        help="Print number of vulns foreach host.")
    parser.add_argument("-p", "--port-statistics", required=False, action='store_true', default=False,
                        help="Print number of 'open' TCP and UDP ports foreach host.")
    parser.add_argument("--host-portlist", required=False, action='store_true', default=False,
                        help="generate a csv with a list of TCP and UDP Ports per host")
    parser.add_argument("-d", "--delimeter", required=False, type=str,  default=";", help="Delimeter for CSV files.")
    parser.add_argument("-o", "--outfile", required=False, default="scandb", help="Prefix for output files.")
    parser.add_argument("-w", "--write-file", required=False, action='store_true', default=False,
                        help="Write data to CSV file. Prefix of filename can be changed with parameter outfile")

    args = parser.parse_args()

    do_stats = False
    if args.scan_statistics or args.vuln_statistics or args.port_statistics:
        do_stats = True

    if not do_stats and not args.host_portlist:
        parser.print_usage()
        return

    if args.scan_statistics:
        handle_scan_stats(args.db, args.outfile, args.write_file, args.delimeter)

    if args.vuln_statistics:
        handle_vuln_stats(args.db, args.outfile, args.write_file, args.delimeter)

    if args.port_statistics:
        handle_port_stats(args.db, args.outfile, args.write_file, args.delimeter)

    if args.host_portlist:
        gen_host_port_list(args.db, args.outfile)