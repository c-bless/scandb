import argparse
import sqlite3


def get_stats(db):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT id,start,end,elapsed,hosts_total,hosts_up,hosts_down,name FROM scan")
    rows = cur.fetchall()
    conn.close()
    return rows


def get_host_list(db, status):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT distinct address FROM host WHERE status like ? ;", (status,))
    rows = cur.fetchall()
    ips = [ x[0] for x in rows]
    conn.close()
    return ips


def get_host_list_by_both(db, tcp, udp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port WHERE port in ({seq_tcp}) and protocol = 'tcp' " \
          "or port in ({seq_udp})  and protocol ='udp'".format(
            seq_tcp=','.join(['?'] * len(tcp)),
            seq_udp=','.join(['?'] * len(udp)))
    cur.execute(sql, (tcp,udp,))
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def get_host_list_by_udp(db, udp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port where port in ({seq_tcp}) and protocol = 'udp'".format(
            seq_tcp=','.join(['?'] * len(udp)))
    cur.execute(sql, udp)
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def get_host_list_by_tcp(db, tcp):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    sql = "SELECT distinct address FROM port where port in ({seq_tcp}) and protocol = 'tcp'".format(
        seq_tcp=','.join(['?'] * len(tcp)))
    cur.execute(sql, tcp)
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def analyzer():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--status", type=str, required=False, default="up",
                        help="Status string stored in database (default: up)")
    parser.add_argument("--statistics", required=False, action='store_true', default=False,
                        help="Print statistics for each scan")
    parser.add_argument("-t", "--tcp", metavar="PORTS", required=False, type=str, default=None,
                        help="TCP ports")
    parser.add_argument("-u", "--udp", metavar="PORTS", required=False, type=str, default=None,
                        help="UDP ports")
    parser.add_argument("-o", "--operation", metavar="UNION|INTERSECTION", required=False, type=str, default="UNION",
                        help="Operation to combine the sets of TCP and UDP ports (default: UNION)")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a target list")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the targets instead of printing them to stdout")
    args = parser.parse_args()

    do_stats = args.statistics
    do_list_gen = True

    if not args.list and args.list_file is None:
        do_list_gen = False

    if not do_stats and not do_list_gen:
        # either --statistics or one of the options --list or --list-file must be used
        parser.print_usage()
        return

    if args.statistics:
        stats = get_stats(args.db)
        fmt = '{0:>10}{1:>15}{2:>15}{3:>12}{4:>12}{5:>12}{6:>12}{7:50}'
        print(fmt.format("scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down", "Parameters"))
        for s in stats:
            id, start, end, elapsed, total, up, down, params = (s)
            print(fmt.format(id, start, end, elapsed, total, up, down, params))

    ips = []
    if args.tcp is None and args.udp is None:
        ips = get_host_list(args.db, args.status)
    else:
        tcp_ports = []
        udp_ports = []
        if args.tcp is not None:
            tcp_ports = get_host_list_by_tcp(args.db, args.tcp.split(","))
        if args.udp is not None:
            udp_ports = get_host_list_by_udp(args.db, args.udp.split(","))

        if args.operation.upper() == 'INTERSECTION':
            ips = set(tcp_ports).intersection(udp_ports)
        else:
            ips = set(tcp_ports).union(udp_ports)

    if args.list:
        print(args.list_delimiter.join(ips))

    if args.list_file:
        with open(args.list, 'w') as f:
            f.write("\n".join(ips))


