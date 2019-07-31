import argparse
import sqlite3


def get_stats(db):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT id,start,end,elapsed,hosts_total,hosts_up,hosts_down,name FROM scan")
    rows = cur.fetchall()
    conn.close()
    return rows


def gen_host_list(db, status):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT distinct address FROM host WHERE status like ? ;", (status,))
    rows = cur.fetchall()
    ips = [ x[0] for x in rows]
    conn.close()
    return ips


def analyzer():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--status", type=str, required=False, default="up",
                        help="Status string stored in database (default: up)")
    parser.add_argument("--statistics", required=False, action='store_true', default=False,
                        help="Print statistics for each scan")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a target list")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the targets instead of printing them to stdout")
    args = parser.parse_args()

    if args.statistics:
        stats = get_stats(args.db)
        fmt = '{0:>10}{1:>15}{2:>15}{3:>12}{4:>12}{5:>12}{6:>12}{7:50}'
        print (fmt.format("scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down", "Parameters"))
        for s in stats:
            id, start, end, elapsed, total, up, down, params = (s)
            print (fmt.format(id, start, end, elapsed, total, up, down, params))


    if args.list:
        ips = gen_host_list(args.db, args.status)
        print (args.list_delimiter.join(ips))

    if args.list_file:
        with open(args.list, 'w') as f:
            f.write("\n".join(gen_host_list(args.db, args.status)))


