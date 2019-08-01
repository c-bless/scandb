import argparse
import sqlite3
import os


host_port_list = """
    select address , group_concat(distinct port), protocol from port where protocol = 'tcp' and status='open' group by address
    union
    select address , group_concat(distinct port), protocol from port where protocol = 'udp' and status='open' group by address;"""


def gen_host_port_list(db,outfile):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(host_port_list)
    rows = cur.fetchall()
    with open(outfile,'w') as f:
        for r in rows:
            f.write(";".join(r))
            f.write("\n")
    conn.close()


def gen_host_list(db, status, delimiter):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT distinct address FROM host WHERE status like ? ;", (status,))
    rows = cur.fetchall()
    ips = [ x[0] for x in rows]
    conn.close()
    return ips


def scandb2hostlist():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--status", type=str, required=False, default="up",
                        help="Status string stored in database (default: up)")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output")
    args = parser.parse_args()

    gen_host_list(args.db, args.status, args.list_delimiter)


def scandb2hostportlist():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("-o","--outfile", metavar="FILE", required=False, type=str, default="hostportlist.csv",
                        help="")

    args = parser.parse_args()

    gen_host_port_list(args.db, args.outfile)
    print("Results written to : {0}".format(args.outfile))
