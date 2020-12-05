import argparse
import sqlite3

def get_vulns_by_cve(db, cve=""):
    cve = "%{0}%".format(cve)
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute("SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE xref like ? ;", (cve,))
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips

def vulns_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--min-severity", type=int, required=False, default=0,
                        help="Minimum severity level (default: 0)")
    parser.add_argument("--cve", metavar="CVE", required=False, type=str, default=None,
                        help="Filter hosts affected by an specific CVE Number")
    parser.add_argument("--plugin", metavar="PLUGIN-ID", required=False, type=str, default=None,
                        help="Filter hosts where a specific Nessus Plugin ")
    parser.add_argument("--description", metavar="TEXT", required=False, type=str, default=None,
                        help="Filter hosts affected by a vulnerability, where the given substring is part of the Nessus description")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a target list")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the targets instead of printing them to stdout")
    args = parser.parse_args()

    if not args.list and args.list_file is None:
        parser.print_usage()
        return

    ips = []

    if args.cve:
        ips = get_vulns_by_cve(args.db, args.cve)

    if args.list:
        print(args.list_delimiter.join(ips))

    if args.list_file:
        with open(args.list_file, 'w') as f:
            f.write("\n".join(ips))


