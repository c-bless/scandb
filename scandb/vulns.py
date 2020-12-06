import argparse
import sqlite3

HOSTS_BY_CVE = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE xref like ? and severity >= ?;"
HOSTS_BY_VULN_DESC = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE description like ? and severity >= ?;"
HOSTS_BY_PID = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_id = ? and severity >= ?;"
HOSTS_BY_PNAME = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_name like ? and severity >= ?;"

HOSTS_DETAILS_BY_CVE = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name FROM vuln join host on vuln.host_id = host.id WHERE xref like ? and severity >= ?;"
HOSTS_DETAILS_BY_VULN_DESC = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name FROM vuln join host on vuln.host_id = host.id WHERE description like ? and severity >= ?;"
HOSTS_DETAILS_BY_PID = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name FROM vuln join host on vuln.host_id = host.id WHERE plugin_id like ? and severity >= ?;"
HOSTS_DETAILS_BY_PNAME = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name FROM vuln join host on vuln.host_id = host.id WHERE plugin_name like ? and severity >= ?;"

def get_ips_by_filter(db, query="", search = "", min_severity=0):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query, (search,min_severity,))
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def get_details_by_filter(db, query="", search = "", min_severity=0):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query, (search,min_severity,))
    rows = cur.fetchall()
    conn.close()
    return rows

def vulns_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--min-severity", type=int, required=False, default=0,
                        help="Minimum severity level (default: 0)")
    parser.add_argument("--filter-by", required=False, choices=['cve', 'plugin-id', 'plugin-name', 'description'],
                        default='description', help="Filter hosts by the given filter. The search value is specified with option --search. The following fields can be used as filter 'cve', 'plugin-id', 'plugin-name', 'description")
    parser.add_argument("--search", metavar="SEARCH-Term", required=True, type=str,
                        help="Search term used for querying the database. The type of the search field can be selected "
                             "with the parameter --filter-by")
    parser.add_argument("--list", required=True, choices=['ips', 'details'], default='ips',
                        help="Generate a target list of ip addresses when selecting 'ips' or display the columns"
                             "Address,Port,Protocol,Severity,Plugin-ID,Plugin-Name")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output. Only when --list ips is used.")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the targets instead of printing them to stdout")
    args = parser.parse_args()

    if not args.list and args.list_file is None and args.details:
        parser.print_usage()
        return

    ips = []
    details = []

    if args.list == 'ips':
        if args.filter_by == "cve":
            cve = "%{0}%".format(args.search)
            ips = get_ips_by_filter(args.db, HOSTS_BY_CVE, cve, args.min_severity)

        if args.filter_by == "plugin-id":
            ips = get_ips_by_filter(args.db, HOSTS_BY_PID, args.search, args.min_severity)

        if args.filter_by == "plugin-name":
            pn = "%{0}%".format(args.search)
            ips = get_ips_by_filter(args.db, HOSTS_BY_PNAME, pn, args.min_severity)

        if args.filter_by == "description":
            desc = "%{0}%".format(args.search)
            ips = get_ips_by_filter(args.db, HOSTS_BY_VULN_DESC, desc, args.min_severity)

        print(args.list_delimiter.join(ips))

    if args.list == 'details':
        if args.filter_by == "cve":
            cve = "%{0}%".format(args.search)
            details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_CVE, cve, args.min_severity)
        if args.filter_by == "plugin-id":
            details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_PID, args.search, args.min_severity)
        if args.filter_by == "plugin-name":
            pn = "%{0}%".format(args.search)
            details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_PNAME, pn, args.min_severity)
        if args.filter_by == "description":
            desc = "%{0}%".format(args.search)
            details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_VULN_DESC, desc, args.min_severity)

        fmt = '{0:>20}{1:>15}{2:>15}{3:>15}{4:>15}{5}'
        print(fmt.format("Address","Port","Protocol","Severity","Plugin-ID","Plugin-Name"))
        for i in details:
            addr, port,proto,severity, pid, pn = i
            print(fmt.format(addr, port,proto,severity, pid, pn))
        
    if args.list_file:
        with open(args.list_file, 'w') as f:
            f.write("\n".join(ips))


