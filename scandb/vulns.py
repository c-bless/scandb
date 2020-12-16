import argparse
import sqlite3
import json

HOSTS_BY_SEVERITY = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE severity >= ?;"
HOSTS_BY_CVE = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE xref like ? and severity >= ?;"
HOSTS_BY_VULN_DESC = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE description like ? and severity >= ?;"
HOSTS_BY_PID = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_id = ? and severity >= ?;"
HOSTS_BY_PNAME = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_name like ? and severity >= ?;"
HOSTS_BY_POUTPUT = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_output like ? and severity >= ?;"
HOSTS_BY_IP = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE address like ? and severity >= ?;"

HOSTS_DETAILS_BY_SEVERITY = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE severity >= ?;"
HOSTS_DETAILS_BY_CVE = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE xref like ? and severity >= ?;"
HOSTS_DETAILS_BY_VULN_DESC = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE description like ? and severity >= ?;"
HOSTS_DETAILS_BY_PID = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE plugin_id like ? and severity >= ?;"
HOSTS_DETAILS_BY_PNAME = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE plugin_name like ? and severity >= ?;"
HOSTS_DETAILS_BY_POUTPUT = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE plugin_output like ? and severity >= ?;"
HOSTS_DETAILS_BY_IP = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE address like ? and severity >= ?;"

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


def get_ips_by_severity(db, min_severity=0):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(HOSTS_BY_SEVERITY, (min_severity,))
    rows = cur.fetchall()
    ips = [x[0] for x in rows]
    conn.close()
    return ips


def get_details_by_severity(db, min_severity=0):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(HOSTS_DETAILS_BY_SEVERITY, (min_severity,))
    rows = cur.fetchall()
    conn.close()
    return rows


def vulns_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--min-severity", type=int, required=False, default=0,
                        help="Minimum severity level (default: 0)")
    parser.add_argument("--filter-by", required=False, choices=['cve', 'plugin-id', 'plugin-name', 'plugin-output',
                                                                'description', 'ip'],
                        default='description', help="Filter hosts by the given filter. The search value is specified "
                                                    "with option --search. The following fields can be used as filter "
                                                    "'cve', 'plugin-id', 'plugin-name', 'description', 'ip'. (Note: "
                                                    "The option 'ip' returns just the ip itself, when '--list ips' "
                                                    "is selected and a vulnerability was detected for that ip, "
                                                    "otherwise the result is empty.) ")
    parser.add_argument("--search", metavar="SEARCH-Term", required=False, type=str, default=None,
                        help="Search term used for querying the database. The type of the search field can be selected "
                             "with the parameter --filter-by")
    parser.add_argument("--list", required=False, choices=['ips', 'details'], default='ips',
                        help="Generate a target list of ip addresses when selecting 'ips' or display the columns "
                             "Address,Port,Protocol,Severity,Plugin-ID,Plugin-Name")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output. Only when --list ips is used.")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the results instead of printing them to stdout. Incase of "
                             "'--list ips' is selected the file contains a list of ip address (one per line), "
                             "in case of '--list details' it will be a csv file")
    args = parser.parse_args()

    if not args.list and args.list_file is None:
        parser.print_usage()
        return

    ips = []
    details = []

    if args.list == 'ips':

        if args.search is not None:
            if args.filter_by == "cve":
                cve = "%{0}%".format(args.search)
                ips = get_ips_by_filter(args.db, HOSTS_BY_CVE, cve, args.min_severity)

            elif args.filter_by == "plugin-id":
                ips = get_ips_by_filter(args.db, HOSTS_BY_PID, args.search, args.min_severity)

            elif args.filter_by == "plugin-name":
                pn = "%{0}%".format(args.search)
                ips = get_ips_by_filter(args.db, HOSTS_BY_PNAME, pn, args.min_severity)

            elif args.filter_by == "description":
                desc = "%{0}%".format(args.search)
                ips = get_ips_by_filter(args.db, HOSTS_BY_VULN_DESC, desc, args.min_severity)

            elif args.filter_by == "plugin-output":
                po = "%{0}%".format(args.search)
                ips = get_ips_by_filter(args.db, HOSTS_BY_POUTPUT, po, args.min_severity)

            elif args.filter_by == "ip":
                ip = "%{0}%".format(args.search)
                ips = get_ips_by_filter(args.db, HOSTS_BY_IP, ip, args.min_severity)
        else:
            ips = get_ips_by_severity(args.db, args.min_severity)

        print(args.list_delimiter.join(ips))

    if args.list == 'details':
        if args.search is not None:
            if args.filter_by == "cve":
                cve = "%{0}%".format(args.search)
                details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_CVE, cve, args.min_severity)
            elif args.filter_by == "plugin-id":
                details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_PID, args.search, args.min_severity)
            elif args.filter_by == "plugin-name":
                pn = "%{0}%".format(args.search)
                details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_PNAME, pn, args.min_severity)
            elif args.filter_by == "description":
                desc = "%{0}%".format(args.search)
                details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_VULN_DESC, desc, args.min_severity)
            elif args.filter_by == "plugin-output":
                po = "%{0}%".format(args.search)
                details =  get_details_by_filter(args.db, HOSTS_DETAILS_BY_POUTPUT, po, args.min_severity)
            elif args.filter_by == "ip":
                ip = "%{0}%".format(args.search)
                details = get_details_by_filter(args.db, HOSTS_DETAILS_BY_IP, ip, args.min_severity)
        else:
            details = get_details_by_severity(args.db, args.min_severity)

        fmt = '{0:>20}{1:>15}{2:>15}{3:>15}{4:>15}{5}'
        print(fmt.format("Address","Port","Protocol","Severity","Plugin-ID","Plugin-Name"))
        for i in details:
            addr, port,proto,severity, pid, pn, description, solution, info, xref = i
            print(fmt.format(addr, port,proto,severity, pid, pn))
        
    if args.list_file:
        if args.list == "ips":
            with open(args.list_file, 'w') as f:
                f.write("\n".join(ips))
        if args.list == "details":
            result = ["Address;Port;Protocol;Severity;Plugin-ID;Plugin-Name;CVE"]
            fmt = '{0};{1};{2};{3};{4};{5};{6}'
            for i in details:
                addr, port, proto, severity, pid, pn, description, solution, info, xref = i
                tmp = json.loads(xref.replace("'","\""))
                cve = ""
                if 'cve' in tmp:
                    cve = ",".join(tmp['cve'])
                result.append(fmt.format(addr, port, proto, severity, pid, pn, cve))
            with open (args.list_file , "w") as f:
                f.write("\n".join(result))

