import argparse
import sqlite3

from scandb.statistics.queries import get_vuln_stats
from scandb.statistics.queries import get_port_stats

SQL_ADDR_FROM_HOSTS = "SELECT distinct address from host where status = 'up'"

host_port_list = """
    select address , group_concat(distinct port || '(' || service || ')'), protocol from port where protocol = 'tcp' and status='open' group by address
    union
    select address , group_concat(distinct port || '(' || service || ')'), protocol from port where protocol = 'udp' and status='open' group by address;"""



def run_query(db, query):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows


def handle_vuln_stats(db1, db2, outfile="scandb"):

    result = {}
    addresses_db1 = [x[0] for x in run_query(db1, SQL_ADDR_FROM_HOSTS)]
    addresses_db2 = [x[0] for x in run_query(db2, SQL_ADDR_FROM_HOSTS)]
    addresses = set(addresses_db1).union(addresses_db2)

    # prepare a dictionary with all ip addresses that exist in one of the databases
    for ip in addresses:
        result[ip] = {'db1': {'critical': '-', 'high': '-', 'medium': '-', 'low': '-', 'info': '-'},
                      'db2': {'critical': '-', 'high': '-', 'medium': '-', 'low': '-', 'info': '-'}}

    stats_db1 = get_vuln_stats(db1)
    for s in stats_db1:
        ip , c, h, m, l, i = s
        result[ip]['db1']['critical'] = c
        result[ip]['db1']['high'] = h
        result[ip]['db1']['medium'] = m
        result[ip]['db1']['low'] = l
        result[ip]['db1']['info'] = i

    stats_db2 = get_vuln_stats(db2)
    for s in stats_db2:
        ip, c, h, m, l, i = s
        result[ip]['db2']['critical'] = c
        result[ip]['db2']['high'] = h
        result[ip]['db2']['medium'] = m
        result[ip]['db2']['low'] = l
        result[ip]['db2']['info'] = i

    outstr = ['Address;Critical-DB1;HIGH-DB1;MEDIUM-DB1;LOW-DB1;INFO-DB1;Critical-DB2;HIGH-DB2;MEDIUM-DB2;LOW-DB2;INFO-DB2']
    fmt = "{0};{1};{2};{3};{4};{5};{6};{7};{8};{9};{10}"
    for ip in result:
        c1 = result[ip]['db1']['critical']
        h1 = result[ip]['db1']['high']
        m1 = result[ip]['db1']['medium']
        l1 = result[ip]['db1']['low']
        i1 = result[ip]['db1']['info']
        c2 = result[ip]['db2']['critical']
        h2 = result[ip]['db2']['high']
        m2 = result[ip]['db2']['medium']
        l2 = result[ip]['db2']['low']
        i2 = result[ip]['db2']['info']
        outstr.append (fmt.format(ip, c1, h1, m1, l1, i1, c2, h2, m2, l2, i2) )

    filename = "{0}-vulns-db1-db2.csv".format(outfile)
    with open(filename, "w") as f:
        f.write("\n".join(outstr))
    print(" Result written to file: {0}".format(filename))


def handle_service_stats(db1, db2, outfile="scandb"):

    result = {}
    addresses_db1 = [ x[0] for x in run_query(db1, SQL_ADDR_FROM_HOSTS)]
    addresses_db2 = [ x[0] for x in run_query(db2, SQL_ADDR_FROM_HOSTS)]
    addresses = set(addresses_db1).union(addresses_db2)

    # prepare a dictionary with all ip addresses that exist in one of the databases
    for ip in addresses:
        result[ip] = {'db1': {'tcp': '-', 'udp': '-'}, 'db2': {'tcp': '-', 'udp': '-'}}

    stats_db1 = run_query(db1, host_port_list)
    for i in stats_db1:
        ip , ports, proto = i
        if proto == 'tcp':
            result[ip]['db1']['tcp'] = ports
        elif proto == 'udp':
            result[ip]['db1']['udp'] = ports

    stats_db2 = run_query(db2, host_port_list)
    for i in stats_db2:
        ip, ports, proto = i
        if proto == 'tcp':
            result[ip]['db2']['tcp'] = ports
        elif proto == 'udp':
            result[ip]['db2']['udp'] = ports

    outstr = ['Address;tcp-db1;udp-db1;tcp-db2;udp-db2']
    fmt = "{0};{1};{2};{3};{4}"
    for ip in result:
        t1 = result[ip]['db1']['tcp']
        u1 = result[ip]['db1']['udp']
        t2 = result[ip]['db2']['tcp']
        u2 = result[ip]['db2']['udp']
        outstr.append(fmt.format(ip, t1, u1, t2, u2,))

    filename = "{0}-services-db1-db2.csv".format(outfile)
    with open(filename, "w") as f:
        f.write("\n".join(outstr))
    print(" Result written to file: {0}".format(filename))


def handle_port_stats(db1, db2, outfile="scandb"):

    result = {}
    addresses_db1 = [ x[0] for x in run_query(db1, SQL_ADDR_FROM_HOSTS)]
    addresses_db2 = [ x[0] for x in run_query(db2, SQL_ADDR_FROM_HOSTS)]
    addresses = set(addresses_db1).union(addresses_db2)

    # prepare a dictionary with all ip addresses that exist in one of the databases
    for ip in addresses:
        result[ip] = {'db1': {'tcp': 0 , 'udp': 0},
                      'db2': {'tcp': 0, 'udp': 0}}

    stats_db1 = get_port_stats(db1)
    for i in stats_db1:
        ip , tcp, udp = i
        result[ip]['db1']['tcp'] = tcp
        result[ip]['db1']['udp'] = udp

    stats_db2 = get_port_stats(db2)
    for i in stats_db2:
        ip, tcp, udp = i
        result[ip]['db2']['tcp'] = tcp
        result[ip]['db2']['udp'] = udp

    outstr = ['Address;tcp-db1;udp-db1;tcp-db2;udp-db2']
    fmt = "{0};{1};{2};{3};{4}"
    for ip in result:
        t1 = result[ip]['db1']['tcp']
        u1 = result[ip]['db1']['udp']
        t2 = result[ip]['db2']['tcp']
        u2 = result[ip]['db2']['udp']
        outstr.append(fmt.format(ip, t1, u1, t2, u2, ))

    filename = "{0}-port-statistics-db1-db2.csv".format(outfile)
    with open(filename, "w") as f:
        f.write("\n".join(outstr))
    print(" Result written to file: {0}".format(filename))


def compare_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db1", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--db2", type=str, required=False, default="scandb-old.sqlite")
    parser.add_argument("-v", "--vuln-statistics", required=False, action='store_true', default=False,
                        help="Print number of vulns foreach host and db.")
    parser.add_argument("-p", "--port-statistics", required=False, action='store_true', default=False,
                        help="Print number of 'open' TCP and UDP ports foreach host and db.")
    parser.add_argument("--host-portlist", required=False, action='store_true', default=False,
                        help="generate a csv with a list of TCP and UDP Ports per host and db")
    parser.add_argument("-o", "--outfile", required=False, default="scandb", help="Prefix for output files.")
    args = parser.parse_args()

    if args.vuln_statistics:
        handle_vuln_stats(args.db1, args.db2, args.outfile)

    if args.port_statistics:
        handle_port_stats(args.db1, args.db2, args.outfile)

    if args.host_portlist:
        handle_service_stats(args.db1, args.db2, args.outfile)