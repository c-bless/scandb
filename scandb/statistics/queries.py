
import sqlite3

from scandb.models.report import ReportScanStat
from scandb.models.report import ReportVulnStat
from scandb.models.report import ReportPortStat
from scandb.models.report import ReportHostPortStat


def execute_query(db, query):
    conn = sqlite3.connect(db)
    cur = conn.cursor()
    cur.execute(query)
    rows = cur.fetchall()
    conn.close()
    return rows


def get_scan_stats(db):
    """
    This function creates a list with statistics for each scan that has been imported by scandb-importer.

    :param db: sqlite database created by scandb-importer
    :return: list of scandb.report.models.ReportScanStat objects
    """
    sql = "SELECT id,start,end,elapsed,hosts_total,hosts_up,hosts_down,name FROM scan"
    rows = execute_query(db, sql)
    result = []
    for r in rows:
        id , start, end, elapsed, total, up, down, name = r
        # on Nessus scans hosts up and hosts down are 'None'
        # convert numbers and None to strings to ensure that they don't case exceptions when used in format() or join()
        id = str(id); up = str(up); down = str(down); total = str(total)
        stat = ReportScanStat(id=id, start=start, end=end, elapsed=elapsed, hosts_total=total, hosts_up=up,
                              hosts_down=down, name=name)
        result.append(stat)
    return result


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
    rows = execute_query(db, sql)
    result = []
    for r in rows:
        address, c, h, m, l, i = (r)
        # convert counter values to strings to ensure that they don't case exceptions when used in format() or join()
        c = str(c); h = str(h); m = str(m); l = str(l); i = str(i)
        stat = ReportVulnStat(address=address, critical=c, high=h, medium=m, low=l, info=i)
        result.append(stat)
    return result


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
    rows = execute_query(db, sql)
    result = []
    for r in rows:
        address, tcp, udp = (r)
        # convert counter values to strings to ensure that they don't case exceptions when used in format() or join()
        tcp = str(tcp); udp = str(udp)
        stat = ReportPortStat(address=address, tcp=tcp, udp=udp)
        result.append(stat)
    return result


def get_host_port_list(db):
    sql = """
        select address , group_concat(distinct port), protocol from port where protocol = 'tcp' and status='open' group by address
        union
        select address , group_concat(distinct port), protocol from port where protocol = 'udp' and status='open' group by address;"""
    rows = execute_query(db, sql)
    result = []
    for r in rows:
        address, ports, protocol = r
        stat = ReportHostPortStat(address=address, ports=ports, protocol=protocol)
        result.append(stat)
    return result