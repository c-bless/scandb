import sqlite3

from scandb.models.db import Vuln, Host
from scandb.report.util import db2ReportVuln

HOSTS_BY_SEVERITY = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE severity >= ?;"
HOSTS_BY_CVE = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE xref like ? and severity >= ?;"
HOSTS_BY_VULN_DESC = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE description like ? and severity >= ?;"
HOSTS_BY_PID = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_id = ? and severity >= ?;"
HOSTS_BY_PNAME = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_name like ? and severity >= ?;"
HOSTS_BY_POUTPUT = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE plugin_output like ? and severity >= ?;"
HOSTS_BY_IP = "SELECT distinct address FROM vuln join host on vuln.host_id = host.id WHERE address like ? and severity >= ?;"

HOSTS_DETAILS_BY_SEVERITY = "SELECT distinct address,port,protocol,severity,plugin_id,plugin_name, description, solution, info, xref FROM vuln join host on vuln.host_id = host.id WHERE severity >= ?;"
#HOSTS_DETAILS_BY_SEVERITY = "SELECT distinct address,port,protocol,severity, service, plugin_id, plugin_name, description, synopsis, solution, info, xref, plugin, plugin_family, plugin_output, risk FROM vuln join host on vuln.host_id = host.id WHERE severity >= ?;"
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
