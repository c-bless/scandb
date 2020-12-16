from scandb.models import Vuln, Host, Scan, Port
from scandb.report.util import db2ReportVulnAddress, db2ReportVulnPlugin, db2ReportVuln

def select_plugin_ids(min_severity = 0):
    ids = Vuln.select(Vuln.plugin_id).where(Vuln.severity >= min_severity).distinct()
    result = [i.plugin_id for i in ids]
    return result


def select_plugin_by_id(id=0):
    vuln = Vuln.select().where(Vuln.plugin_id == id).first()
    return db2ReportVulnPlugin(vuln)


def select_vuln_addr_by_plugin(pid):
    vulns = Vuln.select().where(Vuln.plugin_id == pid)
    result = [db2ReportVulnAddress(v) for v in vulns]
    return result


def select_ips(min_severity = 0):
    result = Vuln.select(Host.address).join(Host).where(Vuln.severity >= min_severity).distinct()
    ips = [i.host.address for i in result]
    return ips


def select_vuln_by_ip(ip, min_severity=0):
    result = Vuln.select(Vuln).join(Host).where(Host.address == ip and Vuln.severity >= min_severity )
    vulns = [db2ReportVuln(v) for v in result]
    return vulns


def select_vulns(min_severity=0):
    result = Vuln.select(Vuln).join(Host).where(Vuln.severity >= min_severity)
    vulns = [db2ReportVuln(v) for v in result]
    return vulns
