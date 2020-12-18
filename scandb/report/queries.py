from scandb.models.db import Vuln, Host, Scan, Port
from scandb.report.util import db2ReportVulnAddress, db2ReportVulnPlugin, db2ReportVuln


def select_plugin_ids(min_severity = 0):
    """
    Returns a list of plugin ids. Only plugins that match the minimum severity level will be present in the list.

    :param min_severity: minimum severity level
    :type min_severity: int

    :return: list of plugin ids
    :rtype: list
    """
    ids = Vuln.select(Vuln.plugin_id).where(Vuln.severity >= min_severity).distinct()
    result = [i.plugin_id for i in ids]
    return result


def select_plugin_by_id(id=0):
    """
    Returns an instance of a ReportVulnPlugin object.

    :param id: plugin id
    :return: instance of a ReportVulnPlugin object
    :rtype: scandb.report.ReportVulnPlugin
    """
    vuln = Vuln.select().where(Vuln.plugin_id == id).first()
    return db2ReportVulnPlugin(vuln)


def select_vuln_addr_by_plugin(pid):
    vulns = Vuln.select().where(Vuln.plugin_id == pid)
    result = [db2ReportVulnAddress(v) for v in vulns]
    return result


def select_ips(min_severity = 0):
    """
    Returns a list of ip addresses of systems that are affected by a vulnerability with the given minimum severity level.

    :param min_severity: minimum severity level of the Nessus Plugin
    :return: list of ip addresses
    """
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


