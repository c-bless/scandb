from scandb.models.db import Vuln, Host, Scan, Port
from scandb.report.util import db2ReportVulnAddress, db2ReportVulnPlugin, db2ReportVuln
from sqlalchemy import select, and_
from sqlalchemy.orm import sessionmaker


def select_plugin_ids(engine, min_severity = 0):
    """
    Returns a list of plugin ids. Only plugins that match the minimum severity level will be present in the list.

    :param min_severity: minimum severity level
    :type min_severity: int

    :param engine: SQLAlchemy Engine object

    :return: list of plugin ids
    :rtype: list
    """
    Session = sessionmaker(bind=engine)
    session = Session()
    ids = session.query(Vuln.plugin_id).filter(Vuln.severity >= min_severity).distinct()
    result = [i[0] for i in ids]
    return result


def select_plugin_by_id(engine, id=0):
    """
    Returns an instance of a ReportVulnPlugin object.

    :param id: plugin id
    :return: instance of a ReportVulnPlugin object
    :rtype: scandb.report.ReportVulnPlugin
    """
    query = select(Vuln).where(Vuln.plugin_id == id)
    vuln = engine.execute(query).fetchone()
    return db2ReportVulnPlugin(vuln)


def select_vuln_addr_by_plugin(engine, pid):
    """
    Returns a list of ReportVulnAddress objects that are affected by a vulnerability with the given Nessus Plugin-ID.

    :param pid: Nessus Plugin-ID
    :return: list of scandb.models.report.ReportVulnAddress objects
    :rtype: list
    """
    result = []
    ip_port_list = []
    Session = sessionmaker(bind=engine)
    session = Session()
    vulns = session.query(Vuln).filter(Vuln.plugin_id == pid).all()
    for v in vulns:
        ip_port = "{0}:{1}".format(v.host.address, v.port)
        if ip_port not in ip_port_list:
            result.append(v)
            ip_port_list.append(ip_port)
    result = [db2ReportVulnAddress(r) for r in result]
    return result


def select_ips(engine, min_severity = 0):
    """
    Returns a list of ip addresses of systems that are affected by a vulnerability with the given minimum severity level.

    :param min_severity: minimum severity level of the Nessus Plugin
    :type min_severity: int

    :return: list of ip addresses
    :rtype: list
    """
    query = select(Host.address).join(Vuln).where(Vuln.severity >= min_severity).distinct()
    result = engine.execute(query).fetchall()
    ips = [i[0] for i in result]
    return ips


def select_vuln_by_ip(engine, ip, min_severity=0):
    """
    Returns a list of vulnerabilities that were identified on a given ip address and that have a minimum severity level.

    :param ip: ip address
    :type ip: str

    :param min_severity: minimum severity level of the Nessus Plugin
    :type min_severity: int

    :return: list of scandb.models.report.ReportVuln objects
    :rtype: list
    """
    result = []
    plugin_port_list = []
    Session = sessionmaker(bind=engine)
    session = Session()
    vulns = session.query(Vuln).join(Host).filter(Vuln.severity >= min_severity).filter(Host.address == ip).all()
    for v in vulns:
        plugin_port = "{0}:{1}".format(v.plugin_id, v.port)
        if plugin_port not in plugin_port_list:
            result.append(v)
            plugin_port_list.append(plugin_port)
    return [db2ReportVuln(v) for v in result]



def select_vulns(engine, min_severity=0):
    """
    Returns a list of vulnerabilities with the given minimum severity level.

    :param min_severity: minimum severity level of the Nessus Plugin
    :type min_severity: int

    :return: list of scandb.models.report.ReportVuln objects
    :rtype: list
    """
    Session = sessionmaker(bind=engine)
    session = Session()
    result = session.query(Vuln).join(Host).filter(Vuln.severity >= min_severity).all()
    vulns = [db2ReportVuln(v) for v in result]
    return vulns



def select_vulns_by_plugins(engine, ids=[]):
    """
    Returns a list of vulnerabilities that have been identified and where the nessus plugin ID is in the given list of
     plugin IDs.

    :param ids: list of Nessus plugin IDs.
    :type ids: list

    :return: list of scandb.models.report.ReportVuln objects
    :rtype: list
    """
    Session = sessionmaker(bind=engine)
    session = Session()
    result = session.query(Vuln).join(Host).filter(Vuln.plugin_id.in_(ids)).order_by(Vuln.plugin_id).all()
    vulns = [db2ReportVuln(v) for v in result]
    return vulns


