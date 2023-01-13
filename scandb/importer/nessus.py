from __future__ import print_function
import json
from libnessus.parser import NessusParser
from termcolor import colored
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import IntegrityError

from scandb.importer.util import hash_file
from scandb.models.db import Scan, Host, Vuln, Port

def _nessus_host_to_dbhost(h, scan):
    """
    Create a database host object with the values from the nessus host object.

    :param h: nessus host object
    :type h: libnessus.objects.reporthost.NessusReportHost

    :param scan: database scan object
    :type scan: scandb.models.Scan

    :return: database host object
    :rtype: scandb.models.Host
    """
    host = Host(address=h.ip, hostname=h.name, scan=scan, status='up')
    # get non-default values from NessusReportHost object
    netbios = h.get_host_properties.get("netbios-name")
    fqdn = h.get_host_properties.get("host-fqdn")
    operating_system = h.get_host_properties.get("operating-system")
    os = h.get_host_properties.get("os")
    # update the database host if these values where not empty
    if netbios:
        host.hostname = netbios
    if fqdn:
        host.hostname = fqdn
    if os:
        host.os = os
    if operating_system:
        host.os = operating_system
    return host


def _nessus_vuln_to_dbvuln(v, host):
    """
    This function creates a database model object (Vuln) and sets the attributes to values read from the given
    NessusReportItem.

    :param v: The NesusReportItem
    :type v: libnessus.objects.reportitem.NessusReportItem
    :return: New database model object
    :rtype: scandb.models.Vuln
    """
    output = ""
    family = ""
    plugin = v.get_vuln_plugin
    if 'plugin_output' in plugin:
        output = plugin['plugin_output']
    if 'pluginFamily' in plugin:
        family = plugin['pluginFamily']
    try:
        info = json.dumps(v.get_vuln_info)
    except:
        info = ""

    try:
        desc = v.description
    except:
        desc = ""

    try:
        synopsis = v.synopsis
    except:
        synopsis = ""

    try:
        port = v.port
    except:
        port = ""

    try:
        protocol = v.protocol
    except:
        protocol = ""

    try:
        plugin_name = v.plugin_name
    except:
        plugin_name = ""

    try:
        solution = v.solution
    except:
        solution = ""

    try:
        severity = v.severity
    except:
        severity = ""

    try:
        plugin_id = v.plugin_id
    except:
        plugin_id = ""

    try:
        plugin = json.dumps(v.get_vuln_plugin)
    except:
        plugin = ""

    try:
        xref = json.dumps(v.get_vuln_xref)
    except:
        xref = ""

    try:
        risk = json.dumps(v.get_vuln_risk)
    except:
        risk = ""

    try:
        service = v.service
    except:
        service = ""
    vuln = Vuln(host=host, description=desc, synopsis=synopsis, port=port, protocol=protocol,
                service=service, solution=solution, severity=severity, xref=xref, info=info,
                plugin=plugin, plugin_id=plugin_id, plugin_family = family, plugin_output=output,
                plugin_name=plugin_name, risk=risk)
    return vuln


def import_nessus_file(infile, engine):
    """
    This function is responsible for importing the given file.  For each file a SHA-512 hash is calculated to ensure
    that the file is only imported once.

    :param infile: nessus XML-file to import

    :param engine: sqlalchemy.orm.engine

    :return:
    """
    print(colored("[*] Importing file: {0}".format(infile), 'green'))

    report = NessusParser.parse_fromfile(infile)
    # calculate a SHA-512 hash. This is used to ensure that the file will not be imported more than once.
    sha512 = hash_file(infile)

    Session = sessionmaker(engine)

    session = Session()

    try:
        # create the database entry for the scan.
        scan = Scan(file_hash=sha512, name=report.name, type='nessus', start=str(report.started), end=str(report.endtime),
                    elapsed=str(report.elapsed), hosts_total=report.hosts_total)
        session.add(scan)

        # import all hosts and ports present in the report
        for h in report.hosts:
            host = _nessus_host_to_dbhost(h, scan=scan)
            session.add(host)
            for v in h.get_report_items:
                vuln = _nessus_vuln_to_dbvuln(v, host)
                session.add(vuln)
                if (vuln.port) != "0":
                    port = Port(host=vuln.host, address=vuln.host.address, port=vuln.port, protocol=vuln.protocol, service=vuln.service, banner="",
                            status="open")
                    session.add(port)
        print(colored("[*] File imported. ", 'green'))
        session.commit()
    except IntegrityError as e:
        # This error is throw when the SHA-512 hash is already present in the database. Therefore, the file cannot be
        # imported again.
        print(colored("[-] File already imported: {0}".format(infile), 'red'))
        #print(colored("[-] {0}".format(str(e), 'red')))
        session.rollback()
    except Exception as e:
        # Invalid file format
        print(colored("[-] {0}".format(str(e), 'red')))
