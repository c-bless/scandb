from __future__ import print_function
import json
import peewee
from libnessus.parser import NessusParser
from termcolor import colored

from scandb.importer.util import hash_file
from scandb.models.db import Scan, Host, Vuln

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
    host = Host(address=h.ip, hostname=h.name, scan=scan)
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
    info = json.dumps(v.get_vuln_info)
    plugin = json.dumps(v.get_vuln_plugin)
    xref = json.dumps(v.get_vuln_xref)
    risk = json.dumps(v.get_vuln_risk)
    vuln = Vuln(host=host, description=v.description, synopsis=v.synopsis, port=v.port, protocol=v.protocol,
                service=v.service, solution=v.solution, severity=v.severity, xref=xref, info=info,
                plugin=plugin, plugin_id=v.plugin_id, plugin_family = family, plugin_output=output,
                plugin_name=v.plugin_name, risk=risk)
    return vuln


def import_nessus_file(infile):
    """
    This function is responsible for importing the given file.  For each file a SHA-512 hash is calculated to ensure
    that the file is only imported once.

    :param infile: nessus XML-file to import
    :return:
    """
    print(colored("[*] Importing file: {0}".format(infile), 'green'))
    try:
        report = NessusParser.parse_fromfile(infile)
        # calculate a SHA-512 hash. This is used to ensure that the file will not be imported more than once.
        sha512 = hash_file(infile)

        # create the database entry for the scan.
        scan = Scan(file_hash=sha512, name=report.name, type='nessus', start=report.started, end=report.endtime,
                    elapsed=report.elapsed, hosts_total=report.hosts_total)
        scan.save()

        # import all hosts and ports present in the report
        for h in report.hosts:
            host = _nessus_host_to_dbhost(h, scan=scan)
            host.save()
            for v in h.get_report_items:
                vuln = _nessus_vuln_to_dbvuln(v, host)
                vuln.save()
        print(colored("[*] File imported. ", 'green'))
    except peewee.IntegrityError as e:
        # This error is throw when the SHA-512 hash is already present in the database. Therefore the file cannot be
        # imported again.
        print(colored("[-] File already imported: {0}".format(infile), 'red'))
        print(colored("[-] {0}".format(e.message), 'red'))
    except Exception as e:
        # Invalid file format
        print(colored("[-] {0}".format(e.message), 'red'))
