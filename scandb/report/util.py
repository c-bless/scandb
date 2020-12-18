import json

from docxtpl import DocxTemplate
from termcolor import colored

from scandb.models.report import ReportVuln
from scandb.models.report import ReportVulnAddress
from scandb.models.report import ReportVulnPlugin

def db2ReportVuln(v):
    """

    :param dbvuln: Vuln
    :return:
    """
    vuln = ReportVuln ( address =v.host.address, description =v.description, synopsis=v.synopsis, port=v.port,
                        protocol=v.protocol, service=v.service, solution=v.solution, severity=v.severity,
                        xref=v.xref, info=v.info, plugin_id=v.plugin_id, plugin_name=v.plugin_name, plugin=v.plugin,
                        plugin_family=v.plugin_family, plugin_output=v.plugin_output,  risk=v.risk)
    return vuln


def db2ReportVulnPlugin(v):
    """

    :param dbvuln: Vuln
    :return:
    """
    i = 0
    plugin = ReportVulnPlugin ( description =v.description, synopsis=v.synopsis, solution=v.solution, severity=v.severity,
                            xref=v.xref, info=v.info, plugin_id=v.plugin_id, plugin_name=v.plugin_name, plugin=v.plugin,
                            plugin_family=v.plugin_family, risk=v.risk)
    return plugin


def db2ReportVulnAddress(v):
    address = ReportVulnAddress ( address =v.host.address, port=v.port, protocol=v.protocol, service=v.service,
                                    plugin_output=v.plugin_output)
    return address





def write_to_template(template, outfile, scan_stats=[], vuln_stats=[], port_stats=[], host_port_list=[],
                      vulns=[], vulns_by_plugin=[], vulns_by_host=[]):
    try:
        doc = DocxTemplate(template)
        context = {'vulns' : vulns, 'scan_stats' : scan_stats, 'vuln_stats': vuln_stats, 'port_stats' : port_stats,
                   'vulns_by_plugin': vulns_by_plugin, 'vulns_by_host': vulns_by_host, 'host_port_list': host_port_list}
        doc.render(context)
        doc.save(outfile)
    except Exception as e:
        print(e)
        print(colored("[-] {0}".format(e.message), "red"))

