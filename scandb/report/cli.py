import argparse
from docxtpl import DocxTemplate, RichText
from termcolor import colored

from scandb.models import init_db, Vuln, Host
from scandb.report.models import ReportVuln
from scandb.report.models import ReportVulnAddress
from scandb.report.models import ReportVulnPlugin
from scandb.report.models import ReportVulnByAddressList



#################################### DB Queries ##########################################


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

#################################### DB model to report model ###########################
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


def create_list_ReportVulnPlugin(min_severity=0):
    """
        This function creates a list with ReportVulnPlugin objects.

        :param min_severity: minimum severity (default = 0)
        :type: int
        :return: list of ReportVulnPlugin objects
        :rtype: list
        """
    result = []
    ids = select_plugin_ids(min_severity=min_severity)
    for id in ids:
        plugin = select_plugin_by_id(id)
        addresses = select_vuln_addr_by_plugin(id)
        plugin.addresses = addresses
        result.append(plugin)
    return result


def create_list_ReportVulnByAddressList(min_severity=0):
    result = []
    ips = select_ips(min_severity=min_severity)
    for ip in ips:
        addr = ReportVulnByAddressList(address=ip)
        addr.vulns = select_vuln_by_ip(ip=ip, min_severity=min_severity)
        result.append(addr)
    return result


def write_to_template(template, outfile, vulns=[], vulns_by_plugin=[], vulns_by_host=[]):
    try:
        doc = DocxTemplate(template)
        context = {'port_statistics': [], 'vuln_statistics': [], 'host_portlist' : [], 'vulns' : vulns,
                   'vulns_by_plugin': vulns_by_plugin, 'vulns_by_host': vulns_by_host}
        doc.render(context)
        doc.save(outfile)
    except Exception as e:
        print(e)
        print(colored("[-] {0}".format(e.message), "red"))

def report_cli():
    parser = argparse.ArgumentParser(description="")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--min-severity", type=int, required=False, default=0,
                        help="Minimum severity level (default: 0)")
    parser.add_argument("--template", type=str, required=False, default="scandb-template.docx",
                        help="Name of the template to render")
    parser.add_argument("--outfile", type=str, required=False, default="scandb-report.docx",
                        help="Name that is used for the generated report.")
    args = parser.parse_args()

    # initialize the database
    database = init_db(args.db)

    vulns = select_vulns(args.min_severity)
    vulns_by_plugin = create_list_ReportVulnPlugin(args.min_severity)
    vulns_by_host = create_list_ReportVulnByAddressList(args.min_severity)

    write_to_template(args.template, outfile=args.outfile, vulns=vulns, vulns_by_plugin=vulns_by_plugin,
                      vulns_by_host=vulns_by_host)