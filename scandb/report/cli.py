import argparse
from docxtpl import DocxTemplate, RichText
from termcolor import colored

from scandb.models import init_db

from scandb.report.models import ReportVulnByAddressList
from scandb.report.queries import select_vulns, select_ips, select_plugin_ids, select_plugin_by_id
from scandb.report.queries import select_vuln_by_ip, select_vuln_addr_by_plugin


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


def create_ReportHost_list():
    hosts = Hos



def write_to_template(template, outfile, vulns=[], vulns_by_plugin=[], vulns_by_host=[], host_portlist=[]):
    try:
        doc = DocxTemplate(template)
        context = {'vulns' : vulns,
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
                        help="Name of the template to render. Examples can be found under: "
                             "https://bitbucket.org/cbless/scandb/src/master/examples/")
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