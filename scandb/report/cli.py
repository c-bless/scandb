import argparse

from scandb.models.db import init_db

from scandb.models.report import ReportVulnByAddressList
from scandb.report.queries import select_vulns, select_ips, select_plugin_ids, select_plugin_by_id
from scandb.report.queries import select_vuln_by_ip, select_vuln_addr_by_plugin, select_vulns_by_plugins
from scandb.report.util import write_to_template, parse_pluginrange

from scandb.statistics.queries import get_vuln_stats
from scandb.statistics.queries import get_port_stats
from scandb.statistics.queries import get_scan_stats
from scandb.statistics.queries import get_host_port_list

def create_list_ReportVulnPlugin(min_severity=0, plugin_ids=[]):
    """
        This function creates a list with ReportVulnPlugin objects.

        :param min_severity: minimum severity (default = 0)
        :type: int
        :return: list of ReportVulnPlugin objects
        :rtype: list
        """
    result = []
    if len(plugin_ids) > 0:
        ids = plugin_ids
    else:
        ids = select_plugin_ids(min_severity=min_severity)
    for id in ids:
        try:
            plugin = select_plugin_by_id(id)
            addresses = select_vuln_addr_by_plugin(id)
            plugin.addresses = addresses
            result.append(plugin)
        except:
            pass
    return result


def create_list_ReportVulnByAddressList(min_severity=0, plugin_ids=[]):
    result = []
    if len(plugin_ids) > 0:
        ips = [v.host.address for v in select_vulns_by_plugins(plugin_ids)]
    else:
        ips = select_ips(min_severity=min_severity)
    for ip in ips:
        addr = ReportVulnByAddressList(address=ip)
        addr.vulns = select_vuln_by_ip(ip=ip, min_severity=min_severity)
        result.append(addr)
    return result


def report_cli():
    parser = argparse.ArgumentParser(description="Generate DOCX reports based on custom templates. "
                                    "See https://bitbucket.org/cbless/scandb/src/master/examples/ for example templates."
                                    "A description of usable objects and their attributes can be found under: \n"
                                    "https://bitbucket.org/cbless/scandb/wiki/Report-Templates")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--min-severity", type=int, required=False, default=0,
                        help="Minimum severity level (default: 0). Either plugins or min-severity can be used.")
    parser.add_argument("--plugins", type=str, required=False, default=None,
                        help="List of plugins to export. Either plugins or min-severity can be used.")
    parser.add_argument("--export-vulns", required=False, choices=['all', 'unsorted', 'host', 'plugin'],
                        default='plugin', help="Can be used to specifiy how the vulnerabilities will be injected into "
                                               "the template. 'unsorted' means that the vulnerabilites will be "
                                               "available unsorted as 'vulns'. 'host' means that a list of "
                                               "vulnerabilities is avaialable per host. 'plugin' means that the list "
                                               "of affected systems is available per plugin/vulnerability as "
                                               "'vulns_by_plugin'. 'all' means that all three options are available in "
                                               "the template. (default 'plugin')")
    parser.add_argument("--template", type=str, required=False, default="scandb-template.docx",
                        help="Name of the template to render. Examples can be found under: "
                             "https://bitbucket.org/cbless/scandb/src/master/examples/")
    parser.add_argument("--outfile", type=str, required=False, default="scandb-report.docx",
                        help="Name that is used for the generated report.")
    args = parser.parse_args()

    # initialize the database
    database = init_db(args.db)

    vulns = []
    vulns_by_plugin = []
    vulns_by_host = []

    if args.plugins:
        plugin_list = parse_pluginrange(args.plugins)
        if len (plugin_list) > 0:
            if args.export_vulns in ['all', 'vulns']:
                vulns = select_vulns_by_plugins(plugin_list)
            if args.export_vulns in ['all', 'plugin']:
                vulns_by_plugin = create_list_ReportVulnPlugin(plugin_ids=plugin_list)
            if args.export_vulns in ['all', 'host']:
                vulns_by_host = create_list_ReportVulnByAddressList(plugin_ids=plugin_list)
    else:
        # select by min-severity (default = 0)
        if args.export_vulns in ['all', 'vulns']:
            vulns = select_vulns(args.min_severity)
        if args.export_vulns in ['all', 'plugin']:
            vulns_by_plugin = create_list_ReportVulnPlugin(args.min_severity)
        if args.export_vulns in ['all', 'host']:
            vulns_by_host = create_list_ReportVulnByAddressList(args.min_severity)

    scan_stats = get_scan_stats(args.db)
    vuln_stats = get_vuln_stats(args.db)
    port_stats = get_port_stats(args.db)
    host_port_list = get_host_port_list(args.db)

    write_to_template(args.template, outfile=args.outfile, vulns=vulns, vulns_by_plugin=vulns_by_plugin,
                      host_port_list=host_port_list, vulns_by_host=vulns_by_host, vuln_stats=vuln_stats,
                      port_stats=port_stats, scan_stats=scan_stats)
