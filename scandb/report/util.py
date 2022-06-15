import json

from docxtpl import DocxTemplate, RichText
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


def parse_pluginrange(plugins):
    pluginlist = []
    if plugins == "" or plugins is None:
        return pluginlist
    for plugin in plugins.split(','):
        if '-' in plugin:
            pluginrange = plugin.split('-')
            for i in range(int(pluginrange[0]), int(pluginrange[1]) + 1):
                # append all plugins in the pluginrange to the new pluginlist
                pluginlist.append(i)
        else:
            # append single plugin to pluginlist
            pluginlist.append(int(plugin))
    return pluginlist


def write_to_template(template, outfile, scan_stats=[], vuln_stats=[], port_stats=[], host_port_list=[],
                      vulns=[], vulns_by_plugin=[], vulns_by_host=[]):
    try:
        # ensure to handle the plugin_output fields a RichText, so that these field doesn't cause an error when they
        # contain html
        for i in vulns_by_plugin:
            for a in i.addresses:
                a.plugin_output = RichText(a.plugin_output)
        for i in vulns:
            i.plugin_output = RichText(i.plugin_output)
        for i in vulns_by_host:
            for v in i.vulns:
                v.plugin_output = RichText(v.plugin_output)
        # inject the given object into the template engine and render the template
        doc = DocxTemplate(template)
        context = {'vulns' : vulns,
                   'scan_stats' : scan_stats,
                   'vuln_stats': vuln_stats,
                   'port_stats' : port_stats,
                   'vulns_by_plugin': vulns_by_plugin,
                   'vulns_by_host': vulns_by_host,
                   'host_port_list': host_port_list}
        doc.render(context)
        doc.save(outfile)
    except Exception as e:
        print(colored("[-] {0}".format(e.message), "red"))

