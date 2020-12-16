
from scandb.report.models import ReportVuln
from scandb.report.models import ReportVulnAddress
from scandb.report.models import ReportVulnPlugin

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