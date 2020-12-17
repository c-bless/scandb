import json

def xref2cve(xref):
    tmp = json.loads(xref.replace("'", "\""))
    cve = ""
    if 'cve' in tmp:
        cve = ",".join(tmp['cve'])
    return cve

class ReportVuln(object):

    def __init__(self, address ="", description ="", synopsis="", port="", protocol="", service="", solution="",
                 severity="", xref="", info="", plugin_id="", plugin_name="", plugin="", plugin_family="",
                 plugin_output="",  risk=""):
        self.address = address
        self.description = description
        self.synopsis = synopsis
        self.port = port
        self.protocol = protocol
        self.service = service
        self.solution = solution
        self.severity = severity
        self.xref = xref
        self.cve = xref2cve(xref)
        self.info = info
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.plugin = plugin
        self.plugin_family = plugin_family
        self.plugin_output = plugin_output
        self.risk = risk


class ReportVulnPlugin(object):
    """
    Subset of fields of the ReportVulns class. Used for the vulns_by_plugin list when generating the report. The
    following fields are missing compared to ReportVulns: plugin_output, address, port, protocol, service. Instead of
    these files a list of address objects is used that provide this information.
    """
    def __init__(self, addresses = [], description ="", synopsis="", solution="", severity="", xref="", info="",
                 plugin_id="", plugin_name="", plugin="", plugin_family="", risk=""):
        self.addresses = addresses
        self.description = description
        self.synopsis = synopsis
        self.solution = solution
        self.severity = severity
        self.xref = xref
        self.info = info
        self.cve = xref2cve(xref)
        self.plugin_id = plugin_id
        self.plugin_name = plugin_name
        self.plugin = plugin
        self.plugin_family = plugin_family
        self.risk = risk


class ReportVulnAddress(object):
    def __init__(self, address ="", port="", protocol="", service="", plugin_output=""):
        self.address = address
        self.port = port
        self.protocol = protocol
        self.service = service
        self.plugin_output = plugin_output


class ReportVulnByAddressList(object):
    def __init__(self, address ="", vulns = []):
        self.address = address
        self.vulns = vulns


class ReportPort(object):
    def __init__(self, port="", protocol="", service="", banner="", status=""):
        self.port = port
        self.protocol = protocol
        self.service = service
        self.banner = banner
        self.status = status


class ReportHost(object):
    def __init__(self, address ="", hostname="", os ="", os_gen="", status="", tcp=[], udp=[]):
        self.address = address
        self.hostname = hostname
        self.os = os
        self.os_gen = os_gen
        self.status = status
        self.tcp = tcp
        self.udp = udp


class ReportVulnStat(object):
    def __init__(self, address ="", critical="", high="", medium="", low="", info=""):
        self.address = address
        self.critical = critical
        self.high = high
        self.medium = medium
        self.low = low
        self.info = info


class ReportPortStat(object):
    def __init__(self, address ="", tcp="", udp=""):
        self.address = address
        self.tcp = tcp
        self.udp = udp


class ReportHostPortStat(object):
    def __init__(self, address ="", ports="", protocol=""):
        self.address = address
        self.ports = ports
        self.protocol = protocol


class ReportScanStat(object):
    def __init__(self, id="", start="", end="", elapsed="", hosts_total="", hosts_up="", hosts_down="", name=""):
        self.id = id
        self.start = start
        self.end = end
        self.elapsed = elapsed
        self.hosts_total = hosts_total
        self.hosts_up = hosts_up
        self.hosts_down = hosts_down
        self.name = name