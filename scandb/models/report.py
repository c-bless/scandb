import json


def xref2cve(xref):
    """
    Function to parse the xref field of the nessus plugin to extract a list of CVE numbers.

    :param xref: Json object with vulnerability references
    :type xref: JSON

    :return: string with a list of comma separated CVE numbers
    :rtype: str
    """
    cve = ""
    try:
        tmp = json.loads(xref.replace("'", "\""))

        if 'cve' in tmp:
            cve = ", ".join(tmp['cve'])
    except:
        pass
    return cve


def xref2bid(xref):
    """
    Function to parse the xref field of the nessus plugin to extract a list of BID numbers.

    :param xref: Json object with vulnerability references
    :type xref: JSON

    :return: string with a list of comma separated BID numbers
    :rtype: str
    """
    bid = ""
    try:
        tmp = json.loads(xref.replace("'", "\""))
        if 'bid' in tmp:
            bid = ",".join(tmp['bid'])
    except:
        pass
    return bid


class ReportVuln(object):
    """
    Object with details of an identified vulnerability and information about the vulnerability scanner plugin that was
    used to identify the vulnerability.
    """
    def __init__(self, address="", description="", synopsis="", port="", protocol="", service="", solution="",
                 severity="", xref="", info="", plugin_id="", plugin_name="", plugin="", plugin_family="",
                 plugin_output="",  risk=""):
        """
        Constructor

        :param address: ip address
        :type address: str

        :param description: Vulnerability description
        :type description: str

        :param synopsis:  Nessus synopsis field / Summary
        :type synopsis: str

        :param port: Port number for the associated finding
        :type port: str

        :param protocol: used transport layer protocol (TCP / UDP)
        :type protocol: str

        :param service: detected service (e.g. www, ftp )
        :type service: str

        :param solution: Vulnerability solution / Mitigation measure
        :type solution: str

        :param severity: Severity rating of the vulnerability (4=critical, 3=High, 2=Medium, 1=Low, 0=Informational)
        :type severity: str

        :param xref: unparsed xref ouput from lib-nessus (JSON)
        :type xref: JSON string

        :param info: unparsed info ouput from lib-nessus (JSON)
        :type info: JSON string

        :param plugin_id: Nessus plugin id
        :type plugin_id: str

        :param plugin_name: Nessus plugin name
        :type plugin_name: str

        :param plugin: unparsed plugin ouput from lib-nessus (JSON)
        :type plugin: JSON string

        :param plugin_family: Nessus plugin plugin_family
        :type plugin_family: str

        :param plugin_output: Nessus plugin output
        :type plugin_output: str

        :param risk: unparsed risk from lib-nessus (JSON)
        :type risk: JSON string
        """
        self._address = address
        self._description = description
        self._synopsis = synopsis
        self._port = str(port)
        self._protocol = protocol
        self._service = service
        self._solution = solution
        self._severity = str(severity)
        self._xref = xref
        self._cve = xref2cve(xref)
        self._bid = xref2bid(xref)
        try:
            self._info = json.loads(info)
        except:
            self._info = info
        self._plugin_id = plugin_id
        self._plugin_name = plugin_name
        try:
            self._plugin = json.loads(plugin)
        except:
            self._plugin = plugin
        self._plugin_family = plugin_family
        self._plugin_output = plugin_output
        self._risk = risk

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, address=""):
        self._address = address

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description=""):
        self._description = description

    @property
    def synopsis(self):
        return self._synopsis

    @synopsis.setter
    def synopsis(self, synopsis=""):
        self._synopsis = synopsis

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, port=""):
        self._port = str(port)

    @property
    def protocol(self):
        return self._protocol

    @protocol.setter
    def protocol(self, protocol=""):
        self._protocol = protocol

    @property
    def service(self):
        return self._service

    @service.setter
    def service(self, service=""):
        self._service = service

    @property
    def solution(self):
        return self._solution

    @solution.setter
    def solution(self, solution=""):
        self._solution = solution

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, severity="0"):
        self._severity = str(severity)

    @property
    def xref(self):
        return self._xref

    @xref.setter
    def xref(self, xref={}):
        self._xref = xref

    @property
    def cve(self):
        return self._cve

    @cve.setter
    def cve (self, xref=""):
        self._cve = xref2cve(xref)

    @property
    def bid(self):
        return self._bid

    @bid.setter
    def bid(self, value):
        self._bid = xref2bid(value)

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = value

    @property
    def plugin_id(self):
        return self.plugin_id

    @plugin_id.setter
    def plugin_id(self, value):
        self._plugin_id = value

    @property
    def plugin_name(self):
        return self._plugin_name

    @plugin_name.setter
    def plugin_name(self, value):
        self.plugin_name = value

    @property
    def plugin(self):
        return self._plugin
    
    @plugin.setter
    def plugin(self, value):
        self._plugin = value

    @property
    def plugin_family(self):
        return self._plugin_family
    
    @plugin_family.setter
    def plugin_family(self, value):
        self._plugin_family = value
        
    @property
    def plugin_output(self):
        return self._plugin_output
    
    @plugin_output.setter
    def plugin_output(self, value):
        self._plugin_output = value
        
    @property
    def risk(self):
        return self._risk
    
    @risk.setter
    def risk(self, value):
        self._risk = value

    @property
    def exploitability_ease(self):
        if 'exploitability_ease' in self._info:
            return self._info['exploitability_ease']
        return ""

    @property
    def exploit_available(self):
        if 'exploit_available' in self._info:
            return self._info['exploit_available']
        return ""

    @property
    def canvas(self):
        if 'canvas' in self._info:
            return self._info['canvas']
        return ""

    @property
    def metasploit(self):
        if 'metasploit' in self._info:
            return self._info['metasploit']
        return ""

    @property
    def core_impact(self):
        if 'core_impact' in self._info:
            return self._info['core_impact']
        return ""

    @property
    def canvas_name(self):
        if 'canvas_name' in self._info:
            return self._info['canvas_name']
        return ""

    @property
    def metasploit_name(self):
        if 'metasploit_name' in self._info:
            return self._info['metasploit_name']
        return ""


class ReportVulnPlugin(object):
    """
    Subset of fields of the ReportVulns class. Used for the vulns_by_plugin list when generating the report. The
    following fields are missing compared to ReportVulns: plugin_output, address, port, protocol, service. Instead of
    these files a list of ReportVulnAddress objects is used that provide this information.
    """
    def __init__(self, addresses=[], description="", synopsis="", solution="", severity="", xref="", info="",
                 plugin_id="", plugin_name="", plugin="", plugin_family="", risk=""):
        """
        Constructor

        :param addresses: ip addresses
        :type addresses: list of scandb.models.report.ReportVulnAddress obejcts

        :param description: Vulnerability description
        :type description: str

        :param synopsis:  Nessus synopsis field / Summary
        :type synopsis: str

        :param solution: Vulnerability solution / Mitigation measure
        :type solution: str

        :param severity: Severity rating of the vulnerability (4=critical, 3=High, 2=Medium, 1=Low,  0=Informational)
        :type severity: str

        :param xref: unparsed xref ouput from lib-nessus (JSON)
        :type xref: JSON string

        :param info: unparsed info ouput from lib-nessus (JSON)
        :type info: JSON string

        :param plugin_id: Nessus plugin id
        :type plugin_id: str

        :param plugin_name: Nessus plugin name
        :type plugin_name: str

        :param plugin: unparsed plugin ouput from lib-nessus (JSON)
        :type plugin: JSON string

        :param plugin_family: Nessus plugin plugin_family
        :type plugin_family: str

        :param risk: unparsed risk from lib-nessus (JSON)
        :type risk: JSON string
        """
        self._addresses = addresses
        self._description = description
        self._synopsis = synopsis
        self._solution = solution
        self._severity = str(severity)
        self._xref = xref
        self._cve = xref2cve(xref)
        self._bid = xref2bid(xref)
        try:
            self._info = json.loads(info)
        except:
            self._info = info
        self._plugin_id = plugin_id
        self._plugin_name = plugin_name
        try:
            self._plugin = json.loads(plugin)
        except:
            self._plugin = plugin
        self._plugin_family = plugin_family
        self._risk = risk

    @property
    def addresses(self):
        return self._addresses

    @addresses.setter
    def addresses(self, addresses=[]):
        self._addresses = addresses

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, description=""):
        self._description = description

    @property
    def synopsis(self):
        return self._synopsis

    @synopsis.setter
    def synopsis(self, synopsis=""):
        self._synopsis = synopsis

    @property
    def solution(self):
        return self._solution

    @solution.setter
    def solution(self, solution=""):
        self._solution = solution

    @property
    def severity(self):
        return self._severity

    @severity.setter
    def severity(self, severity="0"):
        self._severity = str(severity)

    @property
    def xref(self):
        return self._xref

    @xref.setter
    def xref(self, xref={}):
        self._xref = xref

    @property
    def cve(self):
        return self._cve

    @cve.setter
    def cve(self, xref=""):
        self._cve = xref2cve(xref)

    @property
    def bid(self):
        return self._bid

    @bid.setter
    def bid(self, value):
        self._bid = xref2bid(value)

    @property
    def info(self):
        return self._info

    @info.setter
    def info(self, value):
        self._info = value

    @property
    def plugin_id(self):
        return self.plugin_id

    @plugin_id.setter
    def plugin_id(self, value):
        self._plugin_id = value

    @property
    def plugin_name(self):
        return self._plugin_name

    @plugin_name.setter
    def plugin_name(self, value):
        self.plugin_name = value

    @property
    def plugin(self):
        return self._plugin

    @plugin.setter
    def plugin(self, value):
        self._plugin = value

    @property
    def plugin_family(self):
        return self._plugin_family

    @plugin_family.setter
    def plugin_family(self, value):
        self._plugin_family = value

    @property
    def risk(self):
        return self._risk

    @risk.setter
    def risk(self, value):
        self._risk = value

    @property
    def exploitability_ease(self):
        if 'exploitability_ease' in self._info:
            return self._info['exploitability_ease']
        return ""

    @property
    def exploit_available(self):
        if 'exploit_available' in self._info:
            return self._info['exploit_available']
        return ""

    @property
    def canvas(self):
        if 'canvas' in self._info:
            return self._info['canvas']
        return ""

    @property
    def metasploit(self):
        if 'metasploit' in self._info:
            return self._info['metasploit']
        return ""

    @property
    def core_impact(self):
        if 'core_impact' in self._info:
            return self._info['core_impact']
        return ""

    @property
    def canvas_name(self):
        if 'canvas_name' in self._info:
            return self._info['canvas_name']
        return ""

    @property
    def metasploit_name(self):
        if 'metasploit_name' in self._info:
            return self._info['metasploit_name']
        return ""


class ReportVulnAddress(object):
    """
    Obejct to store information about hosts as well as the Nessus plugin output. This object is used as nested object
    in ReportVulnPlugin.
    """

    def __init__(self, address ="", port="", protocol="", service="", plugin_output=""):
        """
        Constructor

        :param address: ip address
        :type address: str

        :param port: Port number for the associated finding
        :type port: str

        :param protocol: used transport layer protocol (TCP / UDP)
        :type protocol: str

        :param service: detected service (e.g. www, ftp )
        :type service: str

        :param plugin_output: Nessus plugin output
        :type plugin_output: str
        """
        self._address = address
        self._port = port
        self._protocol = protocol
        self._service = service
        self._plugin_output = plugin_output

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = str(value)
        
    @property
    def protocol(self):
        return self._protocol
    
    @protocol.setter
    def protocol(self, value):
        self._protocol = value

    @property
    def service(self):
        return self._service
    
    @service.setter
    def service(self, value):
        self._service = value
        
    @property
    def plugin_output(self):
        return self._plugin_output
    
    @plugin_output.setter
    def plugin_output(self, value):
        self._plugin_output = value


class ReportVulnByAddressList(object):
    def __init__(self, address="", vulns=[]):
        self._address = address
        self._vulns = vulns

    @property
    def address(self):
        return self._address
    
    @address.setter
    def address(self, value):
        self._address = value
    
    @property
    def vulns(self):
        return self._vulns
    
    @vulns.setter
    def vulns(self, value=[]):
        self._vulns = value


class ReportPort(object):
    def __init__(self, port="", protocol="", service="", banner="", status=""):
        self._port = port
        self._protocol = protocol
        self._service = service
        self._banner = banner
        self._status = status

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = str(value)

    @property
    def protocol(self):
        return self._protocol
    
    @protocol.setter
    def protocol(self, value):
        self._protocol = value
        
    @property
    def service(self):
        return self._service
    
    @service.setter
    def service(self, value):
        self._service = value
    
    @property
    def banner(self):
        return self._banner
    
    @banner.setter
    def banner(self, value):
        self._banner = value
        
    @property
    def status(self):
        return self._status
    
    @status.setter
    def status(self, value):
        self._status = value


class ReportHost(object):
    def __init__(self, address ="", hostname="", os ="", os_gen="", status="", tcp=[], udp=[]):
        self._address = address
        self._hostname = hostname
        self._os = os
        self._os_gen = os_gen
        self._status = status
        self._tcp = tcp
        self._udp = udp

    @property
    def address(self):
        return self._address

    @address.setter
    def address(self, value):
        self._address = value

    @property
    def hostname(self):
        return self._hostname

    @hostname.setter
    def hostname(self, value):
        self._hostname = value

    @property
    def os(self):
        return self._os

    @os.setter
    def os(self, value):
        self._os = value

    @property
    def os_gen(self):
        return self._os_gen

    @os_gen.setter
    def os_gen(self, value):
        self._os_gen = value

    @property
    def status(self):
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def tcp(self):
        return self._tcp

    @tcp.setter
    def tcp(self, value=[]):
        self._tcp = value

    @property
    def udp(self):
        return self._udp

    @udp.setter
    def udp(self, value=[]):
        self._udp = value


############## Statistic objects

class ReportVulnStat(object):

    def __init__(self, address ="", critical=0, high=0, medium=0, low=0, info=0):
        self._address = address
        self._critical = critical
        self._high = high
        self._medium = medium
        self._low = low
        self._info = info

    @property
    def address(self):
        return self._address
    
    @address.setter
    def address(self, value):
        self._address = value
    
    @property
    def critical(self):
        return self._critical
    
    @critical.setter
    def critical(self, value):
        self._critical = value
        
    @property
    def high(self):
        return self._high
    
    @high.setter
    def high(self, value):
        self._high = value
        
    @property
    def medium(self):
        return self._medium
    
    @medium.setter
    def medium(self, value):
        self._medium = value
        
    @property
    def low(self):
        return self._low
    
    @low.setter
    def low(self, value):
        self._low = value
        
    @property
    def info(self):
        return self._info
    
    @info.setter
    def info(self, value):
        self._info = value

    @staticmethod
    def get_csv_header(delimiter=";"):
        return delimiter.join(["Address", "Critical", "High", "Medium", "Low", "Info"])

    def as_csv(self, delimiter=";"):
        return delimiter.join([self.address, str(self.critical), str(self.high), str(self.medium), str(self.low),
                               str(self.info)])


class ReportPortStat(object):
    def __init__(self, address ="", tcp="", udp=""):
        self._address = address
        self._tcp = tcp
        self._udp = udp
        
    @property
    def address(self):
        return self._address
    
    @address.setter
    def address(self, value):
        self._address = value
        
    @property
    def tcp(self):
        return self._tcp
    
    @tcp.setter
    def tcp(self, value):
        self._tcp = value

    @property
    def udp(self):
        return self._udp
    
    @udp.setter
    def udp(self, value):
        self._udp = value

    @staticmethod
    def get_csv_header(delimiter=";"):
        return delimiter.join(["Address", "TCP", "UDP"])

    def as_csv(self, delimiter=";"):
        return delimiter.join([self.address, self.tcp, self.udp])


class ReportHostPortStat(object):
    def __init__(self, address ="", ports="", protocol=""):
        self._address = address
        self._ports = ports
        self._protocol = protocol
        
    @property
    def address(self):
        return self._address
    
    @address.setter
    def address(self, value):
        self._address = value

    @property
    def ports(self):
        return self._ports
    
    @ports.setter
    def ports(self, value):
        self._ports = value
        
    @property
    def protocol(self):
        return self._protocol
    
    @protocol.setter
    def protocol(self, value):
        self._protocol = value    
    
    @staticmethod
    def get_csv_header(delimiter=";"):
        return delimiter.join(["Address", "Ports", "Protocol"])

    def as_csv(self, delimiter=";"):
        return delimiter.join([self.address, self.ports, self.protocol])


class ReportScanStat(object):
    def __init__(self, id="", type="", start="", end="", elapsed="", hosts_total="", hosts_up="", hosts_down="", name=""):
        self._id = id
        self._type = type
        self._start = start
        self._end = end
        self._elapsed = elapsed
        self._hosts_total = hosts_total
        self._hosts_up = hosts_up
        self._hosts_down = hosts_down
        self._name = name

    @property
    def id(self):
        return self._id

    @id.setter
    def id(self, value):
        self._id = str(value)

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        self._type = value

    @property
    def start(self):
        return self._start

    @start.setter
    def start(self, value):
        self._start = str(value)

    @property
    def end(self):
        return self._end

    @end.setter
    def end(self, value):
        self._end = str(value)

    @property
    def elapsed(self):
        return self._elapsed

    @elapsed.setter
    def elapsed(self, value):
        self._elapsed = str(value)

    @property
    def hosts_total(self):
        return self._hosts_total

    @hosts_total.setter
    def hosts_total(self, value):
        self._hosts_total = str(value)

    @property
    def hosts_up(self):
        return self._hosts_up

    @hosts_up.setter
    def hosts_up(self, value):
        self._hosts_up = str(value)

    @property
    def hosts_down(self):
        return self._hosts_down

    @hosts_down.setter
    def hosts_down(self, value):
        self._hosts_down = str(value)

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @staticmethod
    def get_csv_header(delimiter=";"):
        return delimiter.join(["scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down",
                               "Parameters"])

    def as_csv(self, delimiter=";"):
        return delimiter.join([self.id, self.start, self.end, self.elapsed, self.hosts_total, self.hosts_up,
                               self.hosts_down, self.name])


