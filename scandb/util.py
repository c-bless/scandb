
def get_open_ports(host, protocol='tcp'):
    ports = []
    for port, proto in host.get_open_ports():
        if protocol == proto:
            ports.append(port)
    return ports


def get_ports(host):
    """
    This function generates a list of open ports. Each entry is a tuple which contains the port, protocol, servicename,
    state and a banner string.

    :param host: The NmapHost object
    :type host libnmap.objects.host.NmapHost

    :return: list of tuples
    """
    ports = []
    for port, proto in host.get_ports():
        if host.get_service(port, proto) is not None:
            service = host.get_service(port, proto)
            servicename = service.service
            state = service.state
            banner = service.banner
            ports.append((port, proto, servicename, state, banner))
    return ports


def get_hostname(host):
    """
    This function get the hostname of the given host.

    :param host: The NmapHost object
    :type host: libnmap.objects.host.NmapHost

    :return: hostname
    :rtype: str
    """
    hostname = ""
    for name in host.hostnames:
        if name == "localhost" and hostname != "":
            continue
        hostname = name
    return hostname


def get_best_os_match(host):
    os_matches = host.os_match_probabilities()
    os = ""
    if len(os_matches) > 0:
        os = os_matches[0].name
    return os


def host_to_tupel(host):
    hostname = get_hostname(host)
    os = get_best_os_match(host)
    return host.address, hostname, os, host.status