import argparse

from scandb.services.queries import get_host_list, get_host_list_by_tcp, get_host_list_by_udp


def services_cli():
    parser = argparse.ArgumentParser(description="I can be used to generate target lists (ip address lists) that can be"
                                                 " used as input for other tools based on given filters.")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("--status", type=str, required=False, default="up",
                        help="Status string stored in database (default: up)")
    parser.add_argument("-t", "--tcp", metavar="PORTS", required=False, type=str, default=None,
                        help="Open TCP ports")
    parser.add_argument("-u", "--udp", metavar="PORTS", required=False, type=str, default=None,
                        help="Open UDP ports")
    parser.add_argument("-o", "--operation", metavar="UNION|INTERSECTION", required=False, type=str, default="UNION",
                        help="Operation to combine the sets of TCP and UDP ports (default: UNION)")
    parser.add_argument("--list", required=False, action='store_true', default=False,
                        help="Generate a target list")
    parser.add_argument("-d", "--list-delimiter", required=False, default="\n",
                        help="Delimiter used to separate hosts in the list output")
    parser.add_argument("--list-file", metavar="FILE", required=False, type=str, default=None,
                        help="Generate a file with the targets instead of printing them to stdout")
    args = parser.parse_args()

    if not args.list and args.list_file is None:
        parser.print_usage()
        return

    ips = []

    if args.tcp is None and args.udp is None:
        ips = get_host_list(args.db, args.status)
    else:
        tcp_ports = []
        udp_ports = []
        if args.tcp is not None:
            tcp_ports = get_host_list_by_tcp(args.db, args.tcp.split(","))
        if args.udp is not None:
            udp_ports = get_host_list_by_udp(args.db, args.udp.split(","))

        if args.operation.upper() == 'INTERSECTION':
            ips = set(tcp_ports).intersection(udp_ports)
        else:
            ips = set(tcp_ports).union(udp_ports)

    if args.list:
        print(args.list_delimiter.join(ips))

    if args.list_file:
        with open(args.list_file, 'w') as f:
            f.write("\n".join(ips))


