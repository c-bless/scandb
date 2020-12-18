import argparse

from scandb.models.report import ReportVulnStat
from scandb.models.report import ReportPortStat
from scandb.models.report import ReportHostPortStat
from scandb.models.report import ReportScanStat

from scandb.report.cli import write_to_template

from scandb.statistics.queries import get_scan_stats
from scandb.statistics.queries import get_port_stats
from scandb.statistics.queries import get_host_port_list
from scandb.statistics.queries import get_vuln_stats


def handle_scan_stats(db, outfile, write_file = False, delimiter= ";", gen_docx=False, template=""):
    results_csv = []
    results_cli = []
    fmt = '{0:^10}{1:^15}{2:^15}{3:^12}{4:^12}{5:^12}{6:^15}{7}'
    results_cli.append(fmt.format("scan id", "Start", "End", "Elapsed", "Hosts total", "Hosts up", "Hosts down",
                                  "Parameters"))
    results_csv.append(ReportScanStat.get_csv_header(delimiter=delimiter))

    stats = get_scan_stats(db)
    for s in stats:
        stat = (s)
        results_cli.append(fmt.format(stat.id, stat.start, stat.end, stat.elapsed, stat.hosts_total, stat.hosts_up,
                                      stat.hosts_down, stat.name))
        results_csv.append(s.as_csv(delimiter=delimiter))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-scan-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))
        print("Results written to : {0}".format(filename))
    if gen_docx:
        filename="{0}-scan-statistics.docx".format(outfile)
        write_to_template(template=template, outfile=filename, scan_stats=stats)


def handle_vuln_stats(db, outfile, write_file = False, delimiter=";", gen_docx=False, template=""):
    results_csv = []
    results_cli = []
    fmt = '{0:>20}{1:>15}{2:>15}{3:>15}{4:>15}{5:>15}'
    results_cli.append(fmt.format("Address", "Critical", "High", "Medium", "Low", "Info"))
    results_csv.append(ReportVulnStat.get_csv_header(delimiter=delimiter))

    stats = get_vuln_stats(db)

    for s in stats:
        results_cli.append(fmt.format(s.address, s.critical, s.high, s.medium, s.low, s.info))
        results_csv.append(s.as_csv(delimiter=delimiter))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-vuln-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))
        print("Results written to : {0}".format(filename))
    if gen_docx:
        filename="{0}-vuln-statistics.docx".format(outfile)
        write_to_template(template=template, outfile=filename, vuln_stats=stats)


def handle_port_stats(db, outfile, write_file = False, delimiter=";", gen_docx=False, template=""):
    results_csv = []
    results_cli = []
    fmt = '{0:>20}{1:>15}{2:>15}'
    results_cli.append(fmt.format("Address", "TCP", "UDP"))
    results_csv.append(ReportPortStat.get_csv_header(delimiter=delimiter))

    stats = get_port_stats(db)
    for s in stats:
        results_cli.append(fmt.format(s.address, s.tcp, s.udp))
        results_csv.append(s.as_csv(delimiter=delimiter))

    print("\n".join(results_cli))
    if write_file:
        filename = "{0}-port-statistics.csv".format(outfile)
        with open(filename, "w") as f:
            f.write("\n".join(results_csv))
        print("Results written to : {0}".format(filename))

    if gen_docx:
        filename="{0}-port-statistics.docx".format(outfile)
        write_to_template(template=template, outfile=filename, port_stats=stats)


def handle_host_port_list(db, outfile, delimiter=";", gen_docx=False, template=""):
    rows = get_host_port_list(db)

    results_csv = [ReportHostPortStat.get_csv_header(delimiter=delimiter)]

    for r in rows:
        results_csv.append(r.as_csv(delimiter=delimiter))

    filename = "{0}-hostportlist.csv".format(outfile)
    with open(filename,'w') as f:
        f.write("\n".join(results_csv))
    print ("Results written to : {0}".format(filename))

    if gen_docx:
        filename="{0}-hostportlist.docx".format(outfile)
        write_to_template(template=template, outfile=filename, host_portlist=rows)


def statistics_cli():
    parser = argparse.ArgumentParser(description="I can generate statistics about vulnerabilities, open ports or "
                                                 "for the imported scans. Furthermore I can generate a host/portlist "
                                                 "as csv file. All statistics can be displayed on stdout or they can "
                                                 "be written to csv or docx files (based on templates). "
                                                 "See https://bitbucket.org/cbless/scandb/src/master/examples/ for "
                                                 "example templates.A description of usable objects and their "
                                                 "attributes can be found under: "
                                                 "https://bitbucket.org/cbless/scandb/wiki/Report-Templates")
    parser.add_argument("--db", type=str, required=False, default="scandb.sqlite")
    parser.add_argument("-s", "--scan-statistics", required=False, action='store_true', default=False,
                        help="Print statistics for each scan")
    parser.add_argument("-v", "--vuln-statistics", required=False, action='store_true', default=False,
                        help="Print number of vulns foreach host.")
    parser.add_argument("-p", "--port-statistics", required=False, action='store_true', default=False,
                        help="Print number of 'open' TCP and UDP ports foreach host.")
    parser.add_argument("--host-portlist", required=False, action='store_true', default=False,
                        help="generate a csv with a list of TCP and UDP Ports per host")
    parser.add_argument("-d", "--delimiter", required=False, type=str,  default=";", help="Delimiter for CSV files.")
    parser.add_argument("-o", "--outfile", required=False, default="scandb", help="Prefix for output files.")
    parser.add_argument("-w", "--write-file", required=False, action='store_true', default=False,
                        help="Write data to CSV file. Prefix of filename can be changed with parameter outfile")
    parser.add_argument("--docx", required=False, action='store_true', default=False,
                        help="Render the given DOCX template for the selected statistics. Prefix of filename can be "
                             "changed with parameter '--outfile'. The template can be specified with parameter "
                             "'--template'")
    parser.add_argument("--template", type=str, required=False, default="scandb-template.docx",
                        help="Name of the template to render. Examples can be found under: "
                             "https://bitbucket.org/cbless/scandb/src/master/examples/")

    args = parser.parse_args()

    do_stats = False
    if args.scan_statistics or args.vuln_statistics or args.port_statistics:
        do_stats = True

    if not do_stats and not args.host_portlist:
        parser.print_usage()
        return

    if args.scan_statistics:
        handle_scan_stats(args.db, args.outfile, args.write_file, args.delimiter, args.docx, args.template)

    if args.vuln_statistics:
        handle_vuln_stats(args.db, args.outfile, args.write_file, args.delimiter, args.docx, args.template)

    if args.port_statistics:
        handle_port_stats(args.db, args.outfile, args.write_file, args.delimiter, args.docx, args.template)

    if args.host_portlist:
        handle_host_port_list(args.db, args.outfile, args.docx, args.template)