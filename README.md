This tool provides some scripts to import Nmap and Nessus scan results into a sqlite database.
The following console commands are available after installation:
- scandb-importer
- scandb-services
- scandb-vulns
- scandb-statistics
- scandb-compare
- scandb-report

## License
This script is licensed under the GNU General Public License in version 3. See http://www.gnu.org/licenses/ for further details.

## Installation
The tool has been published to pypi and can be installed via *pip*.

```
pip install scandb
```

## scandb-importer
This command can be used do import a single file or many files at once to a sqlite database.
You can use the parameters *--file* and *--dir* to specify the files that should be imported.

```
$  scandb-importer -h     
usage: scandb-importer [-h] [--db DB] [--file [FILE [FILE ...]]] [--dir DIR]

I will import Nmap and Nessus scans into a SQLite database.

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --file [FILE [FILE ...]]
                        The nessus and/or nmap file(s)
  --dir DIR             Directory name with nessus and/or nmap files

```


## scandb-services
This command can be used to generate target lists based on port filters.

```
$ scandb-services -h
usage: scandb-services [-h] [--db DB] [--status STATUS] [-t PORTS] [-u PORTS] [-o UNION|INTERSECTION] [--list] [-d LIST_DELIMITER] [--list-file FILE]

I can be used to generate target lists (ip address lists) that can be used as input for other tools based on given filters.

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --status STATUS       Status string stored in database (default: up)
  -t PORTS, --tcp PORTS
                        Open TCP ports
  -u PORTS, --udp PORTS
                        Open UDP ports
  -o UNION|INTERSECTION, --operation UNION|INTERSECTION
                        Operation to combine the sets of TCP and UDP ports (default: UNION)
  --list                Generate a target list
  -d LIST_DELIMITER, --list-delimiter LIST_DELIMITER
                        Delimiter used to separate hosts in the list output
  --list-file FILE      Generate a file with the targets instead of printing them to stdout

```

Generate a list of all hosts (with status 'up'):
```
$ scandb-services --list
192.168.1.2
192.168.1.1
192.168.1.11
192.168.1.19
```

Generate a list of all hosts (with status 'up') and use the delimiter "," instead of a new line:
```
$ scandb-services --list -d ","
192.168.1.2,192.168.1.1,192.168.1.11,192.168.1.19
```

Generate a list of hosts with open tcp port 80:
```
$ scandb-services --list -d " " -t 80
192.168.1.2 192.168.1.1
```

Generate a list of hosts with open udp port 53:
```
$ scandb-services --list -d " " -u 53
192.168.1.19 192.168.1.1
```


Generate a list of hosts with open tcp port 80 or udp port 53:
```
$ scandb-services --list -d " " -u 53 -t 80
192.168.1.19 192.168.1.2 192.168.1.1
```

Generate a list of hosts with open tcp port 80 and udp port 53:
```
$ scandb-services --list -d " " -u 53 -t 80 -o intersection
192.168.1.1
```




## scandb-statistics
This command can be used to display statistics or to create a csv file with all IP addresses and their open ports.
```
$  scandb-statistics -h
usage: scandb-statistics [-h] [--db DB] [-s] [-v] [-p] [--host-portlist] [-d DELIMITER] [-o OUTFILE] [-w] [--docx] [--template TEMPLATE]

I can generate statistics about vulnerabilities, open ports or for the imported scans. Furthermore I can generate a host/portlist as csv file. All statistics can be displayed on stdout or they can be written to csv or docx files (based on templates). See
https://bitbucket.org/cbless/scandb/src/master/examples/ for example templates.A description of usable objects and their attributes can be found under: https://bitbucket.org/cbless/scandb/wiki/Report-Templates

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  -s, --scan-statistics
                        Print statistics for each scan
  -v, --vuln-statistics
                        Print number of vulns foreach host.
  -p, --port-statistics
                        Print number of 'open' TCP and UDP ports foreach host.
  --host-portlist       generate a csv with a list of TCP and UDP Ports per host
  -d DELIMITER, --delimiter DELIMITER
                        Delimiter for CSV files.
  -o OUTFILE, --outfile OUTFILE
                        Prefix for output files.
  -w, --write-file      Write data to CSV file. Prefix of filename can be changed with parameter outfile
  --docx                Render the given DOCX template for the selected statistics. Prefix of filename can be changed with parameter '--outfile'. The template can be specified with parameter '--template'
  --template TEMPLATE   Name of the template to render. Examples can be found under: https://bitbucket.org/cbless/scandb/src/master/examples/
```

To generate a list of open TCP and UDP ports you can use the following command:
```
$  scandb-statistics --host-portlist
Results written to : scandb-hostportlist.csv
```

The content of the file scandb-hostportlist.csv will looks like this.
```
192.168.1.1;53;udp
192.168.1.1;53,80,443,5060,8181;tcp
192.168.1.19;161;udp
192.168.1.2;53,80,5060,8089;tcp
```


## scandb-vulns
This command can be used to generate target lists based on vulnerability filters.
```
$    scandb-vulns -h        
usage: scandb-vulns [-h] [--db DB] [--min-severity MIN_SEVERITY] [--filter-by {cve,plugin-id,plugin-name,plugin-output,description,ip}] [--search SEARCH-Term] [--list {ips,details}] [-d LIST_DELIMITER] [--list-file FILE]

I can be used to query the sqlite database to filter specific vulnerabilities. Results can be displayed to stdout or written to a csv file.

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --min-severity MIN_SEVERITY
                        Minimum severity level (default: 0)
  --filter-by {cve,plugin-id,plugin-name,plugin-output,description,ip}
                        Filter hosts by the given filter. The search value is specified with option --search. The following fields can be used as filter 'cve', 'plugin-id', 'plugin-name', 'description', 'ip'. (Note: The option 'ip' returns just the ip itself, when '
                        --list ips' is selected and a vulnerability was detected for that ip, otherwise the result is empty.)
  --search SEARCH-Term  Search term used for querying the database. The type of the search field can be selected with the parameter --filter-by
  --list {ips,details}  Generate a target list of ip addresses when selecting 'ips' or display the columns Address,Port,Protocol,Severity,Plugin-ID,Plugin-Name
  -d LIST_DELIMITER, --list-delimiter LIST_DELIMITER
                        Delimiter used to separate hosts in the list output. Only when --list ips is used.
  --list-file FILE      Generate a file with the results instead of printing them to stdout. Incase of '--list ips' is selected the file contains a list of ip address (one per line), in case of '--list details' it will be a csv file
```

Select hosts that are affected by a cve starting with CVE-2015- and display only the ip address. 
```
scandb-vulns --filter-by cve --search CVE-2015- --list ips
```

Select hosts that are affected by a vulnerability with Plugin-ID 48243 and display the columns Address,Port,Protocol,Severity,Plugin-ID,Plugin-Name. 
```
 scandb-vulns --db test.sqlite --filter-by plugin-id --search 48243 --list details
             Address           Port       Protocol       Severity      Plugin-IDPlugin-Name
      192.168.100.101            443            tcp              0          48243PHP Version Detection
      192.168.100.111             80            tcp              0          48243PHP Version Detection
      192.168.100.122            443            tcp              0          48243PHP Version Detection
```

## scandb-compare
This command can be used to compare two scandb database instances (databases must be created with scandb v0.4.0 or 
a later version). 
```
$   scandb-compare -h
usage: scandb-compare [-h] [--db1 DB1] [--db2 DB2] [-v] [-p] [--host-portlist] [-o OUTFILE]

optional arguments:
  -h, --help            show this help message and exit
  --db1 DB1
  --db2 DB2
  -v, --vuln-statistics
                        Print number of vulns foreach host and db.
  -p, --port-statistics
                        Print number of 'open' TCP and UDP ports foreach host and db.
  --host-portlist       generate a csv with a list of TCP and UDP Ports per host and db
  -o OUTFILE, --outfile OUTFILE
                        Prefix for output files.

```

## scandb-report
This command can be used to export vulnerabilities to a docx format based on custom templates (statistics and host/port lists will be added as well). 
Examples can be found under:  https://bitbucket.org/cbless/scandb/src/master/examples/


```
$     scandb-report -h       
usage: scandb-report [-h] [--db DB] [--min-severity MIN_SEVERITY] [--template TEMPLATE] [--outfile OUTFILE]

Generate DOCX reports based on custom templates. See https://bitbucket.org/cbless/scandb/src/master/examples/ for example templates.A description of usable objects and their attributes can be found under: https://bitbucket.org/cbless/scandb/wiki/Report-Templates

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --min-severity MIN_SEVERITY
                        Minimum severity level (default: 0)
  --template TEMPLATE   Name of the template to render. Examples can be found under: https://bitbucket.org/cbless/scandb/src/master/examples/
  --outfile OUTFILE     Name that is used for the generated report.
```