This tool provides some scripts to import Nmap and Nessus scan results into a sqlite database.
The following console commands are available after installation:
- scandb-importer
- scandb-services
- scandb-vulns
- scandb-statistics

## Installation
The tool has been published to pypi and can be installed via *pip*.

```
pip install scandb
```

## scandb-importer
This command can be used do import a single file or many files at once to a sqlite database.
You can use the parameters *--file* and *--dir* to specify the files that should be imported.

```
$ scandb-importer -h
usage: scandb-importer [-h] [--db DB] [--file [FILE [FILE ...]]] [--dir DIR]

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

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --status STATUS       Status string stored in database (default: up)
  -t PORTS, --tcp PORTS
                        TCP ports
  -u PORTS, --udp PORTS
                        UDP ports
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
usage: scandb-statistics [-h] [--db DB] [-s] [-v] [-p] [--host-portlist] [-d DELIMETER] [-o OUTFILE] [-w]

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
  -d DELIMETER, --delimeter DELIMETER
                        Delimeter for CSV files.
  -o OUTFILE, --outfile OUTFILE
                        Prefix for output files.
  -w, --write-file      Write data to CSV file. Prefix of filename can be changed with parameter outfile
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
$   scandb-vulns -h                                                                                           
usage: scandb-vulns [-h] [--db DB] [--min-severity MIN_SEVERITY] [--filter-by {cve,plugin-id,plugin-name,description}] --search SEARCH-Term --list {ips,details} [-d LIST_DELIMITER] [--list-file FILE]

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --min-severity MIN_SEVERITY
                        Minimum severity level (default: 0)
  --filter-by {cve,plugin-id,plugin-name,description}
                        Filter hosts by the given filter. The search value is specified with option --search. The following fields can be used as filter 'cve', 'plugin-id', 'plugin-name', 'description
  --search SEARCH-Term  Search term used for querying the database. The type of the search field can be selected with the parameter --filter-by
  --list {ips,details}  Generate a target list of ip addresses when selecting 'ips' or display the columnsAddress,Port,Protocol,Severity,Plugin-ID,Plugin-Name
  -d LIST_DELIMITER, --list-delimiter LIST_DELIMITER
                        Delimiter used to separate hosts in the list output. Only when --list ips is used.
  --list-file FILE      Generate a file with the targets instead of printing them to stdout
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
