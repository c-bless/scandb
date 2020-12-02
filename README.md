This tool provides some scripts to import Nmap and Nessus scan results into a sqlite database.
The following console commands are available after installation:
- scandb-importer
- scandb-analyzer
- scandb-genhostportlist


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


## scandb-analyzer
This command can be used to display scan statistics or to generate target lists.

```
$ scandb-analyzer -h       
usage: scandb-analyzer [-h] [--db DB] [--scan-statistics] [--vuln-statistics] [--port-statistics] [--status STATUS] [-t PORTS] [-u PORTS] [-o UNION|INTERSECTION] [--list] [-d LIST_DELIMITER] [--list-file FILE]

optional arguments:
  -h, --help            show this help message and exit
  --db DB
  --scan-statistics     Print statistics for each scan
  --vuln-statistics     Print number of vulns foreach host.
  --port-statistics     Print number of 'open' TCP and UDP ports foreach host.
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
$ scandb-analyzer --list
192.168.1.2
192.168.1.1
192.168.1.11
192.168.1.19
```

Generate a list of all hosts (with status 'up') and use the delimiter "," instead of a new line:
```
$ scandb-analyzer --list -d ","
192.168.1.2,192.168.1.1,192.168.1.11,192.168.1.19
```

Generate a list of hosts with open tcp port 80:
```
$ scandb-analyzer --list -d " " -t 80
192.168.1.2 192.168.1.1
```

Generate a list of hosts with open udp port 53:
```
$ scandb-analyzer --list -d " " -u 53
192.168.1.19 192.168.1.1
```


Generate a list of hosts with open tcp port 80 or udp port 53:
```
$ scandb-analyzer --list -d " " -u 53 -t 80
192.168.1.19 192.168.1.2 192.168.1.1
```

Generate a list of hosts with open tcp port 80 and udp port 53:
```
$ scandb-analyzer --list -d " " -u 53 -t 80 -o intersection
192.168.1.1
```




## scandb-genhostportlist
This command creates a csv file with all IP addresses and their open ports.
```
$ scandb-genhostportlist
Results written to : hostportlist.csv
```

```
192.168.1.1;53;udp
192.168.1.1;53,80,443,5060,8181;tcp
192.168.1.19;161;udp
192.168.1.2;53,80,5060,8089;tcp
```


## scandb-genvulnstat
This command creates a csv file with numbers of vulnerabilities per category and host.
```
$ scandb-genvulnstat
Results written to : vulnstat.csv
```