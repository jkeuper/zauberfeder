---
hostname: 'example'
ip: '10.11.1.1'
tcpports: '1, 2, 3, 4'
udpports: '5, 6, 7, 8'
vulnx: 'SomeWebService <= 1.3.3 Directory Traversal RCE (CVE-2001-10000)
severity: 'Critical'
rooted: true
---

## Vulnerability Explanation:
SomeWebService is subject to a path traversal vulnerability leading to
remote code execution. This vulnerability affects SomeWebService versions 1.3.3 and below. This is
caused by an unchecked "hackme" parameter that is used to override the flux capacitor bypass.

## Vulnerability Fix:
Install the latest version of SomeWebService, current latest version 2.1.

## Severity: Critical

## Proof of Concept Code:
The only modifications made to the proof of concept code is where the reverse
shell should connect to. See marked in red below.

The exploit can be found here:
https://www.exploitdb.com/exploits/1337

```
#!/bin/bash
echo argument 1: $1
echo argument 2: $2
echo all arguments: $@
```

## Information gathering, with nmap scan
```
Starting Nmap 7.80 ( https://nmap.org ) at 2001-01-01 13:37 CET
NSE: Loaded 45 scripts for scanning.
Initiating Ping Scan at 09:23
Scanning 10.11.1.1 [4 ports]
Completed Ping Scan at 09:24, 0.16s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 09:24
Completed Parallel DNS resolution of 1 host. at 09:24, 8.02s elapsed
Initiating SYN Stealth Scan at 09:24
Scanning 10.11.1.1 [65535 ports]
Discovered open port 1/tcp on 10.11.1.1
...
Completed SYN Stealth Scan at 13:38, 41.69s elapsed (65535 total ports)
Initiating Service scan at 13:38
Scanning 13 services on 10.11.1.1
Service scan Timing: About 53.85% done; ETC: 09:26 (0:00:48 remaining)
Completed Service scan at 09:25, 55.42s elapsed (13 services on 1 host)
NSE: Script scanning 10.11.1.1.
Initiating NSE at 09:25
Completed NSE at 09:25, 0.66s elapsed
Initiating NSE at 09:25
Completed NSE at 09:25, 0.48s elapsed
Nmap scan report for 10.11.1.1
Host is up, received echo-reply ttl 127 (0.12s latency).
Not shown: 63673 closed ports, 1849 filtered ports
Reason: 63673 resets and 1849 no-responses
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT STATE SERVICE REASON VERSION
1/tcp open msrpc syn-ack ttl 127 Microsoft Windows RPC
Service Info: OSs: Windows, Windows Server 1995 R1 - 2000; CPE: cpe:/o:microsoft:windows
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 107.01 seconds
Raw packets sent: 85444 (3.760MB) | Rcvd: 74052 (2.979M
```
## Check the robots.txt
![](screenshot.png)

## Check the url /SomeWebService/
![](screenshot.png)

## Check version
The source of the page reveals the version is 1.3.3.7:
![](screenshot.png)

## Default credentials
Searching for default credentials works and we find “admin/admin”:
![](screenshot.png)

## Exploit searching
A quick search finds the following exploit:
https://www.exploit-db.com/exploits/1337

## Exploiting:
We setup a reverse shell and trigger the following url:
http://10.11.1.1/SomeWebService/?flux=GimmeReverseShell
Which results in a reverse shell connecting back to our machine
![](screenshot.png)

## Proof
![](screenshot.png)


