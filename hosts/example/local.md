---
vulnx: "snapd &lt; 2.37 (Ubuntu) - 'dirty_sock' Local Privilege Escalation"
---

## Vulnerability Explanation:
This exploit bypasses access control checks to use a restricted API function (POST /v2/create-user) of the local snapd service. This queries the Ubuntu SSO for a username and public SSH key of a provided email address, and then creates a local user based on these value.

## Vulnerability Fix:
Install a version greater than 2.37 of snapd.

## Severity: Critical

## Proof of Concept Code:
No modifications made to the proof of concept code.

The exploit can be found here:
https://www.exploit-db.com/exploits/46361

## Further exploitation:
During the exam we ran linuxprivchecker.py to find a vulnerability:

https://github.com/sleventyeleven/linuxprivchecker/blob/master/linuxprivchecker.py

The output quickly reveals that snapd is vulnerable.

```
<snip>

[+] snapd is vulnerable! 

<snip>
```

## Exploit searching
A quick search finds the following exploit:
https://www.exploit-db.com/exploits/46361

## Exploiting:
We setup a reverse shell and we run the script.
```
dirty_sock.py 10.11.1.1
```

Which results in a reverse shell connecting back to our machine
![](screenshot.png)

## Proof
The reverse shell alows us to retrieve the proof.txt file.
![](screenshot.png)

