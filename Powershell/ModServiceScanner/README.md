# ModServiceScanner v0.1
## A simple scanner to check windows services for vulnerabilities,
The first check looks to see if any service misconfigurations that are modifiable for groups User and Everyone, \
The second check looks to see if any service binary paths are unquoted and have a space in them, \
The User can then use icacls to check whether the directory is modifiable and a malicious application can be inserted.

```
[+] Scanning Services for misconfigurations:

[!] Vulnerable Services Found:
[+] Checking for Unquoted Service Paths:
[!] Path: C:\Program Files\Redis\redis-service.exe

[+] Check if the directory has AD/WD permissions with icacls
```
