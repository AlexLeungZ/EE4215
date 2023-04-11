# Kali Tools with used commends

## [Kali Tools](https://www.kali.org/tools/)

## Used tools

1. ifconfig / route

   ```bash
   route
   ```

2. [nmap](https://www.kali.org/tools/nmap/)

   ```bash
   nmap -v -A -sV 10.5.0.1
   ```

3. nslookup

   ```bash
   nslookup -type=any megacorpone.com
   ```

4. [dnsrecon](https://www.kali.org/tools/dnsrecon/)

   ```bash
   dnsrecon -d megacorpone.com -a
   ```

## Result

```bash
ifconfig
```

```markdown
eth-lab: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.5.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::c4bc:aaff:fead:64c9  prefixlen 64  scopeid 0x20<link>
        ether c6:bc:aa:ad:64:c9  txqueuelen 1000  (Ethernet)
        RX packets 26681  bytes 3740210 (3.5 MiB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 39544  bytes 2348474 (2.2 MiB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

```bash
nmap -v -A -sV 10.5.0.0/24
```

```markdown
Nmap scan report for ip-10-5-0-254.ec2.internal (10.5.0.254)
Host is up (0.000070s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
80/tcp open  http    Apache httpd 2.4.10 ((Debian) PHP/5.5.29)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: exploit.co.il : Articles : Tutorials : Reviews : Videos
|_http-server-header: Apache/2.4.10 (Debian) PHP/5.5.29
|_http-favicon: Unknown favicon MD5: 2DE296AD0CB13A815DE44437D64EE8AA
MAC Address: CA:96:35:0C:59:A9 (Unknown)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.93%E=4%D=3/20%OT=21%CT=1%CU=42964%PV=Y%DS=1%DC=D%G=Y%M=CA9635%T
OS:M=6417CCAF%P=x86_64-pc-linux-gnu)SEQ(SP=108%GCD=1%ISR=10C%TI=Z%CI=Z%II=I
OS:%TS=A)OPS(O1=M5B4ST11NW7%O2=M5B4ST11NW7%O3=M5B4NNT11NW7%O4=M5B4ST11NW7%O
OS:5=M5B4ST11NW7%O6=M5B4ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6
OS:=FE88)ECN(R=Y%DF=Y%T=3F%W=FAF0%O=M5B4NNSNW7%CC=Y%Q=)T1(R=Y%DF=Y%T=3F%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=Y%DF=Y%T=40%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)T3(R=Y%D
OS:F=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T4(R=Y%DF=Y%T=3F%W=0%S=A%A=Z%F=R%O=
OS:%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%
OS:W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=
OS:)U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%
OS:DFI=N%T=40%CD=S)

Uptime guess: 34.227 days (since Mon Feb 13 21:35:37 2023)
Network Distance: 1 hop
TCP Sequence Prediction: Difficulty=264 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE
HOP RTT     ADDRESS
1   0.07 ms ip-10-5-0-254.ec2.internal (10.5.0.254)


Nmap scan report for ip-10-5-0-1.ec2.internal (10.5.0.1)
Host is up (0.000056s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 099aaeb88ff400b961db3b43d9655d9d (RSA)
|   256 d8cd6a3b85c8f3119d64d2149a51f407 (ECDSA)
|_  256 023146bcfd88cca4ee6f899ade2d85f1 (ED25519)
53/tcp open  domain  (generic dns response: REFUSED)
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.93%I=7%D=3/20%Time=6417CCBA%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x85\x05\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Uptime guess: 42.021 days (since Mon Feb  6 02:31:36 2023)
Network Distance: 0 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```bash
nmap -v -A -sV 10.5.1.0/24
```

```markdown
Nmap scan report for ip-10-5-1-10.ec2.internal (10.5.1.10)
Host is up (0.000069s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.10 ((Debian) PHP/5.5.29)
|_http-server-header: Apache/2.4.10 (Debian) PHP/5.5.29
|_http-favicon: Unknown favicon MD5: 2DE296AD0CB13A815DE44437D64EE8AA
|_http-title: exploit.co.il : Articles : Tutorials : Reviews : Videos
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Uptime guess: 3.458 days (since Thu Mar 16 16:05:42 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=260 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   0.01 ms ip-10-5-0-254.ec2.internal (10.5.0.254)
2   0.06 ms ip-10-5-1-10.ec2.internal (10.5.1.10)


Nmap scan report for ip-10-5-1-11.ec2.internal (10.5.1.11)
Host is up (0.000022s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Uptime guess: 34.229 days (since Mon Feb 13 21:35:37 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Unix

TRACEROUTE (using port 443/tcp)
HOP RTT     ADDRESS
-   Hop 1 is the same as for 10.5.1.10
2   0.03 ms ip-10-5-1-11.ec2.internal (10.5.1.11)


Nmap scan report for ip-10-5-1-12.ec2.internal (10.5.1.12)
Host is up (0.000019s latency).
Not shown: 999 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
3306/tcp open  mysql   MySQL 5.7.39
| mysql-info:
|   Protocol: 10
|   Version: 5.7.39
|   Thread ID: 206
|   Capabilities flags: 65535
|   Some Capabilities: Support41Auth, Speaks41ProtocolOld, IgnoreSigpipes, SwitchToSSLAfterHandshake, SupportsTransactions, SupportsCompression, InteractiveClient, ConnectWithDatabase, ODBCClient, Speaks41ProtocolNew, LongPassword, LongColumnFlag, DontAllowDatabaseTableColumn, IgnoreSpaceBeforeParenthesis, SupportsLoadDataLocal, FoundRows, SupportsMultipleResults, SupportsAuthPlugins, SupportsMultipleStatments
|   Status: Autocommit
|   Salt: \x11\x08\x07Ve\x05G4%\x10
| \x06 ! ?#\x07j@
|_  Auth Plugin Name: mysql_native_password
| ssl-cert: Subject: commonName=MySQL_Server_5.7.39_Auto_Generated_Server_Certificate
| Issuer: commonName=MySQL_Server_5.7.39_Auto_Generated_CA_Certificate
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-10-01T05:21:09
| Not valid after:  2032-09-28T05:21:09
| MD5:   2e2e0ac0b5d55f2cef076bd80a382ea6
|_SHA-1: e3e3d1f83c816e4ad15b6d0df04d5f5f2d8bdb93
|_ssl-date: TLS randomness does not represent time
Device type: general purpose
Running: Linux 4.X|5.X
OS CPE: cpe:/o:linux:linux_kernel:4 cpe:/o:linux:linux_kernel:5
OS details: Linux 4.15 - 5.6
Uptime guess: 10.744 days (since Thu Mar  9 09:13:48 2023)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=255 (Good luck!)
IP ID Sequence Generation: All zeros

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
-   Hop 1 is the same as for 10.5.1.10
2   0.03 ms ip-10-5-1-12.ec2.internal (10.5.1.12)


Nmap scan report for ip-10-5-1-254.ec2.internal (10.5.1.254)
Host is up (0.000036s latency).
All 1000 scanned ports on ip-10-5-1-254.ec2.internal (10.5.1.254) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE (using port 21/tcp)
HOP RTT     ADDRESS
1   0.01 ms ip-10-5-1-254.ec2.internal (10.5.1.254)
```

```bash
nmap -v -A -sV 10.5.2.0/24
```

```markdown
Nmap scan report for ip-10-5-2-254.ec2.internal (10.5.2.254)
Host is up (0.000040s latency).
All 1000 scanned ports on ip-10-5-2-254.ec2.internal (10.5.2.254) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
Too many fingerprints match this host to give specific OS details
Network Distance: 1 hop

TRACEROUTE (using port 1720/tcp)
HOP RTT     ADDRESS
1   0.03 ms ip-10-5-2-254.ec2.internal (10.5.2.254)
```

## Extra

```bash
nmap -v -A -sV 10.5.0.1
```

```markdown
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-20 01:28 UTC
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 01:28
Completed Parallel DNS resolution of 1 host. at 01:28, 0.00s elapsed
Initiating SYN Stealth Scan at 01:28
Scanning ip-10-5-0-1.ec2.internal (10.5.0.1) [1000 ports]
Discovered open port 22/tcp on 10.5.0.1
Discovered open port 53/tcp on 10.5.0.1
Completed SYN Stealth Scan at 01:28, 0.02s elapsed (1000 total ports)
Initiating Service scan at 01:28
Scanning 2 services on ip-10-5-0-1.ec2.internal (10.5.0.1)
Completed Service scan at 01:28, 16.01s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against ip-10-5-0-1.ec2.internal (10.5.0.1)
NSE: Script scanning 10.5.0.1.
Initiating NSE at 01:28
Completed NSE at 01:28, 8.05s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Nmap scan report for ip-10-5-0-1.ec2.internal (10.5.0.1)
Host is up (0.000052s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.4p1 Debian 5+deb11u1 (protocol 2.0)
| ssh-hostkey:
|   3072 099aaeb88ff400b961db3b43d9655d9d (RSA)
|   256 d8cd6a3b85c8f3119d64d2149a51f407 (ECDSA)
|_  256 023146bcfd88cca4ee6f899ade2d85f1 (ED25519)
53/tcp open  domain  (generic dns response: REFUSED)
| fingerprint-strings:
|   DNSVersionBindReqTCP:
|     version
|_    bind
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.93%I=7%D=3/20%Time=6417B6CA%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x85\x05\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Uptime guess: 41.956 days (since Mon Feb  6 02:31:36 2023)
Network Distance: 0 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Initiating NSE at 01:28
Completed NSE at 01:28, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.18 seconds
           Raw packets sent: 1022 (45.778KB) | Rcvd: 2044 (87.068KB)
```

```bash
nslookup -type=any megacorpone.com
```

```markdown
Server:         172.31.0.2
Address:        172.31.0.2#53

Non-authoritative answer:
megacorpone.com nameserver = ns3.megacorpone.com.
megacorpone.com nameserver = ns1.megacorpone.com.
megacorpone.com nameserver = ns2.megacorpone.com.
megacorpone.com mail exchanger = 20 spool.mail.gandi.net.
megacorpone.com mail exchanger = 50 mail.megacorpone.com.
megacorpone.com mail exchanger = 60 mail2.megacorpone.com.
megacorpone.com mail exchanger = 10 fb.mail.gandi.net.
megacorpone.com text = "Try Harder"
megacorpone.com text = "google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA"
megacorpone.com
        origin = ns1.megacorpone.com
        mail addr = admin.megacorpone.com
        serial = 202102161
        refresh = 28800
        retry = 7200
        expire = 2419200
        minimum = 300

Authoritative answers can be found from:
```

```bash
dnsrecon -d megacorpone.com -a
```

```markdown
[*] std: Performing General Enumeration against: megacorpone.com...
[*] Checking for Zone Transfer for megacorpone.com name servers
[*] Resolving SOA Record
[+]      SOA ns1.megacorpone.com 51.79.37.18
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS ns3.megacorpone.com 66.70.207.180
[+]      NS ns1.megacorpone.com 51.79.37.18
[+]      NS ns2.megacorpone.com 51.222.39.63
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server 51.222.39.63
[+] 51.222.39.63 Has port 53 TCP Open
[+] Zone Transfer was successful!!
[*]      NS ns1.megacorpone.com 51.79.37.18
[*]      NS ns2.megacorpone.com 51.222.39.63
[*]      NS ns3.megacorpone.com 66.70.207.180
[*]      TXT Try Harder
[*]      TXT google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.217
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.215
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.216
[*]      MX @.megacorpone.com spool.mail.gandi.net 217.70.178.1
[*]      A admin.megacorpone.com 51.222.169.208
[*]      A beta.megacorpone.com 51.222.169.209
[*]      A fs1.megacorpone.com 51.222.169.210
[*]      A intranet.megacorpone.com 51.222.169.211
[*]      A mail.megacorpone.com 51.222.169.212
[*]      A mail2.megacorpone.com 51.222.169.213
[*]      A ns1.megacorpone.com 51.79.37.18
[*]      A ns2.megacorpone.com 51.222.39.63
[*]      A ns3.megacorpone.com 66.70.207.180
[*]      A router.megacorpone.com 51.222.169.214
[*]      A siem.megacorpone.com 51.222.169.215
[*]      A snmp.megacorpone.com 51.222.169.216
[*]      A support.megacorpone.com 51.222.169.218
[*]      A syslog.megacorpone.com 51.222.169.217
[*]      A test.megacorpone.com 51.222.169.219
[*]      A vpn.megacorpone.com 51.222.169.220
[*]      A www.megacorpone.com 149.56.244.87
[*]      A www2.megacorpone.com 149.56.244.87
[*]
[*] Trying NS server 66.70.207.180
[+] 66.70.207.180 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server 51.79.37.18
[+] 51.79.37.18 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*] Checking for Zone Transfer for megacorpone.com name servers
[*] Resolving SOA Record
[+]      SOA ns1.megacorpone.com 51.79.37.18
[*] Resolving NS Records
[*] NS Servers found:
[+]      NS ns3.megacorpone.com 66.70.207.180
[+]      NS ns1.megacorpone.com 51.79.37.18
[+]      NS ns2.megacorpone.com 51.222.39.63
[*] Removing any duplicate NS server IP Addresses...
[*]
[*] Trying NS server 51.222.39.63
[+] 51.222.39.63 Has port 53 TCP Open
[+] Zone Transfer was successful!!
[*]      NS ns1.megacorpone.com 51.79.37.18
[*]      NS ns2.megacorpone.com 51.222.39.63
[*]      NS ns3.megacorpone.com 66.70.207.180
[*]      TXT Try Harder
[*]      TXT google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.216
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.217
[*]      MX @.megacorpone.com fb.mail.gandi.net 217.70.178.215
[*]      MX @.megacorpone.com spool.mail.gandi.net 217.70.178.1
[*]      A admin.megacorpone.com 51.222.169.208
[*]      A beta.megacorpone.com 51.222.169.209
[*]      A fs1.megacorpone.com 51.222.169.210
[*]      A intranet.megacorpone.com 51.222.169.211
[*]      A mail.megacorpone.com 51.222.169.212
[*]      A mail2.megacorpone.com 51.222.169.213
[*]      A ns1.megacorpone.com 51.79.37.18
[*]      A ns2.megacorpone.com 51.222.39.63
[*]      A ns3.megacorpone.com 66.70.207.180
[*]      A router.megacorpone.com 51.222.169.214
[*]      A siem.megacorpone.com 51.222.169.215
[*]      A snmp.megacorpone.com 51.222.169.216
[*]      A support.megacorpone.com 51.222.169.218
[*]      A syslog.megacorpone.com 51.222.169.217
[*]      A test.megacorpone.com 51.222.169.219
[*]      A vpn.megacorpone.com 51.222.169.220
[*]      A www.megacorpone.com 149.56.244.87
[*]      A www2.megacorpone.com 149.56.244.87
[*]
[*] Trying NS server 66.70.207.180
[+] 66.70.207.180 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[*]
[*] Trying NS server 51.79.37.18
[+] 51.79.37.18 Has port 53 TCP Open
[-] Zone Transfer Failed (Zone transfer error: REFUSED)
[-] DNSSEC is not configured for megacorpone.com
[*]      SOA ns1.megacorpone.com 51.79.37.18
[*]      NS ns1.megacorpone.com 51.79.37.18
[*]      Bind Version for 51.79.37.18 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      NS ns2.megacorpone.com 51.222.39.63
[*]      Bind Version for 51.222.39.63 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      NS ns3.megacorpone.com 66.70.207.180
[*]      Bind Version for 66.70.207.180 "9.11.5-P4-5.1+deb10u2-Debian"
[*]      MX fb.mail.gandi.net 217.70.178.215
[*]      MX fb.mail.gandi.net 217.70.178.216
[*]      MX fb.mail.gandi.net 217.70.178.217
[*]      MX spool.mail.gandi.net 217.70.178.1
[*]      MX mail.megacorpone.com 51.222.169.212
[*]      MX mail2.megacorpone.com 51.222.169.213
[*]      TXT megacorpone.com google-site-verification=U7B_b0HNeBtY4qYGQZNsEYXfCJ32hMNV3GtC0wWq5pA
[*]      TXT megacorpone.com Try Harder
[*] Enumerating SRV Records
[+] 0 Records Found
```

## Terminal output

- [tmux](tmux.txt)
