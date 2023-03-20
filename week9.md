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
route
```

```markdown
Kernel IP routing table
Destination     Gateway         Genmask         Flags Metric Ref    Use Iface
default         ip-172-31-0-1.e 0.0.0.0         UG    0      0        0 eth0
10.5.0.0        0.0.0.0         255.255.255.0   U     0      0        0 eth-lab
10.5.1.0        ip-10-5-0-254.e 255.255.255.0   UG    0      0        0 eth-lab
10.5.2.0        ip-10-5-0-254.e 255.255.255.0   UG    0      0        0 eth-lab
172.17.0.0      0.0.0.0         255.255.0.0     U     0      0        0 docker0
172.18.0.0      0.0.0.0         255.255.0.0     U     0      0        0 br-064138aa09a5
172.31.0.0      0.0.0.0         255.255.240.0   U     0      0        0 eth0
```

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
