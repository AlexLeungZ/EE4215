# Kali Tools with used commends

## [Kali Tools](https://www.kali.org/tools/)

## Used tools

1. ifconfig
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
nmap -v -A -sV 10.5.0.1
```

```markdown
Starting Nmap 7.93 ( https://nmap.org ) at 2023-03-15 06:35 UTC
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 06:35
Completed Parallel DNS resolution of 1 host. at 06:35, 0.00s elapsed
Initiating SYN Stealth Scan at 06:35
Scanning ip-10-5-0-1.ec2.internal (10.5.0.1) [1000 ports]
Discovered open port 53/tcp on 10.5.0.1
Discovered open port 22/tcp on 10.5.0.1
Completed SYN Stealth Scan at 06:35, 0.02s elapsed (1000 total ports)
Initiating Service scan at 06:35
Scanning 2 services on ip-10-5-0-1.ec2.internal (10.5.0.1)
Completed Service scan at 06:35, 16.01s elapsed (2 services on 1 host)
Initiating OS detection (try #1) against ip-10-5-0-1.ec2.internal (10.5.0.1)
NSE: Script scanning 10.5.0.1.
Initiating NSE at 06:35
Completed NSE at 06:35, 8.05s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Nmap scan report for ip-10-5-0-1.ec2.internal (10.5.0.1)
Host is up (0.000042s latency).
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
SF-Port53-TCP:V=7.93%I=7%D=3/15%Time=6411673A%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x85\x05\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Device type: general purpose
Running: Linux 2.6.X
OS CPE: cpe:/o:linux:linux_kernel:2.6.32
OS details: Linux 2.6.32
Uptime guess: 9.344 days (since Sun Mar  5 22:20:25 2023)
Network Distance: 0 hops
TCP Sequence Prediction: Difficulty=257 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Initiating NSE at 06:35
Completed NSE at 06:35, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.16 seconds
           Raw packets sent: 1022 (45.778KB) | Rcvd: 2046 (87.172KB)
```
