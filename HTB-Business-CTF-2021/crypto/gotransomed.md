# Got Ransomed

Got Ransomed was the least solved crypto challenge. It involved retrieving the Python source code of a PyInstaller executable and abusing a weak prime number generator to factorize a 2048-bit RSA modulus.

## Where is the source code?!

We were given SSH access to a machine which was hit by a ransomware:

```
$ ssh -p 30137 developer@159.65.58.156
developer@159.65.58.156's password: 
*** You got ransomed!***
Seems like your manager lacks some basic training on phishing campaigns.

developer@cryptobusinessgotransomed-12164-64dd76694c-zmvkb:~$ cd /home/manager/
developer@cryptobusinessgotransomed-12164-64dd76694c-zmvkb:/home/manager$ ls -la
total 2816
drwxr-xr-x 1 manager manager    4096 Jul 19 10:19 .
drwxr-xr-x 1 root    root       4096 Jul 19 10:19 ..
-rw-r--r-- 1 root    root        240 Jul 19 10:19 .bash_logout.enc
-rw-r--r-- 1 root    root       3792 Jul 19 10:19 .bashrc.enc
-rwxr-xr-x 1 root    root    1383160 Jul 19 09:33 .evil
-rw-r--r-- 1 root    root        832 Jul 19 10:19 .profile.enc
-rw-r--r-- 1 root    root    1385680 Jul 19 10:19 Payroll_Schedule.pdf.enc
-rw-r--r-- 1 root    root      74016 Jul 19 10:19 data_breach_response.pdf.enc
-rw-r--r-- 1 root    root         64 Jul 19 10:19 flag.txt.enc
-rw-r--r-- 1 root    root       1289 Jul 19 10:19 public_key.txt
```

Among the files is an executable named `.evil` that seems rather intriguing. I first tried to open it in a decompiler but the executable seemed a bit non-standard and reversing is not my strong suit so I just ran it in a VM :). I got the following error:

```
$ ./.evil
Fatal Python error: initfsencoding: Unable to get the locale encoding
ModuleNotFoundError: No module named 'encodings'

Current thread 0x00007f2208114b80 (most recent call first):
```

It seems like the program is trying to load some Python module. It sure looks like some PyInstaller generated executable! Basically, what PyInstaller does is archiving the Python source code as well as the Python interpreter into a single executable file so that it can act as a standalone binary. When executed, the source code and the interpreter are uncompressed into a temporary folder. Finally, the Python code is executed the same it would normally be executed.

This is rather good news as it means we do not have to reverse anything because we can just extract the compiled Python source code from the binary and uncompile it.

Extracting the compiled Python source code can be done with [pyinstxtractor](https://github.com/extremecoders-re/pyinstxtractor). Be careful to use the same Python version as the one used to create the PyInstaller executable (pyinstxtractor will print a warning otherwise). For ELF binaries, [an additionnal step](https://github.com/extremecoders-re/pyinstxtractor/wiki/Extracting-Linux-ELF-binaries) must be done:

```
$ objcopy --dump-section pydata=pydata.dump .evil
$ python3 pyinstxtractor.py pydata.dump

[+] Processing pydata.dump
[+] Pyinstaller version: 2.1+
[+] Python version: 37
[+] Length of package: 1339359 bytes
[+] Found 7 files in CArchive
[+] Beginning extraction...please standby
[+] Possible entry point: pyiboot01_bootstrap.pyc
[+] Possible entry point: ransomware.pyc
[+] Found 181 files in PYZ archive
[+] Successfully extracted pyinstaller archive: pydata.dump

You can now use a python decompiler on the pyc files within the extracted directory

$ ls pydata.dump_extracted/
pyiboot01_bootstrap.pyc  pyimod01_os_path.pyc  pyimod02_archive.pyc  pyimod03_importers.pyc  PYZ-00.pyz  PYZ-00.pyz_extracted  ransomware.pyc  struct.pyc
```

Hmmm, the ransomware.pyc file seems particularly interesting! Compiled Python files can be easily uncompiled with [uncompyle6](https://github.com/rocky/python-uncompyle6):

```
$ uncompyle6 pydata.dump_extracted/ransomware.pyc > ransomware.py
```

## This prime is sus

The ransomware script is rather straightforward:

  1. A random AES key is generated
  2. An 2048-bit RSA key is generated with a custom prime generator
  3. Each file is encrypted with AES-CBC and the encryption key previously generated
  4. The AES key is encrypted with the RSA key

Everything is standard cryptographically speaking, except for the prime number generation function:

```
def getPrime(self, bits):
    while 1:
        prime = getrandbits(32) * (2 ** bits - getrandbits(128) - getrandbits(32)) + getrandbits(128)
        if isPrime(prime):
            return prime
```

From now on, the goal is pretty clear: we need to abuse this weird prime generator to factorise the RSA modulus, retrieve the private key, decrypt the AES key and eventually decrypt the flag.

The encrypted AES key and the RSA public key are given in the `public_key.txt` file on the compromised machine:

```
$ cat public_key.txt
ct =103277426890378325116816003823204413405697650803883027924499155808207579502838049594785647296354171560091380575609023224236810984380471514427263389631556751378748850781417708570684336755006577867552855825522332814965118168493717583064825727041281736124508427759186701963677317409867086473936244440084864793145556452777286279898290377902029996126279559998481885748242510379854444310318155405626576074833498899206869904384273094040008044549784792603559691212527347536160482541620839919378963435565991783142960512680000026995612778965267032398130337317184716910656244337935483878555511428645495753032285992542849349183330115270055128424706
n =138207419695384547988912711812284775202209436526033230198940565547636825580747672789492797274333315722907773523517227770864272553877067922737653082336474664566217666931535461616165422003336643572287256862845919431302341192342221401941030920157743737894770635943413313928841178881232020910281701384625077903386156608333697476127454650836483136951229948246099472175058826799041197871948492587237632210327332983333713524046342665918954004211660592218839111231622727156788937696335536810341922886296485903618849914312160102415163875162998413750215079864835041806222675907005982658170273293041649903396166676084266968673498852755429449249441
e =6553
```

By representing the generated primes in hexadecimal, we observe a weird structure:

```
>>> hex(getPrime(1024))
'0x9b961fc1ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff923050f97695bf2fdb06f493c8192014a37fbb81'
```

Most of the bytes are just `0xff`, meaning the primes have only a few bytes of entropy.

From the `getPrime` function, the generated primes `p` and `q` can be represented as:

p = u<sub>1</sub>(2<sup>1024</sup> + v<sub>1</sub>) + w<sub>1</sub> = u<sub>1</sub>2<sup>1024</sup> + u<sub>1</sub>v<sub>1</sub> + w<sub>1</sub>

q = u<sub>2</sub>(2<sup>1024</sup> + v<sub>2</sub>) + w<sub>2</sub> = u<sub>2</sub>2<sup>1024</sup> + u<sub>2</sub>v<sub>2</sub> + w<sub>2</sub>

Therefore, the modulus `n` can be written as:

n = pq

  = (u<sub>1</sub>2<sup>1024</sup> + u<sub>1</sub>v<sub>1</sub> + w<sub>1</sub>)(u<sub>2</sub>2<sup>1024</sup> + u<sub>2</sub>v<sub>2</sub> + w<sub>2</sub>)

  = u<sub>1</sub>u<sub>2</sub>2<sup>2048</sup> + u<sub>1</sub>u<sub>2</sub>v<sub>2</sub>2<sup>1024</sup> + u<sub>1</sub>w<sub>2</sub>2<sup>1024</sup> + u<sub>1</sub>v<sub>1</sub>u<sub>2</sub>2<sup>1024</sup> + u<sub>1</sub>v<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + u<sub>1</sub>v<sub>1</sub>w<sub>2</sub> + w<sub>1</sub>u<sub>2</sub>2<sup>1024</sup> + w<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + w<sub>1</sub>w<sub>2</sub>

  = u<sub>1</sub>u<sub>2</sub>2<sup>2048</sup> + (u<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + u<sub>1</sub>w<sub>2</sub> + u<sub>1</sub>v<sub>1</sub>u<sub>2</sub> + w<sub>1</sub>u<sub>2</sub>)2<sup>1024</sup> + u<sub>1</sub>v<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + u<sub>1</sub>v<sub>1</sub>w<sub>2</sub> + w<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + w<sub>1</sub>w<sub>2</sub>

  = a2<sup>2048</sup> + b2<sup>1024</sup> + c

with:

a = u<sub>1</sub>u<sub>2</sub>

b = u<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + u<sub>1</sub>w<sub>2</sub> + u<sub>1</sub>v<sub>1</sub>u<sub>2</sub> + w<sub>1</sub>u<sub>2</sub>

c = u<sub>1</sub>v<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + u<sub>1</sub>v<sub>1</sub>w<sub>2</sub> + w<sub>1</sub>u<sub>2</sub>v<sub>2</sub> + w<sub>1</sub>w<sub>2</sub>


By substituting 2<sup>2014</sup> with x, we get:

n = ax<sup>2</sup> + bx + c

The generated modulus can be represented as a second-degree polynomial! This is good news as such a polynimial can be trivially factorised into:

ax<sup>2</sup> + bx + c = (s<sub>1</sub>x + t<sub>1</sub>)(s<sub>2</sub>x + t<sub>2</sub>) = pq

`a`, `b` and `c` can be retrieved simply by looking at the hexadecimal representation of `n`:

```
>>> hex(n)
'0x3b599770048e9bacffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd5449e2d90aa5712a21ba34aa1b2c62fbebe83d77a5da7f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c04599c8b423852045a385916c68dd3eba0aaef4488cae357fc2b52aecd0d256103eac3fc3b2a1'
```

```
a = 0x3b599770048e9bad
b = -0x2abb61d26f55a8ed5de45cb55e4d39d041417c2885a2580e
c = 0x1c04599c8b423852045a385916c68dd3eba0aaef4488cae357fc2b52aecd0d256103eac3fc3b2a1
```

And that's it! We have all the elements needed to solve the challenge. The following script factorises the polynomial with [sympy](https://www.sympy.org/), computes the private exponent, decrypts the encryption key and decrypt the flag:

```
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
from sympy import mod_inverse, poly
from sympy.abc import x


ct = 0x2c599fad32765bdd5ac1de9284cd6fd6e5f47e097ab42c457fd4b8c2ca49eb6c437871539786ba64f3bf23027fd1be69a25a974497639c45cad549f3174630f6c4faceb81d6be893842231c95b214411eec1e4600fd7c323a6f45667b9497b98dc37f401f741cae4e6520517be29a29d14a28c7f55c45ad0a33fd62ffca573da8dcd9b5aa8cf29a1d2b3047782713c31168fa1e90006fd73328844c382b8757ef9459079346a74c1747a27e03852aaf9b33a114ecff94d0d6858abb188426e859f37cf9c2f1b28fcba9fba1e5f16eff14122bf7b3e15ebf992ea8c890f253f2d351492175aa1796a7756d57e63c1d1e8d06474a4e1afc2e65a5a0a15bf8097965ac250fe71736102
n = 0x3b599770048e9bacffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd5449e2d90aa5712a21ba34aa1b2c62fbebe83d77a5da7f20000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001c04599c8b423852045a385916c68dd3eba0aaef4488cae357fc2b52aecd0d256103eac3fc3b2a1
e = 0x10001
a = 0x3b599770048e9bad
b = -0x2abb61d26f55a8ed5de45cb55e4d39d041417c2885a2580e
c = 0x1c04599c8b423852045a385916c68dd3eba0aaef4488cae357fc2b52aecd0d256103eac3fc3b2a1

assert(a * 2 ** 2048 + b * 2 ** 1024 + c == n)


# Factorise n
P = poly(a * x ** 2 + b * x + c)
factors = P.factor_list()[1]
p = factors[0][0].eval(2 ** 1024)
q = factors[1][0].eval(2 ** 1024)

assert(p * q == n)


# Decrypt the encryption key
phi = (p - 1) * (q - 1)
d = mod_inverse(e, phi)
key = pow(ct, d, n).to_bytes(32, 'big')


# Get the flag!
with open('flag.txt.enc', 'rb') as f:
    data = f.read()

iv = data[:16]
cipher = AES.new(key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(data[16:]), AES.block_size).decode())
# HTB{n3v3r_p4y_y0ur_r4ns0m_04e1f9}
```
