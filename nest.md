# Enumeration

# Auto Recon

### NMAP

```console
# Nmap 7.92 scan initiated Fri Apr 29 16:40:29 2022 as: nmap -vv --reason -Pn -T4 -sV -sC --version-all -A --osscan-guess -p- -oN /home/noob2uub/ctf/htb/nest/results/10.10.10.178/scans/_full_tcp_nmap.txt -oX /home/noob2uub/ctf/htb/nest/results/10.10.10.178/scans/xml/_full_tcp_nmap.xml 10.10.10.178
Nmap scan report for 10.10.10.178
Host is up, received user-set (0.070s latency).
Scanned at 2022-04-29 16:40:30 PDT for 660s
Not shown: 65533 filtered tcp ports (no-response)
PORT     STATE SERVICE       REASON          VERSION
445/tcp  open  microsoft-ds? syn-ack ttl 127
4386/tcp open  unknown       syn-ack ttl 127
| fingerprint-strings: 
|   DNSStatusRequestTCP, DNSVersionBindReqTCP, Kerberos, LDAPBindReq, LDAPSearchReq, LPDString, NULL, RPCCheck, SMBProgNeg, SSLSessionReq, SSLv23SessionReq, TLSSessionReq, TerminalServerCookie, X11Probe: 
|     Reporting Service V1.2
|   FourOhFourRequest, GenericLines, GetRequest, HTTPOptions, Hello, RTSPRequest, SIPOptions: 
|     Reporting Service V1.2
|     Unrecognised command
|   Help: 
|     Reporting Service V1.2
|     This service allows users to run queries against databases using the legacy HQK format
|     AVAILABLE COMMANDS ---
|     LIST
|     SETDIR <Directory_Name>
|     RUNQUERY <Query_ID>
|     DEBUG <Password>
|_    HELP <Command>
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port4386-TCP:V=7.92%I=9%D=4/29%Time=626C77D0%P=x86_64-pc-linux-gnu%r(NU
SF:LL,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(GenericLin
SF:es,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognise
SF:d\x20command\r\n>")%r(GetRequest,3A,"\r\nHQK\x20Reporting\x20Service\x2
SF:0V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(HTTPOptions,3A,"\r\
SF:nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20comma
SF:nd\r\n>")%r(RTSPRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\
SF:n\r\n>\r\nUnrecognised\x20command\r\n>")%r(RPCCheck,21,"\r\nHQK\x20Repo
SF:rting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSVersionBindReqTCP,21,"\r\nHQK
SF:\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(DNSStatusRequestTCP,21,"
SF:\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(Hello,3A,"\r\nHQK
SF:\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r
SF:\n>")%r(Help,F2,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n>\r\nT
SF:his\x20service\x20allows\x20users\x20to\x20run\x20queries\x20against\x2
SF:0databases\x20using\x20the\x20legacy\x20HQK\x20format\r\n\r\n---\x20AVA
SF:ILABLE\x20COMMANDS\x20---\r\n\r\nLIST\r\nSETDIR\x20<Directory_Name>\r\n
SF:RUNQUERY\x20<Query_ID>\r\nDEBUG\x20<Password>\r\nHELP\x20<Command>\r\n>
SF:")%r(SSLSessionReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\r\n
SF:>")%r(TerminalServerCookie,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>")%r(TLSSessionReq,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.
SF:2\r\n\r\n>")%r(SSLv23SessionReq,21,"\r\nHQK\x20Reporting\x20Service\x20
SF:V1\.2\r\n\r\n>")%r(Kerberos,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.
SF:2\r\n\r\n>")%r(SMBProgNeg,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\
SF:r\n\r\n>")%r(X11Probe,21,"\r\nHQK\x20Reporting\x20Service\x20V1\.2\r\n\
SF:r\n>")%r(FourOhFourRequest,3A,"\r\nHQK\x20Reporting\x20Service\x20V1\.2
SF:\r\n\r\n>\r\nUnrecognised\x20command\r\n>")%r(LPDString,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(LDAPSearchReq,21,"\r\nHQK\x2
SF:0Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(LDAPBindReq,21,"\r\nHQK\x20
SF:Reporting\x20Service\x20V1\.2\r\n\r\n>")%r(SIPOptions,3A,"\r\nHQK\x20Re
SF:porting\x20Service\x20V1\.2\r\n\r\n>\r\nUnrecognised\x20command\r\n>");
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose|phone|specialized
Running (JUST GUESSING): Microsoft Windows 8|Phone|2008|7|8.1|Vista|2012 (92%)
OS CPE: cpe:/o:microsoft:windows_8 cpe:/o:microsoft:windows cpe:/o:microsoft:windows_server_2008:r2 cpe:/o:microsoft:windows_7 cpe:/o:microsoft:windows_8.1 cpe:/o:microsoft:windows_vista::- cpe:/o:microsoft:windows_vista::sp1 cpe:/o:microsoft:windows_server_2012:r2
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 8.1 Update 1 (92%), Microsoft Windows Phone 7.5 or 8.0 (92%), Microsoft Windows 7 or Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 (91%), Microsoft Windows Server 2008 R2 or Windows 8.1 (91%), Microsoft Windows Server 2008 R2 SP1 or Windows 8 (91%), Microsoft Windows 7 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 R2 (91%), Microsoft Windows 7 SP1 or Windows Server 2008 SP2 or 2008 R2 SP1 (91%), Microsoft Windows Vista SP0 or SP1, Windows Server 2008 SP1, or Windows 7 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=4/29%OT=445%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=626C7A02%P=x86_64-pc-linux-gnu)
SEQ(SP=107%GCD=1%ISR=109%TI=I%II=I%SS=S%TS=7)
OPS(O1=M505NW8ST11%O2=M505NW8ST11%O3=M505NW8NNT11%O4=M505NW8ST11%O5=M505NW8ST11%O6=M505ST11)
WIN(W1=2000%W2=2000%W3=2000%W4=2000%W5=2000%W6=2000)
ECN(R=Y%DF=Y%TG=80%W=2000%O=M505NW8NNS%CC=N%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Uptime guess: 0.008 days (since Fri Apr 29 16:39:36 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=263 (Good luck!)
IP ID Sequence Generation: Incremental

Host script results:
|_clock-skew: -1m16s
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 28056/tcp): CLEAN (Timeout)
|   Check 2 (port 23990/tcp): CLEAN (Timeout)
|   Check 3 (port 17014/udp): CLEAN (Timeout)
|   Check 4 (port 2897/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-time: 
|   date: 2022-04-29T23:49:35
|_  start_date: 2022-04-29T23:38:34
| smb2-security-mode: 
|   2.1: 
|_    Message signing enabled but not required

TRACEROUTE (using port 445/tcp)
HOP RTT      ADDRESS
1   69.39 ms 10.10.14.1
2   69.78 ms 10.10.10.178

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri Apr 29 16:51:30 2022 -- 1 IP address (1 host up) scanned in 660.67 seconds
```
SO we find that we have two ports open port 445 and 4386

### SMB Client

```console
do_connect: Connection to 10.10.10.178 failed (Error NT_STATUS_IO_TIMEOUT)

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Data            Disk
	IPC$            IPC       Remote IPC
	Secure$         Disk
	Users           Disk
Reconnecting with SMB1 for workgroup listing.
Unable to connect with SMB1 -- no workgroup available
```
### SMB MAP

```console
	Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Data                                              	READ ONLY
	.\Data\*
	dr--r--r--                0 Wed Aug  7 15:53:46 2019	.
	dr--r--r--                0 Wed Aug  7 15:53:46 2019	..
	dr--r--r--                0 Wed Aug  7 15:58:07 2019	IT
	dr--r--r--                0 Mon Aug  5 14:53:41 2019	Production
	dr--r--r--                0 Mon Aug  5 14:53:50 2019	Reports
	dr--r--r--                0 Wed Aug  7 12:07:51 2019	Shared
	.\Data\Shared\*
	dr--r--r--                0 Wed Aug  7 12:07:51 2019	.
	dr--r--r--                0 Wed Aug  7 12:07:51 2019	..
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	Maintenance
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	Templates
	.\Data\Shared\Maintenance\*
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	.
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	..
	fr--r--r--               48 Wed Jul 21 11:47:05 2021	Maintenance Alerts.txt
	.\Data\Shared\Templates\*
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	.
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	..
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	HR
	dr--r--r--                0 Wed Aug  7 12:08:07 2019	Marketing
	.\Data\Shared\Templates\HR\*
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	.
	dr--r--r--                0 Wed Jul 21 11:47:12 2021	..
	fr--r--r--              425 Wed Jul 21 11:47:12 2021	Welcome Email.txt
	IPC$                                              	NO ACCESS	Remote IPC
	Secure$                                           	NO ACCESS
	Users                                             	READ ONLY
	.\Users\*
	dr--r--r--                0 Sat Jan 25 15:04:21 2020	.
	dr--r--r--                0 Sat Jan 25 15:04:21 2020	..
	dr--r--r--                0 Wed Jul 21 11:47:04 2021	Administrator
	dr--r--r--                0 Wed Jul 21 11:47:04 2021	C.Smith
	dr--r--r--                0 Thu Aug  8 10:03:29 2019	L.Frost
	dr--r--r--                0 Thu Aug  8 10:02:56 2019	R.Thompson
	dr--r--r--                0 Wed Jul 21 11:47:15 2021	TempUser
```

We have some user names C.Smith, L.Frost,  and R.Thompson

now lets take a look at data by starting with:
.\Data\Shared\Templates\HR\*
.\Data\Shared\Maintenance\*

### SMB Client

```console
noob2uub@kali:~/ctf/htb/nest$ smbclient -N //10.10.10.178/data
Try "help" to get a list of possible commands.
smb: \> cd /Shared/Templates/HR
smb: \Shared\Templates\HR\> ls
  .                                   D        0  Wed Aug  7 12:08:01 2019
  ..                                  D        0  Wed Aug  7 12:08:01 2019
  Welcome Email.txt                   A      425  Wed Aug  7 15:55:36 2019

		5242623 blocks of size 4096. 1840045 blocks available
smb: \Shared\Templates\HR\> get "Welcome Email.txt"
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Welcome Email.txt (1.5 KiloBytes/sec) (average 1.5 KiloBytes/sec)
smb: \Shared\Templates\HR\> cd ..
smb: \Shared\Templates\> cd ..
smb: \Shared\> cd ..
smb: \> ls
  .                                   D        0  Wed Aug  7 15:53:46 2019
  ..                                  D        0  Wed Aug  7 15:53:46 2019
  IT                                  D        0  Wed Aug  7 15:58:07 2019
  Production                          D        0  Mon Aug  5 14:53:38 2019
  Reports                             D        0  Mon Aug  5 14:53:44 2019
  Shared                              D        0  Wed Aug  7 12:07:51 2019

		5242623 blocks of size 4096. 1840045 blocks available
smb: \> cd /Shared/Maintenance
smb: \Shared\Maintenance\> ls
  .                                   D        0  Wed Aug  7 12:07:32 2019
  ..                                  D        0  Wed Aug  7 12:07:32 2019
  Maintenance Alerts.txt              A       48  Mon Aug  5 16:01:44 2019

		5242623 blocks of size 4096. 1840045 blocks available
smb: \Shared\Maintenance\> get "Maintenance Alerts.txt"
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Maintenance Alerts.txt (0.2 KiloBytes/sec) (average 0.8 KiloBytes/sec)
```

Lets take a look at our files now.

### Welcome Email

```console
noob2uub@kali:~/ctf/htb/nest$ cat 'Welcome Email.txt' 
We would like to extend a warm welcome to our newest member of staff, <FIRSTNAME> <SURNAME>

You will find your home folder in the following location: 
\\HTB-NEST\Users\<USERNAME>

If you have any issues accessing specific services or workstations, please inform the 
IT department and use the credentials below until all systems have been set up for you.

Username: TempUser
Password: welcome2019


Thank you
```

We haev TempUser credentials

### Maintenance Alerts

```console
noob2uub@kali:~/ctf/htb/nest$ cat 'Maintenance Alerts.txt' 
There is currently no scheduled maintenance work
```
Nothing here

Now lets see what I can see with TempUser

### SMB Map

```console
noob2uub@kali:~/ctf/htb/nest$ smbmap -H 10.10.10.178 -u TempUser -p welcome2019
[+] IP: 10.10.10.178:445	Name: 10.10.10.178                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Data                                              	READ ONLY	
	IPC$                                              	NO ACCESS	Remote IPC
	Secure$                                           	READ ONLY	
	Users                                             	READ ONLY
```

I cant access anything in secure

### SMB Client

```console
noob2uub@kali:~/ctf/htb/nest$ smbclient -U TempUser //10.10.10.178/Secure$ welcome2019
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 16:08:12 2019
  ..                                  D        0  Wed Aug  7 16:08:12 2019
  Finance                             D        0  Wed Aug  7 12:40:13 2019
  HR                                  D        0  Wed Aug  7 16:08:11 2019
  IT                                  D        0  Thu Aug  8 03:59:25 2019

		5242623 blocks of size 4096. 1839915 blocks available
smb: \> cd HR
smb: \HR\> ls
NT_STATUS_ACCESS_DENIED listing \HR\*
smb: \HR\> cd .
smb: \HR\> cd IT
cd \HR\IT\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \HR\> cd ..
smb: \> ls
  .                                   D        0  Wed Aug  7 16:08:12 2019
  ..                                  D        0  Wed Aug  7 16:08:12 2019
  Finance                             D        0  Wed Aug  7 12:40:13 2019
  HR                                  D        0  Wed Aug  7 16:08:11 2019
  IT                                  D        0  Thu Aug  8 03:59:25 2019

		5242623 blocks of size 4096. 1839915 blocks available
smb: \> cd IT
smb: \IT\> ls
NT_STATUS_ACCESS_DENIED listing \IT\*
smb: \IT\> CD ..
smb: \> cd Finance
smb: \Finance\> ls
NT_STATUS_ACCESS_DENIED listing \Finance\*
smb: \Finance\> 
```
now lets take a look at Data and I also googled a simple way to do this :)

### SMB Client with mget

```console
noob2uub@kali:~/ctf/htb/nest$ smbclient -U TempUser //10.10.10.178/Data welcome2019
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Aug  7 15:53:46 2019
  ..                                  D        0  Wed Aug  7 15:53:46 2019
  IT                                  D        0  Wed Aug  7 15:58:07 2019
  Production                          D        0  Mon Aug  5 14:53:38 2019
  Reports                             D        0  Mon Aug  5 14:53:44 2019
  Shared                              D        0  Wed Aug  7 12:07:51 2019

		5242623 blocks of size 4096. 1840043 blocks available
smb: \> cd Shared
smb: \Shared\> ls
  .                                   D        0  Wed Aug  7 12:07:51 2019
  ..                                  D        0  Wed Aug  7 12:07:51 2019
  Maintenance                         D        0  Wed Aug  7 12:07:32 2019
  Templates                           D        0  Wed Aug  7 12:08:07 2019

		5242623 blocks of size 4096. 1840043 blocks available
smb: \Shared\> cd ..
smb: \> recurse on
smb: \> prompt off
smb: \> mget *
getting file \Shared\Maintenance\Maintenance Alerts.txt of size 48 as Shared/Maintenance/Maintenance Alerts.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Configs\Adobe\editing.xml of size 246 as IT/Configs/Adobe/editing.xml (0.9 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \IT\Configs\Adobe\Options.txt of size 0 as IT/Configs/Adobe/Options.txt (0.0 KiloBytes/sec) (average 0.4 KiloBytes/sec)
getting file \IT\Configs\Adobe\projects.xml of size 258 as IT/Configs/Adobe/projects.xml (0.9 KiloBytes/sec) (average 0.5 KiloBytes/sec)
getting file \IT\Configs\Adobe\settings.xml of size 1274 as IT/Configs/Adobe/settings.xml (4.6 KiloBytes/sec) (average 1.4 KiloBytes/sec)
getting file \IT\Configs\Atlas\Temp.XML of size 1369 as IT/Configs/Atlas/Temp.XML (5.0 KiloBytes/sec) (average 2.0 KiloBytes/sec)
getting file \IT\Configs\Microsoft\Options.xml of size 4598 as IT/Configs/Microsoft/Options.xml (14.6 KiloBytes/sec) (average 4.1 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\config.xml of size 6451 as IT/Configs/NotepadPlusPlus/config.xml (23.4 KiloBytes/sec) (average 6.5 KiloBytes/sec)
getting file \IT\Configs\NotepadPlusPlus\shortcuts.xml of size 2108 as IT/Configs/NotepadPlusPlus/shortcuts.xml (7.7 KiloBytes/sec) (average 6.6 KiloBytes/sec)
getting file \IT\Configs\RU Scanner\RU_config.xml of size 270 as IT/Configs/RU Scanner/RU_config.xml (1.0 KiloBytes/sec) (average 6.1 KiloBytes/sec)
getting file \Shared\Templates\HR\Welcome Email.txt of size 425 as Shared/Templates/HR/Welcome Email.txt (1.5 KiloBytes/sec) (average 5.7 KiloBytes/sec)
smb: \> 
```

### Findings

IT Directory
Atlas/temp.xml
Possible new users: 
Deanna Meyes
Jolie Lenehan
Robert O'hara

Configs/notepadplusplus/config.xml
<File filename="C:\windows\System32\drivers\etc\hosts"/><File filename="\\HTB-NEST\Secure$\IT\Carl\Temp.txt"/><File filename="C:\Users\C.Smith\Desktop\todo.txt"/>
User: Carl

RU Scanner
RU_Config.xml
<ConfigFile><Port>389</Port><Username>c.smith</Username><Password>fTEzAfYDoz1YzkqhQkH6GQFYKp1XY5hm7bjOP86yYxE=</Password></ConfigFile>
We have c.smith's password

