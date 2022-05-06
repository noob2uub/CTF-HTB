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













