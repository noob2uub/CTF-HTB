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

