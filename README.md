# Network-Penetration-Testing-Capstone

Project Overview
This project documents a complete penetration testing assessment performed on a simulated corporate network (10.5.5.0/24). The objective was to identify vulnerabilities, exploit them to retrieve sensitive "flag" data, and propose remediation strategies to secure the infrastructure.

Key Skills Demonstrated:
Network Reconnaissance: Nmap scanning and service enumeration.
Web Application Security: Identifying Directory Listing vulnerabilities.
System Exploitation: SMB share enumeration and credential reuse attacks.
Traffic Analysis: Packet capture inspection using Wireshark.
Remediation: Providing actionable security fixes for identified flaws.

 Tools & Environment
Operating System: Kali Linux
network Scanner: Nmap
SMB Enumeration: Smbclient, Enum4linux
Traffic Analysis: Wireshark
Web Tools: Firefox, Manual URL Manipulation

Challenge Walkthrough

Challenge 1: System Access via SSH
Objective: Gain access to a restricted server using compromised credentials found via vulnerability assessment.
Target: 10.5.5.11

Methodology:
Located a password hash during initial reconnaissance.
Cracked the hash to retrieve the plaintext password.
Authenticated via SSH to the target machine.

Command Used:
ssh smithy@10.5.5.11
cat my_passwords.txt
Outcome: Successfully retrieved the flag 8748wf8j.

Challenge 2: Web Server Misconfiguration (Directory Listing)
Objective: Exploit a web server misconfiguration to access hidden files.
Target: 10.5.5.12
Vulnerability: Directory Listing (The server allowed users to view file lists in directories without an index file).

Methodology:
Manually browsed URLs to find unprotected directories.
Identified /config/ and /docs/ as vulnerable paths.
Located hidden file db_form.html.
Outcome: Found the flag aWe-4975 embedded in the HTML.
Remediation: Disable directory browsing (e.g., Options -Indexes in Apache) and ensure default index files exist.

 Challenge 3: Exploiting Open SMB Shares
Objective: Enumerate and access unsecured file shares on a Windows/Samba server.
Target: 10.5.5.14 (Hostname: gravemind)

Methodology:
Scanning: Used nmap to identify open port 445 (SMB).

nmap -p 445 10.5.5.0/24 --open
Enumeration: Used enum4linux to identify valid usernames, discovering user robert.

enum4linux -a 10.5.5.14
Exploitation: Accessed the user's home directory using discovered credentials.

smbclient //10.5.5.14/homes -U robert
Outcome: Retrieved Challenge3.txt containing flag f823-99aF.

Remediation: Disable anonymous SMB access, enforce strong password policies, and restrict share permissions.

 Challenge 4: Traffic Analysis (PCAP)
Objective: Analyze captured network traffic to find data leaked in clear text.
Target: 10.5.5.11

Methodology:
Opened SA.pcap in Wireshark.
Filtered for http traffic to isolate web requests.
Identified GET requests for a /confidential/ directory.
Reconstructed the attack by visiting the URL http://10.5.5.11/confidential/.

Outcome: Discovered a file containing Credit Card Numbers and flag 5629-0092.

Remediation: Implement SSL/TLS (HTTPS) to encrypt all web traffic and prevent eavesdropping.
