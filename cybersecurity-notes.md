# Cybersecurity Resources - Comprehensive Notes

A curated collection of resources I explored while learning TryHackMe pathways. This compilation includes tools, tutorials, and references categorized by their purpose in cybersecurity.

Table of Contents

1. Cryptography and Hash Analysis
2. Memory and Forensics Analysis
3. Reconnaissance and OSINT
4. Exploitation and Vulnerability Research
5. Privilege Escalation
6. Payload Development and Reverse Engineering
7. Red Teaming and Post-Exploitation
8. Password Cracking and Default Credentials
9. Miscellaneous Tools and Resources

10. Cryptography and Hash Analysis

- RSA Tools
  - [RSATool](https://github.com/ius/rsatool): Generate RSA private keys with arbitrary exponents.
  - [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool): Analyze weak RSA keys.
- Hash Analysis
  - [Hashcat Example Hashes](https://hashcat.net/wiki/doku.php?id=example_hashes): Common hash examples for password cracking.
  - [TunnelsUp Hash Analyzer](https://www.tunnelsup.com/hash-analyzer/): Identify hash types.
  - [SriHash](https://www.srihash.org/): Generate file hashes for verification.
- Base64 Encoding/Decoding
  - [Base64 Encoder/Decoder (AppDevTools)](https://appdevtools.com/base64-encoder-decoder): Encode and decode Base64 strings.
  - [Base64Encode](https://www.base64encode.org/): Simple Base64 encoding.

2.  Memory and Forensics Analysis

- Memory Analysis
  - [Volatility Foundation](https://volatilityfoundation.org/): Framework for memory forensics.
  - [DumpIt Memory Dump Tools](https://www.toolwar.com/2014/01/dumpit-memory-dump-tools.html): Tools to create memory dumps.
- File Signatures
  - [List of File Signatures (Wikipedia)](https://en.wikipedia.org/wiki/List_of_file_signatures): Identify file types based on headers.

3.  Reconnaissance and OSINT

- OSINT Tools
  - [Shodan](https://www.shodan.io/): Search engine for IoT devices.
  - [Censys](https://search.censys.io/): Internet-wide search engine.
  - [crt.sh](https://crt.sh/): Monitor SSL/TLS certificates.
  - [ViewDNS](https://viewdns.info/): Tools for DNS, IP, and domain analysis.
- Google Hacking
  - [Google Hacking (Wikipedia)](https://en.wikipedia.org/wiki/Google_hacking): Techniques for advanced Google search queries.
  - [Bug Bounty Dorks](https://github.com/sushiwushi/bug-bounty-dorks/blob/master/dorks.txt): Google dorks for bug bounty hunting.
- DNS Enumeration
  - [DNSDumpster](https://dnsdumpster.com/): Map DNS records.

4.  Exploitation and Vulnerability Research

- Exploit Databases
  - [Exploit-DB](https://www.exploit-db.com/): Public exploits and vulnerable software.
  - [Rapid7 Vulnerability Database](https://www.rapid7.com/db/): Comprehensive vulnerability data.
  - [NVD](https://nvd.nist.gov/vuln): National Vulnerability Database.
- Command Injection
  - [PayloadBox Command Injection Payloads](https://github.com/payloadbox/command-injection-payload-list): Pre-built payloads.
- SQL Injection
  - [SQLNinja](https://github.com/xxgrunge/sqlninja): Exploitation tool for SQL injection.
  - [BBQSQL](https://github.com/CiscoCXSecurity/bbqsql): SQL injection exploitation framework.

5.  Privilege Escalation

- Windows Privilege Escalation
  - [WinPEAS](https://github.com/peass-ng/PEASS-ng/tree/master/winPEAS): Privilege escalation enumeration script.
  - [GTFOBins](https://gtfobins.github.io/): Exploitable binaries for privilege escalation.
  - [BloodHound](https://bloodhound.readthedocs.io/en/latest/): Analyze Active Directory environments.
  - [AccessChk](https://learn.microsoft.com/en-us/sysinternals/downloads/accesschk): Permissions enumeration tool.
  - [Linux Privilege Escalation Cheatsheet](https://github.com/rmusser01/Infosec_Reference/blob/master/Draft/Cheat%20sheets%20reference%20pages%20Checklists%20-/Linux/cheat%20sheet%20Basic%20Linux%20Privilege%20Escalation.txt): Common privilege escalation techniques.

6.  Payload Development and Reverse Engineering

- Payload Generators
  - [MSFVenom Cheat Sheet](https://web.archive.org/web/20220607215637/https://thedarksource.com/msfvenom-cheat-sheet-create-metasploit-payloads/): Generate custom payloads with Metasploit.
  - [Revshells](https://www.revshells.com/): Generate reverse shell commands.
- Reverse Engineering
  - [Obfuscation Tools](https://codebeautify.org/javascript-obfuscator#): Obfuscate code to prevent reverse engineering.
  - [ConfuserEx](https://github.com/mkaring/ConfuserEx/releases/tag/v1.6.0): .NET obfuscation tool.

7.  Red Teaming and Post-Exploitation

- Red Team Tools
  - [Red Teaming Toolkit](https://github.com/infosecn1nja/Red-Teaming-Toolkit#Payload%20Development): A comprehensive list of tools for red teaming.
- Post-Exploitation Frameworks
  - [BloodHound Legacy](https://github.com/SpecterOps/BloodHound-Legacy): Analyze AD attack paths.
  - [Mimikatz](https://github.com/gentilkiwi/mimikatz): Credential dumping tool.
  - [PowerView](https://github.com/PowerShellEmpire/PowerTools/tree/master/PowerView): PowerShell tools for AD enumeration.

8.  Password Cracking and Default Credentials

- Password Lists
  - [SecLists](https://github.com/danielmiessler/SecLists): Precompiled lists for pentesting.
  - [Default Password Lists](https://default-password.info/): Known default credentials for devices.
- Cracking Tools
  - [Hash Analyzer](https://hashes.com/en/decrypt/hash): Identify and decrypt hashed passwords.

9.  Miscellaneous Tools and Resources

- CyberChef
  - [CyberChef](https://gchq.github.io/CyberChef/): Perform encoding, decoding, and data transformations.
- MITRE ATT&CK
  - [MITRE Navigator](https://mitre-attack.github.io/attack-navigator/): Visualize attack tactics and techniques.
  - [ATT&CK Framework](https://attack.mitre.org/): Industry-standard for mapping attack behavior.
- Online Utilities
  - [What’s My Name](https://whatsmyname.app/): Username enumeration tool.
  - [Pipedream RequestBin](https://pipedream.com/requestbin): Debug HTTP requests.
