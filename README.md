# Cybersecurity and CTF Resource Book for those who need
This repository compiles an extensive collection of cybersecurity tools, resources, and CTF (Capture the Flag) practice platforms for anyone involved in digital security

---

## Introduction
This guide aims to be your ultimate reference, whether you're prepping for a CTF competition, strengthening your pentesting toolkit, or learning cybersecurity essentials. Organized by categories, each section covers tools, their functions, and direct links to resources. This format allows you to easily locate the tools you need, understand their capabilities, and access them instantly.

## How to Use This Guide
Each section provides a focused list of tools, organized by their category, such as OSINT (Open Source Intelligence), steganography, reverse engineering, and more. Here’s how you can make the most out of each category in this guide:

- **Identify Your Objective**: Whether you’re looking for exploitation tools, malware analysis frameworks, or OSINT utilities, navigate to the relevant section in the guide to find the tools specifically curated for that purpose.
- **Direct Links**: Each tool includes a direct link for easy access. Just click to go straight to the download or official page.
- **Combine Tools for Comprehensive Use**: In many cases, you may need to combine tools from various categories. For example, if you're working on a web security assessment, you might need to pull tools from both the "Penetration Testing" and "Web Vulnerability Scanners" sections.
- **Explore Platforms for Skill Development**: Check out CTF platforms like Hack The Box and TryHackMe for practical, hands-on exercises that incorporate many of these tools.

Here’s a breakdown of the main categories and how to best utilize each:

### 1. OSINT (Open Source Intelligence)
These tools are essential for reconnaissance and data gathering. Start with **Shodan** or **Censys** to scan for internet-connected devices. Use **theHarvester** to gather emails and subdomains, while **Maltego** helps map and visualize relationships. Combine tools like **Recon-ng** and **SpiderFoot** for a complete view of your target's digital footprint.

### 2. Steganography
For CTFs or forensic analysis, **Steghide** allows for data concealment and extraction from images, and **zsteg** is excellent for hidden data in PNG/BMP files. **AperiSolve** and **StegSolve** offer online and local analysis of hidden image content, while **ExifTool** reveals metadata, often containing valuable information for investigations.

### 3. Anonymity and Privacy
To maintain anonymity, start with **Tor Browser** for browsing and **Tails OS** as a secure operating system. **ProtonMail** and **Signal** provide encrypted communication, while **Orbot** and **AnonAddy** offer anonymous web browsing and email forwarding. These tools help you stay untraceable and protect sensitive information.

### 4. Exploitation and Reverse Shells
For exploitation, use **Metasploit** for payload and exploit delivery, and **GTFOBins** for privilege escalation on Unix. **PayloadsAllTheThings** offers a vast repository of payloads, and **RevShells** simplifies generating reverse shell payloads. **MSFvenom** is useful for custom payload generation, while **Nishang** aids in PowerShell-based exploitation.

### 5. Cryptography and Hash Cracking
For cracking passwords or cryptography challenges, **Hashcat** and **John the Ripper** are powerful tools. **CyberChef** provides extensive encoding, encryption, and data analysis, while **Ciphey** automates decryption tasks. Use **CrackStation** for online hash cracking, and **Hash-Identifier** to determine hash types, making cryptanalysis more manageable.

### 6. Penetration Testing
For penetration testing, **Nmap** is essential for network discovery, **Wireshark** for packet analysis, **Burp Suite** for web vulnerabilities, and **SQLMap** for SQL injection exploitation. Use **Nikto** and **Dirbuster** for web content and server scanning, **Hydra** for network logon brute-forcing, and **Impacket** for managing network protocols during exploitation.

### 7. Red and Blue Team Tools
**Red Team**: For offensive operations, **Cobalt Strike** and **BloodHound** are invaluable for adversary simulations and Active Directory mapping. Tools like **Empire** and **Sliver** support post-exploitation, while **Mimikatz** and **SharpHound** handle credential dumping and Active Directory enumeration. **Obfuscators** like **PEzor** and **ScareCrow** help evade detection.

**Blue Team**: For defense, **Security Onion** and **Wazuh** provide intrusion detection and monitoring. **Suricata** and **TheHive** support threat detection and incident response, while **Velociraptor** aids in endpoint visibility. **ELK Stack** is excellent for managing and analyzing logs to track potential threats.

### 8. CTF and Training Platforms
This section offers CTF platforms like **Hack The Box** and **TryHackMe** for hands-on training, **PicoCTF** and **OverTheWire** for beginner to intermediate challenges, and **Root Me** for web and binary exploitation. **CTFtime** helps track global events, and **VulnHub** provides vulnerable virtual machines for practice. Use these to build practical skills in a controlled environment.

### 9. Cheat Sheets and Reference
Quick references like **PayloadsAllTheThings** and **HackTricks** are invaluable for live challenges, offering extensive payload lists and techniques. **GTFOBins** provides privilege escalation techniques, while **Linux and Windows Privilege Escalation** guides give targeted resources for each operating system. For reverse engineering, **Reverse Engineering Cheat Sheet** provides quick tips, and **Pentest Monkey** is a great go-to for shell and payload references.

### 10. Extra CTF Tools
Specialized tools like **PwnTools** and **Angr** assist in exploit development and binary analysis. **Qiling** supports cross-platform emulation for reverse engineering, while **ROPgadget** and **OneGadget** help locate gadgets for ROP chain building. For Android CTF challenges, **Apktool** enables APK decompilation. **SecLists** and **Insomni'hack payloads** provide payloads and wordlists, while **CyberChef** and **Cryptool** aid in cryptography challenges.

---

---

## 1. Open Source Intelligence (OSINT)

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Shodan**         | Search engine for internet-connected devices.                | [shodan.io](https://shodan.io)                             |
| **Censys**         | Internet-wide scanning and data analysis platform.           | [censys.io](https://censys.io)                             |
| **theHarvester**   | Tool to gather emails, subdomains, hosts, and more.          | [GitHub](https://github.com/laramies/theHarvester)         |
| **Maltego**        | Data mining and link analysis platform for intelligence gathering.| [maltego.com](https://maltego.com)                     |
| **OSINT Framework**| Categorized collection of OSINT resources.                   | [osintframework.com](https://osintframework.com)           |
| **Recon-ng**       | Web reconnaissance tool with various OSINT modules.          | [GitHub](https://github.com/lanmaster53/recon-ng)          |
| **SpiderFoot**     | OSINT automation tool for threat intelligence gathering.     | [spiderfoot.net](https://www.spiderfoot.net)               |
| **Amass**          | Tool for in-depth domain mapping and DNS enumeration.        | [GitHub](https://github.com/OWASP/Amass)                   |

---

## 2. Steganography Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Steghide**       | Hide data in images and audio files.                         | [SourceForge](https://steghide.sourceforge.net)            |
| **AperiSolve**     | Online image steganography analyzer.                         | [aperisolve.com](https://aperisolve.com)                   |
| **Binwalk**        | Extract data from binary files; often used for embedded files.| [GitHub](https://github.com/ReFirmLabs/binwalk)           |
| **ExifTool**       | Read, write, and edit file metadata, often used in forensics.| [exiftool.org](https://exiftool.org)                       |
| **zsteg**          | PNG/BMP analysis tool for finding hidden data.               | [GitHub](https://github.com/zed-0xff/zsteg)                |
| **StegOnline**     | Web-based steganography tool for encoding/decoding images.   | [stegonline.georgeom.net](https://stegonline.georgeom.net) |
| **OpenStego**      | Open-source tool for image steganography with encryption options.| [openstego.com](https://www.openstego.com)             |
| **OutGuess**       | Universal steganographic tool for JPEG files.                | [freebsd.org](https://www.freebsd.org/cgi/man.cgi?query=outguess) |

---

## 3. Anonymous Communication & Identity

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Tor Browser**    | Browse the internet anonymously, routing traffic through Tor. | [torproject.org](https://www.torproject.org)               |
| **ProtonMail**     | Encrypted email service with strong privacy policies.        | [protonmail.com](https://protonmail.com)                   |
| **Tails OS**       | Live operating system focused on privacy; leaves no trace.   | [tails.boum.org](https://tails.boum.org)                   |
| **Signal**         | Secure, end-to-end encrypted messaging app.                  | [signal.org](https://signal.org)                           |
| **Orbot**          | Tor proxy for Android devices, enabling anonymous browsing.  | [guardianproject.info](https://guardianproject.info/apps/orbot) |
| **AnonAddy**       | Anonymous email forwarding to protect real email address.    | [anonaddy.com](https://anonaddy.com)                       |
| **Guerrilla Mail** | Disposable, temporary email service.                         | [guerrillamail.com](https://www.guerrillamail.com)         |
| **Mailinator**     | Public, disposable email system for quick registrations.     | [mailinator.com](https://www.mailinator.com)               |

---

## 4. Reverse Shells & Exploits

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Metasploit**         | Full exploitation framework.                                     | [metasploit.com](https://www.metasploit.com)               |
| **GTFOBins**           | Unix binaries for privilege escalation.                          | [gtfobins.github.io](https://gtfobins.github.io)           |
| **SearchSploit**       | CLI search for Exploit Database.                                 | [GitHub](https://github.com/offensive-security/exploitdb)  |
| **PayloadsAllTheThings** | Comprehensive collection of payloads and bypasses.           | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **RevShells**          | Generate reverse shell payloads in multiple languages.           | [revshells.com](https://revshells.com)                     |
| **MSFvenom**           | Command-line payload generation tool for Metasploit.             | [NetSec](https://www.rapid7.com/db/modules/payload/generate) |
| **Nishang**            | PowerShell for penetration testing and red teaming.              | [GitHub](https://github.com/samratashok/nishang)           |
| **Covenant**           | C2 framework with .NET capabilities.                             | [GitHub](https://github.com/cobbr/Covenant)                |

---

## 5. Cryptography & Hash Cracking

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Hashcat**        | High-performance password cracker, supporting GPU acceleration. | [hashcat.net](https://hashcat.net)                      |
| **John the Ripper**| Popular open-source password cracker.                        | [openwall.com/john](https://www.openwall.com/john/)        |
| **CyberChef**      | Versatile web-based tool for encryption, encoding, and data analysis. | [cyberchef.io](https://gchq.github.io/CyberChef)    |
| **Ciphey**         | Automated decryption tool that works without a password.     | [GitHub](https://github.com/Ciphey/Ciphey)                 |
| **CrackStation**   | Online password hash cracking using large databases.         | [crackstation.net](https://crackstation.net)               |
| **Hash-Identifier**| Tool to identify the type of hash used.                      | [GitHub](https://github.com/blackploit/hash-identifier)    |
| **Hydra**          | Network logon cracker supporting numerous protocols.         | [GitHub](https://github.com/vanhauser-thc/thc-hydra)       |
| **RSA Tool**       | Tool for RSA encryption and decryption.                      | [rsatool.org](https://rsatool.org)                         |

---

## 6. Penetration Testing Tools

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Nmap**               | Network discovery and security auditing.                         | [nmap.org](https://nmap.org)                               |
| **Wireshark**          | Network protocol analyzer.                                       | [wireshark.org](https://wireshark.org)                     |
| **Burp Suite**         | Web vulnerability scanner and proxy tool.                        | [portswigger.net](https://portswigger.net/burp)            |
| **SQLMap**             | SQL injection automation tool.                                   | [sqlmap.org](https://sqlmap.org)                           |
| **Hydra**              | Network logon cracker for numerous protocols.                    | [GitHub](https://github.com/vanhauser-thc/thc-hydra)       |
| **Nikto**              | Web server scanner for known vulnerabilities.                    | [cirt.net](https://cirt.net/Nikto2)                        |
| **Aircrack-ng**        | Suite for WiFi network security assessment.                      | [aircrack-ng.org](https://www.aircrack-ng.org)             |
| **Impacket**           | Python library for working with network protocols.               | [GitHub](https://github.com/SecureAuthCorp/impacket)       |

---

## 7. Red Team Tools

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Cobalt Strike**      | Adversary simulation and red team operations.                    | [cobaltstrike.com](https://www.cobaltstrike.com)           |
| **BloodHound**         | AD enumeration and mapping.                                      | [GitHub](https://github.com/BloodHoundAD/BloodHound)       |
| **Empire**             | Post-exploitation framework.                                     | [GitHub](https://github.com/EmpireProject/Empire)          |
| **Mimikatz**           | Credential dumping tool.                                         | [GitHub](https://github.com/gentilkiwi/mimikatz)           |
| **Sliver**             | Open-source C2 platform for adversary emulation.                 | [GitHub](https://github.com/BishopFox/sliver)              |
| **SharpHound**         | Data collector for BloodHound, focusing on AD enumeration.       | [GitHub](https://github.com/BloodHoundAD/SharpHound)       |
| **SilentTrinity**      | Post-exploitation framework leveraging IronPython.               | [GitHub](https://github.com/byt3bl33d3r/SILENTTRINITY)     |
| **Merlin**             | Cross-platform post-exploitation C2 tool.                        | [GitHub](https://github.com/Ne0nd0g/merlin)                |

---

## 8. Blue Team Tools

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Security Onion**     | Linux distro for intrusion detection and monitoring.             | [securityonion.net](https://securityonion.net)             |
| **Wazuh**              | Open-source security monitoring platform.                        | [wazuh.com](https://wazuh.com)                             |
| **Suricata**           | Network threat detection engine.                                 | [suricata.io](https://suricata.io)                         |
| **ELK Stack**          | Log management and analytics platform.                           | [elastic.co](https://www.elastic.co)                       |
| **Zeek**               | Network monitoring and analysis framework.                       | [zeek.org](https://zeek.org)                               |
| **Velociraptor**       | Endpoint visibility and forensic analysis tool.                  | [GitHub](https://github.com/Velocidex/velociraptor)        |
| **MISP**               | Open-source threat intelligence platform.                        | [misp-project.org](https://www.misp-project.org)           |
| **TheHive**            | Scalable incident response platform.                             | [thehive-project.org](https://thehive-project.org)         |

---

## 9. Malware Analysis Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Ghidra**         | Open-source reverse engineering tool developed by the NSA.   | [ghidra-sre.org](https://ghidra-sre.org)                   |
| **IDA Pro**        | Leading disassembler and debugger for software analysis.     | [hex-rays.com](https://hex-rays.com)                       |
| **Remnux**         | Linux toolkit for reverse engineering and malware analysis.  | [remnux.org](https://remnux.org)                           |
| **Cuckoo Sandbox** | Automated malware analysis sandbox environment.              | [cuckoosandbox.org](https://cuckoosandbox.org)             |
| **x64dbg**         | Open-source debugger for x64/x32 Windows binaries.           | [x64dbg.com](https://x64dbg.com)                           |
| **Radare2**        | Powerful open-source framework for reverse engineering.      | [rada.re](https://rada.re)                                 |
| **PE Studio**      | Portable executable analysis tool for malware forensics.     | [winitor.com](https://www.winitor.com/)                    |
| **ANY.RUN**        | Interactive online malware sandbox for real-time analysis.   | [any.run](https://any.run)                                 |

---

## 10. CTF Platforms and Training Resources

| Platform           | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Hack The Box**   | CTF platform with labs for hands-on cybersecurity training.  | [hackthebox.com](https://hackthebox.com)                   |
| **TryHackMe**      | Beginner-friendly platform with guided labs and challenges.  | [tryhackme.com](https://tryhackme.com)                     |
| **PicoCTF**        | CTF platform targeting students and beginners.               | [picoctf.com](https://picoctf.com)                         |
| **OverTheWire**    | Wargames for learning Linux and cybersecurity basics.        | [overthewire.org](https://overthewire.org)                 |
| **Root Me**        | Challenges across various hacking domains for skill building.| [root-me.org](https://www.root-me.org)                     |
| **CTFtime**        | Calendar and ranking of global CTF events.                   | [ctftime.org](https://ctftime.org)                         |
| **VulnHub**        | Download vulnerable virtual machines for practice.           | [vulnhub.com](https://www.vulnhub.com)                     |
| **PentesterLab**   | Paid platform offering in-depth labs on web and network security. | [pentesterlab.com](https://pentesterlab.com)           |

---

## 11. File Transfer & Sharing

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **OnionShare**     | Share files securely and anonymously over Tor.               | [onionshare.org](https://onionshare.org)                   |
| **Syncthing**      | Decentralized file synchronization across devices.           | [syncthing.net](https://syncthing.net)                     |
| **FilePizza**      | Peer-to-peer file sharing via WebRTC; no server storage.     | [file.pizza](https://file.pizza)                           |
| **Wormhole**       | Encrypted file sharing that auto-deletes after transfer.     | [wormhole.app](https://wormhole.app)                       |
| **ToffeeShare**    | Direct, encrypted file sharing without middlemen.            | [toffeeshare.com](https://toffeeshare.com)                 |
| **Transfer.sh**    | Command-line-friendly file sharing with encryption options.  | [transfer.sh](https://transfer.sh)                         |

---

## 12. Reverse Engineering Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Binary Ninja**   | Reverse engineering platform for complex binary analysis.    | [binary.ninja](https://binary.ninja)                       |
| **Cutter**         | GUI front-end for Radare2, suitable for beginners.           | [cutter.re](https://cutter.re)                             |
| **OllyDbg**        | Classic 32-bit debugger popular for Windows reverse engineering.| [ollydbg.de](https://ollydbg.de)                         |
| **Frida**          | Dynamic instrumentation toolkit for testing application behaviors.| [frida.re](https://frida.re)                           |
| **Apktool**        | Reverse-engineering tool for Android APK files.              | [GitHub](https://github.com/iBotPeaches/Apktool)          |
| **Angr**           | Binary analysis framework useful for symbolic execution.     | [angr.io](https://angr.io)                                 |
| **Radare2**        | Full reverse engineering and binary analysis suite.          | [rada.re](https://rada.re)                                 |
| **WinDbg**         | Microsoft’s debugger for Windows applications and drivers.   | [docs.microsoft.com](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger) |

---

## 13. Web Vulnerability Scanners

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **OWASP ZAP**      | Comprehensive open-source web application security scanner.  | [zaproxy.org](https://www.zaproxy.org)                     |
| **Nikto**          | Scanner for known vulnerabilities on web servers.            | [cirt.net](https://cirt.net/Nikto2)                        |
| **W3AF**           | Web application attack and audit framework.                  | [w3af.org](https://w3af.org)                               |
| **Skipfish**       | Security reconnaissance tool for web applications.           | [GitHub](https://github.com/spinkham/skipfish)             |
| **Acunetix**       | Advanced automated web application vulnerability scanner.    | [acunetix.com](https://www.acunetix.com)                   |
| **Arachni**        | Modular web application security scanner framework.          | [arachni-scanner.com](http://www.arachni-scanner.com)      |
| **Burp Suite**     | Web vulnerability scanning and exploitation platform.        | [portswigger.net](https://portswigger.net/burp)            |
| **Wapiti**         | Open-source web application vulnerability scanner.           | [wapiti.sourceforge.io](https://wapiti.sourceforge.io)     |

---

## 14. Password Managers

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **KeePassXC**      | Open-source password manager.                                | [keepassxc.org](https://keepassxc.org)                     |
| **Bitwarden**      | Secure, open-source password management.                     | [bitwarden.com](https://bitwarden.com)                     |
| **LastPass**       | Password vault and manager.                                  | [lastpass.com](https://lastpass.com)                       |
| **1Password**      | Password manager and digital vault.                          | [1password.com](https://1password.com)                     |

---

## 15. Cheat Sheets

| Resource           | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **PayloadsAllTheThings** | Collection of payloads for various pentesting scenarios. | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **HackTricks**     | Tips, tricks, and cheatsheets for penetration testing.       | [book.hacktricks.xyz](https://book.hacktricks.xyz)         |
| **GTFOBins**       | Unix binaries that help with privilege escalation.           | [gtfobins.github.io](https://gtfobins.github.io)           |
| **Linux Privilege Escalation** | Guide and resources for escalating privileges on Linux. | [GitHub](https://github.com/sleventyeleven/linuxprivchecker) |
| **Windows Privilege Escalation** | Comprehensive cheatsheet for privilege escalation on Windows. | [GitHub](https://github.com/swisskyrepo/Windows-Privilege-Escalation) |
| **Reverse Engineering Cheat Sheet** | Handy reference for common reverse engineering tasks. | [GitHub](https://github.com/mytechnotalent/Reverse-Engineering-Cheatsheet) |
| **PenTest Monkey** | Cheatsheets for reverse shells and more.                    | [pentestmonkey.net](http://pentestmonkey.net/)             |

---

## 16. Learning Resources

| Resource                     | Description                                                 | Link                                                       |
|------------------------------|-------------------------------------------------------------|------------------------------------------------------------|
| **Cybrary**                  | Free IT and cybersecurity courses.                          | [cybrary.it](https://cybrary.it)                           |
| **CTF Field Guide by Trail of Bits** | Comprehensive guide for CTF prep.               | [trailofbits.com](https://trailofbits.github.io/ctf)       |
| **OverTheWire**              | Wargames focused on Linux and security concepts.            | [overthewire.org](https://overthewire.org)                 |
| **Hack The Box**             | Hands-on platform for cybersecurity training.               | [hackthebox.com](https://hackthebox.com)                   |
| **TryHackMe**                | Accessible CTF and training labs for all levels.            | [tryhackme.com](https://tryhackme.com)                     |
| **PicoCTF**                  | Beginner-friendly CTF platform for students.                | [picoctf.com](https://picoctf.com)                         |
| **SANS Cyber Aces**          | Free training in foundational cybersecurity concepts.       | [cyberaces.org](https://www.cyberaces.org)                 |
| **Codecademy**               | Online coding and security fundamentals courses.            | [codecademy.com](https://www.codecademy.com)               |

---

## 17. Obfuscators & Evasion Tools

These tools are geared toward obfuscation, evasion, and payload manipulation, making them ideal for red team operations. They allow you to craft undetectable payloads, evade antivirus (AV) detection, and cloak activities to bypass security measures. 

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Veil**               | Evasion framework for generating undetectable payloads.         | [veil-framework.com](https://www.veil-framework.com)       |
| **Shellter**           | Dynamic shellcode injection tool for Windows, used to evade AV. | [shellterproject.com](https://www.shellterproject.com)     |
| **Hyperion**           | Binary obfuscator to bypass AV detection.                        | [GitHub](https://github.com/nullsecuritynet/tools/tree/master/binary/hyperion) |
| **Obfuscator.io**      | JavaScript and Node.js obfuscator for web applications.         | [obfuscator.io](https://obfuscator.io/)                    |
| **ConfuserEx**         | .NET obfuscator widely used for software protection.            | [GitHub](https://github.com/mkaring/ConfuserEx)            |
| **PEzor**              | Shellcode and PE file obfuscation tool for AV evasion.          | [GitHub](https://github.com/phra/PEzor)                    |
| **Exeinfo PE**         | Packed executable identifier; detects PE file packers and crypters.| [exeinfo.com](https://exeinfo.com/)                       |
| **DNGuard HVM**        | Professional .NET code protection with dynamic virtualization.  | [dnguard.net](https://www.dnguard.net)                     |
| **obfuscar**           | Basic .NET obfuscator to protect managed code.                  | [GitHub](https://github.com/obfuscar/obfuscar)             |
| **NetCrypt**           | Tool for encrypting and obfuscating .NET binaries.              | [GitHub](https://github.com/netcrypt/NetCrypt)             |
| **Dynamic Camo**       | Framework for obfuscating C2 traffic using various network camouflage techniques. | [GitHub](https://github.com/praetorian-inc/Dynamic-Camo) |

---

## 18. Advanced Red Team Tools

These tools are essential for red team operators who need to execute, maintain, and manage advanced attacks, often leveraging techniques for persistence, lateral movement, and stealth across target environments.

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Covenant**           | .NET-based C2 framework with encrypted communication for post-exploitation. | [GitHub](https://github.com/cobbr/Covenant)         |
| **Sliver**             | Open-source C2 framework supporting various payloads for adversary emulation. | [GitHub](https://github.com/BishopFox/sliver)     |
| **PoshC2**             | PowerShell-based C2 framework with extensive post-exploitation tools. | [GitHub](https://github.com/nettitude/PoshC2)    |
| **Merlin**             | C2 tool for managing multiple clients across different platforms with HTTPS-based communication. | [GitHub](https://github.com/Ne0nd0g/merlin)       |
| **Rubeus**             | Tool for Kerberos abuse, allowing credential extraction and golden ticket attacks. | [GitHub](https://github.com/GhostPack/Rubeus)    |
| **SharpHound**         | Data collector for BloodHound, used to map out AD relationships and find attack paths. | [GitHub](https://github.com/BloodHoundAD/SharpHound) |
| **Impacket**           | Collection of Python classes for SMB, Kerberos, and other protocols used in network attacks. | [GitHub](https://github.com/SecureAuthCorp/impacket) |
| **PowerSploit**        | Post-exploitation framework for PowerShell-based attack techniques. | [GitHub](https://github.com/PowerShellMafia/PowerSploit) |
| **DeathStar**          | Automates Active Directory attacks using Empire and BloodHound. | [GitHub](https://github.com/byt3bl33d3r/DeathStar) |
| **Seatbelt**           | Post-exploitation tool that collects security-relevant information on Windows systems. | [GitHub](https://github.com/GhostPack/Seatbelt) |
| **FruityC2**           | C2 framework focused on web-based operations and automation.     | [GitHub](https://github.com/xtr4nge/FruityC2)            |
| **Koadic**             | JScript RAT for Windows; similar to Meterpreter but for JavaScript. | [GitHub](https://github.com/zerosum0x0/koadic)           |
| **SharpLocker**        | Payload that creates a fake lock screen on Windows to capture credentials. | [GitHub](https://github.com/GhostPack/SharpLocker)      |
| **GhostPack**          | Collection of tools for offensive security operations, including credential and token abuse. | [GitHub](https://github.com/GhostPack)            |
| **Evil-WinRM**         | PowerShell-based WinRM shell for accessing Windows machines remotely. | [GitHub](https://github.com/Hackplayers/evil-winrm)      |
| **CredNinja**          | Tool for discovering and managing credentials across Active Directory environments. | [GitHub](https://github.com/Raikia/CredNinja)            |

---

## 19. Specialized Red Team Creation Tools

For red team operators crafting complex, customized attacks and bypasses, these tools allow for advanced payload development, exploit creation, and extensive evasion capabilities.

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Mythic**             | Open-source C2 framework that supports custom agents and payload flexibility. | [GitHub](https://github.com/its-a-feature/Mythic)         |
| **Obsidian C2**        | Modular C2 framework designed for stealth and payload customization. | [GitHub](https://github.com/ObsidianLabs/Obsidian)       |
| **SharpSploit**        | Post-exploitation library for .NET with credential extraction and token manipulation. | [GitHub](https://github.com/cobbr/SharpSploit)   |
| **Metta**              | Adversary simulation tool that uses scripts to emulate attacker behavior. | [GitHub](https://github.com/uber-common/metta)            |
| **ScareCrow**          | Payload generation framework that focuses on evading Windows Defender and AMSI. | [GitHub](https://github.com/optiv/ScareCrow)              |
| **Invoke-DOSfuscation** | DOS command obfuscation techniques to evade command-line detection. | [GitHub](https://github.com/danielbohannon/Invoke-DOSfuscation) |
| **Koadic**             | JScript-based RAT for advanced post-exploitation on Windows.     | [GitHub](https://github.com/zerosum0x0/koadic)            |
| **Octopus C2**         | Cross-platform C2 with support for modular agent and payload creation. | [GitHub](https://github.com/krishpranav/OctopusC2)       |
| **FUD-Crypter**        | Framework for creating fully undetectable payloads to bypass AV detection. | [GitHub](https://github.com/r00t-3xp10it/FUD-crypter)    |
| **RedELK**             | Red team tracking and logging solution, designed for monitoring attacks. | [GitHub](https://github.com/outflanknl/RedELK)            |
| **Demiguise**          | Tool for obfuscating AMSI bypasses on Windows, used in red team engagements. | [GitHub](https://github.com/nccgroup/demiguise)           |
| **Unicorn**            | PowerShell tool for obfuscating shellcode and delivering payloads through injection. | [GitHub](https://github.com/trustedsec/unicorn)           |
| **Caldera**            | Automated adversary emulation platform by MITRE for scalable attack testing. | [GitHub](https://github.com/mitre/caldera)                |
| **Ebowla**             | Tool for generating encrypted payloads and adding obfuscation for stealth. | [GitHub](https://github.com/Genetic-Malware/Ebowla)       |

---

## 20 Extra CTF Tools

These additional tools and resources support niche CTF challenges across cryptography, reverse engineering, web exploitation, and binary analysis, giving you an edge in tackling specific categories.

| Tool                   | Description                                                      | Link                                                       |
|------------------------|------------------------------------------------------------------|------------------------------------------------------------|
| **Qiling**             | Emulation framework for binary analysis across multiple architectures. | [GitHub](https://github.com/qilingframework/qiling)       |
| **OneGadget**          | Finds usable RCE (remote code execution) gadgets in binaries for one-shot exploits. | [GitHub](https://github.com/david942j/one_gadget) |
| **GEF (GDB Enhanced Features)** | Enhanced GDB features for debugging and exploit development. | [GitHub](https://github.com/hugsy/gef)                    |
| **pwndbg**             | GDB plugin tailored for exploit development and debugging binaries in CTFs. | [GitHub](https://github.com/pwndbg/pwndbg)               |
| **Apktool**            | Tool for decompiling and analyzing Android APK files, commonly used in mobile CTFs. | [GitHub](https://github.com/iBotPeaches/Apktool)          |
| **Hash Extender**      | Command-line tool for performing length extension attacks on hashes. | [GitHub](https://github.com/iagox86/hash_extender)       |
| **Z3**                 | Theorem prover often used for symbolic execution in reverse engineering challenges. | [GitHub](https://github.com/Z3Prover/z3)                  |
| **Binary Ninja Free**  | Reverse engineering platform (free edition) with powerful binary analysis tools. | [binary.ninja](https://binary.ninja)                       |
| **Insomni'hack payloads** | Payload collection tailored for various CTF challenges and penetration testing. | [GitHub](https://github.com/insomniacslk/InsomniHack-CTF) |
| **NCLab**              | Training platform offering hands-on labs and virtual machines for CTF practice. | [nclab.com](https://nclab.com/)                           |
| **SecLists**           | Compilation of attack payloads, wordlists, and fuzzing lists, commonly used in web and network challenges. | [GitHub](https://github.com/danielmiessler/SecLists)    |
| **Forensics Wiki**     | Resource wiki for digital forensics techniques, tools, and CTF challenges. | [forensicswiki.org](https://forensicswiki.org)             |
| **StegSolve**          | Java-based tool for stegano analysis, particularly with LSB modifications in images. | [GitHub](https://github.com/zardus/ctf-tools/tree/master/stegsolve) |
| **CertGraph**          | SSL certificate visualization tool, useful in OSINT and network mapping challenges. | [GitHub](https://github.com/lanrat/certgraph)             |
| **Cryptool**           | Interactive cryptography learning tool for understanding and analyzing cryptographic techniques. | [cryptool.org](https://www.cryptool.org/en/)              |

---


## Contributions
If you’d like to contribute, feel free to fork this repository and add any tools or resources that enhance the guide. Contributions to specific examples or additional resources will help this collection grow and stay up-to-date with the latest in cybersecurity.

Thank you for exploring the **Cybersecurity and CTF Resource Guide**. Together, we’re building a one-stop resource for digital security mastery. 

Happy hacking! 👾
