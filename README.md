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
These tools are perfect for reconnaissance and data gathering. Start with **Shodan** or **Censys** for IoT and device information. Use **theHarvester** to uncover emails and subdomains, and then dive into **Maltego** for mapping relationships. Combine multiple OSINT tools for a comprehensive overview of your target.

### 2. Steganography
For CTFs or forensic analysis, use tools like **Steghide** to conceal or reveal hidden data in images. **AperiSolve** offers a fast online platform for analyzing hidden image content, while **ExifTool** allows metadata examination in files, often revealing hidden or extra information useful for digital forensics.

### 3. Anonymity and Privacy
To keep your activities secure and untraceable, check out **Tor Browser** for anonymized browsing or **Tails OS** for a secure operating system. **ProtonMail** and **Signal** are ideal for encrypted communications.

### 4. Exploitation and Reverse Shells
Use the **Metasploit Framework** for full-fledged exploit and payload delivery, or check out **GTFOBins** for privilege escalation on Unix systems. **PayloadsAllTheThings** is also included here, providing a huge repository of payloads for testing different exploit methods.

### 5. Cryptography and Hash Cracking
When cracking passwords or dealing with cryptographic challenges, turn to **Hashcat** or **John the Ripper**. For decryption and encoding tasks, **CyberChef** is invaluable.

### 6. Penetration Testing
For a comprehensive pentest toolkit, use **Nmap** for network scanning, **Wireshark** for traffic analysis, **Burp Suite** for web vulnerabilities, and **SQLMap** for SQL injection exploits. This category has essential tools for every stage of a penetration test.

### 7. Red and Blue Team Tools
Red team tools like **Cobalt Strike** and **BloodHound** are essential for adversary simulations and lateral movement within networks. For defensive (blue team) activities, check out **Security Onion** for intrusion detection and **Wazuh** for monitoring and incident response.

### 8. CTF and Training Platforms
This section features CTF platforms like **Hack The Box** and **TryHackMe**, where you can practice using these tools in real scenarios. If you're preparing for a CTF event, check out the **CTF Field Guide by Trail of Bits**.

### 9. Cheat Sheets and Reference
Use this section for quick references and cheat sheets. **PayloadsAllTheThings** and **HackTricks** offer an extensive set of attack payloads and pentesting techniques to apply in live environments.

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

## Contributions
If you’d like to contribute, feel free to fork this repository and add any tools or resources that enhance the guide. Contributions to specific examples or additional resources will help this collection grow and stay up-to-date with the latest in cybersecurity.

Thank you for exploring the **Cybersecurity and CTF Resource Guide**. Together, we’re building a one-stop resource for digital security mastery. 

Happy hacking! 👾
