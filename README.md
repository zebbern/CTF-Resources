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
| **Censys**         | Internet-wide scan data and analysis.                        | [censys.io](https://censys.io)                             |
| **theHarvester**   | Harvest emails, subdomains, and people names.                | [GitHub](https://github.com/laramies/theHarvester)         |
| **Maltego**        | Interactive data mining and visualization.                   | [maltego.com](https://maltego.com)                         |
| **OSINT Framework**| Categorized collection of OSINT tools.                       | [osintframework.com](https://osintframework.com)           |

---

## 2. Steganography Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Steghide**       | Hide data in images and audio files.                         | [SourceForge](https://steghide.sourceforge.net)            |
| **AperiSolve**     | Image steganography analyzer.                                | [aperisolve.com](https://aperisolve.com)                   |
| **Binwalk**        | Extract data from binary files.                              | [GitHub](https://github.com/ReFirmLabs/binwalk)            |
| **ExifTool**       | Read and edit file metadata.                                 | [exiftool.org](https://exiftool.org)                       |

---

## 3. Anonymous Communication & Identity

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Tor Browser**    | Browse anonymously.                                          | [torproject.org](https://www.torproject.org)               |
| **ProtonMail**     | Encrypted email service.                                     | [protonmail.com](https://protonmail.com)                   |
| **Tails OS**       | Privacy-focused, portable operating system.                  | [tails.boum.org](https://tails.boum.org)                   |
| **Signal**         | Secure messaging app.                                        | [signal.org](https://signal.org)                           |

---

## 4. Reverse Shells & Exploits

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Metasploit**     | Full exploitation framework.                                 | [metasploit.com](https://www.metasploit.com)               |
| **GTFOBins**       | Unix binaries for privilege escalation.                      | [gtfobins.github.io](https://gtfobins.github.io)           |
| **SearchSploit**   | CLI search for Exploit Database.                             | [GitHub](https://github.com/offensive-security/exploitdb)  |
| **PayloadsAllTheThings** | Comprehensive payload collection for pentesting.      | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings) |

---

## 5. Cryptography & Hash Cracking

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Hashcat**        | Advanced password recovery tool.                             | [hashcat.net](https://hashcat.net)                         |
| **John the Ripper**| Popular password cracker.                                    | [openwall.com/john](https://www.openwall.com/john/)        |
| **CyberChef**      | Encoding, encryption, and data analysis.                     | [cyberchef.io](https://gchq.github.io/CyberChef)           |
| **Ciphey**         | Automated decryption tool.                                   | [GitHub](https://github.com/Ciphey/Ciphey)                 |

---

## 6. Penetration Testing Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Nmap**           | Network discovery and security auditing.                     | [nmap.org](https://nmap.org)                               |
| **Wireshark**      | Network protocol analyzer.                                   | [wireshark.org](https://wireshark.org)                     |
| **Burp Suite**     | Web vulnerability scanner and proxy tool.                    | [portswigger.net](https://portswigger.net/burp)            |
| **SQLMap**         | SQL injection automation tool.                               | [sqlmap.org](https://sqlmap.org)                           |
| **Hydra**          | Network logon cracker supporting various protocols.          | [GitHub](https://github.com/vanhauser-thc/thc-hydra)       |

---

## 7. Red Team Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Cobalt Strike**  | Adversary simulation and red team operations.                | [cobaltstrike.com](https://www.cobaltstrike.com)           |
| **BloodHound**     | AD enumeration and mapping.                                  | [GitHub](https://github.com/BloodHoundAD/BloodHound)       |
| **Empire**         | Post-exploitation framework.                                 | [GitHub](https://github.com/EmpireProject/Empire)          |
| **Mimikatz**       | Credential dumping tool.                                     | [GitHub](https://github.com/gentilkiwi/mimikatz)           |

---

## 8. Blue Team Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Security Onion** | Linux distro for intrusion detection and monitoring.         | [securityonion.net](https://securityonion.net)             |
| **Wazuh**          | Open-source security monitoring platform.                    | [wazuh.com](https://wazuh.com)                             |
| **Suricata**       | Network threat detection engine.                             | [suricata.io](https://suricata.io)                         |
| **ELK Stack**      | Log management and analytics platform.                       | [elastic.co](https://www.elastic.co)                       |

---

## 9. Malware Analysis Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Ghidra**         | Reverse engineering suite.                                   | [ghidra-sre.org](https://ghidra-sre.org)                   |
| **IDA Pro**        | Disassembler and debugger.                                   | [hex-rays.com](https://hex-rays.com)                       |
| **Remnux**         | Malware analysis toolkit.                                    | [remnux.org](https://remnux.org)                           |
| **Cuckoo Sandbox** | Automated malware analysis system.                           | [cuckoosandbox.org](https://cuckoosandbox.org)             |

---

## 10. CTF Platforms and Training Resources

| Platform           | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Hack The Box**   | CTF platform with virtual labs.                              | [hackthebox.com](https://hackthebox.com)                   |
| **TryHackMe**      | Beginner-friendly cybersecurity platform.                    | [tryhackme.com](https://tryhackme.com)                     |
| **PicoCTF**        | CTF platform for students.                                   | [picoctf.com](https://picoctf.com)                         |
| **OverTheWire**    | Linux and security challenges.                               | [overthewire.org](https://overthewire.org)                 |

---

## 11. File Transfer & Sharing

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **OnionShare**     | Secure file sharing over Tor.                                | [onionshare.org](https://onionshare.org)                   |
| **Syncthing**      | Continuous file synchronization between devices.             | [syncthing.net](https://syncthing.net)                     |
| **FilePizza**      | P2P file sharing via WebRTC.                                 | [file.pizza](https://file.pizza)                           |

---

## 12. Reverse Engineering Tools

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Binary Ninja**   | Reverse engineering platform.                                | [binary.ninja](https://binary.ninja)                       |
| **Cutter**         | GUI for the Radare2 reverse engineering framework.           | [cutter.re](https://cutter.re)                             |
| **OllyDbg**        | 32-bit assembler level debugger.                             | [ollydbg.de](https://ollydbg.de)                           |

---

## 13. Web Vulnerability Scanners

| Tool               | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **OWASP ZAP**      | Open-source web application security scanner.                |```markdown
| **OWASP ZAP**      | Open-source web application security scanner.                | [zaproxy.org](https://www.zaproxy.org)                     |
| **Nikto**          | Web server vulnerability scanner.                            | [cirt.net](https://cirt.net/Nikto2)                        |
| **W3AF**           | Web application attack and audit framework.                  | [w3af.org](https://w3af.org)                               |
| **Skipfish**       | Web application security reconnaissance tool.                | [GitHub](https://github.com/spinkham/skipfish)             |

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
| **PayloadsAllTheThings** | Collection of payloads for pentesting.             | [GitHub](https://github.com/swisskyrepo/PayloadsAllTheThings) |
| **HackTricks**     | Cheatsheets and tips for pentesting.                         | [book.hacktricks.xyz](https://book.hacktricks.xyz)         |
| **GTFOBins**       | Unix binaries for privilege escalation.                      | [gtfobins.github.io](https://gtfobins.github.io)           |
| **Linux Privilege Escalation** | Privilege escalation resources for Linux.     | [GitHub](https://github.com/sleventyeleven/linuxprivchecker) |

---

## 16. Learning Resources

| Resource           | Description                                                  | Link                                                       |
|--------------------|--------------------------------------------------------------|------------------------------------------------------------|
| **Cybrary**        | Free IT and cybersecurity courses.                           | [cybrary.it](https://cybrary.it)                           |
| **CTF Field Guide by Trail of Bits** | Comprehensive CTF preparation guide.    | [trailofbits.com](https://trailofbits.github.io/ctf)       |
| **OverTheWire**    | Wargames for Linux and security concepts.                    | [overthewire.org](https://overthewire.org)                 |
| **Hack The Box**   | Online platform for hands-on cybersecurity training.         | [hackthebox.com](https://hackthebox.com)                   |

---

## Contributions
If you’d like to contribute, feel free to fork this repository and add any tools or resources that enhance the guide. Contributions to specific examples or additional resources will help this collection grow and stay up-to-date with the latest in cybersecurity.

Thank you for exploring the **Cybersecurity and CTF Resource Guide**. Together, we’re building a one-stop resource for digital security mastery. 

Happy hacking! 👾
