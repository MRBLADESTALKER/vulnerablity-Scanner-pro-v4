Cyber Expert Bladex Pro v4 is an advanced graphical user interface (GUI) tool built in Python for performing Nmap scans. It enhances the standard Nmap functionality with a professional, hacker-themed interface, secure user authentication, scan history management, and a wide range of pre-configured scan presets. This tool is designed for cybersecurity professionals, penetration testers, and auditors to conduct network scans efficiently and securely. 🔍

Note: This is an ethical hacking tool intended for authorized use only. It helps defenders and auditors identify vulnerabilities in controlled environments. ⚠️

Tool LOOK <img width="1366" height="768" alt="nmapv4" src="https://github.com/user-attachments/assets/1d3bb6c6-07cc-4af0-b5f3-dd62c932dcfe" />

Key Features ✨

• Comprehensive Nmap Command Presets: Over 50 ready-to-use Nmap scan types (e.g., Quick Scan, Intense Scan, Vulnerability Scan) with click-to-run functionality and search filtering. 📋

• Secure Login/Logout System: User authentication with hashed passwords, role-based access (e.g., admin/user), and secure credential storage using encryption. 🔒

• Scan History Tracking: Automatically logs scans per user, including targets, arguments, timestamps, and result counts. View, reload, or clear history easily. 📜

• Vulnerability Enrichment: Integrates with NVD API for detailed CVE information, including scores, severity, and references. 🛡️

• Credential Vault: Secure storage for service credentials (e.g., SMB/SSH) to inject into scans. 🗝️

• Results Visualization: Tree-based results viewer with filters (e.g., show only open ports or vulnerabilities), detailed port/service info, and export to JSON. 📊

• Live Logging and Details: Real-time scan logs and clickable details for hosts, ports, and vulnerabilities. 📝

• All Existing Functionality Preserved: Builds on core Nmap scanning with added GUI enhancements without breaking compatibility. 🔄

Requirements 📋

• Python Version: 3.8 or higher. 🐍

• Dependencies: python-nmap: For Nmap integration.

• PyQt5: For the GUI framework.

• cryptography: For secure encryption and hashing.


• External Tools: Nmap binary must be installed and available in your system's PATH. 🛠️

• Operating System: Tested on Linux (e.g., Kali), Windows, and macOS. Cross-platform compatible. 💻
Installation 🔧

• Install Python Dependencies:
text

pip install python-nmap PyQt5 cryptography requests 

• Install Nmap:

• On Linux (e.g., Ubuntu/Kali): sudo apt install nmap 🐧

• On Windows: Download from nmap.org 🖥️

• On macOS: brew install nmap (using Homebrew) 🍏

• Download the Script:

• Save the provided Python script as Cyber_Expert_Bladex_Pro_v4.py. 📥

• Optional: NVD API Key:

• For vulnerability enrichment, obtain a free API key from NVD and set it in the VulnerabilityEnricher class. 🔑

Usage 🚀

• Run the Tool:  ./v4.sh

• Login:

• Default credentials: Username admin, Password bladex2025. 🔑

• Create new users via the UserManager class if needed.

• Perform a Scan:

• Enter targets (e.g., IP, hostname, CIDR) in the "Targets" field. 🎯

• Enter Nmap arguments or select a preset from the list. ⚙️

Legal Disclaimer ⚠️

• Authorized Use Only: This tool is for educational, defensive, and auditing purposes. Only scan targets you own or have explicit permission to test. 🚫

• Compliance: Ensure compliance with local laws (e.g., no unauthorized hacking). The developers are not responsible for misuse. 📜

• Ethical Note: Designed to assist cybersecurity defenders and ethical hackers. Always obtain consent before scanning. 🤝
Troubleshooting 🛠️

• Nmap Not Found: Ensure Nmap is installed and in your PATH. 🔍


• Built with: Python, Nmap, PyQt5. 🛠️

• Inspired by: Open-source cybersecurity tools like Nmap and custom GUI scanners. 💡

Contact 💬

For issues or suggestions, reach out on Telegram: @mrbladestalker35. 🚀

Happy scanning! 🛡️
