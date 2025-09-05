#PyCyberShield
   
   PyCyberShield is a Python-based integrated cybersecurity defense system designed for foundational cybersecurity skills (COP 400). It provides tools for system security analysis, network scanning, log forensics, risk assessment, compliance mapping, data encryption, and comprehensive reporting. Built by Group 6, this tool helps detect suspicious activities, vulnerabilities, and threats in a modular and extensible way.

Features

System Security Analysis: Monitors running processes, detects suspicious activities, and checks security services (e.g., firewall, antivirus).
Network Security Assessment: Scans for open ports, detects intrusions, and analyzes connection attempts using Nmap and Scapy.
Log Analysis & Forensics: Parses system logs (Linux/Windows) to identify brute-force attacks, failed logins, and suspicious events.
Risk Assessment & Compliance: Maps findings to frameworks like ISO 27001 and NIST CSF, calculates risk scores, and generates recommendations.
Cryptographic Services: Encrypts sensitive logs and signs reports using Fernet and RSA.
Security Reporting: Generates PDF reports with charts, executive summaries, and detailed findings using ReportLab and Matplotlib.
Interactive CLI: User-friendly command-line interface for running scans, viewing dashboards, and configuring settings.
Modular Design: Easily extendable with additional modules.

   This tool is ideal for educational purposes, security audits, and basic threat detection.

Installation

Clone the repository:
git clone https://github.com/Squar3-K/PyCyberShield.git
cd PyCyberShield


Install dependencies (Python 3.8+ required):
pip install -r requirements.txt

Note: On Linux, install additional system packages for Nmap and Scapy:
sudo apt-get install nmap python3-scapy

On Windows, ensure Event Viewer access for log analysis.

(Optional) Set up a virtual environment:
python -m venv venv
source venv/bin/activate  # On Linux/Mac
venv\Scripts\activate     # On Windows

Usage
   Run the interactive CLI to access all features:
python pycybershield_cli.py

CLI Menu Options

1. System Security Analysis: Scan processes and flag suspicious ones.
2. Network Security Assessment: Perform port scans and traffic analysis.
3. Log Analysis & Forensics: Analyze logs for attacks and events.
4. Risk Assessment & Compliance: Map findings to standards and assess risks.
5. Cryptographic Services: Encrypt logs and sign reports.
6. Security Reporting: Generate PDF reports with visualizations.
7. Comprehensive Security Scan: Run all modules in one go.
8. Security Dashboard: View scan results and trends.
9. Configuration & Settings: Customize paths, thresholds, etc.
0. Exit: Quit the tool.

   Output files are saved in the reports/ directory (not tracked by Git).
   For programmatic use:
from System_Security import run_system_security
results = run_system_security()

Project Structure

.gitignore: Excludes generated files and Python cache.
LICENSE: MIT License for the project.
requirements.txt: Python dependencies.
Crypto_module.py: Encryption and signing utilities.
Grc_module.py: Governance, Risk, and Compliance tools.
Log_analysis.py: Log parsing and attack detection.
System_Security.py: Process and system monitoring.
main.py: Core integration script.
network_security.py: Network scanning and analysis.
pycybershield_cli.py: Interactive CLI.
reporting.py: PDF report generation with charts.

Contributing
   Contributions are welcome! Please:

Fork the repository.
Create a feature branch: git checkout -b feature/YourFeature.
Commit changes: git commit -m "Add YourFeature".
Push to the branch: git push origin feature/YourFeature.
Open a Pull Request.

   Report issues or suggest features via GitHub Issues.
Credits
   Developed by Group 6 for COP 400 - Cybersecurity Foundational Skills:

Alex Kamwende
Killo Philip
Harrison Mwambui
Blessing Mabonga

   Special thanks to open-source libraries: psutil, python-nmap, scapy, cryptography, reportlab, pandas, matplotlib.
License
   This project is licensed under the MIT License - see the LICENSE file for details.

   For questions, contact the contributors or open an issue.