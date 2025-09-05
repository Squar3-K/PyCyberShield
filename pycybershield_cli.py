#!/usr/bin/env python3
"""
PyCyberShield - Command Line Interface
Interactive CLI for comprehensive cybersecurity assessment and analysis.
"""

import os
import sys
import time
import json
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Import all modules
try:
    from System_Security import run_system_security
    from network_security import scan_open_ports, detect_repeated_attempts, connection_attempts
    from Log_analysis import LogAnalyzer
    from Grc_module import assign_risk_score, map_to_standard
    from Crypto_module import run_crypto, generate_fernet_key
    from reporting import SecurityReporter
    from main import PyCyberShield
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are in the same directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pycybershield_cli.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class PyCyberShieldCLI:
    """Command Line Interface for PyCyberShield security assessment suite."""
    
    def __init__(self):
        """Initialize the CLI interface."""
        self.shield = PyCyberShield()
        self.output_dir = Path("reports")
        self.output_dir.mkdir(exist_ok=True)
        
    def display_header(self):
        """Display creative ASCII art header with group information."""
        header = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗ ██╗   ██╗ ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗       ║
║    ██╔══██╗╚██╗ ██╔╝██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝       ║
║    ██████╔╝ ╚████╔╝ ██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗       ║
║    ██╔═══╝   ╚██╔╝  ██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║       ║
║    ██║        ██║   ╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║       ║
║    ╚═╝        ╚═╝    ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝       ║
║                                                                              ║
║                     🛡️  CYBERSECURITY ASSESSMENT SUITE  🛡️                   ║
║                                                                              ║
║                                   GROUP 6                                   ║
║                                                                              ║
║               Created by: Alex Kamwende, Killo Philip,                       ║
║                          Harrison Mwambui, Blessing Mabonga                        ║
║                                                                              ║
║              🔒 Advanced Security Analysis & Threat Detection 🔒             ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        # Add some color and animation
        colors = ['\033[91m', '\033[92m', '\033[93m', '\033[94m', '\033[95m', '\033[96m']
        
        print('\033[2J\033[H')  # Clear screen and move cursor to top
        
        for i, line in enumerate(header.split('\n')):
            color = colors[i % len(colors)]
            print(f"{color}{line}\033[0m")
            time.sleep(0.1)
        
        print(f"\n{' ' * 20} Welcome to PyCyberShield v2.0")
        print(f"{' ' * 25}Current Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)

    def display_menu(self):
        """Display the main menu options."""
        menu = """
┌─────────────────────────────────────────────────────────────────────────────┐
│                           🔧 SECURITY MODULES MENU 🔧                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. 🖥️  System Security Analysis                                            │
│      └─ Process monitoring, suspicious activity detection                   │
│                                                                             │
│  2. 🌐 Network Security Assessment                                          │
│      └─ Port scanning, connection analysis, intrusion detection            │
│                                                                             │
│  3. 📋 Log Analysis & Forensics                                             │
│      └─ System log parsing, brute-force detection, timeline analysis       │
│                                                                             │
│  4. ⚖️  Risk Assessment & Compliance                                         │
│      └─ GRC analysis, compliance mapping (ISO27001, NIST CSF)              │
│                                                                             │
│  5. 🔐 Cryptographic Services                                               │
│      └─ Data encryption, digital signatures, key management                │
│                                                                             │
│  6. 📊 Security Reporting                                                   │
│      └─ PDF reports, charts, executive summaries                           │
│                                                                             │
│  7. 🚀 COMPREHENSIVE SECURITY SCAN                                          │
│      └─ Run all modules with integrated analysis                           │
│                                                                             │
│  8. 📈 Security Dashboard                                                   │
│      └─ View previous scan results and trends                              │
│                                                                             │
│  9. ⚙️  Configuration & Settings                                            │
│      └─ Customize scan parameters and output options                       │
│                                                                             │
│  0. 🚪 Exit PyCyberShield                                                   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
        """
        print(menu)

    def run_system_security_module(self):
        """Execute System Security Analysis."""
        print("\n🖥️  INITIATING SYSTEM SECURITY ANALYSIS...")
        print("=" * 60)
        
        try:
            self.animate_progress("Scanning running processes")
            results = self.shield.run_system_scan()
            
            if results:
                print(f"\n✅ System Security Analysis Complete!")
                print(f"📊 Total Processes Scanned: {len(results.get('processes', []))}")
                print(f"⚠️  Suspicious Processes Found: {len(results.get('suspicious', []))}")
                print(f"🛡️  Security Services Status: {results.get('services', {})}")
                
                # Show top suspicious processes
                suspicious = results.get('suspicious', [])[:5]
                if suspicious:
                    print("\n🚨 Top Suspicious Processes:")
                    for i, proc in enumerate(suspicious, 1):
                        print(f"   {i}. {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'N/A')}, "
                              f"CPU: {proc.get('cpu_percent', 0):.1f}%)")
                
                self.save_module_results("system_security", results)
            else:
                print("❌ System security analysis failed or returned no results.")
                
        except Exception as e:
            logger.error(f"System security analysis failed: {e}")
            print(f"❌ Error during system analysis: {e}")
        
        self.pause_for_user()

    def run_network_security_module(self):
        """Execute Network Security Assessment."""
        print("\n🌐 INITIATING NETWORK SECURITY ASSESSMENT...")
        print("=" * 60)
        
        try:
            self.animate_progress("Scanning network infrastructure")
            results = self.shield.run_network_scan()
            
            if results:
                print(f"\n✅ Network Security Assessment Complete!")
                
                unusual_ports = results.get('unusual_ports', {})
                total_unusual = sum(len(ports) for ports in unusual_ports.values())
                
                print(f"🔍 Network Scan Results:")
                print(f"   • Unusual Ports Detected: {total_unusual}")
                print(f"   • Hosts Scanned: {len(unusual_ports)}")
                print(f"   • Risk Level: {results.get('risk_score', 'Unknown')}")
                
                if unusual_ports:
                    print("\n🚨 Unusual Open Ports by Host:")
                    for host, ports in unusual_ports.items():
                        print(f"   📍 {host}: Ports {', '.join(map(str, ports))}")
                
                self.save_module_results("network_security", results)
            else:
                print("❌ Network security assessment failed or returned no results.")
                
        except Exception as e:
            logger.error(f"Network security assessment failed: {e}")
            print(f"❌ Error during network analysis: {e}")
        
        self.pause_for_user()

    def run_log_analysis_module(self):
        """Execute Log Analysis & Forensics."""
        print("\n📋 INITIATING LOG ANALYSIS & FORENSICS...")
        print("=" * 60)
        
        try:
            self.animate_progress("Analyzing system logs")
            results = self.shield.run_log_analysis()
            
            if results:
                print(f"\n✅ Log Analysis Complete!")
                print(f"📊 Analysis Results:")
                print(f"   • Total Log Entries: {results.get('total_entries', 0)}")
                print(f"   • Suspicious Entries: {results.get('total_suspicious_entries', 0)}")
                print(f"   • Failed Login Attempts: {results.get('total_failed_logins', 0)}")
                print(f"   • Brute Force Attacks: {results.get('brute_force_attacks_detected', 0)}")
                print(f"   • Risk Level: {results.get('risk_score', 'Unknown')}")
                
                if results.get('brute_force_attacks_detected', 0) > 0:
                    print("\n🚨 CRITICAL: Brute force attacks detected!")
                    print("   Immediate security attention required.")
                
                self.save_module_results("log_analysis", results)
            else:
                print("❌ Log analysis failed or returned no results.")
                
        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            print(f"❌ Error during log analysis: {e}")
        
        self.pause_for_user()

    def run_risk_assessment_module(self):
        """Execute Risk Assessment & Compliance."""
        print("\n⚖️  INITIATING RISK ASSESSMENT & COMPLIANCE ANALYSIS...")
        print("=" * 60)
        
        try:
            self.animate_progress("Performing risk assessment")
            results = self.shield.perform_risk_assessment()
            
            if results:
                print(f"\n✅ Risk Assessment Complete!")
                print(f"📊 Risk Analysis Results:")
                print(f"   • Overall Risk Level: {results.get('overall_risk', 'Unknown')}")
                print(f"   • Total Findings: {results.get('total_findings', 0)}")
                print(f"   • Assessment Timestamp: {results.get('assessment_timestamp', 'N/A')}")
                
                # Show compliance mapping
                compliance = results.get('compliance_mapping', {})
                if compliance:
                    print(f"\n🏛️  Compliance Framework Mapping:")
                    for finding, frameworks in list(compliance.items())[:3]:
                        print(f"   📋 {finding}:")
                        for framework, control in frameworks.items():
                            print(f"      • {framework}: {control}")
                
                self.save_module_results("risk_assessment", results)
            else:
                print("❌ Risk assessment failed or returned no results.")
                
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            print(f"❌ Error during risk assessment: {e}")
        
        self.pause_for_user()

    def run_crypto_module(self):
        """Execute Cryptographic Services."""
        print("\n🔐 INITIATING CRYPTOGRAPHIC SERVICES...")
        print("=" * 60)
        
        try:
            self.animate_progress("Encrypting sensitive data")
            results = self.shield.encrypt_sensitive_data()
            
            if results and not results.get('error'):
                print(f"\n✅ Cryptographic Operations Complete!")
                
                encrypted_files = results.get('encrypted_files', [])
                print(f"🔒 Encryption Results:")
                print(f"   • Files Encrypted: {len(encrypted_files)}")
                print(f"   • Key File Generated: {results.get('key_file', 'N/A')}")
                
                if encrypted_files:
                    print(f"\n📁 Encrypted Files:")
                    for file_info in encrypted_files[:5]:  # Show first 5
                        original = Path(file_info['original']).name
                        encrypted = Path(file_info['encrypted']).name
                        print(f"   📄 {original} → {encrypted}")
                
                print(f"\n⚠️  Important: Keep the encryption key secure!")
                
                self.save_module_results("crypto_services", results)
            else:
                print("❌ Cryptographic services failed or no files to encrypt.")
                
        except Exception as e:
            logger.error(f"Cryptographic services failed: {e}")
            print(f"❌ Error during encryption: {e}")
        
        self.pause_for_user()

    def run_reporting_module(self):
        """Execute Security Reporting."""
        print("\n📊 INITIATING SECURITY REPORTING...")
        print("=" * 60)
        
        try:
            # Load previous results if available
            results_file = self.output_dir / "scan_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    results = json.load(f)
                
                self.animate_progress("Generating comprehensive report")
                
                reporter = SecurityReporter(str(self.output_dir))
                report_path = reporter.generate_comprehensive_report(results)
                
                if report_path:
                    print(f"\n✅ Security Report Generated!")
                    print(f"📄 Report Location: {report_path}")
                    print(f"📊 Report includes:")
                    print(f"   • Executive Summary")
                    print(f"   • Detailed Findings")
                    print(f"   • Risk Assessment Charts")
                    print(f"   • Compliance Mapping")
                    print(f"   • Security Recommendations")
                else:
                    print("❌ Report generation failed.")
            else:
                print("❌ No scan results found. Please run a security scan first.")
                
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            print(f"❌ Error during report generation: {e}")
        
        self.pause_for_user()

    def run_comprehensive_scan(self):
        """Execute comprehensive security scan."""
        print("\n🚀 INITIATING COMPREHENSIVE SECURITY SCAN...")
        print("=" * 60)
        print("This will run all security modules in sequence...")
        
        try:
            start_time = datetime.now()
            
            # Run full scan
            results = self.shield.run_full_scan()
            
            end_time = datetime.now()
            duration = (end_time - start_time).total_seconds()
            
            print(f"\n🎉 COMPREHENSIVE SCAN COMPLETED!")
            print(f"⏱️  Total Duration: {duration:.2f} seconds")
            print(f"📁 Results Directory: {results.get('results_file', 'N/A')}")
            print(f"📊 PDF Report: {results.get('report_path', 'N/A')}")
            
            # Display dashboard
            self.shield.display_dashboard()
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed: {e}")
            print(f"❌ Error during comprehensive scan: {e}")
        
        self.pause_for_user()

    def view_security_dashboard(self):
        """Display security dashboard."""
        print("\n📈 SECURITY DASHBOARD")
        print("=" * 60)
        
        try:
            # Load previous results
            results_file = self.output_dir / "scan_results.json"
            if results_file.exists():
                with open(results_file, 'r') as f:
                    results = json.load(f)
                
                # Create a temporary shield instance to display dashboard
                temp_shield = PyCyberShield()
                temp_shield.results = results
                temp_shield.display_dashboard()
                
            else:
                print("❌ No previous scan results found.")
                print("   Please run a security scan first to view the dashboard.")
                
        except Exception as e:
            logger.error(f"Dashboard display failed: {e}")
            print(f"❌ Error loading dashboard: {e}")
        
        self.pause_for_user()

    def configuration_settings(self):
        """Display configuration and settings menu."""
        print("\n⚙️  CONFIGURATION & SETTINGS")
        print("=" * 60)
        
        config_menu = """
1. 📁 Set Output Directory
2. 🔧 Configure Scan Parameters
3. 🌐 Network Scan Targets
4. ⏰ Set Scan Timeouts
5. 📧 Notification Settings
6. 🔒 Security Thresholds
7. 📋 Log File Locations
8. 🔄 Reset to Defaults
9. 📄 View Current Configuration
0. 🔙 Back to Main Menu
        """
        
        print(config_menu)
        
        while True:
            try:
                choice = input("\n🔧 Select configuration option (0-9): ").strip()
                
                if choice == '0':
                    break
                elif choice == '1':
                    new_dir = input("📁 Enter new output directory path: ").strip()
                    if new_dir:
                        self.output_dir = Path(new_dir)
                        self.output_dir.mkdir(exist_ok=True)
                        print(f"✅ Output directory set to: {self.output_dir}")
                elif choice == '9':
                    self.display_current_config()
                else:
                    print("🚧 This configuration option is under development.")
                    
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"❌ Configuration error: {e}")

    def display_current_config(self):
        """Display current configuration."""
        print(f"\n📋 CURRENT CONFIGURATION:")
        print(f"   • Output Directory: {self.output_dir}")
        print(f"   • Log Level: {logger.level}")
        print(f"   • Python Version: {sys.version}")
        print(f"   • Platform: {sys.platform}")

    def animate_progress(self, message: str, duration: int = 3):
        """Display animated progress indicator."""
        animations = ["|", "/", "-", "\\"]
        end_time = time.time() + duration
        i = 0
        
        while time.time() < end_time:
            print(f"\r🔄 {message} {animations[i % len(animations)]}", end="", flush=True)
            time.sleep(0.2)
            i += 1
        
        print(f"\r✅ {message} Complete!" + " " * 10)

    def save_module_results(self, module_name: str, results: Dict[str, Any]):
        """Save individual module results."""
        try:
            results_file = self.output_dir / f"{module_name}_results.json"
            with open(results_file, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            print(f"💾 Results saved to: {results_file}")
        except Exception as e:
            logger.error(f"Failed to save {module_name} results: {e}")

    def pause_for_user(self):
        """Pause execution and wait for user input."""
        print("\n" + "─" * 60)
        input("Press Enter to continue...")

    def run(self):
        """Main CLI execution loop."""
        self.display_header()
        
        while True:
            try:
                self.display_menu()
                choice = input("\n🎯 Select an option (0-9): ").strip()
                
                if choice == '0':
                    self.display_exit_message()
                    break
                elif choice == '1':
                    self.run_system_security_module()
                elif choice == '2':
                    self.run_network_security_module()
                elif choice == '3':
                    self.run_log_analysis_module()
                elif choice == '4':
                    self.run_risk_assessment_module()
                elif choice == '5':
                    self.run_crypto_module()
                elif choice == '6':
                    self.run_reporting_module()
                elif choice == '7':
                    self.run_comprehensive_scan()
                elif choice == '8':
                    self.view_security_dashboard()
                elif choice == '9':
                    self.configuration_settings()
                else:
                    print("❌ Invalid option. Please select a number between 0-9.")
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("\n\n🛑 Operation cancelled by user.")
                confirm = input("Do you want to exit PyCyberShield? (y/N): ").strip().lower()
                if confirm in ['y', 'yes']:
                    self.display_exit_message()
                    break
            except Exception as e:
                logger.error(f"CLI error: {e}")
                print(f"\n❌ An error occurred: {e}")
                print("Please try again or contact support.")
                time.sleep(2)

    def display_exit_message(self):
        """Display exit message with group credits."""
        exit_message = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                      🛡️  Thank you for using PyCyberShield! 🛡️                ║
║                                                                              ║
║                    Your digital security is our priority.                    ║
║                                                                              ║
║                              Stay Safe Online! 🔒                            ║
║                                                                              ║
║                                 GROUP 6                                      ║
║         Alex Kamwende • Killo Philip • Harrison Mwambui • Blessing Mabonga   ║
║                                                                              ║
║                          © 2024 PyCyberShield Project                        ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        print(exit_message)


def main():
    """Main entry point for the CLI application."""
    try:
        cli = PyCyberShieldCLI()
        cli.run()
        return 0
    except Exception as e:
        logger.error(f"CLI startup failed: {e}")
        print(f"❌ Failed to start PyCyberShield CLI: {e}")
        return 1


if __name__ == "__main__":
    exit(main())