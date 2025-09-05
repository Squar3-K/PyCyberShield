#!/usr/bin/env python3
"""
PyCyberShield - Main Integration Module
Integrates all security modules and generates comprehensive reports.
"""

import os
import sys
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
except ImportError as e:
    print(f"Error importing modules: {e}")
    print("Please ensure all required modules are in the same directory")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pycybershield.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class PyCyberShield:
    """Main PyCyberShield class that orchestrates all security modules."""
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize PyCyberShield with output directory."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Results storage
        self.results = {
            'timestamp': datetime.now().isoformat(),
            'system_security': {},
            'network_security': {},
            'log_analysis': {},
            'risk_assessment': {},
            'encrypted_files': [],
            'summary': {}
        }
        
        logger.info("PyCyberShield initialized")

    def run_system_scan(self) -> Dict[str, Any]:
        """Run system security analysis."""
        logger.info("Starting system security scan...")
        
        try:
            system_results = run_system_security()
            self.results['system_security'] = system_results
            
            # Calculate risk scores for system findings
            suspicious_count = len(system_results.get('suspicious', []))
            if suspicious_count > 10:
                system_risk = 8  # High risk
            elif suspicious_count > 5:
                system_risk = 5  # Medium risk
            else:
                system_risk = 2  # Low risk
            
            self.results['system_security']['risk_score'] = assign_risk_score(system_risk)
            self.results['system_security']['severity_value'] = system_risk
            
            logger.info(f"System scan completed. Found {suspicious_count} suspicious processes")
            return system_results
            
        except Exception as e:
            logger.error(f"System scan failed: {e}")
            self.results['system_security'] = {'error': str(e)}
            return {}

    def run_network_scan(self) -> Dict[str, Any]:
        """Run network security analysis."""
        logger.info("Starting network security scan...")
        
        try:
            # Port scanning
            unusual_ports = scan_open_ports()
            
            # Packet analysis (commented out for now to avoid blocking)
            # detect_repeated_attempts()
            
            network_results = {
                'unusual_ports': unusual_ports,
                'connection_attempts': dict(connection_attempts),
                'scan_timestamp': datetime.now().isoformat()
            }
            
            # Calculate risk based on findings
            unusual_port_count = sum(len(ports) for ports in unusual_ports.values())
            suspicious_connections = len([count for count in connection_attempts.values() if count >= 5])
            
            network_risk = min(10, unusual_port_count * 2 + suspicious_connections)
            network_results['risk_score'] = assign_risk_score(network_risk)
            network_results['severity_value'] = network_risk
            
            self.results['network_security'] = network_results
            logger.info(f"Network scan completed. Found {unusual_port_count} unusual ports")
            
            return network_results
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            self.results['network_security'] = {'error': str(e)}
            return {}

    def run_log_analysis(self) -> Dict[str, Any]:
        """Run log analysis."""
        logger.info("Starting log analysis...")
        
        try:
            analyzer = LogAnalyzer(str(self.output_dir))
            log_results = analyzer.analyze_logs()
            
            # Get detailed report
            detailed_report = analyzer.get_detailed_report()
            
            # Calculate risk based on findings
            suspicious_entries = log_results.get('total_suspicious_entries', 0)
            brute_force_attacks = log_results.get('brute_force_attacks_detected', 0)
            
            log_risk = min(10, suspicious_entries + brute_force_attacks * 3)
            log_results['risk_score'] = assign_risk_score(log_risk)
            log_results['severity_value'] = log_risk
            
            self.results['log_analysis'] = {
                **log_results,
                'detailed_findings': detailed_report
            }
            
            logger.info(f"Log analysis completed. Found {suspicious_entries} suspicious entries")
            return log_results
            
        except Exception as e:
            logger.error(f"Log analysis failed: {e}")
            self.results['log_analysis'] = {'error': str(e)}
            return {}

    def perform_risk_assessment(self) -> Dict[str, Any]:
        """Perform comprehensive risk assessment and compliance mapping."""
        logger.info("Performing risk assessment...")
        
        try:
            findings = []
            
            # System security findings
            if 'system_security' in self.results and 'suspicious' in self.results['system_security']:
                suspicious_count = len(self.results['system_security']['suspicious'])
                if suspicious_count > 0:
                    findings.append({
                        'category': 'System Security',
                        'finding': 'Suspicious Processes',
                        'severity': self.results['system_security'].get('severity_value', 0),
                        'description': f"{suspicious_count} suspicious processes detected"
                    })
            
            # Network security findings
            if 'network_security' in self.results:
                unusual_ports = self.results['network_security'].get('unusual_ports', {})
                if unusual_ports:
                    findings.append({
                        'category': 'Network Security',
                        'finding': 'Unusual Open Ports',
                        'severity': self.results['network_security'].get('severity_value', 0),
                        'description': f"Unusual ports detected: {unusual_ports}"
                    })
            
            # Log analysis findings
            if 'log_analysis' in self.results:
                brute_force = self.results['log_analysis'].get('brute_force_attacks_detected', 0)
                if brute_force > 0:
                    findings.append({
                        'category': 'Authentication Security',
                        'finding': 'Brute Force Attacks',
                        'severity': self.results['log_analysis'].get('severity_value', 0),
                        'description': f"{brute_force} brute force attacks detected"
                    })
            
            # Calculate overall risk
            if findings:
                avg_severity = sum(f['severity'] for f in findings) / len(findings)
                overall_risk = assign_risk_score(avg_severity)
            else:
                overall_risk = "Low"
            
            # Map to compliance frameworks
            compliance_mapping = {}
            for finding in findings:
                iso_mapping = map_to_standard(finding['finding'], "ISO27001")
                nist_mapping = map_to_standard(finding['finding'], "NIST")
                
                compliance_mapping[finding['finding']] = {
                    'ISO27001': iso_mapping,
                    'NIST_CSF': nist_mapping
                }
            
            risk_assessment = {
                'overall_risk': overall_risk,
                'total_findings': len(findings),
                'findings': findings,
                'compliance_mapping': compliance_mapping,
                'assessment_timestamp': datetime.now().isoformat()
            }
            
            self.results['risk_assessment'] = risk_assessment
            logger.info(f"Risk assessment completed. Overall risk: {overall_risk}")
            
            return risk_assessment
            
        except Exception as e:
            logger.error(f"Risk assessment failed: {e}")
            self.results['risk_assessment'] = {'error': str(e)}
            return {}

    def encrypt_sensitive_data(self) -> Dict[str, Any]:
        """Encrypt sensitive log files and sign reports."""
        logger.info("Encrypting sensitive data...")
        
        try:
            encrypted_files = []
            
            # Find log files to encrypt
            log_files = list(self.output_dir.glob("*.csv")) + list(self.output_dir.glob("*.log"))
            
            if not log_files:
                logger.warning("No log files found to encrypt")
                return {'encrypted_files': []}
            
            # Generate encryption key
            fernet_key = generate_fernet_key()
            
            for log_file in log_files:
                try:
                    from Crypto_module import encrypt_log
                    encrypted_file = encrypt_log(str(log_file), fernet_key)
                    encrypted_files.append({
                        'original': str(log_file),
                        'encrypted': encrypted_file,
                        'timestamp': datetime.now().isoformat()
                    })
                    logger.info(f"Encrypted: {log_file} -> {encrypted_file}")
                except Exception as e:
                    logger.error(f"Failed to encrypt {log_file}: {e}")
            
            # Save encryption key securely (in real deployment, use proper key management)
            key_file = self.output_dir / "encryption_key.key"
            with open(key_file, 'wb') as f:
                f.write(fernet_key)
            
            encryption_results = {
                'encrypted_files': encrypted_files,
                'key_file': str(key_file),
                'encryption_timestamp': datetime.now().isoformat()
            }
            
            self.results['encrypted_files'] = encryption_results
            logger.info(f"Encryption completed. {len(encrypted_files)} files encrypted")
            
            return encryption_results
            
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            self.results['encrypted_files'] = {'error': str(e)}
            return {}

    def generate_report(self) -> str:
        """Generate comprehensive security report."""
        logger.info("Generating security report...")
        
        try:
            reporter = SecurityReporter(str(self.output_dir))
            report_path = reporter.generate_comprehensive_report(self.results)
            
            logger.info(f"Report generated: {report_path}")
            return report_path
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return ""

    def save_results(self) -> str:
        """Save all results to JSON file."""
        results_file = self.output_dir / "scan_results.json"
        
        try:
            with open(results_file, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=2, default=str)
            
            logger.info(f"Results saved to: {results_file}")
            return str(results_file)
            
        except Exception as e:
            logger.error(f"Failed to save results: {e}")
            return ""

    def run_full_scan(self) -> Dict[str, Any]:
        """Run complete security assessment."""
        logger.info("=" * 60)
        logger.info("STARTING PYCYBERSHIELD FULL SECURITY SCAN")
        logger.info("=" * 60)
        
        # Run all modules
        self.run_system_scan()
        self.run_network_scan()
        self.run_log_analysis()
        self.perform_risk_assessment()
        self.encrypt_sensitive_data()
        
        # Generate summary
        self.results['summary'] = {
            'scan_completed': datetime.now().isoformat(),
            'modules_run': ['system_security', 'network_security', 'log_analysis', 'risk_assessment', 'encryption'],
            'overall_status': 'completed',
            'output_directory': str(self.output_dir)
        }
        
        # Save results
        results_file = self.save_results()
        
        # Generate report
        report_path = self.generate_report()
        
        logger.info("=" * 60)
        logger.info("PYCYBERSHIELD SCAN COMPLETED")
        logger.info("=" * 60)
        
        return {
            'results': self.results,
            'results_file': results_file,
            'report_path': report_path
        }

    def display_dashboard(self):
        """Display summary dashboard in terminal."""
        print("\n" + "=" * 80)
        print("                    PYCYBERSHIELD SECURITY DASHBOARD")
        print("=" * 80)
        
        # System Security Summary
        if 'system_security' in self.results:
            sys_data = self.results['system_security']
            print(f"\n🖥️  SYSTEM SECURITY:")
            print(f"   Total Processes: {len(sys_data.get('processes', []))}")
            print(f"   Suspicious Processes: {len(sys_data.get('suspicious', []))}")
            print(f"   Risk Level: {sys_data.get('risk_score', 'Unknown')}")
            print(f"   Services Status: {sys_data.get('services', {})}")
        
        # Network Security Summary
        if 'network_security' in self.results:
            net_data = self.results['network_security']
            print(f"\n🌐 NETWORK SECURITY:")
            unusual_ports = net_data.get('unusual_ports', {})
            print(f"   Unusual Ports Found: {sum(len(ports) for ports in unusual_ports.values())}")
            print(f"   Suspicious Connections: {len(net_data.get('connection_attempts', {}))}")
            print(f"   Risk Level: {net_data.get('risk_score', 'Unknown')}")
        
        # Log Analysis Summary
        if 'log_analysis' in self.results:
            log_data = self.results['log_analysis']
            print(f"\n📋 LOG ANALYSIS:")
            print(f"   Total Entries: {log_data.get('total_entries', 0)}")
            print(f"   Suspicious Entries: {log_data.get('total_suspicious_entries', 0)}")
            print(f"   Failed Logins: {log_data.get('total_failed_logins', 0)}")
            print(f"   Brute Force Attacks: {log_data.get('brute_force_attacks_detected', 0)}")
            print(f"   Risk Level: {log_data.get('risk_score', 'Unknown')}")
        
        # Risk Assessment Summary
        if 'risk_assessment' in self.results:
            risk_data = self.results['risk_assessment']
            print(f"\n⚠️  RISK ASSESSMENT:")
            print(f"   Overall Risk: {risk_data.get('overall_risk', 'Unknown')}")
            print(f"   Total Findings: {risk_data.get('total_findings', 0)}")
            
            if 'findings' in risk_data:
                print("   Critical Findings:")
                for finding in risk_data['findings'][:3]:  # Show top 3
                    print(f"     • {finding['finding']}: {finding['description']}")
        
        # Encryption Status
        if 'encrypted_files' in self.results:
            enc_data = self.results['encrypted_files']
            if isinstance(enc_data, dict) and 'encrypted_files' in enc_data:
                print(f"\n🔒 ENCRYPTION:")
                print(f"   Files Encrypted: {len(enc_data['encrypted_files'])}")
        
        print(f"\n📁 Output Directory: {self.output_dir}")
        print(f"⏰ Scan Completed: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 80)


def main():
    """Main function to run PyCyberShield."""
    print("🛡️  PyCyberShield - Python-Based Integrated Cyber Defense System")
    print("   Developed for COP 400 - Cybersecurity Foundational Skills")
    print()
    
    try:
        # Initialize PyCyberShield
        shield = PyCyberShield()
        
        # Run full security scan
        results = shield.run_full_scan()
        
        # Display dashboard
        shield.display_dashboard()
        
        print(f"\n✅ Full scan completed successfully!")
        print(f"📊 Results saved to: {results['results_file']}")
        if results['report_path']:
            print(f"📄 PDF Report: {results['report_path']}")
        
        return 0
        
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print("\n❌ Scan interrupted by user")
        return 1
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        print(f"\n❌ Fatal error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())