"""
PyCyberShield - Enhanced GRC (Governance, Risk, and Compliance) Module
Provides comprehensive risk assessment, compliance mapping, and governance reporting
aligned with industry standards like ISO 27001, NIST CSF, and other frameworks.
"""

import logging
from datetime import datetime
from typing import Dict, List, Any
from dataclasses import dataclass

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class RiskFinding:
    """Data structure for risk findings."""
    category: str
    finding: str
    severity: int
    description: str
    impact: str
    likelihood: str
    cvss_score: float = 0.0
    remediation_effort: str = "Unknown"
    business_impact: str = "Unknown"

class ComplianceFramework:
    """Base class for compliance frameworks."""
    
    def __init__(self, name: str, version: str):
        self.name = name
        self.version = version
        self.controls = {}
    
    def map_finding(self, finding: str) -> str:
        """Map a finding to framework controls."""
        return self.controls.get(finding, "Not Mapped")

class ISO27001Framework(ComplianceFramework):
    """ISO 27001:2013 Information Security Management System."""
    
    def __init__(self):
        super().__init__("ISO 27001", "2013")
        self.controls = {
            # System Security Mappings
            "Suspicious Processes": "A.12.2 - Protection from malware",
            "Unauthorized System Access": "A.9.1 - Business requirements of access control",
            "Privilege Escalation": "A.9.2 - User access management",
            "System Vulnerabilities": "A.12.6 - Management of technical vulnerabilities",
            "Malware Detection": "A.12.2 - Protection from malware",
            "Service Disruption": "A.17.1 - Information security continuity",
            
            # Network Security Mappings
            "Unusual Open Ports": "A.13.1 - Network security management",
            "Network Intrusion": "A.13.1 - Network security management",
            "Port Scanning": "A.13.1 - Network security management",
            "Unauthorized Network Access": "A.13.2 - Information transfer",
            "Network Vulnerability": "A.12.6 - Management of technical vulnerabilities",
            "DNS Issues": "A.13.1 - Network security management",
            
            # Authentication & Access Control
            "Brute Force Attacks": "A.9.4 - System and application access control",
            "Authentication Failure": "A.9.4 - System and application access control",
            "Account Lockout": "A.9.4 - System and application access control",
            "Invalid User": "A.9.2 - User access management",
            "Failed Login": "A.9.4 - System and application access control",
            "Unauthorized Login Attempt": "A.9.4 - System and application access control",
            
            # Log Analysis & Monitoring
            "Log Manipulation": "A.12.4 - Logging and monitoring",
            "Audit Trail Issues": "A.12.4 - Logging and monitoring",
            "Security Event": "A.16.1 - Management of information security incidents",
            "Monitoring Failure": "A.12.4 - Logging and monitoring",
            
            # Cryptography & Data Protection
            "Encryption Weakness": "A.10.1 - Cryptographic controls",
            "Data Integrity": "A.10.1 - Cryptographic controls",
            "Key Management": "A.10.1 - Cryptographic controls",
            "Data Breach": "A.16.1 - Management of information security incidents",
            
            # General Security
            "Security Policy Violation": "A.5.1 - Information security policies",
            "Configuration Error": "A.12.6 - Management of technical vulnerabilities",
            "Patch Management": "A.12.6 - Management of technical vulnerabilities",
            "Default": "A.18.2 - Information security reviews"
        }

class NISTFramework(ComplianceFramework):
    """NIST Cybersecurity Framework."""
    
    def __init__(self):
        super().__init__("NIST CSF", "1.1")
        self.controls = {
            # Identify Function
            "System Vulnerabilities": "ID.RA-1: Asset vulnerabilities are identified",
            "Network Vulnerability": "ID.RA-1: Asset vulnerabilities are identified",
            "Configuration Error": "ID.GV-1: Organizational cybersecurity policy",
            
            # Protect Function
            "Unusual Open Ports": "PR.AC-4: Access permissions and authorizations",
            "Unauthorized System Access": "PR.AC-1: Identities and credentials are issued",
            "Privilege Escalation": "PR.AC-6: Identities are proofed and bound to credentials",
            "Encryption Weakness": "PR.DS-1: Data-at-rest is protected",
            "Authentication Failure": "PR.AC-1: Identities and credentials are issued",
            "Brute Force Attacks": "PR.AC-7: Users, devices, and other assets are authenticated",
            "Suspicious Processes": "PR.PT-1: Audit/log records are determined",
            
            # Detect Function
            "Security Event": "DE.AE-1: A baseline of network operations is established",
            "Malware Detection": "DE.CM-4: Malicious code is detected",
            "Network Intrusion": "DE.CM-1: The network is monitored",
            "Port Scanning": "DE.CM-1: The network is monitored",
            "Failed Login": "DE.CM-6: External service provider activity is monitored",
            "Log Manipulation": "DE.AE-3: Event data are collected and correlated",
            
            # Respond Function
            "Data Breach": "RS.CO-2: Incidents are reported consistent with established criteria",
            "Security Policy Violation": "RS.AN-1: Notifications from detection systems are investigated",
            "Service Disruption": "RS.MI-1: Incidents are contained",
            
            # Recover Function
            "System Recovery": "RC.RP-1: Recovery plan is executed during or after a cybersecurity incident",
            "Default": "ID.GV-1: Organizational cybersecurity policy is established"
        }

class CISControlsFramework(ComplianceFramework):
    """CIS Critical Security Controls."""
    
    def __init__(self):
        super().__init__("CIS Controls", "v8")
        self.controls = {
            "System Vulnerabilities": "CIS 7: Continuous Vulnerability Management",
            "Patch Management": "CIS 7: Continuous Vulnerability Management",
            "Malware Detection": "CIS 10: Malware Defenses",
            "Suspicious Processes": "CIS 8: Audit Log Management",
            "Network Intrusion": "CIS 12: Network Infrastructure Management",
            "Unusual Open Ports": "CIS 12: Network Infrastructure Management",
            "Port Scanning": "CIS 13: Network Monitoring and Defense",
            "Brute Force Attacks": "CIS 6: Access Control Management",
            "Authentication Failure": "CIS 6: Access Control Management",
            "Privilege Escalation": "CIS 6: Access Control Management",
            "Log Manipulation": "CIS 8: Audit Log Management",
            "Encryption Weakness": "CIS 3: Data Protection",
            "Default": "CIS 1: Inventory and Control of Enterprise Assets"
        }

class EnhancedGRCModule:
    """Enhanced GRC module with comprehensive risk assessment capabilities."""
    
    def __init__(self):
        """Initialize the Enhanced GRC Module."""
        self.frameworks = {
            'ISO27001': ISO27001Framework(),
            'NIST_CSF': NISTFramework(),
            'CIS_CONTROLS': CISControlsFramework()
        }
        
        # Risk calculation matrices
        self.impact_levels = {
            'Low': 1,
            'Medium': 2,
            'High': 3,
            'Critical': 4
        }
        
        self.likelihood_levels = {
            'Very Low': 1,
            'Low': 2,
            'Medium': 3,
            'High': 4,
            'Very High': 5
        }
        
        # CVSS v3.0 severity ranges
        self.cvss_ranges = {
            'Low': (0.1, 3.9),
            'Medium': (4.0, 6.9),
            'High': (7.0, 8.9),
            'Critical': (9.0, 10.0)
        }

    def calculate_comprehensive_risk(self, findings: List[Dict]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk assessment from security findings.
        
        Args:
            findings: List of security findings with severity and category information
            
        Returns:
            Dictionary containing comprehensive risk assessment
        """
        logger.info("Performing comprehensive risk assessment...")
        
        if not findings:
            return {
                'overall_risk': 'Low',
                'risk_score': 1.0,
                'total_findings': 0,
                'risk_breakdown': {},
                'recommendations': []
            }
        
        risk_findings = []
        
        for finding in findings:
            risk_finding = self._analyze_finding(finding)
            risk_findings.append(risk_finding)
        
        # Calculate overall risk metrics
        risk_assessment = self._calculate_overall_risk(risk_findings)
        
        # Generate compliance mappings
        compliance_mapping = self._generate_compliance_mapping(risk_findings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(risk_findings)
        
        risk_assessment.update({
            'findings': [self._finding_to_dict(rf) for rf in risk_findings],
            'compliance_mapping': compliance_mapping,
            'recommendations': recommendations,
            'assessment_timestamp': datetime.now().isoformat()
        })
        
        logger.info(f"Risk assessment completed. Overall risk: {risk_assessment['overall_risk']}")
        return risk_assessment

    def _analyze_finding(self, finding: Dict) -> RiskFinding:
        """Analyze a security finding and create a comprehensive risk assessment."""
        category = finding.get('category', 'General')
        finding_name = finding.get('finding', 'Unknown Finding')
        severity = finding.get('severity', 0)
        description = finding.get('description', 'No description provided')
        
        # Determine impact and likelihood based on category and severity
        impact, likelihood = self._assess_impact_likelihood(category, finding_name, severity)
        
        # Calculate CVSS-like score
        cvss_score = self._calculate_cvss_score(severity, impact, likelihood)
        
        # Determine remediation effort
        remediation_effort = self._assess_remediation_effort(finding_name, severity)
        
        # Assess business impact
        business_impact = self._assess_business_impact(category, severity)
        
        return RiskFinding(
            category=category,
            finding=finding_name,
            severity=severity,
            description=description,
            impact=impact,
            likelihood=likelihood,
            cvss_score=cvss_score,
            remediation_effort=remediation_effort,
            business_impact=business_impact
        )

    def _assess_impact_likelihood(self, category: str, finding: str, severity: int) -> tuple:
        """Assess impact and likelihood based on finding characteristics."""
        
        # High-impact categories
        high_impact_categories = ['Authentication Security', 'System Security', 'Data Protection']
        high_impact_findings = ['Brute Force Attacks', 'Privilege Escalation', 'Data Breach', 'Malware Detection']
        
        # Determine impact
        if category in high_impact_categories or any(hif in finding for hif in high_impact_findings):
            if severity >= 8:
                impact = 'Critical'
            elif severity >= 6:
                impact = 'High'
            else:
                impact = 'Medium'
        else:
            if severity >= 7:
                impact = 'High'
            elif severity >= 4:
                impact = 'Medium'
            else:
                impact = 'Low'
        
        # Determine likelihood based on finding type
        likelihood_mapping = {
            'Brute Force Attacks': 'High',
            'Port Scanning': 'Medium',
            'Failed Login': 'High',
            'Suspicious Processes': 'Medium',
            'Unusual Open Ports': 'Medium',
            'Authentication Failure': 'High',
            'Privilege Escalation': 'Low',
            'Malware Detection': 'Low'
        }
        
        likelihood = likelihood_mapping.get(finding, 'Medium')
        
        # Adjust likelihood based on severity
        if severity >= 8:
            likelihood_levels = ['Medium', 'High', 'Very High']
            current_idx = ['Very Low', 'Low', 'Medium', 'High', 'Very High'].index(likelihood)
            likelihood = likelihood_levels[min(current_idx, len(likelihood_levels) - 1)]
        
        return impact, likelihood

    def _calculate_cvss_score(self, severity: int, impact: str, likelihood: str) -> float:
        """Calculate a CVSS-like score for the finding."""
        base_score = severity
        
        # Adjust based on impact
        impact_multiplier = self.impact_levels.get(impact, 2) / 2.0
        
        # Adjust based on likelihood
        likelihood_multiplier = self.likelihood_levels.get(likelihood, 3) / 3.0
        
        # Calculate final score (0-10 scale)
        cvss_score = min(10.0, base_score * impact_multiplier * likelihood_multiplier)
        
        return round(cvss_score, 1)

    def _assess_remediation_effort(self, finding: str, severity: int) -> str:
        """Assess the effort required to remediate the finding."""
        
        low_effort_findings = ['Configuration Error', 'Patch Management', 'Log Analysis']
        medium_effort_findings = ['Authentication Failure', 'Unusual Open Ports', 'Failed Login']
        high_effort_findings = ['Brute Force Attacks', 'Privilege Escalation', 'System Vulnerability']
        
        if any(lef in finding for lef in low_effort_findings):
            return 'Low' if severity < 6 else 'Medium'
        elif any(mef in finding for mef in medium_effort_findings):
            return 'Medium' if severity < 8 else 'High'
        elif any(hef in finding for hef in high_effort_findings):
            return 'High' if severity < 9 else 'Very High'
        else:
            return 'Medium'

    def _assess_business_impact(self, category: str, severity: int) -> str:
        """Assess the business impact of the finding."""
        
        critical_categories = ['Data Protection', 'Authentication Security']
        high_categories = ['System Security', 'Network Security']
        
        if category in critical_categories:
            return 'Critical' if severity >= 7 else 'High'
        elif category in high_categories:
            return 'High' if severity >= 8 else 'Medium'
        else:
            return 'Medium' if severity >= 6 else 'Low'

    def _calculate_overall_risk(self, risk_findings: List[RiskFinding]) -> Dict[str, Any]:
        """Calculate overall risk metrics from all findings."""
        
        if not risk_findings:
            return {
                'overall_risk': 'Low',
                'risk_score': 1.0,
                'total_findings': 0,
                'risk_breakdown': {}
            }
        
        # Calculate weighted risk score
        total_score = sum(rf.cvss_score for rf in risk_findings)
        avg_score = total_score / len(risk_findings)
        
        # Determine overall risk level
        if avg_score >= 7.0:
            overall_risk = 'Critical'
        elif avg_score >= 5.0:
            overall_risk = 'High'
        elif avg_score >= 3.0:
            overall_risk = 'Medium'
        else:
            overall_risk = 'Low'
        
        # Create risk breakdown by category
        category_risks = {}
        for rf in risk_findings:
            if rf.category not in category_risks:
                category_risks[rf.category] = {
                    'count': 0,
                    'avg_severity': 0,
                    'max_severity': 0,
                    'findings': []
                }
            
            category_risks[rf.category]['count'] += 1
            category_risks[rf.category]['findings'].append(rf.finding)
            category_risks[rf.category]['max_severity'] = max(
                category_risks[rf.category]['max_severity'], rf.severity
            )
        
        # Calculate average severity per category
        for category in category_risks:
            category_findings = [rf for rf in risk_findings if rf.category == category]
            category_risks[category]['avg_severity'] = sum(rf.severity for rf in category_findings) / len(category_findings)
        
        return {
            'overall_risk': overall_risk,
            'risk_score': round(avg_score, 2),
            'total_findings': len(risk_findings),
            'critical_findings': len([rf for rf in risk_findings if rf.cvss_score >= 9.0]),
            'high_findings': len([rf for rf in risk_findings if 7.0 <= rf.cvss_score < 9.0]),
            'medium_findings': len([rf for rf in risk_findings if 4.0 <= rf.cvss_score < 7.0]),
            'low_findings': len([rf for rf in risk_findings if rf.cvss_score < 4.0]),
            'risk_breakdown': category_risks
        }

    def _generate_compliance_mapping(self, risk_findings: List[RiskFinding]) -> Dict[str, Dict[str, str]]:
        """Generate compliance framework mappings for all findings."""
        
        compliance_mapping = {}
        
        for rf in risk_findings:
            finding_mappings = {}
            
            for framework_name, framework in self.frameworks.items():
                control = framework.map_finding(rf.finding)
                finding_mappings[framework_name] = control
            
            compliance_mapping[rf.finding] = finding_mappings
        
        return compliance_mapping

    def _generate_recommendations(self, risk_findings: List[RiskFinding]) -> List[Dict[str, Any]]:
        """Generate specific recommendations based on findings."""
        
        recommendations = []
        
        # Priority-based recommendations
        critical_findings = [rf for rf in risk_findings if rf.cvss_score >= 9.0]
        high_findings = [rf for rf in risk_findings if 7.0 <= rf.cvss_score < 9.0]
        
        if critical_findings:
            recommendations.append({
                'priority': 'CRITICAL',
                'action': 'Immediate Action Required',
                'description': f'Address {len(critical_findings)} critical security findings immediately',
                'findings': [rf.finding for rf in critical_findings],
                'timeframe': '24 hours'
            })
        
        if high_findings:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Urgent Security Measures',
                'description': f'Implement security controls for {len(high_findings)} high-risk findings',
                'findings': [rf.finding for rf in high_findings],
                'timeframe': '1 week'
            })
        
        # Category-specific recommendations
        category_counts = {}
        for rf in risk_findings:
            category_counts[rf.category] = category_counts.get(rf.category, 0) + 1
        
        if category_counts.get('Authentication Security', 0) > 0:
            recommendations.append({
                'priority': 'HIGH',
                'action': 'Strengthen Authentication Controls',
                'description': 'Implement multi-factor authentication and account lockout policies',
                'timeframe': '2 weeks'
            })
        
        if category_counts.get('Network Security', 0) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'Network Security Hardening',
                'description': 'Review firewall rules, close unnecessary ports, implement network monitoring',
                'timeframe': '1 month'
            })
        
        if category_counts.get('System Security', 0) > 0:
            recommendations.append({
                'priority': 'MEDIUM',
                'action': 'System Security Enhancement',
                'description': 'Update antivirus, implement endpoint protection, review running processes',
                'timeframe': '2 weeks'
            })
        
        # General recommendations
        recommendations.extend([
            {
                'priority': 'MEDIUM',
                'action': 'Security Awareness Training',
                'description': 'Conduct regular security training for all personnel',
                'timeframe': 'Ongoing'
            },
            {
                'priority': 'LOW',
                'action': 'Regular Security Assessments',
                'description': 'Schedule quarterly security assessments and penetration testing',
                'timeframe': 'Quarterly'
            }
        ])
        
        return recommendations

    def _finding_to_dict(self, risk_finding: RiskFinding) -> Dict[str, Any]:
        """Convert RiskFinding object to dictionary."""
        return {
            'category': risk_finding.category,
            'finding': risk_finding.finding,
            'severity': risk_finding.severity,
            'description': risk_finding.description,
            'impact': risk_finding.impact,
            'likelihood': risk_finding.likelihood,
            'cvss_score': risk_finding.cvss_score,
            'remediation_effort': risk_finding.remediation_effort,
            'business_impact': risk_finding.business_impact
        }


# Legacy compatibility functions
def assign_risk_score(severity_value: int) -> str:
    """
    Assign a risk score based on a numeric severity value (0-10 scale).
    Maintained for backward compatibility.
    """
    if severity_value >= 7:
        return "High"
    elif severity_value >= 4:
        return "Medium"
    else:
        return "Low"

def map_to_standard(finding: str, framework: str = "ISO27001") -> str:
    """
    Map a finding to the chosen framework category.
    Enhanced version with more comprehensive mappings.
    """
    grc_module = EnhancedGRCModule()
    
    framework_key = framework.upper().replace(' ', '_')
    if framework_key == 'NIST':
        framework_key = 'NIST_CSF'
    
    if framework_key in grc_module.frameworks:
        return grc_module.frameworks[framework_key].map_finding(finding)
    else:
        return "Framework Not Supported"


def main():
    """Test the enhanced GRC module with sample findings."""
    grc = EnhancedGRCModule()
    
    # Sample findings that match the project requirements
    test_findings = [
        {
            "category": "System Security",
            "finding": "Suspicious Processes",
            "severity": 8,
            "description": "Multiple suspicious processes detected running with elevated privileges"
        },
        {
            "category": "Authentication Security", 
            "finding": "Brute Force Attacks",
            "severity": 9,
            "description": "Multiple brute force attacks detected from external IP addresses"
        },
        {
            "category": "Network Security",
            "finding": "Unusual Open Ports",
            "severity": 5,
            "description": "Several unusual ports detected open on critical systems"
        },
        {
            "category": "Log Analysis",
            "finding": "Failed Login",
            "severity": 6,
            "description": "High number of failed login attempts detected in system logs"
        }
    ]
    
    # Perform comprehensive risk assessment
    risk_assessment = grc.calculate_comprehensive_risk(test_findings)
    
    print("\n=== Enhanced GRC Risk Assessment Results ===")
    print(f"Overall Risk Level: {risk_assessment['overall_risk']}")
    print(f"Risk Score: {risk_assessment['risk_score']}/10")
    print(f"Total Findings: {risk_assessment['total_findings']}")
    print(f"Critical Findings: {risk_assessment['critical_findings']}")
    print(f"High Findings: {risk_assessment['high_findings']}")
    
    print("\n=== Risk Breakdown by Category ===")
    for category, info in risk_assessment['risk_breakdown'].items():
        print(f"{category}: {info['count']} findings (avg severity: {info['avg_severity']:.1f})")
    
    print("\n=== Compliance Mapping ===")
    for finding, mappings in list(risk_assessment['compliance_mapping'].items())[:2]:
        print(f"\n{finding}:")
        for framework, control in mappings.items():
            print(f"  {framework}: {control}")
    
    print("\n=== Priority Recommendations ===")
    for rec in risk_assessment['recommendations'][:3]:
        print(f"[{rec['priority']}] {rec['action']}: {rec['description']}")


if __name__ == "__main__":
    main()