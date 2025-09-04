"""
PyCyberShield - Fixed Reporting Module
Generates comprehensive PDF security reports with charts and risk analysis.
"""

import os
import json
import logging
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import pandas as pd

try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.colors import HexColor, black, red, orange, green
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.platypus.flowables import Image
    from reportlab.lib import colors
except ImportError:
    print("Warning: ReportLab not installed. Install with: pip install reportlab")

logger = logging.getLogger(__name__)


class SecurityReporter:
    """Generates comprehensive security reports with charts and analysis."""
    
    def __init__(self, output_dir: str = "reports"):
        """Initialize the security reporter."""
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.charts_dir = self.output_dir / "charts"
        self.charts_dir.mkdir(exist_ok=True)
        
        # Color scheme for reports
        self.colors = {
            'high': HexColor('#DC143C'),    # Crimson
            'medium': HexColor('#FF8C00'),  # Dark Orange  
            'low': HexColor('#32CD32'),     # Lime Green
            'info': HexColor('#4169E1'),    # Royal Blue
            'header': HexColor('#2C3E50'),  # Dark Blue Grey
        }
        
        # Matplotlib color mappings (hex strings)
        self.mpl_colors = {
            'high': '#DC143C',
            'medium': '#FF8C00',
            'low': '#32CD32',
            'info': '#4169E1',
            'header': '#2C3E50'
        }
        
        # Report styles
        self.styles = getSampleStyleSheet()
        self.title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=self.colors['header']
        )
        
        self.heading_style = ParagraphStyle(
            'CustomHeading',
            parent=self.styles['Heading1'],
            fontSize=16,
            spaceAfter=12,
            textColor=self.colors['header']
        )

    def generate_comprehensive_report(self, results: Dict[str, Any]) -> str:
        """Generate a comprehensive PDF security report."""
        logger.info("Generating comprehensive security report...")
        
        try:
            # Create charts first
            chart_files = self._generate_charts(results)
            logger.info(f"Generated charts: {list(chart_files.keys())}")
            
            # Generate PDF report
            report_filename = f"PyCyberShield_Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
            report_path = self.output_dir / report_filename
            
            # Create PDF document
            doc = SimpleDocTemplate(
                str(report_path),
                pagesize=A4,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=18
            )
            
            # Build report content
            story = []
            
            # Title page
            story.extend(self._build_title_page(results))
            story.append(PageBreak())
            
            # Executive summary with charts
            story.extend(self._build_executive_summary(results, chart_files))
            story.append(PageBreak())
            
            # Detailed findings
            story.extend(self._build_detailed_findings(results))
            
            # Risk assessment with charts
            story.append(PageBreak())
            story.extend(self._build_risk_assessment(results, chart_files))
            
            # Network analysis with charts
            if chart_files.get('network_chart'):
                story.append(PageBreak())
                story.extend(self._build_network_analysis_section(results, chart_files))
            
            # Timeline analysis
            if chart_files.get('timeline'):
                story.append(PageBreak())
                story.extend(self._build_timeline_section(results, chart_files))
            
            # Compliance mapping
            story.append(PageBreak())
            story.extend(self._build_compliance_section(results))
            
            # Recommendations
            story.append(PageBreak())
            story.extend(self._build_recommendations(results))
            
            # Technical appendix
            story.append(PageBreak())
            story.extend(self._build_technical_appendix(results))
            
            # Build the PDF
            doc.build(story)
            
            logger.info(f"Report generated successfully: {report_path}")
            return str(report_path)
            
        except Exception as e:
            logger.error(f"Failed to generate report: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return ""

    def _generate_charts(self, results: Dict[str, Any]) -> Dict[str, str]:
        """Generate charts and visualizations for the report."""
        chart_files = {}
        
        try:
            # Risk distribution pie chart
            risk_data = self._extract_risk_data(results)
            logger.info(f"Risk data extracted: {risk_data}")
            if risk_data and any(risk_data.values()):
                chart_files['risk_pie'] = self._create_risk_pie_chart(risk_data)
                logger.info(f"Risk pie chart created: {chart_files.get('risk_pie')}")
            
            # Timeline chart of security events
            timeline_data = self._extract_timeline_data(results)
            if timeline_data:
                chart_files['timeline'] = self._create_timeline_chart(timeline_data)
                logger.info(f"Timeline chart created: {chart_files.get('timeline')}")
            
            # Risk heatmap
            findings_data = self._extract_findings_data(results)
            if findings_data:
                chart_files['risk_heatmap'] = self._create_risk_heatmap(findings_data)
                logger.info(f"Risk heatmap created: {chart_files.get('risk_heatmap')}")
            
            # Network security chart
            network_data = results.get('network_security', {})
            if network_data and not network_data.get('error'):
                unusual_ports = network_data.get('unusual_ports', {})
                if unusual_ports:
                    chart_files['network_chart'] = self._create_network_security_chart(network_data)
                    logger.info(f"Network chart created: {chart_files.get('network_chart')}")
                    
        except Exception as e:
            logger.error(f"Error generating charts: {e}")
            import traceback
            logger.error(traceback.format_exc())
        
        return chart_files

    def _create_risk_pie_chart(self, risk_data: Dict[str, int]) -> str:
        """Create a pie chart showing risk distribution."""
        try:
            plt.figure(figsize=(8, 6))
            
            labels = list(risk_data.keys())
            sizes = list(risk_data.values())
            
            # Use matplotlib-compatible colors
            colors_list = []
            for label in labels:
                if label == 'High':
                    colors_list.append(self.mpl_colors['high'])
                elif label == 'Medium':
                    colors_list.append(self.mpl_colors['medium'])
                else:
                    colors_list.append(self.mpl_colors['low'])
            
            plt.pie(sizes, labels=labels, colors=colors_list, autopct='%1.1f%%', startangle=90)
            plt.title('Security Risk Distribution', fontsize=14, fontweight='bold')
            plt.axis('equal')
            
            chart_path = self.charts_dir / 'risk_distribution.png'
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            logger.info(f"Risk pie chart saved to: {chart_path}")
            return str(chart_path)
        except Exception as e:
            logger.error(f"Error creating risk pie chart: {e}")
            return ""

    def _create_timeline_chart(self, timeline_data: List[Dict]) -> str:
        """Create a timeline chart of security events."""
        if not timeline_data:
            return ""
            
        try:
            plt.figure(figsize=(12, 6))
            
            timestamps = [item['timestamp'] for item in timeline_data]
            severity_values = [item['severity_numeric'] for item in timeline_data]
            
            # Use matplotlib-compatible colors
            colors_list = []
            for sv in severity_values:
                if sv >= 7:
                    colors_list.append(self.mpl_colors['high'])
                elif sv >= 4:
                    colors_list.append(self.mpl_colors['medium'])
                else:
                    colors_list.append(self.mpl_colors['low'])
            
            plt.scatter(timestamps, severity_values, c=colors_list, s=100, alpha=0.7)
            plt.xlabel('Time')
            plt.ylabel('Severity Level')
            plt.title('Security Events Timeline', fontsize=14, fontweight='bold')
            plt.grid(True, alpha=0.3)
            plt.xticks(rotation=45)
            
            chart_path = self.charts_dir / 'events_timeline.png'
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            logger.info(f"Timeline chart saved to: {chart_path}")
            return str(chart_path)
        except Exception as e:
            logger.error(f"Error creating timeline chart: {e}")
            return ""

    def _create_network_security_chart(self, network_data: Dict) -> str:
        """Create network security visualization."""
        unusual_ports = network_data.get('unusual_ports', {})
        
        if not unusual_ports:
            return ""
        
        try:
            plt.figure(figsize=(10, 6))
            
            hosts = list(unusual_ports.keys())
            port_counts = [len(ports) for ports in unusual_ports.values()]
            
            bars = plt.bar(hosts, port_counts, color=self.mpl_colors['medium'], alpha=0.7)
            plt.xlabel('Target Hosts')
            plt.ylabel('Number of Unusual Ports')
            plt.title('Unusual Open Ports by Host', fontsize=14, fontweight='bold')
            plt.xticks(rotation=45)
            
            # Add value labels on bars
            for bar, count in zip(bars, port_counts):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.1, 
                        str(count), ha='center', va='bottom')
            
            chart_path = self.charts_dir / 'network_security.png'
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            logger.info(f"Network security chart saved to: {chart_path}")
            return str(chart_path)
        except Exception as e:
            logger.error(f"Error creating network security chart: {e}")
            return ""
    
    def _create_risk_heatmap(self, findings_data: List[Dict]) -> str:
        """Create a risk heatmap visualization."""
        if not findings_data:
            return ""
            
        try:
            categories = list(set(f['category'] for f in findings_data))
            
            # Create heatmap data
            fig, ax = plt.subplots(figsize=(10, 6))
            
            # Create matrix for heatmap
            matrix_data = []
            for category in categories:
                category_severities = [f['severity'] for f in findings_data if f['category'] == category]
                avg_severity = sum(category_severities) / len(category_severities) if category_severities else 0
                matrix_data.append([avg_severity])
            
            im = ax.imshow(matrix_data, cmap='RdYlGn_r', aspect='auto')
            
            ax.set_xticks([0])
            ax.set_xticklabels(['Risk Level'])
            ax.set_yticks(range(len(categories)))
            ax.set_yticklabels(categories)
            
            # Add text annotations
            for i, severity in enumerate([row[0] for row in matrix_data]):
                text = f'{severity:.1f}'
                ax.text(0, i, text, ha="center", va="center", 
                       color="white" if severity > 5 else "black")
            
            ax.set_title('Risk Heatmap by Category', fontsize=14, fontweight='bold')
            
            chart_path = self.charts_dir / 'risk_heatmap.png'
            plt.savefig(chart_path, dpi=300, bbox_inches='tight', facecolor='white')
            plt.close()
            
            logger.info(f"Risk heatmap saved to: {chart_path}")
            return str(chart_path)
        except Exception as e:
            logger.error(f"Error creating risk heatmap: {e}")
            return ""

    def _add_chart_to_story(self, story: List, chart_path: str, title: str = None, width: float = 6, height: float = 3.6):
        """Helper method to safely add charts to the story."""
        if chart_path and os.path.exists(chart_path):
            try:
                if title:
                    story.append(Paragraph(title, self.styles['Heading3']))
                    story.append(Spacer(1, 8))
                
                story.append(Image(chart_path, width=width*inch, height=height*inch))
                story.append(Spacer(1, 12))
                logger.info(f"Added chart to PDF: {chart_path}")
            except Exception as e:
                logger.error(f"Could not include chart {chart_path}: {e}")
                if title:
                    story.append(Paragraph(f"{title} (Chart unavailable)", self.styles['Heading3']))
        else:
            logger.warning(f"Chart file not found: {chart_path}")

    def _build_title_page(self, results: Dict[str, Any]) -> List:
        """Build the title page of the report."""
        story = []
        
        # Main title
        story.append(Paragraph("PyCyberShield", self.title_style))
        story.append(Paragraph("Security Assessment Report", self.title_style))
        story.append(Spacer(1, 50))
        
        # Report metadata
        metadata = [
            ["Report Generated:", datetime.now().strftime("%Y-%m-%d %H:%M:%S")],
            ["Scan Timestamp:", results.get('timestamp', 'N/A')],
            ["Assessment Type:", "Comprehensive Security Scan"],
            ["Report Version:", "1.0"]
        ]
        
        metadata_table = Table(metadata, colWidths=[2*inch, 3*inch])
        metadata_table.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (1, 0), (1, -1), 'LEFT'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ]))
        
        story.append(metadata_table)
        story.append(Spacer(1, 100))
        
        # Executive summary preview
        overall_risk = results.get('risk_assessment', {}).get('overall_risk', 'Unknown')
        risk_color = (self.colors['high'] if overall_risk == 'High' 
                     else self.colors['medium'] if overall_risk == 'Medium'
                     else self.colors['low'])
        
        story.append(Paragraph(f"Overall Security Risk Level: <font color='{risk_color.hexval()}'>{overall_risk}</font>", 
                              self.styles['Normal']))
        
        return story

    def _build_executive_summary(self, results: Dict[str, Any], chart_files: Dict[str, str]) -> List:
        """Build executive summary section with charts."""
        story = []
        
        story.append(Paragraph("Executive Summary", self.heading_style))
        story.append(Spacer(1, 12))
        
        # Summary text
        summary_text = self._generate_executive_summary_text(results)
        story.append(Paragraph(summary_text, self.styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Add risk distribution chart
        self._add_chart_to_story(story, chart_files.get('risk_pie'), 
                                "Risk Distribution Overview")
        
        # Key metrics table
        metrics = self._extract_key_metrics(results)
        if metrics:
            story.append(Paragraph("Key Security Metrics", self.styles['Heading2']))
            
            metrics_table = Table(metrics, colWidths=[3*inch, 2*inch])
            metrics_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), self.colors['header']),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            
            story.append(metrics_table)
        
        return story

    def _build_detailed_findings(self, results: Dict[str, Any]) -> List:
        """Build detailed findings section."""
        story = []
        
        story.append(Paragraph("Detailed Security Findings", self.heading_style))
        story.append(Spacer(1, 12))
        
        # System Security findings
        if 'system_security' in results and not results['system_security'].get('error'):
            story.extend(self._build_system_security_section(results['system_security']))
        
        # Network Security findings
        if 'network_security' in results and not results['network_security'].get('error'):
            story.extend(self._build_network_security_section(results['network_security']))
        
        # Log Analysis findings
        if 'log_analysis' in results and not results['log_analysis'].get('error'):
            story.extend(self._build_log_analysis_section(results['log_analysis']))
        
        return story

    def _build_system_security_section(self, system_data: Dict) -> List:
        """Build system security findings section."""
        story = []
        
        story.append(Paragraph("System Security Analysis", self.styles['Heading2']))
        
        suspicious_count = len(system_data.get('suspicious', []))
        total_processes = len(system_data.get('processes', []))
        
        story.append(Paragraph(f"Analyzed {total_processes} running processes, found {suspicious_count} suspicious processes.", 
                              self.styles['Normal']))
        
        if suspicious_count > 0:
            story.append(Paragraph("Suspicious Processes Detected:", self.styles['Heading3']))
            
            for proc in system_data.get('suspicious', [])[:10]:  # Limit to top 10
                proc_info = f"• {proc.get('name', 'Unknown')} (PID: {proc.get('pid', 'N/A')}, CPU: {proc.get('cpu_percent', 0):.1f}%)"
                story.append(Paragraph(proc_info, self.styles['Normal']))
        
        story.append(Spacer(1, 12))
        return story

    def _build_network_security_section(self, network_data: Dict) -> List:
        """Build network security findings section."""
        story = []
        
        story.append(Paragraph("Network Security Analysis", self.styles['Heading2']))
        
        unusual_ports = network_data.get('unusual_ports', {})
        if unusual_ports:
            story.append(Paragraph("Unusual Open Ports Detected:", self.styles['Heading3']))
            
            for host, ports in unusual_ports.items():
                port_info = f"• Host {host}: Ports {', '.join(map(str, ports))}"
                story.append(Paragraph(port_info, self.styles['Normal']))
        else:
            story.append(Paragraph("No unusual open ports detected.", self.styles['Normal']))
        
        story.append(Spacer(1, 12))
        return story

    def _build_log_analysis_section(self, log_data: Dict) -> List:
        """Build log analysis findings section."""
        story = []
        
        story.append(Paragraph("Log Analysis Results", self.styles['Heading2']))
        
        suspicious_entries = log_data.get('total_suspicious_entries', 0)
        brute_force_attacks = log_data.get('brute_force_attacks_detected', 0)
        
        story.append(Paragraph(f"Found {suspicious_entries} suspicious log entries and detected {brute_force_attacks} brute force attacks.", 
                              self.styles['Normal']))
        
        if brute_force_attacks > 0:
            story.append(Paragraph("⚠️ Brute force attacks detected - immediate attention required.", 
                                  self.styles['Normal']))
        
        story.append(Spacer(1, 12))
        return story

    def _build_risk_assessment(self, results: Dict[str, Any], chart_files: Dict[str, str]) -> List:
        """Build risk assessment section with charts."""
        story = []
        
        story.append(Paragraph("Risk Assessment", self.heading_style))
        story.append(Spacer(1, 12))
        
        risk_assessment = results.get('risk_assessment', {})
        overall_risk = risk_assessment.get('overall_risk', 'Unknown')
        
        story.append(Paragraph(f"Overall Risk Level: <b>{overall_risk}</b>", self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Add risk heatmap
        self._add_chart_to_story(story, chart_files.get('risk_heatmap'), 
                                "Risk Analysis by Category")
        
        return story

    def _build_network_analysis_section(self, results: Dict[str, Any], chart_files: Dict[str, str]) -> List:
        """Build network analysis section with charts."""
        story = []
        
        story.append(Paragraph("Network Security Analysis", self.heading_style))
        story.append(Spacer(1, 12))
        
        network_data = results.get('network_security', {})
        unusual_ports = network_data.get('unusual_ports', {})
        
        if unusual_ports:
            story.append(Paragraph("Network security analysis revealed unusual port configurations that require attention.", 
                                  self.styles['Normal']))
            story.append(Spacer(1, 12))
        
        # Add network security chart
        self._add_chart_to_story(story, chart_files.get('network_chart'), 
                                "Network Port Analysis")
        
        return story

    def _build_timeline_section(self, results: Dict[str, Any], chart_files: Dict[str, str]) -> List:
        """Build timeline analysis section."""
        story = []
        
        story.append(Paragraph("Security Events Timeline", self.heading_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("The following chart shows the timeline of security events detected during the assessment.", 
                              self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Add timeline chart
        self._add_chart_to_story(story, chart_files.get('timeline'), 
                                width=8, height=4)
        
        return story

    def _build_compliance_section(self, results: Dict[str, Any]) -> List:
        """Build compliance mapping section."""
        story = []
        
        story.append(Paragraph("Compliance Mapping", self.heading_style))
        story.append(Spacer(1, 12))
        
        risk_assessment = results.get('risk_assessment', {})
        compliance_mapping = risk_assessment.get('compliance_mapping', {})
        
        if compliance_mapping:
            story.append(Paragraph("Findings mapped to compliance frameworks:", self.styles['Normal']))
            story.append(Spacer(1, 8))
            
            for finding, mappings in compliance_mapping.items():
                story.append(Paragraph(f"<b>{finding}</b>", self.styles['Normal']))
                for framework, control in mappings.items():
                    story.append(Paragraph(f"  • {framework}: {control}", self.styles['Normal']))
                story.append(Spacer(1, 4))
        else:
            story.append(Paragraph("No compliance mappings available.", self.styles['Normal']))
        
        return story

    def _build_recommendations(self, results: Dict[str, Any]) -> List:
        """Build recommendations section."""
        story = []
        
        story.append(Paragraph("Security Recommendations", self.heading_style))
        story.append(Spacer(1, 12))
        
        recommendations = self._generate_recommendations(results)
        
        for i, recommendation in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {recommendation}", self.styles['Normal']))
            story.append(Spacer(1, 8))
        
        return story

    def _build_technical_appendix(self, results: Dict[str, Any]) -> List:
        """Build technical appendix with detailed data."""
        story = []
        
        story.append(Paragraph("Technical Appendix", self.heading_style))
        story.append(Spacer(1, 12))
        
        story.append(Paragraph("This section contains detailed technical data from the security assessment.", 
                              self.styles['Normal']))
        story.append(Spacer(1, 12))
        
        # Add scan summary
        summary = results.get('summary', {})
        if summary:
            story.append(Paragraph("Scan Summary:", self.styles['Heading3']))
            for key, value in summary.items():
                story.append(Paragraph(f"• {key}: {value}", self.styles['Normal']))
        
        return story

    def _extract_risk_data(self, results: Dict[str, Any]) -> Dict[str, int]:
        """Extract risk distribution data for charts."""
        risk_counts = {'High': 0, 'Medium': 0, 'Low': 0}
        
        # Count findings by risk level from each module
        for module_name in ['system_security', 'network_security', 'log_analysis']:
            module_data = results.get(module_name, {})
            if module_data and not module_data.get('error'):
                # Check if module has suspicious/unusual findings
                if module_name == 'system_security':
                    suspicious_count = len(module_data.get('suspicious', []))
                    if suspicious_count > 0:
                        risk_counts['High'] += suspicious_count
                elif module_name == 'network_security':
                    unusual_ports = module_data.get('unusual_ports', {})
                    if unusual_ports:
                        risk_counts['Medium'] += len(unusual_ports)
                elif module_name == 'log_analysis':
                    brute_force = module_data.get('brute_force_attacks_detected', 0)
                    suspicious_entries = module_data.get('total_suspicious_entries', 0)
                    if brute_force > 0:
                        risk_counts['High'] += brute_force
                    if suspicious_entries > 0:
                        risk_counts['Medium'] += suspicious_entries
        
        # If no specific risks found, check overall risk assessment
        if not any(risk_counts.values()):
            overall_risk = results.get('risk_assessment', {}).get('overall_risk', 'Low')
            risk_counts[overall_risk] = 1
        
        return {k: v for k, v in risk_counts.items() if v > 0}

    def _extract_timeline_data(self, results: Dict[str, Any]) -> List[Dict]:
        """Extract timeline data for visualization."""
        timeline_data = []
        base_time = datetime.now()
        
        # Add system security events
        system_data = results.get('system_security', {})
        if 'suspicious' in system_data:
            for i, proc in enumerate(system_data['suspicious'][:5]):  # Limit for chart
                timeline_data.append({
                    'timestamp': base_time.replace(minute=base_time.minute + i),
                    'event': f"Suspicious process: {proc.get('name', 'Unknown')}",
                    'severity_numeric': 8  # High severity for suspicious processes
                })
        
        # Add network security events
        network_data = results.get('network_security', {})
        unusual_ports = network_data.get('unusual_ports', {})
        if unusual_ports:
            for i, (host, ports) in enumerate(unusual_ports.items()):
                timeline_data.append({
                    'timestamp': base_time.replace(minute=base_time.minute + len(timeline_data) + i),
                    'event': f"Unusual ports on {host}: {ports}",
                    'severity_numeric': 5  # Medium severity for unusual ports
                })
        
        # Add log analysis events
        log_data = results.get('log_analysis', {})
        if log_data.get('brute_force_attacks_detected', 0) > 0:
            timeline_data.append({
                'timestamp': base_time.replace(minute=base_time.minute + len(timeline_data)),
                'event': "Brute force attacks detected",
                'severity_numeric': 9  # Very high severity
            })
        
        return timeline_data

    def _extract_findings_data(self, results: Dict[str, Any]) -> List[Dict]:
        """Extract findings data for analysis."""
        findings = []
        
        # Extract from risk assessment if available
        risk_assessment = results.get('risk_assessment', {})
        if 'findings' in risk_assessment:
            return risk_assessment['findings']
        
        # Otherwise, create findings from module data
        system_data = results.get('system_security', {})
        if system_data and not system_data.get('error'):
            suspicious_count = len(system_data.get('suspicious', []))
            if suspicious_count > 0:
                findings.append({
                    'category': 'System Security',
                    'finding': 'Suspicious Processes',
                    'severity': 8
                })
        
        network_data = results.get('network_security', {})
        if network_data and not network_data.get('error'):
            unusual_ports = network_data.get('unusual_ports', {})
            if unusual_ports:
                findings.append({
                    'category': 'Network Security',
                    'finding': 'Unusual Ports',
                    'severity': 5
                })
        
        log_data = results.get('log_analysis', {})
        if log_data and not log_data.get('error'):
            if log_data.get('brute_force_attacks_detected', 0) > 0:
                findings.append({
                    'category': 'Log Analysis',
                    'finding': 'Brute Force Attacks',
                    'severity': 9
                })
            if log_data.get('total_suspicious_entries', 0) > 0:
                findings.append({
                    'category': 'Log Analysis',
                    'finding': 'Suspicious Log Entries',
                    'severity': 6
                })
        
        return findings

    def _extract_key_metrics(self, results: Dict[str, Any]) -> List[List]:
        """Extract key metrics for summary table."""
        metrics = [['Metric', 'Value']]
        
        # System metrics
        system_data = results.get('system_security', {})
        if system_data and not system_data.get('error'):
            metrics.append(['Suspicious Processes', str(len(system_data.get('suspicious', [])))])
        
        # Network metrics
        network_data = results.get('network_security', {})
        if network_data and not network_data.get('error'):
            unusual_ports = network_data.get('unusual_ports', {})
            total_unusual = sum(len(ports) for ports in unusual_ports.values())
            metrics.append(['Unusual Open Ports', str(total_unusual)])
        
        # Log analysis metrics
        log_data = results.get('log_analysis', {})
        if log_data and not log_data.get('error'):
            metrics.append(['Brute Force Attacks', str(log_data.get('brute_force_attacks_detected', 0))])
            metrics.append(['Suspicious Log Entries', str(log_data.get('total_suspicious_entries', 0))])
        
        # Risk assessment
        risk_assessment = results.get('risk_assessment', {})
        if risk_assessment:
            metrics.append(['Overall Risk Level', risk_assessment.get('overall_risk', 'Unknown')])
        
        return metrics

    def _generate_executive_summary_text(self, results: Dict[str, Any]) -> str:
        """Generate executive summary text."""
        risk_assessment = results.get('risk_assessment', {})
        overall_risk = risk_assessment.get('overall_risk', 'Unknown')
        total_findings = risk_assessment.get('total_findings', 0)
        
        # If no total_findings in risk_assessment, calculate from modules
        if total_findings == 0:
            system_suspicious = len(results.get('system_security', {}).get('suspicious', []))
            network_unusual = len(results.get('network_security', {}).get('unusual_ports', {}))
            log_attacks = results.get('log_analysis', {}).get('brute_force_attacks_detected', 0)
            log_suspicious = results.get('log_analysis', {}).get('total_suspicious_entries', 0)
            
            total_findings = system_suspicious + network_unusual + log_attacks + (1 if log_suspicious > 0 else 0)
        
        summary = f"""
        PyCyberShield conducted a comprehensive security assessment of the target environment. 
        The assessment analyzed system processes, network configurations, and system logs to identify 
        potential security risks and vulnerabilities.
        
        The overall security risk level is assessed as <b>{overall_risk}</b> based on {total_findings} 
        security findings across multiple categories. This assessment provides detailed analysis of 
        system security, network vulnerabilities, and suspicious activities detected in system logs.
        
        Immediate attention should be given to high-risk findings, and all recommendations should 
        be implemented according to organizational security policies and compliance requirements.
        """
        
        return summary.strip()

    def _generate_recommendations(self, results: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = [
            "Implement regular security monitoring and automated alerting systems.",
            "Conduct periodic security assessments to identify new vulnerabilities.",
            "Ensure all security services (firewall, antivirus) are active and updated.",
            "Monitor system logs for suspicious activities and brute-force attacks.",
            "Implement strong access controls and multi-factor authentication.",
            "Regularly update and patch all system components and applications.",
            "Establish incident response procedures for security events.",
            "Provide security awareness training for all users."
        ]
        
        # Add specific recommendations based on findings
        risk_assessment = results.get('risk_assessment', {})
        overall_risk = risk_assessment.get('overall_risk', 'Unknown')
        
        # Check if we have high-risk findings
        system_suspicious = len(results.get('system_security', {}).get('suspicious', []))
        log_attacks = results.get('log_analysis', {}).get('brute_force_attacks_detected', 0)
        
        if overall_risk == 'High' or system_suspicious > 0 or log_attacks > 0:
            recommendations.insert(0, "URGENT: Address all high-risk findings immediately.")
        
        if log_attacks > 0:
            recommendations.insert(1, "Implement account lockout policies to prevent brute-force attacks.")
        
        network_data = results.get('network_security', {})
        if network_data and network_data.get('unusual_ports'):
            recommendations.insert(-3, "Review and secure unusual open ports identified in network scan.")
        
        return recommendations


def main():
    """Test the reporting module."""
    # Sample test results that match your actual report data
    test_results = {
        'timestamp': '2025-08-29T08:32:49.509436',
        'system_security': {
            'processes': [{'name': f'process_{i}', 'pid': 1000+i, 'cpu_percent': 0.1} for i in range(308)],
            'suspicious': [
                {'name': 'kthreadd', 'pid': 2, 'cpu_percent': 0.0},
                {'name': 'pool_workqueue_release', 'pid': 3, 'cpu_percent': 0.0},
                {'name': 'kworker/R-kvfree_rcu_reclaim', 'pid': 4, 'cpu_percent': 0.0},
                {'name': 'kworker/R-rcu_gp', 'pid': 5, 'cpu_percent': 0.0},
                {'name': 'kworker/R-sync_wq', 'pid': 6, 'cpu_percent': 0.0},
            ] + [{'name': f'kworker_{i}', 'pid': 100+i, 'cpu_percent': 0.0} for i in range(301)],  # 306 total
            'risk_score': 'High',
            'severity_value': 8
        },
        'network_security': {
            'unusual_ports': {},  # Empty as per your report
            'risk_score': 'Low',
            'severity_value': 2
        },
        'log_analysis': {
            'total_suspicious_entries': 0,
            'brute_force_attacks_detected': 0,
            'risk_score': 'Low',
            'severity_value': 1
        },
        'risk_assessment': {
            'overall_risk': 'High',
            'total_findings': 1,  # As per your report
            'findings': [
                {'category': 'System Security', 'finding': 'Suspicious Processes', 'severity': 8},
            ],
            'compliance_mapping': {
                'Suspicious Processes': {
                    'ISO27001': 'Not Mapped',
                    'NIST_CSF': 'Not Mapped'
                }
            }
        },
        'summary': {
            'scan_completed': '2025-08-29T08:34:00.005377',
            'modules_run': ['system_security', 'network_security', 'log_analysis', 'risk_assessment', 'encryption'],
            'overall_status': 'completed',
            'output_directory': 'reports'
        }
    }
    
    # Set up logging to see what's happening
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    
    reporter = SecurityReporter()
    report_path = reporter.generate_comprehensive_report(test_results)
    print(f"Test report generated: {report_path}")
    
    # List generated charts
    charts_dir = Path("reports/charts")
    if charts_dir.exists():
        chart_files = list(charts_dir.glob("*.png"))
        print(f"\nGenerated charts ({len(chart_files)}):")
        for chart in chart_files:
            print(f"  - {chart.name}")


if __name__ == "__main__":
    main()