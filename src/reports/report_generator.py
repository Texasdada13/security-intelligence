"""Report generator for Security Intelligence dashboards."""
import csv
import io
from datetime import datetime
from typing import Dict, List, Any, Optional


class ReportGenerator:
    """Generate exportable reports from security data."""

    def __init__(self):
        self.product_name = "Security Intelligence"
        self.product_color = "#28a745"  # Green

    def generate_csv(self, data: Dict[str, Any], report_type: str = 'full') -> str:
        """Generate CSV report from dashboard data."""
        output = io.StringIO()
        writer = csv.writer(output)

        # Header
        writer.writerow([f'{self.product_name} Report'])
        writer.writerow([f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}'])
        writer.writerow([])

        if report_type in ['full', 'metrics']:
            # Key Metrics
            writer.writerow(['SECURITY METRICS'])
            writer.writerow(['Metric', 'Value'])
            metrics = data.get('metrics', {})
            writer.writerow(['Security Posture Score', f"{metrics.get('posture_score', 0)}/100"])
            writer.writerow(['Critical Vulnerabilities', metrics.get('critical_vulns', 0)])
            writer.writerow(['Open Incidents', metrics.get('open_incidents', 0)])
            writer.writerow(['Compliance Score', f"{metrics.get('compliance_score', 0)}%"])
            writer.writerow(['MTTR (Hours)', f"{metrics.get('mttr_hours', 0):.1f}"])
            writer.writerow([])

        if report_type in ['full', 'vulnerabilities']:
            # Vulnerabilities by Severity
            writer.writerow(['VULNERABILITIES BY SEVERITY'])
            writer.writerow(['Severity', 'Count'])
            vulns = data.get('vulnerabilities_by_severity', {})
            writer.writerow(['Critical', vulns.get('critical', 0)])
            writer.writerow(['High', vulns.get('high', 0)])
            writer.writerow(['Medium', vulns.get('medium', 0)])
            writer.writerow(['Low', vulns.get('low', 0)])
            writer.writerow([])

        if report_type in ['full', 'incidents']:
            # Incidents by Status
            writer.writerow(['INCIDENTS BY STATUS'])
            writer.writerow(['Status', 'Count'])
            incidents = data.get('incidents_by_status', {})
            writer.writerow(['Open', incidents.get('open', 0)])
            writer.writerow(['Investigating', incidents.get('investigating', 0)])
            writer.writerow(['Contained', incidents.get('contained', 0)])
            writer.writerow(['Resolved', incidents.get('resolved', 0)])
            writer.writerow([])

        if report_type in ['full', 'compliance']:
            # Compliance Frameworks
            writer.writerow(['COMPLIANCE FRAMEWORK SCORES'])
            writer.writerow(['Framework', 'Score'])
            for framework in data.get('compliance', []):
                writer.writerow([framework.get('framework', ''), f"{framework.get('score', 0)}%"])

        return output.getvalue()

    def generate_html_report(self, data: Dict[str, Any], org_name: str = '') -> str:
        """Generate HTML report for PDF conversion."""
        metrics = data.get('metrics', {})
        vulns = data.get('vulnerabilities_by_severity', {})
        incidents = data.get('incidents_by_status', {})
        compliance = data.get('compliance', [])

        # Determine posture status
        posture = metrics.get('posture_score', 0)
        if posture >= 80:
            posture_status = 'Good'
            posture_color = '#28a745'
        elif posture >= 60:
            posture_status = 'Warning'
            posture_color = '#ffc107'
        else:
            posture_status = 'Critical'
            posture_color = '#dc3545'

        html = f'''<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Security Intelligence Report</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 40px; color: #333; }}
        .header {{ background: linear-gradient(135deg, {self.product_color}, #17a2b8); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 28px; }}
        .header p {{ margin: 5px 0 0; opacity: 0.9; }}
        .posture-card {{ background: linear-gradient(135deg, {posture_color}, {posture_color}dd); color: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 30px; }}
        .posture-score {{ font-size: 48px; font-weight: bold; }}
        .posture-label {{ font-size: 14px; text-transform: uppercase; opacity: 0.9; }}
        .metrics-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 30px; }}
        .metric-card {{ background: #f8f9fa; padding: 20px; border-radius: 8px; text-align: center; border-left: 4px solid {self.product_color}; }}
        .metric-value {{ font-size: 24px; font-weight: bold; color: {self.product_color}; }}
        .metric-label {{ font-size: 12px; color: #666; text-transform: uppercase; }}
        table {{ width: 100%; border-collapse: collapse; margin-bottom: 30px; }}
        th {{ background: {self.product_color}; color: white; padding: 12px; text-align: left; }}
        td {{ padding: 10px 12px; border-bottom: 1px solid #eee; }}
        tr:hover {{ background: #f8f9fa; }}
        .section-title {{ font-size: 18px; color: #333; margin: 30px 0 15px; border-bottom: 2px solid {self.product_color}; padding-bottom: 5px; }}
        .footer {{ text-align: center; color: #999; font-size: 12px; margin-top: 40px; padding-top: 20px; border-top: 1px solid #eee; }}
        .severity-critical {{ color: #dc3545; font-weight: bold; }}
        .severity-high {{ color: #fd7e14; font-weight: bold; }}
        .severity-medium {{ color: #ffc107; }}
        .severity-low {{ color: #28a745; }}
        .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 30px; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Security Intelligence Report</h1>
        <p>{org_name or 'Organization'} - Generated {datetime.now().strftime("%B %d, %Y")}</p>
    </div>

    <div class="posture-card">
        <div class="posture-score">{posture}</div>
        <div class="posture-label">Security Posture Score - {posture_status}</div>
    </div>

    <div class="metrics-grid">
        <div class="metric-card">
            <div class="metric-value" style="color: #dc3545;">{metrics.get('critical_vulns', 0)}</div>
            <div class="metric-label">Critical Vulns</div>
        </div>
        <div class="metric-card">
            <div class="metric-value" style="color: #fd7e14;">{metrics.get('open_incidents', 0)}</div>
            <div class="metric-label">Open Incidents</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics.get('compliance_score', 0)}%</div>
            <div class="metric-label">Compliance</div>
        </div>
        <div class="metric-card">
            <div class="metric-value">{metrics.get('mttr_hours', 0):.1f}h</div>
            <div class="metric-label">MTTR</div>
        </div>
    </div>

    <div class="two-col">
        <div>
            <h2 class="section-title">Vulnerabilities by Severity</h2>
            <table>
                <thead>
                    <tr><th>Severity</th><th>Count</th></tr>
                </thead>
                <tbody>
                    <tr><td class="severity-critical">Critical</td><td>{vulns.get('critical', 0)}</td></tr>
                    <tr><td class="severity-high">High</td><td>{vulns.get('high', 0)}</td></tr>
                    <tr><td class="severity-medium">Medium</td><td>{vulns.get('medium', 0)}</td></tr>
                    <tr><td class="severity-low">Low</td><td>{vulns.get('low', 0)}</td></tr>
                </tbody>
            </table>
        </div>
        <div>
            <h2 class="section-title">Incidents by Status</h2>
            <table>
                <thead>
                    <tr><th>Status</th><th>Count</th></tr>
                </thead>
                <tbody>
                    <tr><td>Open</td><td>{incidents.get('open', 0)}</td></tr>
                    <tr><td>Investigating</td><td>{incidents.get('investigating', 0)}</td></tr>
                    <tr><td>Contained</td><td>{incidents.get('contained', 0)}</td></tr>
                    <tr><td>Resolved</td><td>{incidents.get('resolved', 0)}</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <h2 class="section-title">Compliance Framework Scores</h2>
    <table>
        <thead>
            <tr><th>Framework</th><th>Score</th><th>Status</th></tr>
        </thead>
        <tbody>'''

        for framework in compliance:
            score = framework.get('score', 0)
            if score >= 80:
                status = 'Compliant'
                status_color = '#28a745'
            elif score >= 60:
                status = 'Needs Improvement'
                status_color = '#ffc107'
            else:
                status = 'Non-Compliant'
                status_color = '#dc3545'
            html += f'''
            <tr>
                <td><strong>{framework.get('framework', '')}</strong></td>
                <td>{score}%</td>
                <td style="color: {status_color}; font-weight: bold;">{status}</td>
            </tr>'''

        html += f'''
        </tbody>
    </table>

    <div class="footer">
        <p>Generated by Security Intelligence - Your Fractional CISO</p>
        <p>Part of the Fractional C-Suite by Patriot Tech Systems</p>
    </div>
</body>
</html>'''

        return html


def create_report_generator() -> ReportGenerator:
    """Factory function to create a report generator."""
    return ReportGenerator()
