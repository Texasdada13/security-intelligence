"""Demo Data Generator for Security Intelligence"""
import random
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import uuid


class SecurityDemoGenerator:
    """Generates realistic demo data for Security Intelligence product."""

    VULNERABILITY_TYPES = [
        'SQL Injection', 'Cross-Site Scripting (XSS)', 'Remote Code Execution',
        'Privilege Escalation', 'Path Traversal', 'Buffer Overflow',
        'Authentication Bypass', 'Information Disclosure', 'CSRF',
        'Insecure Deserialization', 'SSRF', 'XML External Entity'
    ]

    ASSET_TYPES = [
        'Web Server', 'Database Server', 'Application Server', 'API Gateway',
        'Load Balancer', 'File Server', 'Email Server', 'DNS Server',
        'Workstation', 'Mobile Device', 'Cloud Instance', 'Container'
    ]

    COMPLIANCE_FRAMEWORKS = [
        'SOC 2 Type II', 'ISO 27001', 'PCI DSS', 'HIPAA',
        'GDPR', 'NIST CSF', 'CIS Controls', 'FedRAMP'
    ]

    INCIDENT_TYPES = [
        'Phishing Attack', 'Malware Detection', 'Unauthorized Access',
        'Data Exfiltration', 'DDoS Attack', 'Ransomware', 'Insider Threat',
        'Account Compromise', 'Policy Violation', 'Configuration Drift'
    ]

    INDUSTRIES = [
        'Technology', 'Healthcare', 'Financial Services', 'Retail',
        'Manufacturing', 'Government', 'Education', 'Media'
    ]

    def __init__(self, seed: Optional[int] = None):
        if seed:
            random.seed(seed)

    def generate_organization(self, name: str = None) -> Dict[str, Any]:
        """Generate a demo organization."""
        name = name or f"SecureCorp {random.randint(1000, 9999)}"
        return {
            'id': str(uuid.uuid4()),
            'name': name,
            'industry': random.choice(self.INDUSTRIES),
            'employee_count': random.randint(50, 5000),
            'asset_count': random.randint(100, 10000),
            'compliance_frameworks': random.sample(self.COMPLIANCE_FRAMEWORKS, random.randint(2, 4)),
            'created_at': datetime.utcnow().isoformat()
        }

    def generate_vulnerabilities(self, org_id: str, count: int = 25) -> List[Dict[str, Any]]:
        """Generate vulnerability data."""
        vulnerabilities = []
        severity_weights = ['critical'] * 5 + ['high'] * 15 + ['medium'] * 40 + ['low'] * 40

        for i in range(count):
            severity = random.choice(severity_weights)
            discovered_date = datetime.utcnow() - timedelta(days=random.randint(1, 90))

            cvss_ranges = {
                'critical': (9.0, 10.0),
                'high': (7.0, 8.9),
                'medium': (4.0, 6.9),
                'low': (0.1, 3.9)
            }
            cvss_range = cvss_ranges[severity]
            cvss = round(random.uniform(*cvss_range), 1)

            vulnerabilities.append({
                'id': str(uuid.uuid4()),
                'organization_id': org_id,
                'cve_id': f"CVE-2024-{random.randint(10000, 99999)}",
                'title': random.choice(self.VULNERABILITY_TYPES),
                'severity': severity,
                'cvss_score': cvss,
                'affected_asset': f"{random.choice(self.ASSET_TYPES)}-{random.randint(1, 50)}",
                'asset_type': random.choice(self.ASSET_TYPES),
                'status': random.choice(['open', 'open', 'open', 'in_progress', 'remediated']),
                'discovered_at': discovered_date.isoformat(),
                'sla_days': {'critical': 7, 'high': 30, 'medium': 90, 'low': 180}[severity],
                'days_open': (datetime.utcnow() - discovered_date).days,
                'exploitable': random.choice([True, False]),
                'has_patch': random.choice([True, True, True, False])
            })

        return vulnerabilities

    def generate_incidents(self, org_id: str, count: int = 10) -> List[Dict[str, Any]]:
        """Generate incident data."""
        incidents = []
        severity_weights = ['critical'] * 5 + ['high'] * 20 + ['medium'] * 40 + ['low'] * 35

        for i in range(count):
            severity = random.choice(severity_weights)
            detected_date = datetime.utcnow() - timedelta(days=random.randint(0, 60))
            status = random.choice(['open', 'investigating', 'contained', 'resolved', 'resolved'])

            response_time_hours = random.randint(1, 48)
            resolution_time_hours = random.randint(response_time_hours, 168) if status == 'resolved' else None

            incidents.append({
                'id': str(uuid.uuid4()),
                'organization_id': org_id,
                'title': random.choice(self.INCIDENT_TYPES),
                'incident_type': random.choice(self.INCIDENT_TYPES),
                'severity': severity,
                'status': status,
                'detected_at': detected_date.isoformat(),
                'response_time_hours': response_time_hours,
                'resolution_time_hours': resolution_time_hours,
                'affected_systems': random.randint(1, 20),
                'affected_users': random.randint(0, 500),
                'data_compromised': random.choice([True, False, False, False]),
                'root_cause': random.choice([
                    'Phishing email', 'Unpatched vulnerability', 'Misconfiguration',
                    'Weak credentials', 'Third-party breach', 'Insider action', 'Unknown'
                ])
            })

        return incidents

    def generate_compliance_status(self, org_id: str, frameworks: List[str]) -> List[Dict[str, Any]]:
        """Generate compliance status for each framework."""
        compliance_data = []

        for framework in frameworks:
            total_controls = random.randint(50, 200)
            compliant = int(total_controls * random.uniform(0.6, 0.95))
            non_compliant = total_controls - compliant
            score = round(compliant / total_controls * 100, 1)

            compliance_data.append({
                'id': str(uuid.uuid4()),
                'organization_id': org_id,
                'framework': framework,
                'total_controls': total_controls,
                'compliant_controls': compliant,
                'non_compliant_controls': non_compliant,
                'score': score,
                'status': 'passing' if score >= 80 else 'failing' if score < 60 else 'at_risk',
                'last_audit_date': (datetime.utcnow() - timedelta(days=random.randint(30, 365))).isoformat(),
                'next_audit_date': (datetime.utcnow() + timedelta(days=random.randint(30, 180))).isoformat(),
                'critical_gaps': random.randint(0, 5) if score < 80 else 0
            })

        return compliance_data

    def generate_risk_register(self, org_id: str, count: int = 8) -> List[Dict[str, Any]]:
        """Generate enterprise risk register."""
        risk_categories = [
            'Cyber Attack', 'Data Breach', 'Compliance Violation', 'Insider Threat',
            'Third-Party Risk', 'Business Continuity', 'Reputation Damage', 'Regulatory Fine'
        ]

        risks = []
        for i in range(min(count, len(risk_categories))):
            likelihood = random.randint(1, 5)
            impact = random.randint(1, 5)
            inherent_score = likelihood * impact

            # Mitigation reduces score
            mitigation_effectiveness = random.uniform(0.3, 0.8)
            residual_score = int(inherent_score * (1 - mitigation_effectiveness))

            risks.append({
                'id': str(uuid.uuid4()),
                'organization_id': org_id,
                'category': risk_categories[i],
                'description': f"Risk of {risk_categories[i].lower()} impacting operations",
                'likelihood': likelihood,
                'impact': impact,
                'inherent_score': inherent_score,
                'residual_score': residual_score,
                'severity': 'critical' if residual_score >= 15 else 'high' if residual_score >= 10 else 'medium' if residual_score >= 5 else 'low',
                'status': random.choice(['identified', 'mitigating', 'mitigated', 'accepted']),
                'owner': random.choice(['CISO', 'CTO', 'CRO', 'IT Director', 'Security Manager']),
                'mitigations': random.randint(1, 5),
                'last_reviewed': (datetime.utcnow() - timedelta(days=random.randint(1, 90))).isoformat()
            })

        return risks

    def generate_security_metrics(
        self,
        vulnerabilities: List[Dict],
        incidents: List[Dict],
        compliance: List[Dict]
    ) -> Dict[str, Any]:
        """Generate overall security metrics summary."""
        vuln_by_severity = {
            'critical': len([v for v in vulnerabilities if v['severity'] == 'critical' and v['status'] != 'remediated']),
            'high': len([v for v in vulnerabilities if v['severity'] == 'high' and v['status'] != 'remediated']),
            'medium': len([v for v in vulnerabilities if v['severity'] == 'medium' and v['status'] != 'remediated']),
            'low': len([v for v in vulnerabilities if v['severity'] == 'low' and v['status'] != 'remediated'])
        }

        open_incidents = [i for i in incidents if i['status'] in ['open', 'investigating', 'contained']]
        resolved_incidents = [i for i in incidents if i['status'] == 'resolved']

        mttr = 0
        if resolved_incidents:
            mttr = sum(i['resolution_time_hours'] for i in resolved_incidents) / len(resolved_incidents)

        avg_compliance = sum(c['score'] for c in compliance) / len(compliance) if compliance else 0

        # Calculate posture score
        vuln_score = max(0, 100 - (vuln_by_severity['critical'] * 20 + vuln_by_severity['high'] * 5))
        incident_score = max(0, 100 - len(open_incidents) * 10)
        compliance_score = avg_compliance

        posture_score = int((vuln_score * 0.4 + incident_score * 0.3 + compliance_score * 0.3))

        return {
            'posture_score': posture_score,
            'vulnerabilities': vuln_by_severity,
            'total_vulnerabilities': sum(vuln_by_severity.values()),
            'remediated_this_month': len([v for v in vulnerabilities if v['status'] == 'remediated']),
            'open_incidents': len(open_incidents),
            'total_incidents': len(incidents),
            'mttr_hours': round(mttr, 1),
            'avg_compliance_score': round(avg_compliance, 1),
            'frameworks_passing': len([c for c in compliance if c['status'] == 'passing']),
            'frameworks_at_risk': len([c for c in compliance if c['status'] in ['at_risk', 'failing']]),
            'patch_compliance': random.randint(75, 98),
            'mfa_adoption': random.randint(70, 99),
            'privileged_users': random.randint(20, 100),
            'generated_at': datetime.utcnow().isoformat()
        }

    def generate_full_demo(self, org_name: str = None) -> Dict[str, Any]:
        """Generate complete demo dataset."""
        org = self.generate_organization(org_name)
        vulnerabilities = self.generate_vulnerabilities(org['id'])
        incidents = self.generate_incidents(org['id'])
        compliance = self.generate_compliance_status(org['id'], org['compliance_frameworks'])
        risks = self.generate_risk_register(org['id'])
        metrics = self.generate_security_metrics(vulnerabilities, incidents, compliance)

        return {
            'organization': org,
            'vulnerabilities': vulnerabilities,
            'incidents': incidents,
            'compliance': compliance,
            'risks': risks,
            'metrics_summary': metrics,
            'context_for_ai': self._build_ai_context(metrics, vulnerabilities, incidents, compliance)
        }

    def _build_ai_context(
        self,
        metrics: Dict[str, Any],
        vulnerabilities: List[Dict],
        incidents: List[Dict],
        compliance: List[Dict]
    ) -> Dict[str, Any]:
        """Build context dictionary for AI suggestion engine."""
        critical_incidents = [i for i in incidents if i['severity'] == 'critical' and i['status'] != 'resolved']
        failing_frameworks = [c for c in compliance if c['status'] == 'failing']

        return {
            'vulnerabilities': metrics['vulnerabilities'],
            'patch_compliance': metrics['patch_compliance'],
            'compliance': {
                'score': metrics['avg_compliance_score']
            },
            'frameworks': compliance,
            'incidents': {
                'open': metrics['open_incidents']
            },
            'incident_list': incidents,
            'mttr_hours': metrics['mttr_hours'],
            'risk_score': 100 - metrics['posture_score'],
            'unmitigated_risks': [],  # Would come from risks with status != 'mitigated'
            'threat_intel': {
                'active_campaigns': random.randint(0, 3)
            },
            'access': {
                'privileged_users': metrics['privileged_users'],
                'mfa_adoption': metrics['mfa_adoption']
            },
            'posture_score': metrics['posture_score']
        }


def create_security_demo_generator(seed: int = None) -> SecurityDemoGenerator:
    """Factory function to create demo generator."""
    return SecurityDemoGenerator(seed)
