"""Demo Data Generator for Security Intelligence"""
import random
from datetime import datetime, timedelta
from typing import Dict, Any, List


def generate_demo_data(org_name: str = "Demo Company") -> Dict[str, Any]:
    """Generate comprehensive demo data for Security Intelligence."""

    org_id = f"demo-{random.randint(1000, 9999)}"

    return {
        'organization': generate_organization(org_id, org_name),
        'assets': generate_assets(org_id),
        'vulnerabilities': generate_vulnerabilities(org_id),
        'incidents': generate_incidents(org_id),
        'compliance': generate_compliance_assessments(org_id),
        'risk_assessment': generate_risk_assessment(org_id),
    }


def generate_organization(org_id: str, name: str) -> Dict[str, Any]:
    """Generate demo organization."""
    industries = ['Technology', 'Healthcare', 'Financial Services', 'Manufacturing', 'Retail']
    sizes = ['SMB', 'Mid-Market', 'Enterprise']
    frameworks_map = {
        'Healthcare': ['HIPAA', 'SOC2'],
        'Financial Services': ['PCI-DSS', 'SOC2', 'SOX'],
        'Technology': ['SOC2', 'ISO27001'],
        'Manufacturing': ['NIST', 'ISO27001'],
        'Retail': ['PCI-DSS', 'SOC2'],
    }

    industry = random.choice(industries)
    return {
        'id': org_id,
        'name': name,
        'industry': industry,
        'size': random.choice(sizes),
        'compliance_frameworks': frameworks_map.get(industry, ['SOC2']),
    }


def generate_assets(org_id: str) -> List[Dict[str, Any]]:
    """Generate demo IT assets."""
    asset_templates = [
        ('Production Web Server 1', 'Server', 'Critical', '10.0.1.10'),
        ('Production Web Server 2', 'Server', 'Critical', '10.0.1.11'),
        ('Database Server - Primary', 'Server', 'Critical', '10.0.2.10'),
        ('Database Server - Replica', 'Server', 'High', '10.0.2.11'),
        ('Application Server', 'Server', 'High', '10.0.1.20'),
        ('Development Server', 'Server', 'Medium', '10.0.3.10'),
        ('Firewall - Primary', 'Network Device', 'Critical', '10.0.0.1'),
        ('Core Switch', 'Network Device', 'Critical', '10.0.0.2'),
        ('VPN Gateway', 'Network Device', 'High', '10.0.0.5'),
        ('Email Server', 'Server', 'High', '10.0.4.10'),
        ('File Server', 'Server', 'Medium', '10.0.4.20'),
        ('Backup Server', 'Server', 'High', '10.0.5.10'),
        ('CI/CD Server', 'Server', 'Medium', '10.0.3.20'),
        ('Monitoring Server', 'Server', 'Medium', '10.0.6.10'),
        ('Customer Data Store', 'Application', 'Critical', 'N/A'),
        ('Internal Wiki', 'Application', 'Low', 'N/A'),
    ]

    assets = []
    for name, atype, criticality, ip in asset_templates:
        hostname = name.lower().replace(' ', '-').replace('---', '-')
        assets.append({
            'id': f"asset-{random.randint(10000, 99999)}",
            'organization_id': org_id,
            'name': name,
            'asset_type': atype,
            'criticality': criticality,
            'ip_address': ip if ip != 'N/A' else None,
            'hostname': f"{hostname}.internal",
            'owner': random.choice(['IT Operations', 'Security Team', 'DevOps', 'Infrastructure']),
            'location': random.choice(['AWS us-east-1', 'AWS us-west-2', 'On-Premise DC1', 'Azure East']),
            'status': 'active',
            'last_scanned': (datetime.now() - timedelta(days=random.randint(1, 14))).isoformat(),
        })

    return assets


def generate_vulnerabilities(org_id: str) -> List[Dict[str, Any]]:
    """Generate demo vulnerability data with realistic CVEs."""
    vuln_templates = [
        ('Apache Log4j RCE (Log4Shell)', 'CVE-2021-44228', 'Critical', 10.0, 'Open'),
        ('OpenSSL Buffer Overflow', 'CVE-2022-3602', 'High', 8.1, 'In Progress'),
        ('Spring4Shell RCE', 'CVE-2022-22965', 'Critical', 9.8, 'Remediated'),
        ('PostgreSQL Authentication Bypass', 'CVE-2021-23214', 'High', 7.5, 'Open'),
        ('Linux Kernel Privilege Escalation', 'CVE-2022-0847', 'High', 7.8, 'In Progress'),
        ('Nginx HTTP/2 DoS', 'CVE-2023-44487', 'High', 7.5, 'Open'),
        ('SSH Terrapin Attack', 'CVE-2023-48795', 'Medium', 5.9, 'Open'),
        ('Redis Lua Sandbox Escape', 'CVE-2022-0543', 'Critical', 10.0, 'In Progress'),
        ('Docker Container Escape', 'CVE-2022-0185', 'High', 8.4, 'Remediated'),
        ('MySQL Authentication Bypass', 'CVE-2022-21417', 'Medium', 6.5, 'Open'),
        ('Node.js Prototype Pollution', 'CVE-2022-21824', 'Medium', 5.3, 'Accepted'),
        ('WordPress SQLi', 'CVE-2022-4974', 'High', 8.8, 'Open'),
        ('SSL/TLS Sweet32', 'CVE-2016-2183', 'Low', 3.4, 'Accepted'),
        ('Weak SSH Ciphers', None, 'Low', 3.1, 'Open'),
        ('Missing Security Headers', None, 'Low', 2.5, 'Open'),
    ]

    vulnerabilities = []
    for title, cve, severity, cvss, status in vuln_templates:
        discovered = datetime.now() - timedelta(days=random.randint(5, 90))
        due_days = {'Critical': 7, 'High': 30, 'Medium': 60, 'Low': 90}

        vulnerabilities.append({
            'id': f"vuln-{random.randint(10000, 99999)}",
            'organization_id': org_id,
            'title': title,
            'cve_id': cve,
            'severity': severity,
            'cvss_score': cvss,
            'status': status,
            'description': f"Vulnerability affecting system components. {title}.",
            'remediation_notes': f"Apply vendor patch or implement compensating controls." if status != 'Open' else None,
            'discovered_at': discovered.isoformat(),
            'due_date': (discovered + timedelta(days=due_days[severity])).isoformat(),
            'remediated_at': (datetime.now() - timedelta(days=random.randint(1, 10))).isoformat() if status == 'Remediated' else None,
        })

    return vulnerabilities


def generate_incidents(org_id: str) -> List[Dict[str, Any]]:
    """Generate demo security incidents."""
    incident_templates = [
        ('Suspicious Login Activity Detected', 'Unauthorized Access', 'Medium', 'Investigating'),
        ('Phishing Email Campaign Targeting Finance', 'Phishing', 'High', 'Contained'),
        ('Malware Detected on Workstation', 'Malware', 'High', 'Resolved'),
        ('Data Exfiltration Attempt Blocked', 'Data Breach', 'Critical', 'Investigating'),
        ('DDoS Attack on Web Services', 'DoS', 'High', 'Resolved'),
        ('Brute Force Attack on VPN', 'Unauthorized Access', 'Medium', 'Contained'),
        ('Ransomware Detection - False Positive', 'Malware', 'Low', 'Closed'),
        ('Insider Threat - Excessive Data Access', 'Insider Threat', 'Medium', 'Investigating'),
    ]

    incidents = []
    for title, category, severity, status in incident_templates:
        detected = datetime.now() - timedelta(days=random.randint(1, 60))

        incidents.append({
            'id': f"inc-{random.randint(10000, 99999)}",
            'organization_id': org_id,
            'title': title,
            'category': category,
            'severity': severity,
            'status': status,
            'description': f"Security incident: {title}. Investigation ongoing.",
            'affected_systems': random.sample([
                'Web Server', 'Email System', 'Workstations', 'VPN',
                'Database', 'File Server', 'AD Controller'
            ], k=random.randint(1, 3)),
            'root_cause': 'Under investigation' if status == 'Investigating' else 'Identified and documented',
            'impact_assessment': f"{severity} impact on operations",
            'assigned_to': random.choice(['Security Analyst', 'SOC Team', 'IR Lead', 'CISO']),
            'detected_at': detected.isoformat(),
            'contained_at': (detected + timedelta(hours=random.randint(1, 24))).isoformat() if status in ['Contained', 'Resolved', 'Closed'] else None,
            'resolved_at': (detected + timedelta(days=random.randint(1, 7))).isoformat() if status in ['Resolved', 'Closed'] else None,
        })

    return incidents


def generate_compliance_assessments(org_id: str) -> List[Dict[str, Any]]:
    """Generate demo compliance assessment data."""
    frameworks = [
        ('SOC2', 85, 'Compliant', 94, 88, 4, 2),
        ('ISO27001', 78, 'Partial', 114, 89, 18, 7),
        ('NIST', 72, 'In Progress', 108, 78, 20, 10),
    ]

    assessments = []
    for framework, score, status, total, impl, partial, missing in frameworks:
        assessments.append({
            'id': f"comp-{random.randint(10000, 99999)}",
            'organization_id': org_id,
            'framework': framework,
            'overall_score': score,
            'overall_status': status,
            'controls_total': total,
            'controls_implemented': impl,
            'controls_partial': partial,
            'controls_missing': missing,
            'category_scores': {
                'Access Control': random.uniform(70, 95),
                'Incident Response': random.uniform(65, 90),
                'Risk Management': random.uniform(60, 85),
                'Data Protection': random.uniform(70, 90),
                'Security Operations': random.uniform(65, 88),
            },
            'critical_gaps': [
                'Multi-factor authentication not fully deployed',
                'Incident response plan needs annual update',
                'Vendor risk assessments incomplete',
            ][:random.randint(1, 3)],
            'remediation_roadmap': [
                {'item': 'Deploy MFA to all users', 'priority': 'High', 'due': '30 days'},
                {'item': 'Update IR playbooks', 'priority': 'Medium', 'due': '60 days'},
                {'item': 'Complete vendor assessments', 'priority': 'Medium', 'due': '90 days'},
            ],
            'audit_readiness': random.choice(['Ready', 'Needs Work', 'On Track']),
            'assessed_at': datetime.now().isoformat(),
        })

    return assessments


def generate_risk_assessment(org_id: str) -> Dict[str, Any]:
    """Generate demo risk assessment data."""
    return {
        'id': f"risk-{random.randint(10000, 99999)}",
        'organization_id': org_id,
        'overall_risk_score': random.uniform(55, 75),
        'overall_risk_level': random.choice(['Medium', 'Medium-High']),
        'total_risks': random.randint(25, 45),
        'critical_count': random.randint(2, 5),
        'high_count': random.randint(5, 10),
        'medium_count': random.randint(10, 20),
        'low_count': random.randint(8, 15),
        'top_risks': [
            {
                'title': 'Unpatched Critical Vulnerabilities',
                'level': 'Critical',
                'likelihood': 'High',
                'impact': 'Critical',
                'mitigation': 'Emergency patching cycle in progress',
            },
            {
                'title': 'Ransomware Exposure',
                'level': 'High',
                'likelihood': 'Medium',
                'impact': 'Critical',
                'mitigation': 'Enhanced backup and EDR deployment',
            },
            {
                'title': 'Third-Party Vendor Risk',
                'level': 'High',
                'likelihood': 'Medium',
                'impact': 'High',
                'mitigation': 'Vendor assessment program underway',
            },
            {
                'title': 'Insider Threat',
                'level': 'Medium',
                'likelihood': 'Low',
                'impact': 'High',
                'mitigation': 'DLP and monitoring controls deployed',
            },
        ],
        'priority_actions': [
            'Complete critical vulnerability remediation within 7 days',
            'Finalize ransomware response playbook',
            'Complete MFA rollout to all privileged accounts',
            'Conduct tabletop exercise for incident response',
        ],
        'risk_trend': random.choice(['Improving', 'Stable', 'Declining']),
        'assessed_at': datetime.now().isoformat(),
    }


def load_demo_data_to_db(db, models, org_name: str = "SecureTech Inc"):
    """Load demo data into the database."""
    data = generate_demo_data(org_name)

    # Create organization
    org = models.Organization(
        id=data['organization']['id'],
        name=data['organization']['name'],
        industry=data['organization']['industry'],
        size=data['organization']['size'],
        compliance_frameworks=data['organization']['compliance_frameworks'],
    )
    db.session.add(org)

    # Create assets
    asset_map = {}
    for a in data['assets']:
        from datetime import datetime
        asset = models.Asset(
            id=a['id'],
            organization_id=a['organization_id'],
            name=a['name'],
            asset_type=a['asset_type'],
            criticality=a['criticality'],
            ip_address=a['ip_address'],
            hostname=a['hostname'],
            owner=a['owner'],
            location=a['location'],
            status=a['status'],
            last_scanned=datetime.fromisoformat(a['last_scanned']) if a['last_scanned'] else None,
        )
        db.session.add(asset)
        asset_map[a['id']] = asset

    # Create vulnerabilities
    for v in data['vulnerabilities']:
        from datetime import datetime
        vuln = models.Vulnerability(
            id=v['id'],
            organization_id=v['organization_id'],
            title=v['title'],
            cve_id=v['cve_id'],
            severity=v['severity'],
            cvss_score=v['cvss_score'],
            status=v['status'],
            description=v['description'],
            remediation_notes=v['remediation_notes'],
            discovered_at=datetime.fromisoformat(v['discovered_at']),
            due_date=datetime.fromisoformat(v['due_date']) if v['due_date'] else None,
            remediated_at=datetime.fromisoformat(v['remediated_at']) if v['remediated_at'] else None,
        )
        db.session.add(vuln)

    # Create incidents
    for i in data['incidents']:
        from datetime import datetime
        incident = models.Incident(
            id=i['id'],
            organization_id=i['organization_id'],
            title=i['title'],
            category=i['category'],
            severity=i['severity'],
            status=i['status'],
            description=i['description'],
            affected_systems=i['affected_systems'],
            root_cause=i['root_cause'],
            impact_assessment=i['impact_assessment'],
            assigned_to=i['assigned_to'],
            detected_at=datetime.fromisoformat(i['detected_at']),
            contained_at=datetime.fromisoformat(i['contained_at']) if i['contained_at'] else None,
            resolved_at=datetime.fromisoformat(i['resolved_at']) if i['resolved_at'] else None,
        )
        db.session.add(incident)

    # Create compliance assessments
    for c in data['compliance']:
        from datetime import datetime
        compliance = models.ComplianceAssessment(
            id=c['id'],
            organization_id=c['organization_id'],
            framework=c['framework'],
            overall_score=c['overall_score'],
            overall_status=c['overall_status'],
            controls_total=c['controls_total'],
            controls_implemented=c['controls_implemented'],
            controls_partial=c['controls_partial'],
            controls_missing=c['controls_missing'],
            category_scores=c['category_scores'],
            critical_gaps=c['critical_gaps'],
            remediation_roadmap=c['remediation_roadmap'],
            audit_readiness=c['audit_readiness'],
            assessed_at=datetime.fromisoformat(c['assessed_at']),
        )
        db.session.add(compliance)

    # Create risk assessment
    r = data['risk_assessment']
    from datetime import datetime
    risk = models.RiskAssessment(
        id=r['id'],
        organization_id=r['organization_id'],
        overall_risk_score=r['overall_risk_score'],
        overall_risk_level=r['overall_risk_level'],
        total_risks=r['total_risks'],
        critical_count=r['critical_count'],
        high_count=r['high_count'],
        medium_count=r['medium_count'],
        low_count=r['low_count'],
        top_risks=r['top_risks'],
        priority_actions=r['priority_actions'],
        risk_trend=r['risk_trend'],
        assessed_at=datetime.fromisoformat(r['assessed_at']),
    )
    db.session.add(risk)

    db.session.commit()

    return data['organization']['id']
