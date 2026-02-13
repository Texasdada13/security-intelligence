"""
Network & Infrastructure Security Assessment Engine

Attack surface illumination across on-prem, hybrid, and cloud:
- External & internal network assessments
- Configuration & hardening reviews
- Firewall, VPN & segmentation validation
- Continuous improvement recommendations
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

HARDENING_BENCHMARKS = {
    'os_windows': {'name': 'Windows Server Hardening', 'source': 'CIS Benchmark', 'controls': 120},
    'os_linux': {'name': 'Linux Server Hardening', 'source': 'CIS Benchmark', 'controls': 95},
    'network_devices': {'name': 'Network Device Hardening', 'source': 'CIS / Vendor', 'controls': 60},
    'cloud_aws': {'name': 'AWS Cloud Security', 'source': 'CIS AWS Foundations', 'controls': 80},
    'cloud_azure': {'name': 'Azure Cloud Security', 'source': 'CIS Azure Foundations', 'controls': 75},
    'cloud_gcp': {'name': 'GCP Cloud Security', 'source': 'CIS GCP Foundations', 'controls': 65},
    'firewall': {'name': 'Firewall Configuration', 'source': 'NIST / CIS', 'controls': 40},
    'vpn': {'name': 'VPN Security', 'source': 'NIST SP 800-77', 'controls': 25},
}

ASSESSMENT_TYPES = {
    'external': {'name': 'External Network Assessment', 'description': 'Assess internet-facing attack surface'},
    'internal': {'name': 'Internal Network Assessment', 'description': 'Assess internal network security posture'},
    'wireless': {'name': 'Wireless Security Assessment', 'description': 'Evaluate wireless network security'},
    'cloud': {'name': 'Cloud Infrastructure Assessment', 'description': 'Assess cloud security configuration'},
    'segmentation': {'name': 'Network Segmentation Review', 'description': 'Validate network segmentation and isolation'},
}


@dataclass
class NetworkFinding:
    id: str
    title: str
    severity: str
    category: str
    affected_systems: List[str]
    description: str
    remediation: str
    status: str = 'open'
    cvss_score: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'title': self.title, 'severity': self.severity,
            'category': self.category, 'affected_systems': self.affected_systems,
            'description': self.description, 'remediation': self.remediation,
            'status': self.status, 'cvss_score': self.cvss_score,
        }


@dataclass
class HardeningScore:
    benchmark: str
    benchmark_name: str
    total_controls: int
    passed: int
    failed: int
    not_applicable: int
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'benchmark': self.benchmark, 'benchmark_name': self.benchmark_name,
            'total_controls': self.total_controls, 'passed': self.passed,
            'failed': self.failed, 'not_applicable': self.not_applicable,
            'score': round(self.score, 1),
        }


@dataclass
class AttackSurface:
    external_ips: int
    open_ports: int
    exposed_services: List[Dict[str, Any]]
    ssl_tls_issues: int
    dns_findings: List[str]
    risk_rating: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'external_ips': self.external_ips, 'open_ports': self.open_ports,
            'exposed_services': self.exposed_services,
            'ssl_tls_issues': self.ssl_tls_issues,
            'dns_findings': self.dns_findings, 'risk_rating': self.risk_rating,
        }


@dataclass
class NetworkResult:
    analysis_id: str
    completed_at: datetime
    overall_score: float
    grade: str
    attack_surface: AttackSurface
    hardening_scores: List[HardeningScore]
    findings: List[NetworkFinding]
    segmentation_review: Dict[str, Any]
    recommendations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analysis_id': self.analysis_id,
            'completed_at': self.completed_at.isoformat(),
            'overall_score': round(self.overall_score, 1), 'grade': self.grade,
            'attack_surface': self.attack_surface.to_dict(),
            'hardening_scores': [h.to_dict() for h in self.hardening_scores],
            'findings': [f.to_dict() for f in self.findings],
            'segmentation_review': self.segmentation_review,
            'recommendations': self.recommendations,
        }


class NetworkAssessmentEngine:
    """Network & infrastructure security assessment engine"""

    def analyze(self, data: Dict[str, Any]) -> NetworkResult:
        """Run complete network assessment"""
        logger.info("Starting network assessment")

        attack_surface = self._assess_attack_surface(data)
        hardening = self._assess_hardening(data)
        findings = self._process_findings(data.get('findings', []))
        segmentation = self._review_segmentation(data)

        scores = [h.score for h in hardening] if hardening else [50]
        overall = sum(scores) / len(scores)
        grade = self._score_to_grade(overall)

        recommendations = self._generate_recommendations(attack_surface, hardening, findings, segmentation)

        return NetworkResult(
            analysis_id=str(uuid.uuid4()), completed_at=datetime.utcnow(),
            overall_score=overall, grade=grade,
            attack_surface=attack_surface, hardening_scores=hardening,
            findings=findings, segmentation_review=segmentation,
            recommendations=recommendations,
        )

    def _assess_attack_surface(self, data: Dict[str, Any]) -> AttackSurface:
        external = data.get('external_ips', 0)
        ports = data.get('open_ports', 0)
        services = data.get('exposed_services', [])
        ssl_issues = data.get('ssl_tls_issues', 0)
        dns = data.get('dns_findings', [])

        if ports > 50 or ssl_issues > 5:
            risk = 'high'
        elif ports > 20 or ssl_issues > 2:
            risk = 'medium'
        else:
            risk = 'low'

        return AttackSurface(
            external_ips=external, open_ports=ports,
            exposed_services=services, ssl_tls_issues=ssl_issues,
            dns_findings=dns, risk_rating=risk,
        )

    def _assess_hardening(self, data: Dict[str, Any]) -> List[HardeningScore]:
        results = []
        assessments = data.get('hardening_assessments', {})

        for bench_id, bench_info in HARDENING_BENCHMARKS.items():
            if bench_id in assessments:
                a = assessments[bench_id]
                total = bench_info['controls']
                passed = a.get('passed', 0)
                failed = a.get('failed', total - passed)
                na = a.get('not_applicable', 0)
                applicable = total - na
                score = (passed / applicable * 100) if applicable > 0 else 0
                results.append(HardeningScore(
                    benchmark=bench_id, benchmark_name=bench_info['name'],
                    total_controls=total, passed=passed, failed=failed,
                    not_applicable=na, score=score,
                ))

        return results

    def _process_findings(self, raw: List[Dict]) -> List[NetworkFinding]:
        return [NetworkFinding(
            id=f.get('id', str(uuid.uuid4())), title=f.get('title', ''),
            severity=f.get('severity', 'Medium'), category=f.get('category', 'Network'),
            affected_systems=f.get('affected_systems', []),
            description=f.get('description', ''), remediation=f.get('remediation', ''),
            status=f.get('status', 'open'), cvss_score=f.get('cvss_score'),
        ) for f in raw]

    def _review_segmentation(self, data: Dict[str, Any]) -> Dict[str, Any]:
        zones = data.get('network_zones', [])
        rules = data.get('firewall_rules', 0)
        violations = data.get('segmentation_violations', 0)

        return {
            'zones': zones if zones else ['DMZ', 'Internal', 'Management', 'Guest'],
            'total_firewall_rules': rules,
            'segmentation_violations': violations,
            'flat_network_risk': not bool(zones) or len(zones) < 3,
            'score': max(0, 100 - violations * 10),
            'assessment': 'Well segmented' if violations == 0 else f'{violations} segmentation issues found',
        }

    def _generate_recommendations(self, surface: AttackSurface, hardening: List[HardeningScore],
                                   findings: List[NetworkFinding], seg: Dict) -> List[Dict]:
        recs = []
        if surface.risk_rating == 'high':
            recs.append({'title': 'Reduce External Attack Surface', 'description': f'{surface.open_ports} open ports detected. Close unnecessary services.', 'priority': 'critical'})

        if surface.ssl_tls_issues > 0:
            recs.append({'title': 'Fix SSL/TLS Issues', 'description': f'{surface.ssl_tls_issues} SSL/TLS configuration issues found', 'priority': 'high'})

        weak = [h for h in hardening if h.score < 70]
        if weak:
            recs.append({'title': 'Improve System Hardening', 'description': f'{len(weak)} benchmarks below 70% compliance: {", ".join(h.benchmark_name for h in weak[:3])}', 'priority': 'high'})

        if seg.get('flat_network_risk'):
            recs.append({'title': 'Implement Network Segmentation', 'description': 'Flat network detected. Segment by function and sensitivity.', 'priority': 'high'})

        critical = [f for f in findings if f.severity == 'Critical']
        if critical:
            recs.append({'title': 'Remediate Critical Network Findings', 'description': f'{len(critical)} critical findings require immediate attention', 'priority': 'critical'})

        return recs

    def _score_to_grade(self, score: float) -> str:
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B+'
        if score >= 60: return 'B'
        if score >= 50: return 'C'
        if score >= 40: return 'D'
        return 'F'
