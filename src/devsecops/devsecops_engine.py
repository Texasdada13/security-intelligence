"""
DevSecOps & Secure SDLC Engine

CI/CD security pipeline integration:
- SAST/DAST/SCA tracking
- Security gate management
- Pipeline security scoring
- Secure SDLC maturity assessment
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

SDLC_PHASES = {
    'requirements': {'name': 'Requirements & Design', 'security_activities': [
        'Security requirements gathering', 'Threat modeling', 'Secure design review', 'Privacy impact assessment',
    ]},
    'development': {'name': 'Development', 'security_activities': [
        'Secure coding standards', 'IDE security plugins', 'Pre-commit hooks', 'Peer code review with security focus',
    ]},
    'build': {'name': 'Build & CI', 'security_activities': [
        'SAST (Static Analysis)', 'SCA (Dependency Scanning)', 'Container image scanning', 'Secrets detection',
    ]},
    'test': {'name': 'Testing', 'security_activities': [
        'DAST (Dynamic Analysis)', 'API security testing', 'Penetration testing', 'Security regression tests',
    ]},
    'deploy': {'name': 'Deployment', 'security_activities': [
        'Infrastructure as Code scanning', 'Configuration validation', 'Security gate approval', 'Deployment signing',
    ]},
    'operate': {'name': 'Operations & Monitoring', 'security_activities': [
        'Runtime application protection (RASP)', 'Security monitoring & alerting', 'Vulnerability management', 'Incident response',
    ]},
}

SECURITY_TOOLS = {
    'sast': ['Semgrep', 'SonarQube', 'Checkmarx', 'CodeQL', 'Bandit', 'ESLint Security'],
    'dast': ['OWASP ZAP', 'Burp Suite', 'Nuclei', 'Nikto'],
    'sca': ['Snyk', 'Dependabot', 'OWASP Dependency-Check', 'npm audit', 'Safety'],
    'container': ['Trivy', 'Grype', 'Docker Scout', 'Snyk Container'],
    'iac': ['Checkov', 'tfsec', 'KICS', 'Terrascan'],
    'secrets': ['GitLeaks', 'TruffleHog', 'detect-secrets', 'git-secrets'],
}


@dataclass
class PipelineScan:
    tool_type: str  # sast, dast, sca, container, iac, secrets
    tool_name: str
    findings_count: int
    critical: int
    high: int
    medium: int
    low: int
    pass_fail: str
    last_run: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'tool_type': self.tool_type, 'tool_name': self.tool_name,
            'findings_count': self.findings_count,
            'critical': self.critical, 'high': self.high,
            'medium': self.medium, 'low': self.low,
            'pass_fail': self.pass_fail, 'last_run': self.last_run,
        }


@dataclass
class SecurityGate:
    name: str
    phase: str
    criteria: List[Dict[str, Any]]
    status: str  # passing, failing, not_configured
    blocking: bool

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name, 'phase': self.phase,
            'criteria': self.criteria, 'status': self.status,
            'blocking': self.blocking,
        }


@dataclass
class SDLCMaturity:
    phase: str
    phase_name: str
    maturity_level: int  # 0-4
    maturity_label: str
    activities_implemented: List[str]
    activities_missing: List[str]
    score: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            'phase': self.phase, 'phase_name': self.phase_name,
            'maturity_level': self.maturity_level,
            'maturity_label': self.maturity_label,
            'activities_implemented': self.activities_implemented,
            'activities_missing': self.activities_missing,
            'score': round(self.score, 1),
        }


@dataclass
class DevSecOpsResult:
    analysis_id: str
    completed_at: datetime
    overall_score: float
    grade: str
    maturity_level: int
    pipeline_scans: List[PipelineScan]
    security_gates: List[SecurityGate]
    sdlc_maturity: List[SDLCMaturity]
    tool_coverage: Dict[str, Any]
    recommendations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analysis_id': self.analysis_id,
            'completed_at': self.completed_at.isoformat(),
            'overall_score': round(self.overall_score, 1), 'grade': self.grade,
            'maturity_level': self.maturity_level,
            'pipeline_scans': [s.to_dict() for s in self.pipeline_scans],
            'security_gates': [g.to_dict() for g in self.security_gates],
            'sdlc_maturity': [m.to_dict() for m in self.sdlc_maturity],
            'tool_coverage': self.tool_coverage,
            'recommendations': self.recommendations,
        }


class DevSecOpsEngine:
    """DevSecOps and Secure SDLC engine"""

    def analyze(self, data: Dict[str, Any]) -> DevSecOpsResult:
        """Run complete DevSecOps analysis"""
        logger.info("Starting DevSecOps analysis")

        scans = self._assess_pipeline_scans(data)
        gates = self._assess_security_gates(data)
        maturity = self._assess_sdlc_maturity(data)
        coverage = self._assess_tool_coverage(data)

        maturity_scores = [m.score for m in maturity]
        overall = sum(maturity_scores) / len(maturity_scores) if maturity_scores else 0
        level = self._overall_maturity_level(maturity)
        grade = self._score_to_grade(overall)

        recommendations = self._generate_recommendations(scans, gates, maturity, coverage)

        return DevSecOpsResult(
            analysis_id=str(uuid.uuid4()), completed_at=datetime.utcnow(),
            overall_score=overall, grade=grade, maturity_level=level,
            pipeline_scans=scans, security_gates=gates,
            sdlc_maturity=maturity, tool_coverage=coverage,
            recommendations=recommendations,
        )

    def _assess_pipeline_scans(self, data: Dict[str, Any]) -> List[PipelineScan]:
        scans = data.get('pipeline_scans', [])
        return [PipelineScan(
            tool_type=s.get('tool_type', 'sast'), tool_name=s.get('tool_name', 'Unknown'),
            findings_count=s.get('findings_count', 0),
            critical=s.get('critical', 0), high=s.get('high', 0),
            medium=s.get('medium', 0), low=s.get('low', 0),
            pass_fail='pass' if s.get('critical', 0) == 0 else 'fail',
            last_run=s.get('last_run', ''),
        ) for s in scans]

    def _assess_security_gates(self, data: Dict[str, Any]) -> List[SecurityGate]:
        gates = data.get('security_gates', [])
        if not gates:
            # Default gates
            return [
                SecurityGate('Pre-Commit Checks', 'development', [{'check': 'Secrets scan', 'threshold': 'Zero secrets'}], 'not_configured', True),
                SecurityGate('CI Security Scan', 'build', [{'check': 'SAST + SCA', 'threshold': 'No critical findings'}], 'not_configured', True),
                SecurityGate('Pre-Deploy Review', 'deploy', [{'check': 'DAST + manual review', 'threshold': 'No high/critical open'}], 'not_configured', True),
            ]
        return [SecurityGate(
            name=g.get('name', ''), phase=g.get('phase', ''),
            criteria=g.get('criteria', []),
            status=g.get('status', 'not_configured'),
            blocking=g.get('blocking', True),
        ) for g in gates]

    def _assess_sdlc_maturity(self, data: Dict[str, Any]) -> List[SDLCMaturity]:
        implemented = data.get('implemented_activities', {})
        results = []
        maturity_labels = {0: 'Ad Hoc', 1: 'Initial', 2: 'Managed', 3: 'Defined', 4: 'Optimizing'}

        for phase_id, phase_info in SDLC_PHASES.items():
            phase_impl = implemented.get(phase_id, [])
            total = len(phase_info['security_activities'])
            impl_count = len([a for a in phase_info['security_activities'] if a in phase_impl])
            missing = [a for a in phase_info['security_activities'] if a not in phase_impl]
            score = (impl_count / total * 100) if total > 0 else 0

            if score >= 90: level = 4
            elif score >= 70: level = 3
            elif score >= 50: level = 2
            elif score >= 25: level = 1
            else: level = 0

            results.append(SDLCMaturity(
                phase=phase_id, phase_name=phase_info['name'],
                maturity_level=level, maturity_label=maturity_labels[level],
                activities_implemented=phase_impl, activities_missing=missing,
                score=score,
            ))
        return results

    def _assess_tool_coverage(self, data: Dict[str, Any]) -> Dict[str, Any]:
        active_tools = data.get('active_tools', {})
        coverage = {}
        for category, tools in SECURITY_TOOLS.items():
            active = active_tools.get(category, [])
            coverage[category] = {
                'name': category.upper(),
                'available_tools': tools,
                'active_tools': active,
                'covered': len(active) > 0,
            }

        covered = sum(1 for c in coverage.values() if c['covered'])
        return {
            'categories': coverage,
            'total_categories': len(SECURITY_TOOLS),
            'covered_categories': covered,
            'coverage_pct': round(covered / len(SECURITY_TOOLS) * 100, 1),
        }

    def _overall_maturity_level(self, maturity: List[SDLCMaturity]) -> int:
        if not maturity:
            return 0
        return min(m.maturity_level for m in maturity)

    def _generate_recommendations(self, scans: List[PipelineScan], gates: List[SecurityGate],
                                   maturity: List[SDLCMaturity], coverage: Dict) -> List[Dict]:
        recs = []
        not_configured = [g for g in gates if g.status == 'not_configured']
        if not_configured:
            recs.append({'title': 'Configure Security Gates', 'description': f'{len(not_configured)} security gates not configured. These are critical to prevent insecure deployments.', 'priority': 'critical'})

        if coverage.get('coverage_pct', 0) < 70:
            uncovered = [k.upper() for k, v in coverage.get('categories', {}).items() if not v.get('covered')]
            recs.append({'title': 'Expand Tool Coverage', 'description': f'Missing security tools for: {", ".join(uncovered[:3])}', 'priority': 'high'})

        low_maturity = [m for m in maturity if m.maturity_level < 2]
        if low_maturity:
            recs.append({'title': 'Improve SDLC Maturity', 'description': f'Low maturity in: {", ".join(m.phase_name for m in low_maturity[:3])}', 'priority': 'high'})

        failing = [s for s in scans if s.pass_fail == 'fail']
        if failing:
            recs.append({'title': 'Address Failing Pipeline Scans', 'description': f'{len(failing)} pipeline scans failing. Fix critical findings to unblock deployments.', 'priority': 'critical'})

        return recs

    def _score_to_grade(self, score: float) -> str:
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B+'
        if score >= 60: return 'B'
        if score >= 50: return 'C'
        if score >= 40: return 'D'
        return 'F'
