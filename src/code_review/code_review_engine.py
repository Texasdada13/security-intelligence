"""
Secure Code Review Engine

Comprehensive source code security review:
- Language & framework-aware reviews
- Critical module focus (auth, crypto, input validation)
- Patterns & guardrails for engineers
- Automated + manual review tracking
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

VULNERABILITY_CATEGORIES = {
    'injection': {'name': 'Injection Flaws', 'cwe': 'CWE-89/CWE-78/CWE-79', 'severity': 'Critical', 'owasp': 'A03'},
    'auth': {'name': 'Authentication & Session', 'cwe': 'CWE-287/CWE-384', 'severity': 'Critical', 'owasp': 'A07'},
    'crypto': {'name': 'Cryptographic Issues', 'cwe': 'CWE-327/CWE-328', 'severity': 'High', 'owasp': 'A02'},
    'access_control': {'name': 'Broken Access Control', 'cwe': 'CWE-284/CWE-639', 'severity': 'Critical', 'owasp': 'A01'},
    'input_validation': {'name': 'Input Validation', 'cwe': 'CWE-20', 'severity': 'High', 'owasp': 'A03'},
    'error_handling': {'name': 'Error Handling & Logging', 'cwe': 'CWE-209/CWE-532', 'severity': 'Medium', 'owasp': 'A09'},
    'config': {'name': 'Security Misconfiguration', 'cwe': 'CWE-16', 'severity': 'Medium', 'owasp': 'A05'},
    'data_exposure': {'name': 'Sensitive Data Exposure', 'cwe': 'CWE-200/CWE-312', 'severity': 'High', 'owasp': 'A02'},
    'dependency': {'name': 'Vulnerable Dependencies', 'cwe': 'CWE-1104', 'severity': 'High', 'owasp': 'A06'},
    'business_logic': {'name': 'Business Logic Flaws', 'cwe': 'CWE-840', 'severity': 'High', 'owasp': 'A04'},
}

LANGUAGE_PROFILES = {
    'python': {'frameworks': ['Django', 'Flask', 'FastAPI'], 'tools': ['Bandit', 'Safety', 'Semgrep'], 'common_issues': ['SQL injection via ORM bypass', 'Insecure deserialization', 'SSRF', 'Template injection']},
    'javascript': {'frameworks': ['React', 'Node.js', 'Express'], 'tools': ['ESLint Security', 'npm audit', 'Semgrep'], 'common_issues': ['XSS', 'Prototype pollution', 'ReDoS', 'Insecure JWT handling']},
    'java': {'frameworks': ['Spring Boot', 'Jakarta EE'], 'tools': ['SpotBugs', 'OWASP Dep Check', 'Semgrep'], 'common_issues': ['Deserialization', 'XXE', 'LDAP injection', 'Path traversal']},
    'go': {'frameworks': ['Gin', 'Echo', 'Fiber'], 'tools': ['gosec', 'staticcheck', 'Semgrep'], 'common_issues': ['Integer overflow', 'Race conditions', 'Improper error handling']},
    'swift': {'frameworks': ['SwiftUI', 'UIKit'], 'tools': ['SwiftLint', 'MobSF'], 'common_issues': ['Insecure data storage', 'Certificate pinning bypass', 'Jailbreak detection bypass']},
    'kotlin': {'frameworks': ['Android SDK', 'Ktor'], 'tools': ['detekt', 'MobSF'], 'common_issues': ['Insecure data storage', 'Intent injection', 'WebView vulnerabilities']},
}


@dataclass
class CodeFinding:
    id: str
    file_path: str
    line_number: int
    category: str
    severity: str
    title: str
    description: str
    code_snippet: str
    remediation: str
    cwe: str
    status: str = 'open'
    automated: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'file_path': self.file_path, 'line_number': self.line_number,
            'category': self.category, 'severity': self.severity,
            'title': self.title, 'description': self.description,
            'code_snippet': self.code_snippet, 'remediation': self.remediation,
            'cwe': self.cwe, 'status': self.status, 'automated': self.automated,
        }


@dataclass
class ReviewSummary:
    total_files: int
    total_lines: int
    findings_count: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    languages: List[str]
    risk_score: float
    grade: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_files': self.total_files, 'total_lines': self.total_lines,
            'findings_count': self.findings_count,
            'by_severity': self.by_severity, 'by_category': self.by_category,
            'languages': self.languages,
            'risk_score': round(self.risk_score, 1), 'grade': self.grade,
        }


@dataclass
class CodeReviewResult:
    analysis_id: str
    completed_at: datetime
    summary: ReviewSummary
    findings: List[CodeFinding]
    guardrails: List[Dict[str, Any]]
    playbook: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analysis_id': self.analysis_id,
            'completed_at': self.completed_at.isoformat(),
            'summary': self.summary.to_dict(),
            'findings': [f.to_dict() for f in self.findings],
            'guardrails': self.guardrails, 'playbook': self.playbook,
            'recommendations': self.recommendations,
        }


class CodeReviewEngine:
    """Comprehensive secure code review engine"""

    def analyze(self, data: Dict[str, Any]) -> CodeReviewResult:
        """Run complete code review analysis"""
        logger.info("Starting code review analysis")

        findings = self._process_findings(data.get('findings', []))
        summary = self._build_summary(data, findings)
        guardrails = self._generate_guardrails(data.get('languages', ['python']))
        playbook = self._generate_playbook(findings)
        recommendations = self._generate_recommendations(summary, findings)

        return CodeReviewResult(
            analysis_id=str(uuid.uuid4()), completed_at=datetime.utcnow(),
            summary=summary, findings=findings, guardrails=guardrails,
            playbook=playbook, recommendations=recommendations,
        )

    def review_language(self, language: str) -> Dict[str, Any]:
        """Get language-specific review guidance"""
        profile = LANGUAGE_PROFILES.get(language, {})
        return {
            'language': language,
            'frameworks': profile.get('frameworks', []),
            'recommended_tools': profile.get('tools', []),
            'common_issues': profile.get('common_issues', []),
            'review_checklist': self._get_language_checklist(language),
        }

    def _process_findings(self, raw_findings: List[Dict]) -> List[CodeFinding]:
        results = []
        for f in raw_findings:
            cat_info = VULNERABILITY_CATEGORIES.get(f.get('category', 'config'), {})
            results.append(CodeFinding(
                id=f.get('id', str(uuid.uuid4())),
                file_path=f.get('file_path', ''), line_number=f.get('line_number', 0),
                category=f.get('category', 'config'),
                severity=f.get('severity', cat_info.get('severity', 'Medium')),
                title=f.get('title', ''), description=f.get('description', ''),
                code_snippet=f.get('code_snippet', ''), remediation=f.get('remediation', ''),
                cwe=f.get('cwe', cat_info.get('cwe', '')),
                status=f.get('status', 'open'), automated=f.get('automated', True),
            ))
        return results

    def _build_summary(self, data: Dict, findings: List[CodeFinding]) -> ReviewSummary:
        by_sev = {}
        by_cat = {}
        for f in findings:
            by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
            by_cat[f.category] = by_cat.get(f.category, 0) + 1

        severity_weights = {'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}
        total_risk = sum(severity_weights.get(f.severity, 0) for f in findings)
        max_risk = len(findings) * 10 if findings else 1
        risk_score = (total_risk / max_risk * 100) if max_risk > 0 else 0
        security_score = 100 - risk_score

        return ReviewSummary(
            total_files=data.get('total_files', 0),
            total_lines=data.get('total_lines', 0),
            findings_count=len(findings), by_severity=by_sev, by_category=by_cat,
            languages=data.get('languages', []),
            risk_score=risk_score, grade=self._score_to_grade(security_score),
        )

    def _generate_guardrails(self, languages: List[str]) -> List[Dict[str, Any]]:
        guardrails = [
            {'rule': 'No hardcoded secrets', 'description': 'Use environment variables or secret managers for all credentials', 'applies_to': 'all', 'severity': 'critical'},
            {'rule': 'Input validation required', 'description': 'All user inputs must be validated and sanitized', 'applies_to': 'all', 'severity': 'critical'},
            {'rule': 'Parameterized queries only', 'description': 'Never construct SQL queries with string concatenation', 'applies_to': 'all', 'severity': 'critical'},
            {'rule': 'Output encoding', 'description': 'Encode all output to prevent XSS', 'applies_to': 'web', 'severity': 'high'},
            {'rule': 'HTTPS enforced', 'description': 'All communications must use TLS', 'applies_to': 'all', 'severity': 'high'},
            {'rule': 'Least privilege access', 'description': 'Grant minimum necessary permissions', 'applies_to': 'all', 'severity': 'high'},
            {'rule': 'Dependency scanning', 'description': 'Run dependency vulnerability checks in CI/CD', 'applies_to': 'all', 'severity': 'medium'},
            {'rule': 'Security logging', 'description': 'Log security-relevant events without sensitive data', 'applies_to': 'all', 'severity': 'medium'},
        ]
        return guardrails

    def _generate_playbook(self, findings: List[CodeFinding]) -> List[Dict[str, Any]]:
        categories_found = set(f.category for f in findings)
        playbook = []
        for cat in categories_found:
            cat_info = VULNERABILITY_CATEGORIES.get(cat, {})
            cat_findings = [f for f in findings if f.category == cat]
            playbook.append({
                'category': cat_info.get('name', cat),
                'owasp': cat_info.get('owasp', 'N/A'),
                'finding_count': len(cat_findings),
                'severity': cat_info.get('severity', 'Medium'),
                'remediation_steps': [
                    f'Review and fix {len(cat_findings)} findings in {cat_info.get("name", cat)}',
                    f'Implement controls per {cat_info.get("cwe", "CWE guidelines")}',
                    'Add automated tests to prevent regression',
                ],
            })
        return sorted(playbook, key=lambda x: {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}.get(x['severity'], 4))

    def _get_language_checklist(self, language: str) -> List[Dict[str, Any]]:
        base = [
            {'item': 'Authentication & authorization checks', 'priority': 'critical'},
            {'item': 'Input validation & sanitization', 'priority': 'critical'},
            {'item': 'Cryptographic implementation review', 'priority': 'high'},
            {'item': 'Error handling & information leakage', 'priority': 'medium'},
            {'item': 'Session management', 'priority': 'high'},
            {'item': 'Third-party dependency audit', 'priority': 'high'},
            {'item': 'Logging & monitoring adequacy', 'priority': 'medium'},
            {'item': 'Configuration & secrets management', 'priority': 'critical'},
        ]
        return base

    def _generate_recommendations(self, summary: ReviewSummary, findings: List[CodeFinding]) -> List[Dict]:
        recs = []
        critical = summary.by_severity.get('Critical', 0)
        if critical > 0:
            recs.append({'title': 'Fix Critical Vulnerabilities Immediately', 'description': f'{critical} critical issues found that could lead to complete compromise', 'priority': 'critical'})

        if summary.risk_score > 50:
            recs.append({'title': 'Comprehensive Security Refactor Needed', 'description': 'High risk score indicates systemic security issues in the codebase', 'priority': 'high'})

        recs.append({'title': 'Integrate SAST into CI/CD', 'description': 'Add automated static analysis to catch issues before merge', 'priority': 'medium'})
        recs.append({'title': 'Developer Security Training', 'description': 'Train developers on secure coding practices for identified vulnerability categories', 'priority': 'medium'})
        return recs

    def _score_to_grade(self, score: float) -> str:
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B+'
        if score >= 60: return 'B'
        if score >= 50: return 'C'
        if score >= 40: return 'D'
        return 'F'
