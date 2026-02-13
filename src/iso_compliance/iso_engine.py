"""
ISO Compliance Engine

Unified ISO framework management:
- ISO 27001 (ISMS - Information Security Management System)
- ISO 42001 (AIMS - AI Management System)
- ISO 22301 (BCMS - Business Continuity Management System)
- Gap assessment and integrated risk management
- Policy design and operational playbooks
- Internal audit and certification readiness
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

ISO_FRAMEWORKS = {
    'iso_27001': {
        'name': 'ISO 27001:2022',
        'full_name': 'Information Security Management System (ISMS)',
        'description': 'International standard for managing information security',
        'clauses': {
            '4': {'name': 'Context of the Organization', 'controls': 4},
            '5': {'name': 'Leadership', 'controls': 3},
            '6': {'name': 'Planning', 'controls': 3},
            '7': {'name': 'Support', 'controls': 5},
            '8': {'name': 'Operation', 'controls': 3},
            '9': {'name': 'Performance Evaluation', 'controls': 3},
            '10': {'name': 'Improvement', 'controls': 2},
        },
        'annex_a_controls': 93,
        'categories': [
            'Organizational Controls (37)', 'People Controls (8)',
            'Physical Controls (14)', 'Technological Controls (34)',
        ],
    },
    'iso_42001': {
        'name': 'ISO 42001:2023',
        'full_name': 'AI Management System (AIMS)',
        'description': 'Standard for responsible AI development and deployment',
        'clauses': {
            '4': {'name': 'Context of the Organization', 'controls': 4},
            '5': {'name': 'Leadership', 'controls': 3},
            '6': {'name': 'Planning', 'controls': 4},
            '7': {'name': 'Support', 'controls': 5},
            '8': {'name': 'Operation', 'controls': 4},
            '9': {'name': 'Performance Evaluation', 'controls': 3},
            '10': {'name': 'Improvement', 'controls': 2},
        },
        'annex_a_controls': 38,
        'categories': [
            'AI System Lifecycle (10)', 'Data Management (8)',
            'AI Risk Management (10)', 'Third Party & Societal (10)',
        ],
    },
    'iso_22301': {
        'name': 'ISO 22301:2019',
        'full_name': 'Business Continuity Management System (BCMS)',
        'description': 'Standard for business continuity management',
        'clauses': {
            '4': {'name': 'Context of the Organization', 'controls': 4},
            '5': {'name': 'Leadership', 'controls': 3},
            '6': {'name': 'Planning', 'controls': 3},
            '7': {'name': 'Support', 'controls': 5},
            '8': {'name': 'Operation', 'controls': 5},
            '9': {'name': 'Performance Evaluation', 'controls': 3},
            '10': {'name': 'Improvement', 'controls': 2},
        },
        'annex_a_controls': 0,
        'categories': [
            'Business Impact Analysis', 'Risk Assessment',
            'BC Strategies', 'BC Plans & Procedures',
        ],
    },
}


@dataclass
class ClauseAssessment:
    clause_id: str
    clause_name: str
    status: str  # compliant, partial, non_compliant, not_applicable
    score: float
    evidence: List[str] = field(default_factory=list)
    gaps: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'clause_id': self.clause_id, 'clause_name': self.clause_name,
            'status': self.status, 'score': round(self.score, 1),
            'evidence': self.evidence, 'gaps': self.gaps,
            'recommendations': self.recommendations,
        }


@dataclass
class GapAnalysis:
    total_requirements: int
    compliant: int
    partial: int
    non_compliant: int
    not_applicable: int
    compliance_pct: float
    critical_gaps: List[Dict[str, Any]]
    remediation_roadmap: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'total_requirements': self.total_requirements,
            'compliant': self.compliant, 'partial': self.partial,
            'non_compliant': self.non_compliant, 'not_applicable': self.not_applicable,
            'compliance_pct': round(self.compliance_pct, 1),
            'critical_gaps': self.critical_gaps,
            'remediation_roadmap': self.remediation_roadmap,
        }


@dataclass
class CertificationReadiness:
    score: float
    grade: str
    ready_for_stage1: bool
    ready_for_stage2: bool
    estimated_timeline_months: int
    blockers: List[str]
    next_steps: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'score': round(self.score, 1), 'grade': self.grade,
            'ready_for_stage1': self.ready_for_stage1,
            'ready_for_stage2': self.ready_for_stage2,
            'estimated_timeline_months': self.estimated_timeline_months,
            'blockers': self.blockers, 'next_steps': self.next_steps,
        }


@dataclass
class ISOResult:
    analysis_id: str
    completed_at: datetime
    framework: str
    framework_name: str
    overall_score: float
    grade: str
    clause_assessments: List[ClauseAssessment]
    gap_analysis: GapAnalysis
    certification_readiness: CertificationReadiness
    policies_needed: List[Dict[str, Any]]
    recommendations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analysis_id': self.analysis_id,
            'completed_at': self.completed_at.isoformat(),
            'framework': self.framework, 'framework_name': self.framework_name,
            'overall_score': round(self.overall_score, 1), 'grade': self.grade,
            'clause_assessments': [c.to_dict() for c in self.clause_assessments],
            'gap_analysis': self.gap_analysis.to_dict(),
            'certification_readiness': self.certification_readiness.to_dict(),
            'policies_needed': self.policies_needed,
            'recommendations': self.recommendations,
        }


class ISOComplianceEngine:
    """Unified ISO compliance engine for 27001, 42001, and 22301"""

    def analyze(self, data: Dict[str, Any], framework: str = 'iso_27001') -> ISOResult:
        """Run complete ISO compliance analysis"""
        logger.info(f"Starting ISO compliance analysis for {framework}")

        fw = ISO_FRAMEWORKS.get(framework, ISO_FRAMEWORKS['iso_27001'])
        clause_assessments = self._assess_clauses(data, fw)
        gap_analysis = self._run_gap_analysis(clause_assessments, fw)
        cert_readiness = self._assess_certification_readiness(gap_analysis, data)
        policies = self._identify_needed_policies(framework, clause_assessments)
        recommendations = self._generate_recommendations(gap_analysis, cert_readiness, framework)

        overall = gap_analysis.compliance_pct
        grade = self._score_to_grade(overall)

        return ISOResult(
            analysis_id=str(uuid.uuid4()), completed_at=datetime.utcnow(),
            framework=framework, framework_name=fw['name'],
            overall_score=overall, grade=grade,
            clause_assessments=clause_assessments, gap_analysis=gap_analysis,
            certification_readiness=cert_readiness,
            policies_needed=policies, recommendations=recommendations,
        )

    def integrated_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Run integrated analysis across all three ISO frameworks"""
        results = {}
        for fw_id in ['iso_27001', 'iso_42001', 'iso_22301']:
            results[fw_id] = self.analyze(data, fw_id)

        avg_score = sum(r.overall_score for r in results.values()) / len(results)
        return {
            'integrated_score': round(avg_score, 1),
            'frameworks': {k: v.to_dict() for k, v in results.items()},
            'synergies': self._identify_synergies(results),
            'integrated_roadmap': self._build_integrated_roadmap(results),
        }

    def _assess_clauses(self, data: Dict[str, Any], fw: Dict) -> List[ClauseAssessment]:
        """Assess each ISO clause"""
        assessments = []
        existing = data.get('existing_controls', {})

        for clause_id, clause_info in fw['clauses'].items():
            clause_data = existing.get(f'clause_{clause_id}', {})
            implemented = clause_data.get('implemented', 0)
            total = clause_info['controls']
            score = (implemented / total * 100) if total > 0 else 0

            if score >= 80:
                status = 'compliant'
            elif score >= 50:
                status = 'partial'
            elif score > 0:
                status = 'non_compliant'
            else:
                status = 'non_compliant'

            gaps = []
            if score < 100:
                gaps.append(f'{total - implemented} of {total} requirements not fully met in Clause {clause_id}')

            assessments.append(ClauseAssessment(
                clause_id=clause_id, clause_name=clause_info['name'],
                status=status, score=score,
                evidence=clause_data.get('evidence', []),
                gaps=gaps,
                recommendations=[f'Address remaining gaps in {clause_info["name"]}'] if gaps else [],
            ))
        return assessments

    def _run_gap_analysis(self, assessments: List[ClauseAssessment], fw: Dict) -> GapAnalysis:
        """Run gap analysis across all clauses"""
        compliant = sum(1 for a in assessments if a.status == 'compliant')
        partial = sum(1 for a in assessments if a.status == 'partial')
        non_compliant = sum(1 for a in assessments if a.status == 'non_compliant')
        na = sum(1 for a in assessments if a.status == 'not_applicable')
        total = len(assessments)
        pct = ((compliant + partial * 0.5) / (total - na) * 100) if (total - na) > 0 else 0

        critical_gaps = [
            {'clause': a.clause_id, 'name': a.clause_name, 'score': a.score, 'gaps': a.gaps}
            for a in assessments if a.status == 'non_compliant'
        ]

        roadmap = []
        for i, gap in enumerate(critical_gaps):
            roadmap.append({
                'phase': i + 1, 'clause': gap['clause'], 'area': gap['name'],
                'priority': 'high' if gap['score'] < 30 else 'medium',
                'estimated_weeks': 4 if gap['score'] < 30 else 2,
                'actions': [f'Address gaps in {gap["name"]}'] + gap['gaps'],
            })

        return GapAnalysis(
            total_requirements=total, compliant=compliant, partial=partial,
            non_compliant=non_compliant, not_applicable=na, compliance_pct=pct,
            critical_gaps=critical_gaps, remediation_roadmap=roadmap,
        )

    def _assess_certification_readiness(self, gap: GapAnalysis, data: Dict) -> CertificationReadiness:
        """Assess readiness for ISO certification"""
        score = gap.compliance_pct
        blockers = []

        if gap.non_compliant > 0:
            blockers.append(f'{gap.non_compliant} clauses are non-compliant')
        if not data.get('management_commitment'):
            blockers.append('Management commitment not documented')
            score -= 10
        if not data.get('risk_assessment_done'):
            blockers.append('Risk assessment not completed')
            score -= 10
        if not data.get('internal_audit_done'):
            blockers.append('Internal audit not performed')
            score -= 10

        score = max(0, min(100, score))
        stage1 = score >= 60 and gap.non_compliant <= 2
        stage2 = score >= 80 and gap.non_compliant == 0

        if score >= 80:
            timeline = 2
        elif score >= 60:
            timeline = 4
        else:
            timeline = 6

        next_steps = []
        if not stage1:
            next_steps.append({'step': 'Close critical gaps', 'priority': 'high', 'timeline': f'{timeline} months'})
        if not data.get('internal_audit_done'):
            next_steps.append({'step': 'Conduct internal audit', 'priority': 'high', 'timeline': '1 month'})
        next_steps.append({'step': 'Management review meeting', 'priority': 'medium', 'timeline': '2 weeks'})

        return CertificationReadiness(
            score=score, grade=self._score_to_grade(score),
            ready_for_stage1=stage1, ready_for_stage2=stage2,
            estimated_timeline_months=timeline,
            blockers=blockers, next_steps=next_steps,
        )

    def _identify_needed_policies(self, framework: str, assessments: List[ClauseAssessment]) -> List[Dict]:
        """Identify policies that need to be created or updated"""
        policy_map = {
            'iso_27001': [
                'Information Security Policy', 'Access Control Policy', 'Risk Management Policy',
                'Incident Management Policy', 'Business Continuity Policy', 'Data Classification Policy',
                'Acceptable Use Policy', 'Cryptography Policy', 'Supplier Security Policy',
            ],
            'iso_42001': [
                'AI Governance Policy', 'AI Risk Management Policy', 'AI Ethics Policy',
                'Data Quality Policy for AI', 'AI System Monitoring Policy', 'AI Bias & Fairness Policy',
                'AI Transparency Policy', 'AI Third-Party Management Policy',
            ],
            'iso_22301': [
                'Business Continuity Policy', 'Crisis Management Plan', 'Disaster Recovery Plan',
                'Business Impact Analysis Procedure', 'BC Testing & Exercise Policy',
                'Communication Plan', 'Recovery Strategies Document',
            ],
        }
        policies = policy_map.get(framework, policy_map['iso_27001'])
        return [{'policy': p, 'status': 'needed', 'priority': 'high' if i < 3 else 'medium'} for i, p in enumerate(policies)]

    def _identify_synergies(self, results: Dict[str, ISOResult]) -> List[Dict]:
        """Identify synergies across ISO frameworks for integrated management"""
        return [
            {'area': 'Risk Management', 'frameworks': ['27001 Clause 6', '42001 Clause 6', '22301 Clause 6'],
             'description': 'Unified risk assessment process covering info security, AI, and business continuity'},
            {'area': 'Internal Audit', 'frameworks': ['27001 Clause 9', '42001 Clause 9', '22301 Clause 9'],
             'description': 'Combined internal audit program across all three management systems'},
            {'area': 'Management Review', 'frameworks': ['27001 Clause 9', '42001 Clause 9', '22301 Clause 9'],
             'description': 'Single management review covering all frameworks'},
            {'area': 'Document Control', 'frameworks': ['27001 Clause 7', '42001 Clause 7', '22301 Clause 7'],
             'description': 'Shared document management and control procedures'},
        ]

    def _build_integrated_roadmap(self, results: Dict[str, ISOResult]) -> List[Dict]:
        return [
            {'phase': 1, 'name': 'Foundation', 'duration': '1-2 months',
             'activities': ['Establish integrated management system scope', 'Unified risk assessment', 'Core policy development']},
            {'phase': 2, 'name': 'Implementation', 'duration': '2-4 months',
             'activities': ['Implement controls across all frameworks', 'Training and awareness', 'Process documentation']},
            {'phase': 3, 'name': 'Verification', 'duration': '1-2 months',
             'activities': ['Internal audit program', 'Management review', 'Corrective actions']},
            {'phase': 4, 'name': 'Certification', 'duration': '1-2 months',
             'activities': ['Stage 1 audit preparation', 'Stage 2 certification audit', 'Surveillance planning']},
        ]

    def _generate_recommendations(self, gap: GapAnalysis, cert: CertificationReadiness, framework: str) -> List[Dict]:
        recs = []
        if gap.non_compliant > 0:
            recs.append({'title': 'Address Non-Compliant Clauses', 'description': f'{gap.non_compliant} clauses need immediate attention', 'priority': 'critical'})
        if cert.blockers:
            recs.append({'title': 'Remove Certification Blockers', 'description': f'Blockers: {", ".join(cert.blockers[:3])}', 'priority': 'high'})
        if gap.compliance_pct < 60:
            recs.append({'title': 'Accelerate Implementation', 'description': f'At {gap.compliance_pct:.0f}% compliance, focused effort needed across multiple clauses', 'priority': 'high'})
        recs.append({'title': 'Engage Certification Body', 'description': 'Select and engage an accredited certification body for audit planning', 'priority': 'medium'})
        return recs

    def _score_to_grade(self, score: float) -> str:
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B+'
        if score >= 60: return 'B'
        if score >= 50: return 'C'
        if score >= 40: return 'D'
        return 'F'
