"""
Audit Readiness Engine

Continuous audit preparation:
- Centralized control-to-evidence mapping
- Live evidence collection tracking
- Dynamic risk linked to controls
- One-click audit export
- Always audit-ready posture
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional
from datetime import datetime
import logging
import uuid

logger = logging.getLogger(__name__)

EVIDENCE_SOURCES = {
    'aws': {'name': 'AWS CloudTrail / Config', 'type': 'automated', 'categories': ['Access Control', 'Logging', 'Configuration']},
    'github': {'name': 'GitHub / GitLab', 'type': 'automated', 'categories': ['Change Management', 'Code Review', 'Access Control']},
    'jira': {'name': 'Jira / Project Management', 'type': 'automated', 'categories': ['Change Management', 'Risk Management', 'Incident Response']},
    'okta': {'name': 'Okta / Identity Provider', 'type': 'automated', 'categories': ['Access Control', 'Authentication', 'User Management']},
    'slack': {'name': 'Slack / Communication', 'type': 'semi_automated', 'categories': ['Awareness', 'Incident Response']},
    'manual': {'name': 'Manual Upload', 'type': 'manual', 'categories': ['Policy', 'Procedure', 'Training', 'General']},
}

CONTROL_FRAMEWORKS = {
    'iso_27001': {
        'name': 'ISO 27001:2022',
        'control_groups': [
            {'id': 'A.5', 'name': 'Organizational Controls', 'control_count': 37},
            {'id': 'A.6', 'name': 'People Controls', 'control_count': 8},
            {'id': 'A.7', 'name': 'Physical Controls', 'control_count': 14},
            {'id': 'A.8', 'name': 'Technological Controls', 'control_count': 34},
        ],
    },
    'soc2': {
        'name': 'SOC 2 Type II',
        'control_groups': [
            {'id': 'CC1', 'name': 'Control Environment', 'control_count': 5},
            {'id': 'CC2', 'name': 'Communication & Information', 'control_count': 3},
            {'id': 'CC3', 'name': 'Risk Assessment', 'control_count': 4},
            {'id': 'CC4', 'name': 'Monitoring Activities', 'control_count': 2},
            {'id': 'CC5', 'name': 'Control Activities', 'control_count': 3},
            {'id': 'CC6', 'name': 'Logical & Physical Access', 'control_count': 8},
            {'id': 'CC7', 'name': 'System Operations', 'control_count': 5},
            {'id': 'CC8', 'name': 'Change Management', 'control_count': 1},
            {'id': 'CC9', 'name': 'Risk Mitigation', 'control_count': 2},
        ],
    },
}


@dataclass
class Evidence:
    id: str
    control_id: str
    title: str
    source: str
    source_type: str  # automated, semi_automated, manual
    status: str  # collected, pending, stale, missing
    collected_at: Optional[str]
    file_path: str = ''
    notes: str = ''

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'control_id': self.control_id, 'title': self.title,
            'source': self.source, 'source_type': self.source_type,
            'status': self.status, 'collected_at': self.collected_at,
            'file_path': self.file_path, 'notes': self.notes,
        }


@dataclass
class ControlMapping:
    control_id: str
    control_name: str
    framework: str
    owner: str
    evidence_items: List[Evidence]
    status: str  # covered, partial, no_evidence
    risk_level: str
    last_reviewed: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'control_id': self.control_id, 'control_name': self.control_name,
            'framework': self.framework, 'owner': self.owner,
            'evidence_count': len(self.evidence_items),
            'evidence_items': [e.to_dict() for e in self.evidence_items],
            'status': self.status, 'risk_level': self.risk_level,
            'last_reviewed': self.last_reviewed,
        }


@dataclass
class AuditReadinessScore:
    score: float
    grade: str
    controls_covered: int
    controls_partial: int
    controls_no_evidence: int
    total_controls: int
    evidence_freshness_pct: float
    automated_collection_pct: float
    days_since_last_review: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            'score': round(self.score, 1), 'grade': self.grade,
            'controls_covered': self.controls_covered,
            'controls_partial': self.controls_partial,
            'controls_no_evidence': self.controls_no_evidence,
            'total_controls': self.total_controls,
            'evidence_freshness_pct': round(self.evidence_freshness_pct, 1),
            'automated_collection_pct': round(self.automated_collection_pct, 1),
            'days_since_last_review': self.days_since_last_review,
        }


@dataclass
class AuditResult:
    analysis_id: str
    completed_at: datetime
    readiness: AuditReadinessScore
    control_mappings: List[ControlMapping]
    evidence_summary: Dict[str, Any]
    audit_export: Dict[str, Any]
    recommendations: List[Dict[str, Any]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            'analysis_id': self.analysis_id,
            'completed_at': self.completed_at.isoformat(),
            'readiness': self.readiness.to_dict(),
            'control_mappings': [c.to_dict() for c in self.control_mappings],
            'evidence_summary': self.evidence_summary,
            'audit_export': self.audit_export,
            'recommendations': self.recommendations,
        }


class AuditReadinessEngine:
    """Continuous audit readiness engine"""

    def analyze(self, data: Dict[str, Any]) -> AuditResult:
        """Run complete audit readiness analysis"""
        logger.info("Starting audit readiness analysis")

        framework = data.get('framework', 'iso_27001')
        mappings = self._build_control_mappings(data, framework)
        readiness = self._calculate_readiness(mappings, data)
        evidence_summary = self._summarize_evidence(mappings)
        export = self._prepare_audit_export(mappings, framework)
        recommendations = self._generate_recommendations(readiness, mappings)

        return AuditResult(
            analysis_id=str(uuid.uuid4()), completed_at=datetime.utcnow(),
            readiness=readiness, control_mappings=mappings,
            evidence_summary=evidence_summary, audit_export=export,
            recommendations=recommendations,
        )

    def _build_control_mappings(self, data: Dict[str, Any], framework: str) -> List[ControlMapping]:
        fw = CONTROL_FRAMEWORKS.get(framework, CONTROL_FRAMEWORKS['iso_27001'])
        existing_evidence = data.get('evidence', {})
        mappings = []

        for group in fw['control_groups']:
            for i in range(group['control_count']):
                ctrl_id = f"{group['id']}.{i+1}"
                ctrl_evidence = existing_evidence.get(ctrl_id, [])

                evidence_items = [Evidence(
                    id=str(uuid.uuid4()), control_id=ctrl_id,
                    title=e.get('title', ''), source=e.get('source', 'manual'),
                    source_type=EVIDENCE_SOURCES.get(e.get('source', 'manual'), {}).get('type', 'manual'),
                    status=e.get('status', 'pending'),
                    collected_at=e.get('collected_at'),
                ) for e in ctrl_evidence]

                if not evidence_items:
                    status = 'no_evidence'
                elif all(e.status == 'collected' for e in evidence_items):
                    status = 'covered'
                else:
                    status = 'partial'

                mappings.append(ControlMapping(
                    control_id=ctrl_id, control_name=f'{group["name"]} - Control {i+1}',
                    framework=framework, owner=data.get('control_owners', {}).get(ctrl_id, 'Unassigned'),
                    evidence_items=evidence_items, status=status,
                    risk_level='high' if status == 'no_evidence' else ('medium' if status == 'partial' else 'low'),
                    last_reviewed=data.get('review_dates', {}).get(ctrl_id),
                ))

        return mappings

    def _calculate_readiness(self, mappings: List[ControlMapping], data: Dict) -> AuditReadinessScore:
        total = len(mappings)
        covered = sum(1 for m in mappings if m.status == 'covered')
        partial = sum(1 for m in mappings if m.status == 'partial')
        no_evidence = sum(1 for m in mappings if m.status == 'no_evidence')

        all_evidence = [e for m in mappings for e in m.evidence_items]
        fresh = sum(1 for e in all_evidence if e.status == 'collected')
        freshness = (fresh / len(all_evidence) * 100) if all_evidence else 0

        automated = sum(1 for e in all_evidence if e.source_type == 'automated')
        auto_pct = (automated / len(all_evidence) * 100) if all_evidence else 0

        score = (covered / total * 100) if total > 0 else 0
        # Boost for partial coverage
        score += (partial / total * 30) if total > 0 else 0
        score = min(100, score)

        return AuditReadinessScore(
            score=score, grade=self._score_to_grade(score),
            controls_covered=covered, controls_partial=partial,
            controls_no_evidence=no_evidence, total_controls=total,
            evidence_freshness_pct=freshness,
            automated_collection_pct=auto_pct,
            days_since_last_review=data.get('days_since_review', 0),
        )

    def _summarize_evidence(self, mappings: List[ControlMapping]) -> Dict[str, Any]:
        all_evidence = [e for m in mappings for e in m.evidence_items]
        by_source = {}
        by_status = {}
        for e in all_evidence:
            by_source[e.source] = by_source.get(e.source, 0) + 1
            by_status[e.status] = by_status.get(e.status, 0) + 1

        return {
            'total_evidence_items': len(all_evidence),
            'by_source': by_source,
            'by_status': by_status,
            'available_sources': {k: v['name'] for k, v in EVIDENCE_SOURCES.items()},
        }

    def _prepare_audit_export(self, mappings: List[ControlMapping], framework: str) -> Dict[str, Any]:
        """Prepare one-click audit export package"""
        fw = CONTROL_FRAMEWORKS.get(framework, {})
        return {
            'framework': fw.get('name', framework),
            'total_controls': len(mappings),
            'controls_with_evidence': sum(1 for m in mappings if m.status != 'no_evidence'),
            'export_ready': all(m.status == 'covered' for m in mappings),
            'package_contents': [
                'Control Matrix (Excel)',
                'Evidence Index',
                'Gap Summary Report',
                'Risk Register Extract',
                'Policy Document Links',
            ],
            'estimated_export_size': f'{len(mappings) * 2}MB',
        }

    def _generate_recommendations(self, readiness: AuditReadinessScore,
                                   mappings: List[ControlMapping]) -> List[Dict]:
        recs = []
        if readiness.controls_no_evidence > 0:
            recs.append({'title': 'Collect Missing Evidence', 'description': f'{readiness.controls_no_evidence} controls have no evidence. Priority: collect for high-risk controls first.', 'priority': 'critical'})

        if readiness.automated_collection_pct < 50:
            recs.append({'title': 'Increase Evidence Automation', 'description': f'Only {readiness.automated_collection_pct:.0f}% of evidence is auto-collected. Connect AWS, GitHub, Jira integrations.', 'priority': 'high'})

        if readiness.evidence_freshness_pct < 80:
            recs.append({'title': 'Refresh Stale Evidence', 'description': f'Evidence freshness at {readiness.evidence_freshness_pct:.0f}%. Re-collect stale evidence items.', 'priority': 'medium'})

        unassigned = [m for m in mappings if m.owner == 'Unassigned']
        if unassigned:
            recs.append({'title': 'Assign Control Owners', 'description': f'{len(unassigned)} controls have no owner. Assign responsibility for evidence collection.', 'priority': 'high'})

        if readiness.score >= 90:
            recs.append({'title': 'Schedule Audit', 'description': 'Audit readiness is high. Consider scheduling your certification audit.', 'priority': 'medium'})

        return recs

    def _score_to_grade(self, score: float) -> str:
        if score >= 90: return 'A+'
        if score >= 80: return 'A'
        if score >= 70: return 'B+'
        if score >= 60: return 'B'
        if score >= 50: return 'C'
        if score >= 40: return 'D'
        return 'F'
