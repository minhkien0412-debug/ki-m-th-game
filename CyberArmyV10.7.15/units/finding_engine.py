"""
Finding Engine Module
Manage state machine of findings
"""

import hashlib
import time
from typing import Dict, Any, List, Optional
from enum import Enum


SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}


class FindingStatus(Enum):
    NEW = "new"
    CANDIDATE = "candidate"
    VALIDATING = "validating"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MANUAL_REVIEW = "manual_review"
    REPORTED = "reported"
    CLOSED = "closed"


class FindingEngine:
    """Manage findings through their lifecycle"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.findings: Dict[str, Dict[str, Any]] = {}
        self._by_signature: Dict[str, str] = {}

    def create_finding(self, finding_type: str, title: str,
                      severity: str = "info", url: str = "",
                      description: str = "", evidence: Dict[str, Any] = None,
                      signature: Optional[str] = None,
                      confidence: str = "medium") -> str:
        """Create a finding, de-duplicating by signature.

        Two findings with the same signature are the same issue observed twice:
        the second call increments the first's ``occurrences`` and returns its
        id instead of creating a duplicate. The id is derived from the signature
        so it is stable across runs (no hash randomization).
        """
        signature = signature or f"{finding_type}|{title}|{url}"

        existing_id = self._by_signature.get(signature)
        if existing_id is not None:
            self.findings[existing_id]['occurrences'] += 1
            return existing_id

        digest = hashlib.sha1(signature.encode('utf-8', 'replace')).hexdigest()[:12]
        finding_id = f"FINDING-{digest}"

        self.findings[finding_id] = {
            'id': finding_id,
            'type': finding_type,
            'title': title,
            'severity': severity,
            'confidence': confidence,
            'url': url,
            'description': description,
            'evidence': evidence or {},
            'signature': signature,
            'occurrences': 1,
            'status': FindingStatus.NEW.value,
            'history': [
                {'status': FindingStatus.NEW.value, 'timestamp': time.time()}
            ]
        }
        self._by_signature[signature] = finding_id

        return finding_id

    def add_findings(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Bulk-add validator findings (dicts), de-duplicated by signature."""
        ids = []
        for finding in findings or []:
            ids.append(self.create_finding(
                finding_type=finding.get('type', 'info'),
                title=finding.get('title', 'Untitled finding'),
                severity=finding.get('severity', 'info'),
                url=finding.get('url', ''),
                description=finding.get('description', ''),
                evidence=finding.get('evidence'),
                signature=finding.get('signature'),
                confidence=finding.get('confidence', 'medium'),
            ))
        return ids

    def get_sorted_findings(self) -> List[Dict[str, Any]]:
        """Return findings ordered by severity (critical first)."""
        return sorted(
            self.findings.values(),
            key=lambda f: (SEVERITY_ORDER.get(f.get('severity', 'info'), 5),
                           f.get('title', '')),
        )
    
    def update_status(self, finding_id: str, new_status: FindingStatus) -> bool:
        """Update finding status"""
        if finding_id not in self.findings:
            return False
        
        import time
        finding = self.findings[finding_id]
        finding['status'] = new_status.value
        finding['history'].append({
            'status': new_status.value,
            'timestamp': time.time()
        })
        
        return True
    
    def get_finding(self, finding_id: str) -> Optional[Dict[str, Any]]:
        """Get a finding by ID"""
        return self.findings.get(finding_id)
    
    def get_findings_by_status(self, status: FindingStatus) -> List[Dict[str, Any]]:
        """Get all findings with a specific status"""
        return [f for f in self.findings.values() if f['status'] == status.value]
    
    def get_findings_by_severity(self, severity: str) -> List[Dict[str, Any]]:
        """Get all findings with a specific severity"""
        return [f for f in self.findings.values() if f['severity'] == severity]
    
    def get_all_findings(self) -> List[Dict[str, Any]]:
        """Get all findings"""
        return list(self.findings.values())
    
    def get_summary(self) -> Dict[str, Any]:
        """Get findings summary"""
        summary = {
            'total': len(self.findings),
            'by_status': {},
            'by_severity': {}
        }
        
        for finding in self.findings.values():
            status = finding['status']
            severity = finding['severity']
            
            summary['by_status'][status] = summary['by_status'].get(status, 0) + 1
            summary['by_severity'][severity] = summary['by_severity'].get(severity, 0) + 1
        
        return summary
    
    def export_findings(self) -> List[Dict[str, Any]]:
        """Export findings for reporting"""
        return list(self.findings.values())
