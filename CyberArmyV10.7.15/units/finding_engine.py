"""
Finding Engine Module
Manage state machine of findings
"""

from typing import Dict, Any, List, Optional
from enum import Enum


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
    
    def create_finding(self, finding_type: str, title: str, 
                      severity: str = "info", url: str = "",
                      description: str = "", evidence: Dict[str, Any] = None) -> str:
        """Create a new finding"""
        import time
        finding_id = f"FINDING-{int(time.time())}-{hash(title) % 10000:04d}"
        
        self.findings[finding_id] = {
            'id': finding_id,
            'type': finding_type,
            'title': title,
            'severity': severity,
            'url': url,
            'description': description,
            'evidence': evidence or {},
            'status': FindingStatus.NEW.value,
            'history': [
                {'status': FindingStatus.NEW.value, 'timestamp': time.time()}
            ]
        }
        
        return finding_id
    
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
