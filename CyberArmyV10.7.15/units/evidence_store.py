"""
Evidence Store Module
Record traffic evidence for findings
"""

import json
import time
from typing import Dict, Any, Optional, List
from pathlib import Path
from datetime import datetime


class EvidenceStore:
    """Store and manage evidence from security testing"""
    
    def __init__(self, evidence_dir: str = "state/evidence"):
        self.evidence_dir = Path(evidence_dir)
        self._ensure_directory()
        self._traffic_file = self.evidence_dir / "traffic.jsonl"
    
    def _ensure_directory(self):
        """Ensure evidence directory exists"""
        self.evidence_dir.mkdir(parents=True, exist_ok=True)
    
    def record_request(self, mission_id: str, request_data: Dict[str, Any], 
                      response_data: Optional[Dict[str, Any]] = None,
                      metadata: Optional[Dict[str, Any]] = None) -> str:
        """Record HTTP request/response as evidence"""
        evidence = {
            'timestamp': datetime.utcnow().isoformat(),
            'mission_id': mission_id,
            'type': 'http_traffic',
            'request': request_data,
            'response': response_data,
            'metadata': metadata or {},
        }
        
        # Write to JSONL file
        with open(self._traffic_file, 'a') as f:
            f.write(json.dumps(evidence) + '\n')
        
        return evidence['timestamp']
    
    def record_finding_evidence(self, mission_id: str, finding_id: str,
                               evidence_type: str, data: Dict[str, Any]) -> str:
        """Record specific evidence for a finding"""
        evidence = {
            'timestamp': datetime.utcnow().isoformat(),
            'mission_id': mission_id,
            'finding_id': finding_id,
            'type': evidence_type,
            'data': data,
        }
        
        evidence_file = self.evidence_dir / f"finding_{finding_id}.json"
        
        # Load existing evidence or create new
        existing = []
        if evidence_file.exists():
            try:
                with open(evidence_file, 'r') as f:
                    existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
        
        existing.append(evidence)
        
        with open(evidence_file, 'w') as f:
            json.dump(existing, f, indent=2)
        
        return evidence['timestamp']
    
    def get_traffic(self, mission_id: str, limit: int = 100) -> List[Dict[str, Any]]:
        """Get recent traffic for a mission"""
        traffic = []
        
        if not self._traffic_file.exists():
            return traffic
        
        with open(self._traffic_file, 'r') as f:
            for line in f:
                try:
                    record = json.loads(line.strip())
                    if record.get('mission_id') == mission_id:
                        traffic.append(record)
                        if len(traffic) >= limit:
                            break
                except json.JSONDecodeError:
                    continue
        
        return traffic
    
    def get_finding_evidence(self, finding_id: str) -> List[Dict[str, Any]]:
        """Get all evidence for a specific finding"""
        evidence_file = self.evidence_dir / f"finding_{finding_id}.json"
        
        if not evidence_file.exists():
            return []
        
        try:
            with open(evidence_file, 'r') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    
    def export_evidence(self, mission_id: str, output_path: str) -> bool:
        """Export all evidence for a mission to a file"""
        traffic = self.get_traffic(mission_id, limit=10000)
        
        # Find all finding evidence files
        finding_evidence = []
        for evidence_file in self.evidence_dir.glob("finding_*.json"):
            finding_id = evidence_file.stem.replace("finding_", "")
            evidence = self.get_finding_evidence(finding_id)
            if evidence:
                finding_evidence.extend(evidence)
        
        export_data = {
            'mission_id': mission_id,
            'exported_at': datetime.utcnow().isoformat(),
            'traffic_count': len(traffic),
            'finding_evidence_count': len(finding_evidence),
            'traffic': traffic,
            'finding_evidence': finding_evidence,
        }
        
        try:
            with open(output_path, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception:
            return False
    
    def clear_mission_evidence(self, mission_id: str):
        """Clear evidence for a specific mission (for cleanup)"""
        # Clear traffic entries for mission
        if self._traffic_file.exists():
            temp_file = self._traffic_file.with_suffix('.tmp')
            
            with open(self._traffic_file, 'r') as f_in, open(temp_file, 'w') as f_out:
                for line in f_in:
                    try:
                        record = json.loads(line.strip())
                        if record.get('mission_id') != mission_id:
                            f_out.write(line)
                    except json.JSONDecodeError:
                        pass
            
            temp_file.rename(self._traffic_file)
        
        # Clear finding evidence files
        for evidence_file in self.evidence_dir.glob("finding_*.json"):
            try:
                with open(evidence_file, 'r') as f:
                    evidence_list = json.load(f)
                
                # Filter out evidence for this mission
                filtered = [e for e in evidence_list if e.get('mission_id') != mission_id]
                
                if filtered:
                    with open(evidence_file, 'w') as f:
                        json.dump(filtered, f, indent=2)
                else:
                    evidence_file.unlink()
            except Exception:
                continue
