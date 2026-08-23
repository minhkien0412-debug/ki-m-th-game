"""
Mission Store Module
Store mission state in SQLite database
"""

import sqlite3
import json
import time
from typing import Dict, Any, Optional, List, Tuple
from pathlib import Path
from datetime import datetime


class MissionStore:
    """SQLite-based mission state storage"""
    
    def __init__(self, db_path: str = "state/mission_store.sqlite"):
        self.db_path = db_path
        self._ensure_directory()
        self._init_db()
    
    def _ensure_directory(self):
        """Ensure database directory exists"""
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
    
    def _init_db(self):
        """Initialize database schema"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        # Create missions table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS missions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT UNIQUE NOT NULL,
                target_name TEXT NOT NULL,
                base_url TEXT NOT NULL,
                status TEXT DEFAULT 'created',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                started_at TIMESTAMP,
                completed_at TIMESTAMP,
                config_hash TEXT,
                policy_acknowledged BOOLEAN DEFAULT FALSE,
                exit_code INTEGER,
                summary TEXT
            )
        ''')
        
        # Create findings table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                finding_id TEXT NOT NULL,
                type TEXT NOT NULL,
                severity TEXT DEFAULT 'info',
                title TEXT NOT NULL,
                description TEXT,
                url TEXT,
                evidence TEXT,
                status TEXT DEFAULT 'new',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                validated BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
            )
        ''')
        
        # Create targets table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS targets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                host TEXT NOT NULL,
                path TEXT,
                discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                source TEXT,
                analyzed BOOLEAN DEFAULT FALSE,
                FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
            )
        ''')
        
        # Create state table for key-value storage
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS state (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mission_id TEXT NOT NULL,
                key TEXT NOT NULL,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(mission_id, key),
                FOREIGN KEY (mission_id) REFERENCES missions(mission_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def create_mission(self, target_name: str, base_url: str, config_hash: str = "") -> str:
        """Create a new mission and return mission_id"""
        mission_id = f"MISSION-{int(time.time())}-{hash(base_url) % 10000:04d}"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO missions (mission_id, target_name, base_url, config_hash, status)
            VALUES (?, ?, ?, ?, 'created')
        ''', (mission_id, target_name, base_url, config_hash))
        
        conn.commit()
        conn.close()
        
        return mission_id
    
    def update_mission_status(self, mission_id: str, status: str, **kwargs):
        """Update mission status"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        updates = ['status = ?', 'updated_at = CURRENT_TIMESTAMP']
        values = [status]
        
        for key, value in kwargs.items():
            if key in ['started_at', 'completed_at', 'exit_code', 'summary']:
                updates.append(f'{key} = ?')
                values.append(value)
        
        values.append(mission_id)
        
        query = f"UPDATE missions SET {', '.join(updates)} WHERE mission_id = ?"
        cursor.execute(query, values)
        
        conn.commit()
        conn.close()
    
    def add_finding(self, mission_id: str, finding_type: str, title: str,
                   severity: str = 'info', description: str = "", 
                   url: str = "", evidence: Dict[str, Any] = None) -> str:
        """Add a finding to the mission"""
        finding_id = f"FINDING-{int(time.time())}-{hash(title) % 10000:04d}"
        
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO findings (mission_id, finding_id, type, severity, title, description, url, evidence)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (mission_id, finding_id, finding_type, severity, title, description, url, json.dumps(evidence or {})))
        
        conn.commit()
        conn.close()
        
        return finding_id
    
    def add_target(self, mission_id: str, host: str, path: str = "", source: str = "discovery"):
        """Add a discovered target"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO targets (mission_id, host, path, source)
            VALUES (?, ?, ?, ?)
        ''', (mission_id, host, path, source))
        
        conn.commit()
        conn.close()
    
    def get_mission(self, mission_id: str) -> Optional[Dict[str, Any]]:
        """Get mission by ID"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM missions WHERE mission_id = ?', (mission_id,))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            return dict(row)
        return None
    
    def get_findings(self, mission_id: str) -> List[Dict[str, Any]]:
        """Get all findings for a mission"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM findings WHERE mission_id = ?', (mission_id,))
        rows = cursor.fetchall()
        
        conn.close()
        
        findings = []
        for row in rows:
            finding = dict(row)
            if finding.get('evidence'):
                try:
                    finding['evidence'] = json.loads(finding['evidence'])
                except json.JSONDecodeError:
                    pass
            findings.append(finding)
        
        return findings
    
    def get_targets(self, mission_id: str) -> List[Dict[str, Any]]:
        """Get all targets for a mission"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM targets WHERE mission_id = ?', (mission_id,))
        rows = cursor.fetchall()
        
        conn.close()
        
        return [dict(row) for row in rows]
    
    def set_state(self, mission_id: str, key: str, value: Any):
        """Set a state value for a mission"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO state (mission_id, key, value, updated_at)
            VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ''', (mission_id, key, json.dumps(value)))
        
        conn.commit()
        conn.close()
    
    def get_state(self, mission_id: str, key: str) -> Optional[Any]:
        """Get a state value for a mission"""
        conn = self._get_connection()
        cursor = conn.cursor()
        
        cursor.execute('SELECT value FROM state WHERE mission_id = ? AND key = ?', (mission_id, key))
        row = cursor.fetchone()
        
        conn.close()
        
        if row:
            try:
                return json.loads(row['value'])
            except json.JSONDecodeError:
                return row['value']
        return None
    
    def get_mission_summary(self, mission_id: str) -> Dict[str, Any]:
        """Get comprehensive mission summary"""
        mission = self.get_mission(mission_id)
        findings = self.get_findings(mission_id)
        targets = self.get_targets(mission_id)
        
        return {
            'mission': mission,
            'findings_count': len(findings),
            'findings_by_severity': {
                'critical': len([f for f in findings if f.get('severity') == 'critical']),
                'high': len([f for f in findings if f.get('severity') == 'high']),
                'medium': len([f for f in findings if f.get('severity') == 'medium']),
                'low': len([f for f in findings if f.get('severity') == 'low']),
                'info': len([f for f in findings if f.get('severity') == 'info']),
            },
            'targets_count': len(targets),
            'analyzed_targets': len([t for t in targets if t.get('analyzed')]),
        }
