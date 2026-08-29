"""
External Intelligence Client Module
Call external APIs for reconnaissance (crt.sh, etc.)
"""

import requests
from typing import Dict, Any, Optional, List


class ExternalIntelClient:
    """Client for external intelligence APIs"""
    
    def __init__(self, rate_limit: int = 5):
        self.rate_limit = rate_limit
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberArmy-Intel-Client/10.7.15'
        })
    
    def query_crtsh(self, domain: str) -> List[Dict[str, Any]]:
        """Query crt.sh for certificate transparency logs"""
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        
        try:
            response = self.session.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                
                # Extract unique subdomains
                subdomains = set()
                for entry in data:
                    name = entry.get('name_value', '')
                    for subdomain in name.split('\n'):
                        subdomain = subdomain.strip().lower()
                        if subdomain and '*' not in subdomain:
                            subdomains.add(subdomain)
                
                return [{'subdomain': s, 'source': 'crt.sh'} for s in subdomains]
            
            return []
        except Exception as e:
            print(f"[crt.sh ERROR] {str(e)}")
            return []
    
    def query_dns(self, domain: str) -> Dict[str, Any]:
        """Query DNS records using public DNS"""
        results = {
            'A': [],
            'AAAA': [],
            'MX': [],
            'TXT': [],
            'NS': [],
            'CNAME': [],
        }
        
        # Using Google Public DNS over HTTPS
        base_url = "https://dns.google/resolve"
        
        for record_type in results.keys():
            try:
                response = self.session.get(
                    base_url,
                    params={'name': domain, 'type': record_type},
                    timeout=10
                )
                if response.status_code == 200:
                    data = response.json()
                    answers = data.get('Answer', [])
                    results[record_type] = [a['data'] for a in answers if a.get('type') == self._get_record_type_num(record_type)]
            except Exception:
                continue
        
        return results
    
    def _get_record_type_num(self, record_type: str) -> int:
        """Get DNS record type number"""
        types = {'A': 1, 'AAAA': 28, 'MX': 15, 'TXT': 16, 'NS': 2, 'CNAME': 5}
        return types.get(record_type, 1)
    
    def get_subdomains_from_sources(self, domain: str) -> List[str]:
        """Aggregate subdomains from multiple sources"""
        all_subdomains = set()
        
        # Query crt.sh
        crtsh_results = self.query_crtsh(domain)
        for result in crtsh_results:
            all_subdomains.add(result['subdomain'])
        
        return list(all_subdomains)
    
    def close(self):
        """Close session"""
        self.session.close()
