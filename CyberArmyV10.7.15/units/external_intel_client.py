"""
External Intelligence Client Module
Call external APIs for reconnaissance (crt.sh, etc.)
"""

import time
import requests
from typing import Dict, Any, Optional, List


class ExternalIntelClient:
    """Client for external intelligence APIs"""

    def __init__(self, rate_limit: int = 5, timeout: int = 60, retries: int = 2):
        self.rate_limit = rate_limit
        self.timeout = timeout
        self.retries = retries
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'CyberArmy-Intel-Client/10.7.15',
            'Accept': 'application/json',
        })

    def query_crtsh(self, domain: str) -> List[Dict[str, Any]]:
        """Query crt.sh certificate transparency logs for subdomains.

        crt.sh is public (it never contacts the target) but slow and prone to
        transient 502/503/429 responses, so this uses a generous timeout, a few
        retries, and — importantly — reports WHY a query returned nothing instead
        of silently yielding an empty list. The query is passed via ``params`` so
        the ``%`` wildcard is encoded correctly.
        """
        params = {'q': f'%.{domain}', 'output': 'json'}
        last_reason = 'unknown error'

        for attempt in range(self.retries + 1):
            try:
                response = self.session.get(
                    'https://crt.sh/', params=params, timeout=self.timeout
                )
            except requests.exceptions.RequestException as exc:
                last_reason = f'request error: {exc}'
            else:
                if response.status_code != 200:
                    last_reason = f'HTTP {response.status_code}'
                elif not response.text.strip():
                    last_reason = 'empty response body'
                else:
                    try:
                        data = response.json()
                    except ValueError:
                        last_reason = 'response was not valid JSON'
                    else:
                        subdomains = set()
                        for entry in data:
                            name = entry.get('name_value', '') or ''
                            for sub in name.split('\n'):
                                sub = sub.strip().lower()
                                if sub and '*' not in sub:
                                    subdomains.add(sub)
                        print(f"[crt.sh] {domain}: {len(data)} cert rows, "
                              f"{len(subdomains)} unique names")
                        return [{'subdomain': s, 'source': 'crt.sh'}
                                for s in sorted(subdomains)]

            if attempt < self.retries:
                time.sleep(2 ** attempt)

        print(f"[crt.sh ERROR] {domain}: no data ({last_reason}). "
              "crt.sh may be rate-limiting or unreachable; retry later, or check "
              "the VM's internet/DNS.")
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
