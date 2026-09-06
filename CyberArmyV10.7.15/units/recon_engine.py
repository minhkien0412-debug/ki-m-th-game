"""
Recon Engine Module
Passive reconnaissance (subfinder, crt.sh)
"""

from typing import Dict, Any, List, Optional
from .external_intel_client import ExternalIntelClient


class ReconEngine:
    """Passive reconnaissance engine"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.recon_config = config.get('recon', {})
        self.intel_client = ExternalIntelClient(
            timeout=int(self.recon_config.get('crtsh_timeout', 60)),
            retries=int(self.recon_config.get('crtsh_retries', 2)),
        )
        self.discovered_hosts: List[Dict[str, Any]] = []
    
    def run_passive_recon(self, domain: str) -> Dict[str, Any]:
        """Run passive reconnaissance on a domain"""
        results = {
            'domain': domain,
            'subdomains': [],
            'sources': {},
        }
        
        # Query crt.sh if enabled
        if self.recon_config.get('crtsh_enabled', True):
            print(f"[*] Querying crt.sh for {domain}...")
            crtsh_results = self.intel_client.query_crtsh(domain)
            results['sources']['crt.sh'] = len(crtsh_results)
            
            for entry in crtsh_results:
                subdomain = entry['subdomain']
                if subdomain not in [h['host'] for h in self.discovered_hosts]:
                    self.discovered_hosts.append({
                        'host': subdomain,
                        'source': 'crt.sh',
                        'passive': True
                    })
                    results['subdomains'].append(subdomain)
        
        return results
    
    def get_discovered_hosts(self) -> List[Dict[str, Any]]:
        """Get all discovered hosts"""
        return self.discovered_hosts.copy()
    
    def clear_cache(self):
        """Clear discovery cache"""
        self.discovered_hosts = []
    
    def close(self):
        """Cleanup resources"""
        self.intel_client.close()
