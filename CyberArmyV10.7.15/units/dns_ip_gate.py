"""
DNS and IP Gate Module
Block DNS rebinding attacks and private IP addresses
"""

import socket
import ipaddress
from typing import List, Tuple, Optional
from urllib.parse import urlparse


class DNSIPGate:
    """Protect against DNS rebinding and private IP access"""
    
    # Private IP ranges that should be blocked
    PRIVATE_RANGES = [
        '10.0.0.0/8',      # Class A private
        '172.16.0.0/12',   # Class B private
        '192.168.0.0/16',  # Class C private
        '127.0.0.0/8',     # Loopback
        '169.254.0.0/16',  # Link-local
        '0.0.0.0/8',       # Current network
        '224.0.0.0/4',     # Multicast
        '240.0.0.0/4',     # Reserved
        '::1/128',         # IPv6 loopback
        'fc00::/7',        # IPv6 unique local
        'fe80::/10',       # IPv6 link-local
    ]
    
    def __init__(self, blocked_ips: Optional[List[str]] = None):
        self.blocked_ips = blocked_ips or []
        self.private_networks = [ipaddress.ip_network(net) for net in self.PRIVATE_RANGES]
    
    def resolve_host(self, hostname: str) -> List[str]:
        """Resolve hostname to IP addresses safely"""
        try:
            # Get all IP addresses for hostname
            addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            ips = list(set([info[4][0] for info in addr_info]))
            return ips
        except socket.gaierror:
            return []
        except Exception:
            return []
    
    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved range"""
        try:
            ip_obj = ipaddress.ip_address(ip)

            mapped_ipv4 = getattr(ip_obj, 'ipv4_mapped', None)
            if mapped_ipv4 is not None:
                return self.is_private_ip(str(mapped_ipv4))

            if any((
                not ip_obj.is_global,
                ip_obj.is_private,
                ip_obj.is_loopback,
                ip_obj.is_link_local,
                ip_obj.is_multicast,
                ip_obj.is_reserved,
                ip_obj.is_unspecified,
            )):
                return True
            
            # Check against private networks
            for network in self.private_networks:
                if ip_obj in network:
                    return True
            
            return False
        except ValueError:
            # Invalid IP format
            return True
    
    def is_blocked_ip(self, ip: str) -> bool:
        """Check if IP is in manually blocked list"""
        return ip in self.blocked_ips
    
    def validate_hostname(self, hostname: str) -> Tuple[bool, Optional[str]]:
        """
        Validate hostname by resolving and checking IPs
        Returns: (is_safe, error_message)
        """
        host = hostname.rstrip('.')
        
        # Resolve hostname
        ips = self.resolve_host(host)
        
        if not ips:
            return False, "Failed to resolve hostname"
        
        # Check each resolved IP
        for ip in ips:
            if self.is_private_ip(ip):
                return False, f"Hostname resolves to private IP: {ip}"
            
            if self.is_blocked_ip(ip):
                return False, f"Hostname resolves to blocked IP: {ip}"
        
        return True, None
    
    def validate_url(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL's hostname"""
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False, "Invalid URL: missing host"
            
            host = parsed.hostname
            
            return self.validate_hostname(host)
        except Exception as e:
            return False, f"Error validating URL: {str(e)}"
    
    def safe_request_check(self, url: str) -> Tuple[bool, Optional[str], List[str]]:
        """
        Comprehensive safety check before making request
        Returns: (is_safe, error_message, resolved_ips)
        """
        try:
            parsed = urlparse(url)
            if not parsed.hostname:
                return False, "Invalid URL: missing host", []
            host = parsed.hostname
            
            # Resolve IPs
            ips = self.resolve_host(host)
            
            if not ips:
                return False, "DNS resolution failed", []
            
            # Validate each IP
            for ip in ips:
                if self.is_private_ip(ip):
                    return False, f"DNS rebinding detected - private IP: {ip}", ips
                
                if self.is_blocked_ip(ip):
                    return False, f"Blocked IP detected: {ip}", ips
            
            return True, None, ips
            
        except Exception as e:
            return False, f"Safety check error: {str(e)}", []
