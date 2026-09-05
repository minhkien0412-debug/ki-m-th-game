"""
Target Request Gate Module
Safe request gateway with multiple security checks
"""

import ipaddress
import requests
import threading
import time
from collections import deque
from typing import Dict, Any, List, Optional, Tuple
from urllib.parse import urljoin, urlparse
from .dns_ip_gate import DNSIPGate
from .canonicalizer import Canonicalizer
from .pinned_connection import pin_host
from .secret_redactor import SecretRedactor


class TargetRequestGate:
    """Safety gate for making HTTP requests to targets"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.rate_limit = config.get('rate_limit', {})
        self.requests_per_second = self._positive_limit('requests_per_second')
        self.requests_per_minute = self._positive_limit('requests_per_minute')
        concurrent = self._positive_limit('concurrent_connections') or 1
        self._concurrency_gate = threading.BoundedSemaphore(concurrent)
        self._rate_lock = threading.Lock()
        self._request_times = deque()
        # Per-thread map of the host -> validated IP that must be used for the
        # next connection, so the address checked is the address dialed.
        self._pin_state = threading.local()
        target_config = config.get('target', {})
        
        # Initialize safety components
        self.dns_gate = DNSIPGate()
        self.canonicalizer = Canonicalizer(
            allowed_hosts=target_config.get('allowed_hosts', []),
            allowed_paths=target_config.get('allowed_paths', []),
            blocked_paths=target_config.get('blocked_paths', [])
        )
        self.redactor = SecretRedactor()
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.trust_env = False
        self.session.headers.update({
            'User-Agent': 'CyberArmy-Security-Scanner/10.7.15 (Authorized Testing)'
        })

    def _positive_limit(self, name: str) -> Optional[int]:
        """Return a positive integer rate limit, or None when disabled."""
        value = self.rate_limit.get(name)
        if value is None:
            return None
        try:
            value = int(value)
        except (TypeError, ValueError):
            return None
        return value if value > 0 else None

    def _wait_for_rate_limit(self):
        """Enforce rolling per-second and per-minute request limits."""
        while True:
            with self._rate_lock:
                now = time.monotonic()
                while self._request_times and now - self._request_times[0] >= 60:
                    self._request_times.popleft()

                waits = []
                if self.requests_per_minute and len(self._request_times) >= self.requests_per_minute:
                    waits.append(60 - (now - self._request_times[0]))

                if self.requests_per_second:
                    recent = [stamp for stamp in self._request_times if now - stamp < 1]
                    if len(recent) >= self.requests_per_second:
                        waits.append(1 - (now - recent[0]))

                wait_for = max(waits, default=0)
                if wait_for <= 0:
                    self._request_times.append(now)
                    return

            time.sleep(wait_for)

    def _send_once(self, method: str, url: str, headers: Dict[str, str],
                   params: Optional[Dict[str, Any]], data: Optional[Any],
                   timeout: int) -> requests.Response:
        """Send one validated request without automatically following redirects.

        The connection is pinned to the IP address that ``validate_before_request``
        already resolved and approved, so a hostile resolver cannot rebind the
        name to a private address between the check and the socket connect.
        """
        self._wait_for_rate_limit()
        host = (urlparse(url).hostname or '').lower().rstrip('.')
        pinned_ip = self._take_pin(host)
        with self._concurrency_gate:
            with pin_host(host, pinned_ip):
                return self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    data=data,
                    timeout=timeout,
                    allow_redirects=False,
                )

    @staticmethod
    def _origin(url: str) -> Tuple[str, Optional[str], Optional[int]]:
        """Return a normalized origin tuple for credential forwarding checks."""
        parsed = urlparse(url)
        default_port = 443 if parsed.scheme.lower() == 'https' else 80
        return parsed.scheme.lower(), parsed.hostname, parsed.port or default_port

    def _pins(self) -> Dict[str, str]:
        pins = getattr(self._pin_state, 'pins', None)
        if pins is None:
            pins = {}
            self._pin_state.pins = pins
        return pins

    def _remember_pin(self, host: str, ip: Optional[str]) -> None:
        """Record the validated IP to dial for ``host`` on the next connection."""
        if not host:
            return
        pins = self._pins()
        if ip:
            pins[host] = ip
        else:
            pins.pop(host, None)

    def _take_pin(self, host: str) -> Optional[str]:
        """Return (without consuming) the pinned IP for ``host``, if any."""
        if not host:
            return None
        return self._pins().get(host)

    @staticmethod
    def _choose_pin_ip(host: str, ips: List[str]) -> Optional[str]:
        """Pick a validated address to pin, or ``None`` when pinning is moot.

        A host that is already an IP literal cannot be rebound, so it needs no
        pin. Otherwise prefer an IPv4 address (widest reachability) and fall
        back to the first validated address.
        """
        try:
            ipaddress.ip_address(host)
            return None
        except ValueError:
            pass
        for ip in ips:
            try:
                if isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address):
                    return ip
            except ValueError:
                continue
        return ips[0] if ips else None

    def validate_before_request(self, url: str) -> Tuple[bool, Optional[str]]:
        """Validate URL before making request.

        Resolves the host exactly once and pins the approved address so the
        subsequent connection cannot be redirected to a blocked IP.
        """
        # Check scope
        is_valid, error = self.canonicalizer.validate_url(url)
        if not is_valid:
            return False, f"Scope violation: {error}"

        # Resolve once, validate every returned address, and remember one to pin.
        is_safe, error, ips = self.dns_gate.safe_request_check(url)
        if not is_safe:
            return False, f"DNS/IP safety check failed: {error}"

        host = (urlparse(url).hostname or '').lower().rstrip('.')
        self._remember_pin(host, self._choose_pin_ip(host, ips))
        return True, None
    
    def make_request(self, url: str, method: str = 'GET', 
                    headers: Optional[Dict[str, str]] = None,
                    params: Optional[Dict[str, Any]] = None,
                    data: Optional[Any] = None,
                    timeout: int = 30,
                    allow_redirects: bool = True) -> Optional[requests.Response]:
        """Make a safe HTTP request through the gate"""

        # Drop any pins left over from an earlier request on this thread.
        self._pins().clear()

        # Pre-request validation
        is_valid, error = self.validate_before_request(url)
        if not is_valid:
            print(f"[GATE BLOCKED] {error}")
            return None
        
        # Normalize URL
        url = self.canonicalizer.normalize_url(url)
        
        # Credentials must reach the target. Redaction is only for logs/evidence.
        request_headers = dict(headers or {})
        
        try:
            current_url = url
            current_method = method.upper()
            current_params = params
            current_data = data

            for _ in range(11):
                response = self._send_once(
                    current_method, current_url, request_headers,
                    current_params, current_data, timeout,
                )

                if not allow_redirects or not response.is_redirect:
                    return response

                location = response.headers.get('Location')
                if not location:
                    return response

                next_url = urljoin(current_url, location)
                is_valid, error = self.validate_before_request(next_url)
                if not is_valid:
                    response.close()
                    print(f"[GATE BLOCKED] Unsafe redirect: {error}")
                    return None

                if self._origin(current_url) != self._origin(next_url):
                    sensitive_headers = {'authorization', 'cookie', 'proxy-authorization'}
                    request_headers = {
                        key: value for key, value in request_headers.items()
                        if key.lower() not in sensitive_headers
                    }

                if response.status_code == 303 or (
                    response.status_code in (301, 302) and current_method not in ('GET', 'HEAD')
                ):
                    current_method = 'GET'
                    current_data = None

                response.close()
                current_url = self.canonicalizer.normalize_url(next_url)
                current_params = None

            response.close()
            print("[GATE BLOCKED] Too many redirects")
            return None
        except requests.exceptions.RequestException as e:
            print(f"[REQUEST ERROR] {str(e)}")
            return None
        except Exception as e:
            print(f"[UNEXPECTED ERROR] {str(e)}")
            return None
    
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe GET request"""
        return self.make_request(url, method='GET', **kwargs)
    
    def post(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe POST request"""
        return self.make_request(url, method='POST', **kwargs)
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe HEAD request"""
        return self.make_request(url, method='HEAD', **kwargs)
    
    def options(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Safe OPTIONS request"""
        return self.make_request(url, method='OPTIONS', **kwargs)
    
    def close(self):
        """Close the session"""
        self.session.close()
