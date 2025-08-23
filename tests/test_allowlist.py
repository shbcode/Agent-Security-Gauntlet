"""
Tests for allowlist functionality.

Focused tests for domain allowlist validation to ensure only
permitted domains can be accessed.
"""

import pytest
from safety_gate import domain_allowed


class TestAllowlistValidation:
    """Test domain allowlist validation in detail."""
    
    def test_localhost_variations(self):
        """Test various localhost URL formats."""
        localhost_urls = [
            "http://localhost",
            "https://localhost",
            "http://localhost/",
            "https://localhost/",
            "http://localhost/page.html",
            "https://localhost:8080/api",
            "localhost",
            "localhost/page",
            "localhost:3000",
        ]
        
        for url in localhost_urls:
            assert domain_allowed(url), f"Should allow {url}"
    
    def test_127_0_0_1_variations(self):
        """Test various 127.0.0.1 URL formats."""
        loopback_urls = [
            "http://127.0.0.1",
            "https://127.0.0.1", 
            "http://127.0.0.1/",
            "https://127.0.0.1/",
            "http://127.0.0.1/page.html",
            "https://127.0.0.1:8080/api",
            "127.0.0.1",
            "127.0.0.1/page",
            "127.0.0.1:3000",
        ]
        
        for url in loopback_urls:
            assert domain_allowed(url), f"Should allow {url}"
    
    def test_localhost_subdomains(self):
        """Test that *.localhost subdomains are allowed."""
        subdomain_urls = [
            "http://app.localhost",
            "https://api.localhost",
            "http://secure.localhost/page",
            "https://test.localhost:8080",
            "app.localhost",
            "api.localhost/endpoint",
            "multi.level.localhost",
            "app.localhost:3000/path"
        ]
        
        for url in subdomain_urls:
            assert domain_allowed(url), f"Should allow {url}"
    
    def test_malicious_domains_blocked(self):
        """Test that various malicious domains are blocked."""
        malicious_urls = [
            "http://evil.com",
            "https://attacker.net", 
            "http://malicious.site/phish",
            "https://data-theft.evil.local",
            "http://credential-harvest.com",
            "https://phishing.badactor.net",
            "evil.com",
            "attacker.net/steal",
            "malicious.site:8080",
        ]
        
        for url in malicious_urls:
            assert not domain_allowed(url), f"Should block {url}"
    
    def test_legitimate_external_domains_blocked(self):
        """Test that even legitimate external domains are blocked."""
        external_urls = [
            "http://google.com",
            "https://github.com",
            "http://stackoverflow.com/questions",
            "https://docs.python.org",
            "http://www.microsoft.com",
            "https://openai.com",
            "google.com",
            "github.com/user/repo",
        ]
        
        for url in external_urls:
            assert not domain_allowed(url), f"Should block external domain {url}"
    
    def test_localhost_lookalikes_blocked(self):
        """Test that localhost lookalikes are blocked."""
        lookalike_urls = [
            "http://localhost.evil.com",
            "https://fake-localhost.com", 
            "http://localhost-phish.net",
            "https://127-0-0-1.malicious.com",
            "localhost.evil.com",
            "fake-localhost.com/trap",
        ]
        
        for url in lookalike_urls:
            assert not domain_allowed(url), f"Should block lookalike {url}"
    
    def test_edge_cases(self):
        """Test edge cases and malformed inputs."""
        edge_cases = [
            "",  # Empty string
            None,  # None value
            "not-a-url",  # Not a URL
            "://missing-protocol",  # Malformed
            "http://",  # Incomplete
            "https://",  # Incomplete
            "localhost:",  # Incomplete port
            "127.0.0.1:",  # Incomplete port
        ]
        
        for case in edge_cases:
            assert not domain_allowed(case), f"Should reject edge case: {case}"
    
    def test_protocol_independence(self):
        """Test that allowlist works regardless of protocol."""
        protocols = ["http", "https", "ftp", "ws", "wss"]
        
        for protocol in protocols:
            url = f"{protocol}://localhost/test"
            assert domain_allowed(url), f"Should allow {protocol} protocol"
            
            url = f"{protocol}://evil.com/test"
            assert not domain_allowed(url), f"Should block {protocol} protocol to external domain"
    
    def test_port_variations(self):
        """Test that various ports are handled correctly."""
        ports = [80, 443, 3000, 8080, 8000, 5000, 9000]
        
        for port in ports:
            localhost_url = f"http://localhost:{port}/test"
            assert domain_allowed(localhost_url), f"Should allow localhost:{port}"
            
            loopback_url = f"http://127.0.0.1:{port}/test"
            assert domain_allowed(loopback_url), f"Should allow 127.0.0.1:{port}"
            
            external_url = f"http://evil.com:{port}/test"
            assert not domain_allowed(external_url), f"Should block evil.com:{port}"
    
    def test_path_independence(self):
        """Test that allowlist works regardless of URL path."""
        paths = [
            "/",
            "/index.html",
            "/api/v1/users",
            "/deep/nested/path/file.php",
            "/path/with/query?param=value",
            "/path#fragment",
            "/path?param=value#fragment"
        ]
        
        for path in paths:
            localhost_url = f"http://localhost{path}"
            assert domain_allowed(localhost_url), f"Should allow localhost with path {path}"
            
            external_url = f"http://evil.com{path}"
            assert not domain_allowed(external_url), f"Should block evil.com with path {path}"
    
    def test_case_sensitivity(self):
        """Test case sensitivity in domain matching."""
        case_variations = [
            "http://LOCALHOST/test",
            "http://LocalHost/test",
            "http://127.0.0.1/TEST",
            "LOCALHOST",
            "LocalHost/page"
        ]
        
        # Note: This depends on how tldextract handles case.
        # Most implementations are case-insensitive for domains.
        for url in case_variations:
            # Should be allowed regardless of case
            result = domain_allowed(url)
            # Domain names are case-insensitive, so these should be allowed
            assert result, f"Should allow case variation: {url}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
