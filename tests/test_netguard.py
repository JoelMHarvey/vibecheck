"""Tests for the SSRF guard protecting the hosted URL scanner.

DNS resolution is stubbed so these run offline and can't be affected by
whatever the real DNS says today.
"""

import unittest

from vibecheck.netguard import check_url


def resolver_for(mapping):
    def resolve(host):
        if host in mapping:
            return mapping[host]
        raise OSError("NXDOMAIN")
    return resolve


PUBLIC = resolver_for({"example.com": ["93.184.216.34"]})


class NetGuardTest(unittest.TestCase):
    def assertRejected(self, url, resolver=PUBLIC):
        ok, reason = check_url(url, resolver=resolver)
        self.assertFalse(ok, f"expected {url} to be rejected")
        self.assertTrue(reason)

    def test_public_https_allowed(self):
        ok, reason = check_url("https://example.com/", resolver=PUBLIC)
        self.assertTrue(ok, reason)

    def test_localhost_blocked(self):
        self.assertRejected("http://localhost:3000/")
        self.assertRejected("http://127.0.0.1/")
        self.assertRejected("http://[::1]/")

    def test_private_ranges_blocked(self):
        for host in ("10.0.0.5", "192.168.1.1", "172.16.4.4"):
            self.assertRejected(f"http://{host}/")

    def test_cloud_metadata_blocked(self):
        # The classic SSRF target: AWS/GCP instance metadata.
        self.assertRejected("http://169.254.169.254/latest/meta-data/")
        self.assertRejected("http://metadata.google.internal/")

    def test_hostname_resolving_to_private_ip_blocked(self):
        # DNS entry that points at a private address (a real SSRF technique).
        sneaky = resolver_for({"evil.example": ["127.0.0.1"]})
        self.assertRejected("http://evil.example/", resolver=sneaky)

    def test_hostname_with_any_private_address_blocked(self):
        # Resolves to one public AND one private address — must still reject.
        mixed = resolver_for({"mixed.example": ["93.184.216.34", "10.1.2.3"]})
        self.assertRejected("http://mixed.example/", resolver=mixed)

    def test_non_http_schemes_blocked(self):
        self.assertRejected("file:///etc/passwd")
        self.assertRejected("gopher://example.com/")
        self.assertRejected("ftp://example.com/")

    def test_unusual_port_blocked(self):
        self.assertRejected("http://example.com:22/")
        self.assertRejected("http://example.com:6379/")

    def test_standard_alt_ports_allowed(self):
        ok, reason = check_url("https://example.com:8443/", resolver=PUBLIC)
        self.assertTrue(ok, reason)

    def test_unresolvable_host_rejected(self):
        self.assertRejected("https://nope.invalid/")

    def test_missing_hostname_rejected(self):
        self.assertRejected("https:///path")


if __name__ == "__main__":
    unittest.main()
