import unittest
from mirage.scope import Scope, ScopeError

class ScopeTests(unittest.TestCase):
    def test_domain_includes_subdomains(self):
        s=Scope("example.com")
        self.assertTrue(s.allows_host("example.com"))
        self.assertTrue(s.allows_host("api.dev.example.com"))
        self.assertFalse(s.allows_host("notexample.com"))
    def test_url_and_path(self):
        s=Scope("https://example.com/login")
        self.assertTrue(s.allows_url("https://example.com/admin"))
        self.assertFalse(s.allows_url("https://evil.test/"))
        self.assertEqual(s.urls,["https://example.com/login"])
    def test_cidr(self):
        s=Scope("192.0.2.0/24")
        self.assertTrue(s.allows_host("192.0.2.10"))
        self.assertFalse(s.allows_host("192.0.3.10"))
    def test_ipv6_target(self):
        s=Scope("2001:db8::1")
        self.assertTrue(s.allows_host("2001:db8::1"))
        self.assertFalse(s.allows_host("2001:db8::2"))
    def test_invalid(self):
        with self.assertRaises(ScopeError): Scope("https://")
        with self.assertRaises(ScopeError): Scope("")

if __name__=="__main__": unittest.main()
