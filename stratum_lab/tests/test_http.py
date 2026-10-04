"""Protokolltests mit echten Loopback-Sockets und synthetischen Requests."""
import importlib.util
from pathlib import Path
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("runner", Path(__file__).parents[1] / "runner.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)


def request():
    return dict(direction="incoming", url="http://suspicious.invalid/beacon?id=fixture", method="POST", headers=[["X-Fixture", "example"]], body="Grüße", simulated_status=200, simulated_body="<script>fixture only</script>", hypothesis="Synthetischer Beacon", source=None)


class ReplayTests(unittest.TestCase):
    def test_isolation_missing_fails_closed(self):
        with patch.object(runner.os, "listdir", return_value=["lo", "eth0"]):
            with self.assertRaises(ValueError):
                runner.main()

    def test_wire_and_no_external_dns(self):
        p = request()
        r = runner.replay(p)
        self.assertEqual(r["status"], 200)
        self.assertEqual(r["peer_ip"], "127.0.0.1")
        self.assertIn("POST /beacon?id=fixture HTTP/1.1\r\nHost: suspicious.invalid\r\n", r["request_wire"])
        self.assertIn("Content-Length: 7\r\n", r["request_wire"])
        self.assertTrue(r["request_wire"].endswith("Grüße"))
        self.assertTrue(r["response_wire"].endswith(p["simulated_body"]))
        self.assertEqual(r["redirects_followed"], 0)

    def test_methods_empty_response_and_https_semantics(self):
        for method in runner.METHODS:
            p = request()
            p["method"] = method
            p["url"] = "https://suspicious.invalid:8443/beacon"
            r = runner.replay(p)
            self.assertFalse(r["tls_replayed"])
            if method == "HEAD":
                self.assertTrue(r["response_wire"].endswith("\r\n\r\n"))
        for status in (204, 304):
            p = request()
            p["simulated_status"] = status
            r = runner.replay(p)
            self.assertTrue(r["response_wire"].endswith("\r\n\r\n"))
            self.assertNotIn("Content-Length", r["response_wire"])

    def test_reject_transport_and_credentials(self):
        for name in ("Host", "Cookie", "Authorization", "Transfer-Encoding", "x\r\ninjection"):
            p = request()
            p["headers"] = [[name, "fixture"]]
            with self.assertRaises(ValueError):
                runner.replay(p)
        p = request()
        p["method"] = "CONNECT"
        with self.assertRaises(ValueError):
            runner.replay(p)


if __name__ == "__main__":
    unittest.main()
