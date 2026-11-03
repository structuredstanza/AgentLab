#!/usr/bin/env python3
"""Offline unit tests for benchmark runner authentication and token resolution.

Run: python3 -m unittest test_run_bench -v
"""
from __future__ import annotations

import http.server
import json
import os
import threading
import unittest
import urllib.error

import run_bench


class MockAuthHandler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == "/api/auth/login":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if body.get("username") == "ARTEX" and body.get("password") == "correct-pass-8+":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"token": "mock-derived-jwt-token"}).encode("utf-8"))
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "invalid credentials"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        pass


class BenchmarkAuthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), MockAuthHandler)
        cls.port = cls.server.server_port
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def setUp(self):
        self._env_backup = dict(os.environ)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._env_backup)

    def test_explicit_token_used_directly(self):
        token = run_bench.resolve_token(token="explicit-valid-token", password="", artex_url=self.url)
        self.assertEqual(token, "explicit-valid-token")

    def test_login_success_with_password(self):
        token = run_bench.resolve_token(token="", password="correct-pass-8+", artex_url=self.url, username="ARTEX")
        self.assertEqual(token, "mock-derived-jwt-token")

    def test_login_failure_raises_system_exit(self):
        with self.assertRaises(SystemExit) as ctx:
            run_bench.resolve_token(token="", password="wrong-password", artex_url=self.url, username="ARTEX")
        self.assertIn("ARTEX login failed: HTTP 401", str(ctx.exception))

    def test_obsolete_jwt_key_raises_informative_exit(self):
        os.environ["ARTEX_JWT_KEY"] = "/some/path/jwt.key"
        with self.assertRaises(SystemExit) as ctx:
            run_bench.resolve_token(token="", password="", artex_url=self.url)
        self.assertIn("ARTEX_JWT_KEY is obsolete", str(ctx.exception))
        self.assertIn("password hash", str(ctx.exception))

    def test_missing_credentials_raises_system_exit(self):
        os.environ.pop("ARTEX_JWT_KEY", None)
        with self.assertRaises(SystemExit) as ctx:
            run_bench.resolve_token(token="", password="", artex_url=self.url)
        self.assertIn("need ARTEX_TOKEN or ARTEX_PASSWORD", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
