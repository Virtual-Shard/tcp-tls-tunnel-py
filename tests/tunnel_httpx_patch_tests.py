import subprocess
import sys

import pkg_resources
if pkg_resources.get_distribution("h2").version < '4':
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--upgrade", 'h2'])

import unittest
from http.client import OK, NOT_FOUND
from typing import List

import jsondiff
from httpx import Client, Response

from tests.test_settings import TEST_TUNNEL_HOST
from tests.test_utils import get_test_tunnel_options
from tests.validation_data import HOWSMYSSL_VALIDATION_RESPONSE
from tls_tunnel.httpx_adapter import TunnelHTTPTransport


class TestTunnelHttpxHttp20Request(unittest.TestCase):
    def setUp(self) -> None:
        self.transport = TunnelHTTPTransport(
            adapter_opts=get_test_tunnel_options()
        )

    def test_tunnel_ip_request(self):
        with Client(transport=self.transport) as client:
            response: Response = client.get("https://api.myip.com/")
            self.assertEqual(response.status_code, OK)

            response_json: dict = response.json()
            self.assertEqual(response_json.get("ip"), TEST_TUNNEL_HOST)

    def test_tunnel_ssl_request(self):
        with Client(transport=self.transport) as client:
            response: Response = client.get('https://www.howsmyssl.com/a/check')
            response_json: dict = response.json()

            diff: dict = jsondiff.diff(HOWSMYSSL_VALIDATION_RESPONSE, response_json)
            given_cipher_suites: List[str] = diff["given_cipher_suites"]

            self.assertEqual(len(given_cipher_suites[jsondiff.symbols.insert]), 1,
                             msg="[given_cipher_suites] TLS_GREASE_IS INSERT parameter check failed.")
            self.assertEqual(len(given_cipher_suites[jsondiff.symbols.delete]), 1,
                             msg="[given_cipher_suites] TLS_GREASE_IS DELETE parameter check failed.")

    def test_several_tunnel_requests(self):
        with Client(transport=self.transport) as client:
            for url in ["https://www.howsmyssl.com/",
                        "https://www.howsmyssl.com/s/api.html",
                        "https://www.howsmyssl.com/s/about.html"]:
                response: Response = client.get(url)
                self.assertEqual(response.status_code, OK)

            failed_response: Response = client.get("https://www.howsmyssl.com/s/api")
            self.assertEqual(failed_response.status_code, NOT_FOUND)

    def test_http2_tunnel_request(self):
        with Client(transport=self.transport) as client:
            response: Response = client.get("https://http2.pro/api/v1")
            response_json: dict = response.json()

            self.assertEqual(response_json.get("http2"), 1)
            self.assertEqual(response_json.get("protocol"), 'HTTP/2.0')

    def test_http_without_tls_tunnel_request(self):
        with Client(transport=self.transport) as client:
            response: Response = client.get("http://httpbin.org/get")
            response_json: dict = response.json()

            self.assertEqual(response.status_code, OK)
            self.assertEqual(response_json.get("origin"), TEST_TUNNEL_HOST)