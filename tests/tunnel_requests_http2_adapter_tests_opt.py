import subprocess
import sys

import pkg_resources
if pkg_resources.get_distribution("h2").version != '2.6.2':
    subprocess.check_call([sys.executable, "-m", "pip", "install", 'h2==2.6.2'])


import unittest
from http.client import OK, NOT_FOUND
from typing import List

import jsondiff
from requests import Response

from tests.test_settings import TEST_TUNNEL_HOST
from tests.test_utils import get_test_tunnel_options, get_test_requests_session
from tests.validation_data import HOWSMYSSL_VALIDATION_RESPONSE
from tls_tunnel.hyper_http2_adapter import TunnelHTTP20Adapter


class TestHTTP20Requests(unittest.TestCase):

    def setUp(self) -> None:
        self.adapter = TunnelHTTP20Adapter(
            adapter_opts=get_test_tunnel_options(secure=True, http2=True)
        )
        self.session = get_test_requests_session(adapter=self.adapter)

    def test_tunnel_ip_request(self):
        response: Response = self.session.get("https://api.myip.com/")
        self.assertEqual(response.status_code, OK)

        response_json: dict = response.json()
        self.assertEqual(response_json.get("ip"), TEST_TUNNEL_HOST)

    def test_http_without_tls_tunnel_request(self):
        response: Response = self.session.get("http://httpbin.org/get")

        response_json: dict = response.json()

        self.assertEqual(response.status_code, OK)
        self.assertEqual(response_json.get("origin"), TEST_TUNNEL_HOST)

    def test_tunnel_request(self):
        response_json: dict = self.session.get('https://www.howsmyssl.com/a/check').json()

        diff: dict = jsondiff.diff(HOWSMYSSL_VALIDATION_RESPONSE, response_json)
        given_cipher_suites: List[str] = diff["given_cipher_suites"]

        self.assertEqual(len(given_cipher_suites[jsondiff.symbols.insert]), 1,
                         msg="[given_cipher_suites] TLS_GREASE_IS INSERT parameter check failed.")
        self.assertEqual(len(given_cipher_suites[jsondiff.symbols.delete]), 1,
                         msg="[given_cipher_suites] TLS_GREASE_IS DELETE parameter check failed.")

    def test_several_tunnel_requests(self):
        for url in ["https://www.howsmyssl.com/",
                    "https://www.howsmyssl.com/s/api.html",
                    "https://www.howsmyssl.com/s/about.html"]:
            response: Response = self.session.get(url)
            self.assertEqual(response.status_code, OK)

        failed_response: Response = self.session.get("https://www.howsmyssl.com/s/api")
        self.assertEqual(failed_response.status_code, NOT_FOUND)
