from http.client import OK, NOT_FOUND
from typing import List

import jsondiff
import unittest

from requests import Response

from tests.test_settings import TEST_TUNNEL_HOST
from tests.test_utils import (
    get_test_tunnel_options,
    get_test_proxy_options,
    get_test_requests_session
)
from tests.validation_data import HOWSMYSSL_VALIDATION_RESPONSE
from tls_tunnel.requests_adapter import TunneledHTTPAdapter


class TestTunnelRequestWithProxy(unittest.TestCase):

    def setUp(self) -> None:
        self.adapter = TunneledHTTPAdapter(
            tunnel_opts=get_test_tunnel_options(),
            proxy_opts=get_test_proxy_options()
        )
        self.session = get_test_requests_session(adapter=self.adapter)

    def test_tunnel_request_with_proxy(self):
        pass
        # response: Response = self.session.get("https://www.google.com/")
        # self.assertEqual(response.status_code, OK)

    def test_several_requests_with_proxy_sequentially(self):
        pass


class TestHTTP11HowsMySSLRequest(unittest.TestCase):

    def setUp(self) -> None:
        self.adapter = TunneledHTTPAdapter(
            tunnel_opts=get_test_tunnel_options()
        )
        self.session = get_test_requests_session(adapter=self.adapter)

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

    def test_http_without_tls_tunnel_request(self):
        response: Response = self.session.get("http://httpbin.org/get")

        response_json: dict = response.json()

        self.assertEqual(response.status_code, OK)
        self.assertEqual(response_json.get("origin"), TEST_TUNNEL_HOST)


if __name__ == '__main__':
    unittest.main()

