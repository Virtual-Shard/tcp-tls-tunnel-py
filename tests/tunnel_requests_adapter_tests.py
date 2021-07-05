from http.client import OK, NOT_FOUND
from typing import List

import jsondiff
import requests
import unittest

import urllib3
from requests import Response

from tests import test_settings
from tls_tunnel.adapter import TunneledHTTPAdapter
from tls_tunnel.dto import TunnelOptions, ProxyOptions


class TestTunnelRequestWithProxy(unittest.TestCase):

    def setUp(self) -> None:
        self.adapter = TunneledHTTPAdapter(
            tunnel_opts=TunnelOptions(
                host=test_settings.TEST_TUNNEL_HOST,
                port=test_settings.TEST_TUNNEL_PORT,
                auth_login=test_settings.TEST_TUNNEL_LOGIN,
                auth_password=test_settings.TEST_TUNNEL_PASSWORD,
                secure=True,
            ),
            proxy_opts=ProxyOptions(
                host=test_settings.TEST_PROXY_HOST,
                port=test_settings.TEST_PROXY_PORT,
                auth_login=test_settings.TEST_PROXY_LOGIN,
                auth_password=test_settings.TEST_PROXY_PASSWORD,
            )
        )
        self.session = requests.Session()
        self.session.headers.update(urllib3.make_headers(
            keep_alive=True,
            disable_cache=True,
            accept_encoding=True,
            user_agent=test_settings.USER_AGENT
        ))

        # connect adapter for requests.Session instance
        self.session.mount("http://", self.adapter)
        self.session.mount("https://", self.adapter)

    def test_tunnel_request_with_proxy(self):
        pass
        # response: Response = self.session.get("https://www.google.com/")
        # self.assertEqual(response.status_code, OK)

    def test_several_requests_with_proxy_sequentially(self):
        pass


class TestHowsMySSLRequest(unittest.TestCase):

    def setUp(self) -> None:
        self.adapter = TunneledHTTPAdapter(
            tunnel_opts=TunnelOptions(
                host=test_settings.TEST_TUNNEL_HOST,
                port=test_settings.TEST_TUNNEL_PORT,
                auth_login=test_settings.TEST_TUNNEL_LOGIN,
                auth_password=test_settings.TEST_TUNNEL_PASSWORD,
                secure=True,
            )
        )
        self.session = requests.Session()
        self.session.headers.update(urllib3.make_headers(
            keep_alive=True,
            disable_cache=True,
            accept_encoding=True,
            user_agent=test_settings.USER_AGENT
        ))

        # connect adapter for requests.Session instance
        self.session.mount("http://", self.adapter)
        self.session.mount("https://", self.adapter)

    def test_tunnel_request(self):
        response_json: dict = self.session.get('https://www.howsmyssl.com/a/check').json()
        validation_json: dict = {
            'given_cipher_suites': [
                'TLS_GREASE_IS_THE_WORD_AA',
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
                'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                'TLS_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_RSA_WITH_AES_128_CBC_SHA',
                'TLS_RSA_WITH_AES_256_CBC_SHA'
            ],
            'ephemeral_keys_supported': True,
            'session_ticket_supported': True,
            'tls_compression_supported': False,
            'unknown_cipher_suite_supported': False,
            'beast_vuln': False,
            'able_to_detect_n_minus_one_splitting': False,
            'insecure_cipher_suites': {},
            'tls_version': 'TLS 1.3',
            'rating': 'Probably Okay'}

        diff: dict = jsondiff.diff(validation_json, response_json)
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


if __name__ == '__main__':
    unittest.main()

