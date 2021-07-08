from typing import Optional, Union

import urllib3
from hyper.contrib import HTTP20Adapter
from requests import Session
from requests.adapters import BaseAdapter

from tests import test_settings
from tls_tunnel.dto import TunnelOptions, ProxyOptions


def get_test_tunnel_options(secure: bool = True, http2: bool = False) -> TunnelOptions:
    return TunnelOptions(
        host=test_settings.TEST_TUNNEL_HOST,
        port=test_settings.TEST_TUNNEL_PORT,
        auth_login=test_settings.TEST_TUNNEL_LOGIN,
        auth_password=test_settings.TEST_TUNNEL_PASSWORD,
        secure=secure,
        http2=http2,
    )


def get_test_proxy_options() -> ProxyOptions:
    return ProxyOptions(
        host=test_settings.TEST_PROXY_HOST,
        port=test_settings.TEST_PROXY_PORT,
        auth_login=test_settings.TEST_PROXY_LOGIN,
        auth_password=test_settings.TEST_PROXY_PASSWORD,
    )


def get_test_requests_session(adapter: Union[BaseAdapter, HTTP20Adapter] = None) -> Session:
    headers = urllib3.make_headers(
        keep_alive=True,
        disable_cache=True,
        accept_encoding=True,
        user_agent=test_settings.USER_AGENT
    )

    session = Session()
    session.headers.update(headers)

    if adapter:
        # Connect adapter for requests.Session instance
        session.mount("http://", adapter=adapter)
        session.mount("https://", adapter=adapter)

    return session
