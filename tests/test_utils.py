from tests import test_settings
from tcp_tls_tunnel.dto import AdapterOptions, ProxyOptions


def get_test_adapter_options() -> AdapterOptions:
    return AdapterOptions(
        host=test_settings.TEST_TUNNEL_HOST,
        port=test_settings.TEST_TUNNEL_PORT,
        auth_login=test_settings.TEST_TUNNEL_LOGIN,
        auth_password=test_settings.TEST_TUNNEL_PASSWORD,
    )


def get_test_proxy_options() -> ProxyOptions:
    return ProxyOptions(
        host=test_settings.TEST_PROXY_HOST,
        port=test_settings.TEST_PROXY_PORT,
        auth_login=test_settings.TEST_PROXY_LOGIN,
        auth_password=test_settings.TEST_PROXY_PASSWORD,
    )