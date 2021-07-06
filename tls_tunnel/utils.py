from base64 import b64encode

from tls_tunnel.dto import ProxyOptions


def generate_basic_header(login: str, password: str):
    auth_string = f"{login}:{password}".encode("utf-8")
    auth_token = b64encode(auth_string).decode("ascii")
    return f"Basic {auth_token}"


def generate_proxy_url(proxy: ProxyOptions):
    if proxy:
        proxy_host_port: str = f"{proxy.host}:{proxy.port}"

        if proxy.auth_login and proxy.auth_password:
            return (
                f"{proxy.auth_login}:"
                f"{proxy.auth_password}@"
                f"{proxy_host_port}"
            )
        else:
            return proxy_host_port
    return None
