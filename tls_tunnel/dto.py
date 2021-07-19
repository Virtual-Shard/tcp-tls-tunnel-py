from dataclasses import dataclass
from tls_tunnel.constants import Client


@dataclass
class AdapterOptions:
    host: str
    port: int

    # auth options
    auth_login: str = None
    auth_password: str = None

    # headers options
    client: Client = Client.CHROME


@dataclass
class TunnelOptions(AdapterOptions):
    secure: bool = False
    http2: bool = False


@dataclass
class ProxyOptions:
    host: str
    port: int

    # auth_options
    auth_login: str = None
    auth_password: str = None
