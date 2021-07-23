from typing import Tuple
import http
import socket
from http import client
from tcp_tls_tunnel.utils import generate_basic_header, generate_proxy_url

from tcp_tls_tunnel.dto import TunnelOptions, ProxyOptions


class TunnelHTTPConnection(client.HTTPConnection):
    def __init__(self,
                 host,
                 port=None,
                 timeout=socket._GLOBAL_DEFAULT_TIMEOUT,
                 source_address=None,
                 blocksize=8192):
        super(TunnelHTTPConnection, self).__init__(
            host=host,
            port=port,
            timeout=timeout,
            source_address=source_address,
            blocksize=blocksize
        )
        self.tunnel_response_headers = {}

    def _tunnel(self):
        self.tunnel_response_headers.clear()
        connect_str = "CONNECT %s:%d HTTP/1.0\r\n" % (self._tunnel_host, self._tunnel_port)
        connect_bytes = connect_str.encode("ascii")
        self.send(connect_bytes)
        for header, value in self._tunnel_headers.items():
            header_str = "%s: %s\r\n" % (header, value)
            header_bytes = header_str.encode("latin-1")
            self.send(header_bytes)
        self.send(b'\r\n')

        response = self.response_class(self.sock, method=self._method)
        (version, code, message) = response._read_status()

        if code != http.HTTPStatus.OK:
            self.close()
            raise OSError("Tunnel connection failed: %d %s" % (code, message.strip()))

        self.tunnel_response_headers = client.parse_headers(response.fp)


def create_tunnel_connection(tunnel_opts: TunnelOptions,
                             dest_host: str,
                             dest_port: int,
                             server_name: str = None,
                             proxy: ProxyOptions = None) -> Tuple[TunnelHTTPConnection, str]:

    conn = TunnelHTTPConnection(tunnel_opts.host, tunnel_opts.port)
    headers = {
        "Authorization": generate_basic_header(tunnel_opts.auth_login, tunnel_opts.auth_password),
        "Client": tunnel_opts.client.value,
        "Connection": 'keep-alive',
        "Server-Name": server_name or dest_host,
        "Host": tunnel_opts.host,
        "Secure": str(int(tunnel_opts.secure)),
        "HTTP2": str(int(tunnel_opts.http2)),
    }

    if proxy:
        headers["Proxy"] = generate_proxy_url(proxy=proxy)

    conn.set_tunnel(dest_host, port=dest_port, headers=headers)
    conn.connect()

    try:
        proto = conn.tunnel_response_headers.get("Alpn-Protocol")
    except TypeError:
        proto = 'http/1.1'

    return conn, proto
