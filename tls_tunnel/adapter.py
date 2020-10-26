from urllib.parse import urlparse

import requests

import requests.cookies
import requests.utils
from http.client import HTTPConnection
from requests.structures import CaseInsensitiveDict
from requests.adapters import BaseAdapter

from tls_tunnel.dto import TunnelOptions, ProxyOptions
from tls_tunnel.utils import generate_basic_header, generate_proxy_url


def create_tunnel_connection(tunnel_opts: TunnelOptions,
                             dest_host: str,
                             dest_port: int,
                             proxy: ProxyOptions = None):
    conn = HTTPConnection(tunnel_opts.host, tunnel_opts.port)
    headers = {
        "Authorization": generate_basic_header(tunnel_opts.auth_login,
                                               tunnel_opts.auth_password),
        "Client": tunnel_opts.client,
        "Connection": 'keep-alive',
        "Server-Name": tunnel_opts.server_name or dest_host,
        "Host": tunnel_opts.host,
        "Secure": str(int(tunnel_opts.secure)),
        "HTTP2": str(int(tunnel_opts.http2)),
    }

    if proxy:
        headers["Proxy"] = generate_proxy_url(proxy=proxy)

    conn.set_tunnel(dest_host, port=dest_port, headers=headers)
    conn.connect()
    return conn


class TunneledHTTPAdapter(BaseAdapter):

    def __init__(self,
                 tunnel_opts: TunnelOptions,
                 dest_host: str,
                 dest_port: int,
                 proxy_options: ProxyOptions = None):
        super(BaseAdapter, self).__init__()
        self.tunnel_opts = tunnel_opts
        self.dest_host = dest_host
        self.dest_port = dest_port
        self.proxy = proxy_options

    def close(self):
        pass

    def send(self, request, **kwargs):
        parsed_url = urlparse(request.url)

        if parsed_url.port:
            destination_port = parsed_url.port
        else:
            destination_port = 443 if self.tunnel_opts.secure else 80

        connection = create_tunnel_connection(
            tunnel_opts=self.tunnel_opts,
            dest_host=parsed_url.hostname,
            dest_port=destination_port,
            proxy=self.proxy
        )

        try:
            connection.request(method=request.method,
                               url=request.url,
                               body=request.body,
                               headers=request.headers)
            r = connection.getresponse()
            response = requests.Response()
            response.status_code = r.status
            response.headers = CaseInsensitiveDict(r.headers)
            response.raw = r
            response.reason = r.reason
            response.url = request.url
            response.request = request
            response.connection = connection
            response.encoding = requests.utils.get_encoding_from_headers(response.headers)
            requests.cookies.extract_cookies_to_jar(response.cookies, request, r)
        finally:
            connection.close()

        return response
