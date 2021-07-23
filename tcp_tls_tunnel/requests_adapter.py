from urllib.parse import urlparse

import requests

import requests.cookies
import requests.utils
from requests.structures import CaseInsensitiveDict
from requests.adapters import BaseAdapter

from tcp_tls_tunnel.dto import AdapterOptions, TunnelOptions, ProxyOptions
from tcp_tls_tunnel.create_tunnel_connection import create_tunnel_connection


class TunneledHTTPAdapter(BaseAdapter):

    def __init__(self,
                 adapter_opts: AdapterOptions,
                 proxy_opts: ProxyOptions = None):
        super(BaseAdapter, self).__init__()
        self.adapter_opts = adapter_opts
        self.proxy = proxy_opts

    def close(self):
        pass

    def send(self, request, **kwargs):
        parsed_url = urlparse(request.url)
        secure = False

        if parsed_url.port:
            destination_port = parsed_url.port
        elif parsed_url.scheme == 'https':
            secure = True
            destination_port = 443
        elif parsed_url.scheme == 'http':
            destination_port = 80
        else:
            raise ValueError("Unexpected url protocol. You can specify port in the url.")

        connection, proto = create_tunnel_connection(
            tunnel_opts=TunnelOptions(
                host=self.adapter_opts.host,
                port=self.adapter_opts.port,
                auth_login=self.adapter_opts.auth_login,
                auth_password=self.adapter_opts.auth_password,
                client=self.adapter_opts.client,
                secure=secure,
                http2=False
            ),
            dest_host=parsed_url.hostname,
            dest_port=destination_port,
            server_name=None,  # TODO: server_name
            proxy=self.proxy
        )

        try:
            connection.request(method=request.method,
                               url=request.url,
                               body=request.body,
                               headers=request.headers)
            r = connection.getresponse()
            # Response preparation process
            response = requests.Response()
            response.status_code = r.status
            response.headers = CaseInsensitiveDict(r.headers)
            response.raw = r
            response.reason = r.reason
            response.url = request.url
            response.request = request
            response.connection = connection

            # Added content to response
            # (under the hood it will set r.text and allow r.json() operation)
            response._content = r.read()
            response.encoding = requests.utils.get_encoding_from_headers(
                response.headers
            )
            requests.cookies.extract_cookies_to_jar(
                response.cookies,
                request,
                r
            )
        finally:
            connection.close()

        return response
