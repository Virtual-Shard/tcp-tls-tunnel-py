import ssl
import socket
from typing import Tuple
from hyper.common.util import to_native_string

from urllib.parse import urlparse
from hyper import HTTP11Connection, HTTPConnection
from hyper.common.bufsocket import BufferedSocket
from hyper.common.exceptions import TLSUpgrade
from hyper.contrib import HTTP20Adapter
from hyper.tls import init_context

from tcp_tls_tunnel.utils import generate_basic_header, generate_proxy_url
from tcp_tls_tunnel.dto import ProxyOptions, AdapterOptions, TunnelOptions
from tcp_tls_tunnel.exceptions import ProxyError


def _create_tunnel(tunnel_opts: TunnelOptions,
                   dest_host: str,
                   dest_port: int,
                   server_name: str = None,
                   proxy: ProxyOptions = None,
                   timeout: int = None) -> Tuple[socket.socket, str]:
    """
    Sends CONNECT method to a proxy and returns a socket with established
    connection to the target.
    :returns: socket, proto
    """

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

    conn = HTTP11Connection(tunnel_opts.host, tunnel_opts.port, timeout=timeout)
    conn.request('CONNECT', '%s:%d' % (dest_host, dest_port),
                 headers=headers)

    resp = conn.get_response()

    try:
        proto = resp.headers.get("Alpn-Protocol")[0].decode('utf-8')
    except TypeError:
        proto = 'http/1.1'

    if resp.status != 200:
        raise ProxyError(
            "Tunnel connection failed: %d %s" %
            (resp.status, to_native_string(resp.reason)),
            response=resp
        )

    return getattr(conn, "_sock"), proto


class TunnelHTTP20Adapter(HTTP20Adapter):
    def __init__(self,
                 adapter_opts: AdapterOptions,
                 proxy_opts: ProxyOptions = None,
                 window_manager=None,
                 *args, **kwargs):
        super(TunnelHTTP20Adapter, self).__init__(window_manager=window_manager, *args, **kwargs)
        self.adapter_opts = adapter_opts
        self.proxy_opts = proxy_opts

    def get_connection(self, host, port, scheme, cert=None, verify=True,
                       proxy=None, timeout=None):

        """
        Gets an appropriate HTTP/2 connection object based on
        host/port/scheme/cert tuples.
        """
        secure = (scheme == 'https')

        if port is None:  # pragma: no cover
            port = 80 if not secure else 443

        ssl_context = None
        if not verify:
            verify = False
            ssl_context = init_context(cert=cert)
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        elif verify is True and cert is not None:
            ssl_context = init_context(cert=cert)
        elif verify is not True:
            ssl_context = init_context(cert_path=verify, cert=cert)

        if proxy:
            proxy_headers = self.proxy_headers(proxy)
            proxy_netloc = urlparse(proxy).netloc
        else:
            proxy_headers = None
            proxy_netloc = None

        # We put proxy headers in the connection_key, because
        # ``proxy_headers`` method might be overridden, so we can't
        # rely on proxy headers being the same for the same proxies.
        proxy_headers_key = (frozenset(proxy_headers.items())
                             if proxy_headers else None)
        connection_key = (host, port, scheme, cert, verify,
                          proxy_netloc, proxy_headers_key)
        try:
            conn = self.connections[connection_key]
        except KeyError:
            conn = TunnelHTTPConnection(
                self.adapter_opts,
                self.proxy_opts,
                host=host,
                port=port,
                secure=secure,
                ssl_context=ssl_context,
                proxy_host=proxy_netloc,
                proxy_headers=proxy_headers,
                timeout=timeout,
            )
            self.connections[connection_key] = conn
        return conn


class TunnelHTTPConnection(HTTPConnection):
    def __init__(self,
                 adapter_opts: AdapterOptions,
                 proxy_opts: ProxyOptions = None,
                 host=None,
                 port=None,
                 secure=None,
                 enable_push=False,
                 ssl_context=None,
                 proxy_host=None,
                 proxy_port=None,
                 proxy_headers=None,
                 timeout=None,
                 **kwargs):
        super().__init__(host=host,
                         port=port,
                         secure=secure,
                         enable_push=enable_push,
                         ssl_context=ssl_context,
                         proxy_host=proxy_host,
                         proxy_port=proxy_port,
                         proxy_headers=proxy_headers,
                         timeout=timeout,
                         **kwargs)

        self._conn = TunnelHTTP11Connection(
            tunnel_opts=TunnelOptions(
                host=adapter_opts.host,
                port=adapter_opts.port,
                auth_login=adapter_opts.auth_login,
                auth_password=adapter_opts.auth_password,
                client=adapter_opts.client,
                secure=secure,
                http2=True
            ),
            proxy_opts=proxy_opts,
            host=self._host,
            port=self._port,
            **self._h1_kwargs
        )

    def __exit__(self, type, value, tb):  # pragma: no cover
        self._conn.close()
        return False


class TunnelHTTP11Connection(HTTP11Connection):
    def __init__(self,
                 tunnel_opts: TunnelOptions,
                 proxy_opts: ProxyOptions = None,
                 host=None, port=None, secure=None, ssl_context=None,
                 proxy_host=None, proxy_port=None, proxy_headers=None,
                 timeout=None,
                 **kwargs):
        super(TunnelHTTP11Connection, self).__init__(host=host, port=port,
                                                     secure=secure, ssl_context=ssl_context,
                                                     proxy_host=proxy_host, proxy_port=proxy_port,
                                                     proxy_headers=proxy_headers, timeout=timeout,
                                                     **kwargs)
        self.tunnel_opts = tunnel_opts
        self.proxy_opts = proxy_opts
        self.timeout = timeout

    def connect(self):
        """
        Connect to the server specified when the object was created. This is a
        no-op if we're already connected.
        :returns: Nothing.
        """

        if self._sock is None:

            # Tunnel socket creation with tunnel's TLS proto
            sock, proto = _create_tunnel(
                tunnel_opts=self.tunnel_opts,
                proxy=self.proxy_opts,
                dest_host=self.host,
                dest_port=self.port,
                server_name=None,  # TODO: server_name
                timeout=self.timeout
            )

            sock = BufferedSocket(sock, self.network_buffer_size)
            sock.settimeout(self.timeout)  # Set read timeout

            if self.secure is not True:
                proto = 'http/1.1'

            if proto not in ('http/1.1', None):
                raise TLSUpgrade(proto, sock)

            self._sock = sock
        return
