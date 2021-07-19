import socket
import ssl
from typing import Tuple

from urllib.parse import urlparse
from hyper import HTTP11Connection, HTTPConnection
from hyper.common.bufsocket import BufferedSocket
from hyper.common.exceptions import TLSUpgrade, ProxyError
from hyper.common.util import to_native_string
from hyper.contrib import HTTP20Adapter
from hyper.tls import init_context

from tls_tunnel.dto import ProxyOptions, AdapterOptions
from tls_tunnel.utils import generate_basic_header


def _create_tunnel(proxy_host: str,
                   proxy_port: int,
                   target_host: str,
                   target_port: int,
                   proxy_headers: dict = None,
                   timeout: int = None) -> Tuple[socket.socket, str]:
    """
    Sends CONNECT method to a proxy and returns a socket with established
    connection to the target.

    :returns: socket, proto
    """
    conn = HTTP11Connection(proxy_host, proxy_port, timeout=timeout)
    conn.request('CONNECT', '%s:%d' % (target_host, target_port),
                 headers=proxy_headers)

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
            conn = CustomHTTPConnection(
                self.adapter_opts,
                self.proxy_opts,
                host=host,
                port=port,
                secure=secure,
                window_manager=self.window_manager,
                ssl_context=ssl_context,
                proxy_host=proxy_netloc,
                proxy_headers=proxy_headers,
                timeout=timeout,
            )
            self.connections[connection_key] = conn
        return conn


class CustomHTTPConnection(HTTPConnection):
    def __init__(self,
                 adapter_opts: AdapterOptions,
                 proxy_opts: ProxyOptions = None,
                 host=None,
                 port=None,
                 secure=None,
                 window_manager=None,
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
                         window_manager=window_manager,
                         enable_push=enable_push,
                         ssl_context=ssl_context,
                         proxy_host=proxy_host,
                         proxy_port=proxy_port,
                         proxy_headers=proxy_headers,
                         timeout=timeout,
                         **kwargs)
        self._conn = TunnelHTTP11Connection(
            adapter_opts=adapter_opts,
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
                 adapter_opts: AdapterOptions,
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
        self.adapter_opts = adapter_opts
        self.proxy_opts = proxy_opts

    def connect(self):
        """
        Connect to the server specified when the object was created. This is a
        no-op if we're already connected.

        :returns: Nothing.
        """
        if self._sock is None:
            if isinstance(self._timeout, tuple):
                read_timeout = self._timeout[1]
            else:
                read_timeout = self._timeout

            # Tunnel socket creation with tunnel's TLS proto
            sock, proto = _create_tunnel(
                target_host=self.host,
                target_port=self.port,
                proxy_host=self.adapter_opts.host,  # "104.248.43.30",
                proxy_port=self.adapter_opts.port,  # 1337,
                proxy_headers={
                    "Authorization": generate_basic_header(self.adapter_opts.auth_login,
                                                           self.adapter_opts.auth_password),
                    "Client": self.adapter_opts.client.value,
                    "Connection": 'keep-alive',
                    "Server-Name": self.host,
                    "Host": self.host,
                    "Secure": str(1 if self.secure is True else 0),
                    "HTTP2": "1",
                }
            )

            sock = BufferedSocket(sock, self.network_buffer_size)
            sock.settimeout(read_timeout)  # Set read timeout

            if self.secure is not True:
                proto = 'http/1.1'

            if proto not in ('http/1.1', None):
                raise TLSUpgrade(proto, sock)

            self._sock = sock
        return
