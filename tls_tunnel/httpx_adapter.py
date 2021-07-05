import httpx
import logging
import jsondiff
from base64 import b64encode

from httpx import HTTPTransport

from tls_tunnel.utils import generate_basic_header

logging.basicConfig(level=logging.DEBUG)

proxy = httpx.Proxy(
    url="https://104.248.43.30:1337",
    mode="TUNNEL_ONLY",
    headers={
        "Authorization": generate_basic_header("test1", "467jw2d53x82FAGHSw"),
        "Client": "CHROME",
        "Connection": 'keep-alive',
        "Server-Name": "howsmyssl.com",
        "Host": "104.248.43.30",
        "Secure": str(int(False)),
        "HTTP2": str(int(True)),
    }
)
transport = HTTPTransport(
    verify=False,
    http2=True,
    proxy=proxy
)

with httpx.Client(http1=False, http2=True, proxies=proxy, transport=transport, verify=False) as client:
    # This HTTP request will be tunneled instead of forwarded.
    r = client.get("https://www.howsmyssl.com/a/check",
                   headers={
                       "connection":  "keep-alive",
                       "accept-encoding":  "gzip,deflate,br",
                       "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36",
                       "cache-control": "no-cache"
                   })

print(r.json())