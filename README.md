# TCP TLS Tunnel Adapter for Python

Provides functionality for creating a TLS tunnel for HTTP / HTTPS 
requests using the overridden `BaseAdapter` from the `requests` library.

## Usage examples

Let's show, how it works for `requests`.

We should import required modules and declare options:
```python

from tls_tunnel.dto import TunnelOptions, ProxyOptions
from tls_tunnel.constants import Client


tunnel_opts = TunnelOptions(
            host="127.0.0.1",  # tunnel address
            port=1337,  # tunnel port
            auth_login="YOUR_LOGIN",
            auth_password="YOUR_PASSWORD",
            secure=True,  # True - TLS, False - TCP
            client=Client.CHROME,  # imitated Client that will be used
       )

# if needed
proxy_opts = ProxyOptions(
        host="your.proxy.host",
        port=1234,
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
)
```

Then we can create tunnnel adapter:

```python
from requests import Session
from tls_tunnel.requests_adapter import TunneledHTTPAdapter

adapter = TunneledHTTPAdapter(
    tunnel_opts=tunnel_opts,
    proxy_opts=proxy_opts  # or None if not required
)

session = Session()

# connect adapter for requests.Session instance
session.mount("http://", adapter)
session.mount("https://", adapter)
```

Request to `howsmyssl.com`:
```python
response = session.get('https://www.howsmyssl.com/a/check')
```
Output:
```python
# response.status_code
200

# response.headers
{'Content-Length': '874', 
 'Access-Control-Allow-Origin': '*', 
 'Connection': 'close', 
 'Content-Type': 'application/json', 
 'Date': 'Mon, 12 Oct 2020 21:55:42 GMT', 
 'Strict-Transport-Security': 'max-age=631138519; includeSubdomains; preload'}

# response.json()
{'able_to_detect_n_minus_one_splitting': False,
 'beast_vuln': False,
 'ephemeral_keys_supported': True,
 'given_cipher_suites': ['TLS_GREASE_IS_THE_WORD_2A',
                         'TLS_AES_128_GCM_SHA256',
                         'TLS_AES_256_GCM_SHA384',
                         'TLS_CHACHA20_POLY1305_SHA256',
                         'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256',
                         'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                         'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
                         'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                         'TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256',
                         'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256',
                         'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
                         'TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA',
                         'TLS_RSA_WITH_AES_128_GCM_SHA256',
                         'TLS_RSA_WITH_AES_256_GCM_SHA384',
                         'TLS_RSA_WITH_AES_128_CBC_SHA',
                         'TLS_RSA_WITH_AES_256_CBC_SHA'],
 'insecure_cipher_suites': {},
 'rating': 'Probably Okay',
 'session_ticket_supported': True,
 'tls_compression_supported': False,
 'tls_version': 'TLS 1.3',
 'unknown_cipher_suite_supported': False}
```