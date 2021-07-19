# TCP TLS Tunnel Adapter for Python

Provides functionality for creating a TCP-TLS tunnel for HTTP / HTTPS 
requests. Currently supported libraries are `request`, `hyper` and `httpx`. 
Our TLS Layer pass ciphers and has SSL session ticket support by default.
If you are really interested in testing it for free, 
you can find out more details in our [Discord Channel](https://discord.gg/4HRVxNP).

## Usage examples

These sections show usage examples for HTTP/1.1 and HTTP/2.0.

### Requests adapter (HTTP/1.1)

#### Installation

```shell
pip install tls-tunnel
```

#### Example
Let's show, how it works for `requests` in case of HTTP/1.1:

```python
from requests import Session
from tls_tunnel.requests_adapter import TunneledHTTPAdapter
from tls_tunnel.constants import Client
from tls_tunnel.dto import TunnelOptions, ProxyOptions


# if necessary
proxy_opts = ProxyOptions(
    host="your.proxy.host",
    port=1234,
    auth_login="YOUR_LOGIN",
    auth_password="YOUR_PASSWORD",
)

httpAdapter = TunneledHTTPAdapter(
    tunnel_opts=TunnelOptions(
        host="127.0.0.1",  # tunnel address
        port=1337,  # tunnel port
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
        secure=True,  # True - TLS, False - TCP
        client=Client.CHROME,  # imitated Client that will be used
    ),
    proxy_opts=proxy_opts  # or None if not required
)

httpsAdapter = TunneledHTTPAdapter(
    tunnel_opts=TunnelOptions(
        host="127.0.0.1",  # tunnel address
        port=1337,  # tunnel port
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
        secure=False,  # True - TLS, False - TCP
        client=Client.CHROME,  # imitated Client that will be used
    ),
    proxy_opts=proxy_opts  # or None if not required
)

session = Session()

# connect adapter for requests.Session instance
session.mount("http://", httpAdapter)
session.mount("https://", httpsAdapter)
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

### Requests adapter (HTTP/2.0 with hyper)

#### Installation

```shell
pip install tls-tunnel[hyper]
```

#### Example
Let's show, how it works for `requests` in case of HTTP/2.0:
```python
import requests
from tls_tunnel.dto import ProxyOptions, AdapterOptions
from tls_tunnel.hyper_http2_adapter import TunnelHTTP20Adapter


adapter = TunnelHTTP20Adapter(
    proxy_opts=ProxyOptions(
        host="your.proxy.host",
        port=1234,
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
    ),
    adapter_opts=AdapterOptions(
        host="127.0.0.1",  # tunnel address
        port=1337,  # tunnel port
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
    ),
)

session = requests.Session()
session.mount("http://", adapter)
session.mount("https://", adapter)
```

Request to `http2.pro`:
```python
response = session.get("https://http2.pro/api/v1")
print(response.json())
```

Output:
```python
{
    'http2': 1, 
    'protocol': 'HTTP/2.0', 
    'push': 0, 
    'user_agent': 'python-requests/2.24.0'
}
```

### HTTPX Transport (HTTP/2.0)

#### Installation

```shell
pip install tls-tunnel[httpx]
```

#### Example
Let's show, how it works for `httpx` in case of HTTP/2.0:
```python
from tls_tunnel.dto import AdapterOptions, ProxyOptions
from tls_tunnel.httpx_adapter import TunnelHTTPTransport

transport = TunnelHTTPTransport(
    adapter_opts=AdapterOptions(
        host="127.0.0.1",  # tunnel address
        port=1337,  # tunnel port
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
    ),
    proxy_opts=ProxyOptions(
        host="your.proxy.host",
        port=1234,
        auth_login="YOUR_LOGIN",
        auth_password="YOUR_PASSWORD",
    ),
)
```

Request to `http2.pro`:
```python
from httpx import Client

with Client(transport=transport) as client:
    response = client.get("https://http2.pro/api/v1")
    print(response.json())
```

Output:
```python
{
    'http2': 1, 
    'protocol': 'HTTP/2.0', 
    'push': 0, 
    'user_agent': 'python-httpx/0.18.2'
}
```

## Tests

In addition, you can try to run the tests that are available in the `tests` directory,
there are more examples of using the right adapters.

In order to use environment variables it is recommended to create directories with tests `.env` file,
which will be used automatically at startup.

You can do this with the command:
```shell
python -m unittest -v tests/*_tests.py
```