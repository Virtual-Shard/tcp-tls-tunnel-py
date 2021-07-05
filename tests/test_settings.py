import os


# Proxy configuration
TEST_PROXY_HOST = os.environ.get("TEST_PROXY_HOST")
TEST_PROXY_PORT = int(os.environ.get("TEST_PROXY_PORT"))
TEST_PROXY_LOGIN = os.environ.get("TEST_PROXY_LOGIN")
TEST_PROXY_PASSWORD = os.environ.get("TEST_PROXY_PASSWORD")

# Tunnel configuration
TEST_TUNNEL_HOST = os.environ.get("TEST_TUNNEL_HOST", "104.248.43.30")
TEST_TUNNEL_PORT = int(os.environ.get("TEST_TUNNEL_PORT", "1337"))
TEST_TUNNEL_LOGIN = os.environ.get("TEST_TUNNEL_LOGIN", "test1")
TEST_TUNNEL_PASSWORD = os.environ.get("TEST_TUNNEL_PASSWORD", "467jw2d53x82FAGHSw")


# Request configuration
USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36"
