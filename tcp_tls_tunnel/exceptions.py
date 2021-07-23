# Create our own ConnectionError.
try:  # pragma: no cover
    ConnectionError = ConnectionError
except NameError:  # pragma: no cover
    class ConnectionError(Exception):
        """
        An error occurred during connection to a host.
        """


class ProxyError(ConnectionError):
    """
    An error occurred during connection to a proxy.
    """
    def __init__(self, message, response):
        self.response = response
        super(ProxyError, self).__init__(message)