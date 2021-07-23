from typing import Union

import urllib3
from tests import test_settings
from hyper.contrib import HTTP20Adapter
from requests import Session
from requests.adapters import BaseAdapter


def get_test_requests_session(adapter: Union[BaseAdapter, HTTP20Adapter] = None) -> Session:
    headers = urllib3.make_headers(
        keep_alive=True,
        disable_cache=True,
        accept_encoding=True,
        user_agent=test_settings.USER_AGENT
    )

    session = Session()
    session.headers.update(headers)

    if adapter:
        # Connect adapter for requests.Session instance
        session.mount("http://", adapter=adapter)
        session.mount("https://", adapter=adapter)

    return session