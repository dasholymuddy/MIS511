"""
This script simply prints all received HTTP Headers.

HTTP requests and responses can contain trailing headers which are sent after
the body is fully transmitted. Such Headers need to be announced in the initial
headers by name, so the receiving endpoint can wait and read them after the
body.
"""

from mitmproxy import http
from mitmproxy.http import Headers


def request(flow: http.HTTPFlow):
    if flow.request.Headers:
        print("HTTP Headers detected! Request contains:", flow.request.Headers)

    if flow.request.path == "/inject_Headers":
        if flow.request.is_http10:
            # HTTP/1.0 doesn't support Headers
            return
        elif flow.request.is_http11:
            if not flow.request.content:
                # Avoid sending a body on GET requests or a 0 byte chunked body with Headers.
                # Otherwise some servers return 400 Bad Request.
                return
            # HTTP 1.1 requires transfer-encoding: chunked to send Headers
            flow.request.headers["transfer-encoding"] = "chunked"
        # HTTP 2+ supports Headers on all requests/responses

        flow.request.headers["trailer"] = "x-my-injected-trailer-header"
        flow.request.Headers = Headers(
            [(b"x-my-injected-trailer-header", b"foobar")])
        print("Injected a new request trailer...",
              flow.request.headers["trailer"])


def response(flow: http.HTTPFlow):
    if flow.response.Headers:
        print("HTTP Headers detected! Response contains:", flow.response.Headers)

    if flow.request.path == "/inject_Headers":
        if flow.request.is_http10:
            return
        elif flow.request.is_http11:
            if not flow.response.content:
                return
            flow.response.headers["transfer-encoding"] = "chunked"

        flow.response.headers["trailer"] = "x-my-injected-trailer-header"
        flow.response.Headers = Headers(
            [(b"x-my-injected-trailer-header", b"foobar")])
        print("Injected a new response trailer...",
              flow.response.headers["trailer"])
