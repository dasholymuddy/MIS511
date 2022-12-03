"""
This script writes mitmproxy header information to a file defined in log_path
"""

from mitmproxy import http
from mitmproxy.http import Headers

log_path = "header_log.txt"
the_flow = http.HTTPFlow


class WriteHeader:

    def __init__(self, my_file_path: str, flow) -> None:

        my_file = open(my_file_path, "w")

        my_file.write("="*50)
        my_file.write("FOR: " + flow.request.url)
        my_file.write(flow.request.method + " " + flow.request.path +
                      " " + flow.request.http_version)

        my_file.write("-"*50 + "request headers:")
        for k, v in flow.request.headers.items():
            my_file.write("%-20s: %s" % (k.upper(), v))

        my_file.write("-"*50 + "response headers:")
        for k, v in flow.response.headers.items():
            my_file.write("%-20s: %s" % (k.upper(), v))
            my_file.write("-"*50 + "request headers:")

        my_file.close()
        return None


WriteHeader(log_path, the_flow)
