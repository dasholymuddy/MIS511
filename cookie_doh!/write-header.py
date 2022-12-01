"""
Generate a mitmproxy dump file.

This script writes mitmproxy header information to a file defined in path
"""
import random
import sys
from typing import BinaryIO

from mitmproxy import io, http

path = "header_log.txt"

headers_cookie = http.Headers.get_all("Cookie")
headers_set_cookie = http.Headers.get_all("Set-Cookie")


class WriteHeader:

    def __init__(self, my_file_path: str, my_headers) -> None:

        my_file = open(my_file_path, "w")
        for h in my_headers:
            line = my_file.write(str(h)+"\n")
        my_file.close()
        return None


# sys.argv[1]
WriteHeader(path, headers_cookie)
