from datetime import datetime
from mitmproxy import http
from mitmproxy.http import Headers

flow = http.HTTPFlow
log_path = "header_log.txt"
my_file = open(log_path, "w")
my_file.write("Date" + "\t" + "Time" + "\t" + "URL" + "\t" + "Request Method" +
              "\t" + "Request Path" + "\t" + "Request HTTP Version" +
              "\t" + "Type" + "\t" + "Header Content" + "\n")

# Getting the current date and time


def response(flow):
    dt = datetime.now()
    the_date = dt.strftime("%m/%d/%Y")
    the_time = dt.strftime("%H:%M:%S")
    metadata = the_date + "\t" + the_time + "\t"
    metadata += flow.request.url + "\t"
    metadata += flow.request.method + "\t"
    metadata += flow.request.path + "\t"
    metadata += flow.request.http_version + "\t"

    for k, v in flow.request.headers.items():
        my_file.write(metadata)
        my_file.write("Request Header" + "\t")
        my_file.write("%-20s: %s" % (k.upper(), v) + "\n")

    for k, v in flow.response.headers.items():
        my_file.write(metadata)
        my_file.write("Response Header" + "\t")
        my_file.write("%-20s: %s" % (k.upper(), v) + "\n")


# mitmdump -q -v -s parse_headers.py -R http://localhost:9200 -p 30001

# -q quiet
# -v vebose logging
# -R reverse proxy
# https://stackoverflow.com/questions/31205415/how-to-capture-http-request-response-headers-with-mitmproxy
