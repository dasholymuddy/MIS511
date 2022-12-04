from datetime import datetime
from mitmproxy import http
from mitmproxy.http import Headers

flow = http.HTTPFlow
log_path = "header_log.txt"
my_file = open(log_path, "w")
my_file.write("Date" + "\t" + "Time" + "\t" + "URL" + "\t" + "Host" +
              "\t" + "Port" + "\t" + "Request Method" + "\t" + "Path" +
              "\t" + "HTTP Version" + "\t" + "Type" + "\t" + "Header" +
              "\t" + "Content" + "\n")


def response(flow):
    dt = datetime.now()
    the_date = dt.strftime("%m/%d/%Y")
    the_time = dt.strftime("%H:%M:%S")

    metadata = the_date + "\t"
    metadata += the_time + "\t"
    metadata += flow.request.url + "\t"
    metadata += flow.request.host + "\t"
    metadata += str(flow.request.port) + "\t"
    metadata += flow.request.method + "\t"
    metadata += flow.request.path + "\t"
    metadata += flow.request.http_version + "\t"

    for k, v in flow.request.headers.items():
        if (k.upper() == "COOKIE" or k.upper() == "SET-COOKIE"):
            my_file.write(metadata)
            my_file.write("Request" + "\t")
            my_file.write(k.upper() + "\t" + v.replace('\n', '') + "\n")

    for k, v in flow.response.headers.items():
        if (k.upper() == "COOKIE" or k.upper() == "SET-COOKIE"):
            my_file.write(metadata)
            my_file.write("Response" + "\t")
            my_file.write(k.upper() + "\t" + v.replace('\n', '') + "\n")
