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


def unpack_cookie(cookie):
    if ("=" in cookie):
        try:
            (name, value) = cookie.split("=")
        except ValueError:
            (name, value) = cookie, ""
        except:
            (name, value) = cookie, ""
    else:
        (name, value) = cookie, ""

    return (name, value)


def unpack_pair(pair):
    if ("=" in pair):
        try:
            (name, value) = pair.split("=")
        except ValueError:
            (name, value) = pair, ""
        except:
            (name, value) = pair, ""
    else:
        (name, value) = pair, ""
    return (name, value)


# clean out messy data that creates errors
def clean_cookies(cookies):

    # some cookies have line returns in them that mess up the data
    clean_cookies = cookies.replace('\n', '')

    return clean_cookies

# clean out messy data that creates errors


def clean_set_cookies(cookies):

    # some cookies have line returns in them that mess up the data
    clean_cookies = cookies.replace('\n', '')

    # Remove delimeter-confusing comma from expires date.
    clean_cookies = clean_cookies.replace("Mon,", "Mon")
    clean_cookies = clean_cookies.replace("Tue,", "Tue")
    clean_cookies = clean_cookies.replace("Wed,", "Wed")
    clean_cookies = clean_cookies.replace("Thu,", "Thu")
    clean_cookies = clean_cookies.replace("Fri,", "Fri")
    clean_cookies = clean_cookies.replace("Sat,", "Sat")
    clean_cookies = clean_cookies.replace("Sun,", "Sun")

    clean_cookies = clean_cookies.replace("Monday,", "Monday")
    clean_cookies = clean_cookies.replace("Tuesday,", "Tuesday")
    clean_cookies = clean_cookies.replace("Wednesday,", "Wednesday")
    clean_cookies = clean_cookies.replace("Thursday,", "Thursday")
    clean_cookies = clean_cookies.replace("Friday,", "Friday")
    clean_cookies = clean_cookies.replace("Saturday,", "Saturday")
    clean_cookies = clean_cookies.replace("Sunday,", "Sunday")

    return clean_cookies


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
        if (k.upper() == "COOKIE"):
            my_file.write(metadata)
            my_file.write("Request" + "\t")

            v_clean = clean_cookies(v)

            # write cookie name and raw cookie value
            my_file.write(k.upper() + "\t" + v_clean + "\t")

            # split out name value pairs for each cookie per RFC 6265; arbitrary numbers of cookies and pairs
            # identify if ; or , split cookies; some cookies are not RFC compliant.
            semicolon_loc = v_clean.rfind(";")
            comma_loc = v_clean.rfind(",")

            if ((comma_loc == -1 and semicolon_loc > -1)):
                cookies = v_clean.split(";")
            else:
                cookies = v_clean.split(",")
            for cookie in cookies:
                (name, value) = unpack_cookie(cookie)
                my_file.write(name + "\t" + value + "\t")
            my_file.write("\n")

    for k, v in flow.response.headers.items():
        if (k.upper() == "SET-COOKIE"):
            my_file.write(metadata)
            my_file.write("Response" + "\t")

            the_set_cookies = clean_set_cookies(v)

            # wrtie cookie name and raw cookie value
            my_file.write(k.upper() + "\t" + the_set_cookies + "\t")

            # split out name value pairs for each cookie per RFC 6265; arbitrary numbers of cookies and pairs
            set_cookies = the_set_cookies.split(",")
            for set_cookie in set_cookies:
                for set_pair in set_cookie.split(";"):
                    set_pair_tuple = unpack_pair(set_pair)

                    if (len(set_pair_tuple) == 2):
                        for x in set_pair_tuple:
                            my_file.write(x + "\t")
                    else:
                        my_file.write(set_pair_tuple + "\t" + "" + "\t")
            my_file.write("\n")
