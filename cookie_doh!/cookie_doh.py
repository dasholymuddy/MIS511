from datetime import datetime
from mitmproxy import http
from mitmproxy.http import Headers
import random

# configurable variable: allow_cookies
# set allow_cookies to True to permit cookies to pass between client and server after logging cookie traffic. (Default)
# set allow_cookies to False to scrub cookies from request and response after logging attempted cookie traffic.
allow_cookies = True

# configurable variable: corrupt_ga_client_id
# set corrupt_ga_client_id to True to alter cookie values that look like Google Analytics Client IDs
# set corrupt_ga_client_id to False to pass Google Analytics Client IDs without modification (Default)
corrupt_ga_client_id = False


# file logging config elements
log_path = "header_log.txt"
my_file = open(log_path, "w")
my_file.write("Date" + "\t" + "Time" + "\t" + "URL" + "\t" + "Host" +
              "\t" + "Port" + "\t" + "Request Method" + "\t" + "Path" +
              "\t" + "HTTP Version" + "\t" + "Type" + "\t" + "Allow Cookies" +
              "\t" + "Corrupt GA Cookies" + "\t" + "Header" + "\t" + "Content" + "\n")

# instantiates the mitmproxy.http.HTTPFlow object we'll be iterating in def response(flow)
flow = http.HTTPFlow


# utility functions

# corrupt Google Analytics Client IDs
def modify_cookie_value(corrupt_ga_client_id, name, value):
    if (corrupt_ga_client_id):

        new_value = ""
        substrings = value.split(".")

        # Google Analytics _ga=GA1... cookie
        if (name == " _ga" and value[0:4] == "GA1."):
            for substr in substrings:
                if (len(substr) > 4):
                    new_substr = ""
                    for char in substr:
                        if (char.isdigit() and random.choice([True, False])):
                            new_substr += str(random.randrange(0, 9, 1))
                        else:
                            new_substr += char
                    new_value += new_substr
                else:
                    new_value += substr
                new_value += "."
            new_value = new_value.rstrip("., ")

        # other cookie patterns TBD
        elif(1==0):
            pass
        # if not a recognized pattern, just pass the original value
        else:
            new_value = value
        return new_value
    else:
        return (value)


# unpack cookie data; we need to handle cases where cookies aren't RFC 6265 compliant
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


# unpack set-cookie name/value pair data; we need to handle cases where cookies aren't RFC 6265 compliant
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


# set-cookie values may have \n and commas in the expires-date, so we need to handle those conditions for better logging
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


# split out name value pairs for each cookie per RFC 6265; arbitrary numbers of cookies and pairs
# identify if ; or , split cookies; some cookies are not RFC compliant.
def find_cookie_delim(cookie_jar_value):
    semicolon_loc = cookie_jar_value.rfind(";")
    comma_loc = cookie_jar_value.rfind(",")

    if ((comma_loc == -1 and semicolon_loc > -1)):
        cookie_delim = ";"
    else:
        cookie_delim = ","

    return cookie_delim


# close the file when flow is done
def done():
    my_file.close()


# this is the main logic, which iterates over the flow
def response(flow):
    dt = datetime.now()
    the_date = dt.strftime("%m/%d/%Y")
    the_time = dt.strftime("%H:%M:%S")

    # set up metadata record for each log entry
    metadata = the_date + "\t"
    metadata += the_time + "\t"
    metadata += flow.request.url + "\t"
    metadata += flow.request.host + "\t"
    metadata += str(flow.request.port) + "\t"
    metadata += flow.request.method + "\t"
    metadata += flow.request.path + "\t"
    metadata += flow.request.http_version + "\t"

    # parse the request headers (from client to server)
    for k, v in flow.request.headers.items():
        if (k.upper() == "COOKIE"):
            my_file.write(metadata)
            my_file.write("Request" + "\t")
            my_file.write(str(allow_cookies) + "\t")
            my_file.write(str(corrupt_ga_client_id) + "\t")

            v_clean = clean_cookies(v)
            new_cookies = ""

            # write cookie name and raw cookie value
            my_file.write(k.upper() + "\t" + v_clean + "\t")

            cookie_delim = find_cookie_delim(v_clean)

            cookies = v_clean.split(cookie_delim)

            for cookie in cookies:
                (name, value) = unpack_cookie(cookie)
                my_file.write(name + "\t" + value + "\t")
                new_value = modify_cookie_value(corrupt_ga_client_id, name, value)
                if (value != new_value):
                    my_file.write(name + " (new value)" +
                                  "\t" + new_value + "\t")
                    new_cookies += name + "=" + new_value + cookie_delim
                else:
                    new_cookies += name + "=" + value + cookie_delim
            if (cookies != new_cookies):
                flow.request.headers["cookie"] = new_cookies.rstrip(", ")

            my_file.write("\n")

    # blow away outbound cookies after logging attempted Cookie traffic
    if (not allow_cookies):
        flow.request.headers.set_all("cookie", "")

    # parse the response headers (from server to client)
    for k, v in flow.response.headers.items():
        if (k.upper() == "SET-COOKIE"):
            my_file.write(metadata)
            my_file.write("Response" + "\t")
            my_file.write(str(allow_cookies) + "\t")

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

    # blow away inbound cookies after logging attempted Set-cookie headers
    if (not allow_cookies):
        flow.response.headers.set_all("Set-Cookie", "")
