from datetime import datetime
from mitmproxy import http
from mitmproxy.http import Headers
import random

# configurable variable: allow_cookies
# set allow_cookies to True to permit cookies to pass between client and server after logging cookie traffic. (Default)
# set allow_cookies to False to scrub cookies from request and response after logging attempted cookie traffic.
allow_cookies = True

# configurable variable: corrupt_ga_client_id
# set corrupt_ga_client_id to True to randomly alter cookies values that look like Google Analytics Client IDs
# set corrupt_ga_client_id to False to pass Google Analytics Client IDs without modification (Default)
corrupt_ga_client_id = True


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

# handle double-click pixel tracker
# add a function to handle these, and call it from request
# https://stats.g.doubleclick.net/j/collect
# ?t=dc
# &aip=1
# &_r=3
# &v=1
# &_v=j98
# &tid=UA-121785700-1
# &cid=444357169.1662670361
# &jid=1571182493
# &uid=4
# &gjid=1407041247
# &_gid=264372301.1670956247
# &_u=SCCAAEIqAAAAACgCIAB~
# &z=308421432
def modify_doubleclick_tracker(corrupt_ga_client_id, host, url, ga_client_id, new_ga_client_id):

    return url

# handle google ads audiences pixel tracker
# add a function to handle these, and call it from request
# https://www.google.com/ads/ga-audiences
# ?t=sr
# &aip=1 # same
# &_r=4 # same possibly as uid=4
# &slf_rd=1
# &v=1 # same
# &_v=j98 # same
# &tid=UA-121785700-1 # same (UA identifier)
# &cid=444357169.1662670361 # same (ga cid)
# &jid=1571182493 # same
# &_u=SCCAAEIqAAAAACgCIAB~ # same
# &z=485372858


def modify_ga_audiences_tracker(corrupt_ga_client_id, host, url, ga_client_id, new_ga_client_id):

    return url

# modify long strings of numbers randomly


def corrupt_string(substr):
    new_substr = ""
    if (len(substr) > 4):
        for char in substr:
            if (char.isdigit()):
                new_substr += str(random.randrange(0, 9, 1))
            else:
                new_substr += char
    else:
        new_substr = substr
    return new_substr


# corrupt Google Analytics Client IDs
def corrupt_ga_cookie(corrupt_ga_client_id, src):
    if (corrupt_ga_client_id):

        new_str = ""
        substrings = src.split(".")

        # Google Analytics GA1 cookie
        if (src[0:4] == "GA1."):
            for substr in substrings:
                new_str = corrupt_string(substr)
                new_str += "."
            new_str = new_str[0:len(new_str)-1]

        # if not a recognized pattern, just pass the original value
        else:
            new_str = src
        return new_str
    else:
        return src


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

# clean out messy data that creates errors


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


# close the file when flow is done
def done():
    my_file.close()


# this is the main logic, which iterates over the flow
def response(flow):
    dt = datetime.now()
    the_date = dt.strftime("%m/%d/%Y")
    the_time = dt.strftime("%H:%M:%S")

    # set up metadata lot record with each entry
    metadata = the_date + "\t"
    metadata += the_time + "\t"
    metadata += flow.request.url + "\t"
    metadata += flow.request.host + "\t"
    metadata += str(flow.request.port) + "\t"
    metadata += flow.request.method + "\t"
    metadata += flow.request.path + "\t"
    metadata += flow.request.http_version + "\t"

    # parse query to handle query based trackers
    if (flow.request.host == "www.google.com"):
        print("path: " + flow.request.path)
        print(flow.request.query)

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

            # split out name value pairs for each cookie per RFC 6265; arbitrary numbers of cookies and pairs
            # identify if ; or , split cookies; some cookies are not RFC compliant.
            semicolon_loc = v_clean.rfind(";")
            comma_loc = v_clean.rfind(",")

            if ((comma_loc == -1 and semicolon_loc > -1)):
                cookie_delim = ";"
            else:
                cookie_delim = ","

            cookies = v_clean.split(cookie_delim)

            for cookie in cookies:
                (name, value) = unpack_cookie(cookie)
                my_file.write(name + "\t" + value + "\t")
                new_value = corrupt_ga_cookie(corrupt_ga_client_id, value)
                if (value != new_value):
                    my_file.write(name + " (new value)" +
                                  "\t" + new_value + "\t")
                    new_cookies += name + cookie_delim + new_value
                else:
                    new_cookies += name + cookie_delim + value
            if (cookies != new_cookies):
                flow.request.headers["cookie"] = new_cookies

            my_file.write("\n")

    # blow away outbound cookies after logging attempted Cookie traffic
    if (not allow_cookies):
        flow.request.headers.set_all("Cookie", "")

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
