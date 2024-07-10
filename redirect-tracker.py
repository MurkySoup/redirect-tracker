#!/usr/bin/env python3
# -*- coding: utf-8 -*-


"""
URL Redirection Tracker, Version 0.7.3-alpha (do not distribute)
By Rick Pelletier (galiagante@gmail.com), 04 July 2024
Last updated: 10 July 2024

Note: AI analysis and optimization has been applied tthis source code.

Example usage and output:

./redirect-tracker.py -u "http://events.desmoinesregister.com/"

Initial URL: http://events.desmoinesregister.com/
Request was redirected
  http://events.desmoinesregister.com/ -> 301 Moved Permanently or Forced SSL
  http://thingstodo.desmoinesregister.com/events -> 301 Moved Permanently or Forced SSL
  http://www.desmoinesregister.com/things-to-do/best-lists/ -> 301 Moved Permanently or Forced SSL
Final URL: https://www.desmoinesregister.com/things-to-do/best-lists/
"""


import sys
import urllib3
import requests
import argparse
from urllib.parse import urlparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def resp_code_info(code:int):
    resp_code_info = [
      { 'code_value': 100, 'text':'Continue', 'memo':'RFC 9110'},
      { 'code_value': 101, 'text':'Switching Protocols', 'memo':'RFC 9110'},
      { 'code_value': 102, 'text':'Processing', 'memo':'WebDAV; RFC 2518'},
      { 'code_value': 103, 'text':'Early Hints', 'memo': 'RFC 8297'},
      { 'code_value': 110, 'text':'Response is Stale', 'memo':'Obsolete'},
      { 'code_value': 111, 'text':'Revalidation Failed', 'memo':'Obsolete'},
      { 'code_value': 112, 'text':'Disconnected Operation', 'memo':'Obsolete'},
      { 'code_value': 113, 'text':'Heuristic Expiration', 'memo':'Obsolete'},
      { 'code_value': 199, 'text':'Miscellaneous Warning', 'memo':'Obsolete'},
      { 'code_value': 200, 'text':'OK', 'memo':'RFC 9110'},
      { 'code_value': 201, 'text':'Created', 'memo':'RFC 9110'},
      { 'code_value': 202, 'text':'Accepted', 'memo':'RFC 9110'},
      { 'code_value': 203, 'text':'Non-Authoritative Information (since HTTP/1.1)', 'memo':'RFC 9110'},
      { 'code_value': 204, 'text':'No Content', 'memo':'RFC 9110'},
      { 'code_value': 205, 'text':'Reset Content', 'memo':'RFC 9110'},
      { 'code_value': 206, 'text':'Partial Content', 'memo':'RFC 9110'},
      { 'code_value': 207, 'text':'Multi-Status', 'memo':'WebDAV; RFC 4918'},
      { 'code_value': 208, 'text':'Already Reported', 'memo':'WebDAV; RFC 5842'},
      { 'code_value': 214, 'text':'Transformation Applied', 'memo':'Obsolete'},
      { 'code_value': 218, 'text':'This is fine', 'memo':'Unofficial; Apache HTTP Server'},
      { 'code_value': 226, 'text':'IM Used', 'memo':'RFC 3229'},
      { 'code_value': 299, 'text':'Miscellaneous Persistent Warning', 'memo':'Obsolete'},
      { 'code_value': 300, 'text':'Multiple Choices', 'memo':'RFC 9110'},
      { 'code_value': 301, 'text':'Moved Permanently or Forced SSL', 'memo':'RFC 9110'},
      { 'code_value': 302, 'text':'Found (Previously "Moved temporarily")', 'memo':'RFC 9110'},
      { 'code_value': 303, 'text':'See Other (since HTTP/1.1)', 'memo':'RFC 9110'},
      { 'code_value': 304, 'text':'Not Modified', 'memo':'RFC 9110'},
      { 'code_value': 305, 'text':'Use Proxy (since HTTP/1.1)', 'memo':'RFC 9110, RFC 7231'},
      { 'code_value': 306, 'text':'Switch Proxy', 'memo':'RFC 9110'},
      { 'code_value': 307, 'text':'Temporary Redirect (since HTTP/1.1)', 'memo':'RFC 9110'},
      { 'code_value': 308, 'text':'Permanent Redirect', 'memo':'RFC 9110, RFC 7538'},
      { 'code_value': 400, 'text':'Bad Request', 'memo':'RFC 9110'},
      { 'code_value': 401, 'text':'Unauthorized', 'memo':'RFC 9110'},
      { 'code_value': 402, 'text':'Payment Required', 'memo':'RFC 9110'},
      { 'code_value': 403, 'text':'Forbidden', 'memo':'RFC 9110'},
      { 'code_value': 404, 'text':'Not Found', 'memo':'RFC 9110'},
      { 'code_value': 405, 'text':'Method Not Allowed', 'memo':'RFC 9110'},
      { 'code_value': 406, 'text':'Not Acceptable', 'memo':'RFC 9110'},
      { 'code_value': 407, 'text':'Proxy Authentication Required', 'memo':'RFC 9110'},
      { 'code_value': 408, 'text':'Request Timeout', 'memo':'RFC 9110'},
      { 'code_value': 409, 'text':'Conflict', 'memo':'RFC 9110'},
      { 'code_value': 410, 'text':'Gone', 'memo':'RFC 9110'},
      { 'code_value': 411, 'text':'Length Required', 'memo':'RFC 9110'},
      { 'code_value': 412, 'text':'Precondition Failed', 'memo':'RFC 9110'},
      { 'code_value': 413, 'text':'Payload Too Large', 'memo':'RFC 9110'},
      { 'code_value': 414, 'text':'URI Too Long', 'memo':'RFC 9110'},
      { 'code_value': 415, 'text':'Unsupported Media Type', 'memo':'RFC 9110'},
      { 'code_value': 416, 'text':'Range Not Satisfiable', 'memo':'RFC 9110'},
      { 'code_value': 417, 'text':'Expectation Failed', 'memo':'RFC 9110'},
      { 'code_value': 418, 'text':'I\'m a teapot', 'memo':'RFC 2324, RFC 7168'},
      { 'code_value': 419, 'text':'Page Expired', 'memo':'Unofficial; Laravel Framework'},
      { 'code_value': 420, 'text':'Enhance Your Calm', 'memo':'Unofficial; Twitter'},
      { 'code_value': 420, 'text':'Method Failure', 'memo':'Unofficial; Spring Framework'},
      { 'code_value': 421, 'text':'Misdirected Request', 'memo':'RFC 9110'},
      { 'code_value': 422, 'text':'Unprocessable Content', 'memo':'RFC 9110'},
      { 'code_value': 423, 'text':'Locked', 'memo':'WebDAV; RFC 4918'},
      { 'code_value': 424, 'text':'Failed Dependency', 'memo':'WebDAV; RFC 4918'},
      { 'code_value': 425, 'text':'Too Early', 'memo':'RFC 8470'},
      { 'code_value': 426, 'text':'Upgrade Required', 'memo':'RFC 9110'},
      { 'code_value': 428, 'text':'Precondition Required', 'memo':'RFC 6585'},
      { 'code_value': 429, 'text':'Too Many Requests', 'memo':'RFC 6585'},
      { 'code_value': 430, 'text':'Request Header Fields Too Large', 'memo':'Unofficial; Shopify'},
      { 'code_value': 430, 'text':'Shopify Security Rejection', 'memo':'Unofficial; Shopify'},
      { 'code_value': 431, 'text':'Request Header Fields Too Large', 'memo':'RFC 6585'},
      { 'code_value': 440, 'text':'Login Time-out', 'memo':'Unofficial; IIS'},
      { 'code_value': 444, 'text':'No Response', 'memo':'Unofficial; NGinx'},
      { 'code_value': 449, 'text':'Retry With', 'memo':'Unofficial; IIS'},
      { 'code_value': 450, 'text':'Blocked by Windows Parental Controls', 'memo':'Unofficial; Microsoft'},
      { 'code_value': 451, 'text':'Redirect', 'memo':'Unofficial; IIS'},
      { 'code_value': 451, 'text':'Unavailable For Legal Reasons', 'memo':'RFC 7725'},
      { 'code_value': 494, 'text':'Request header too large', 'memo':'Unofficial; NGinx'},
      { 'code_value': 495, 'text':'SSL Certificate Error', 'memo':'Unofficial; NGinx'},
      { 'code_value': 496, 'text':'SSL Certificate Required', 'memo':'Unofficial; NGinx'},
      { 'code_value': 497, 'text':'HTTP Request Sent to HTTPS Port', 'memo':'Unofficial; NGinx'},
      { 'code_value': 498, 'text':'Invalid Token', 'memo':'Unofficial; Esri'},
      { 'code_value': 499, 'text':'Client Closed Request', 'memo':'Unofficial; NGinx'},
      { 'code_value': 499, 'text':'Token Required', 'memo':'Unofficial; Esri'},
      { 'code_value': 500, 'text':'Internal Server Error', 'memo':'RFC 9110'},
      { 'code_value': 501, 'text':'Not Implemented', 'memo':'RFC 9110'},
      { 'code_value': 502, 'text':'Bad Gateway', 'memo':'RFC 9110'},
      { 'code_value': 503, 'text':'Service Unavailable', 'memo':'RFC 9110'},
      { 'code_value': 504, 'text':'Gateway Timeout', 'memo':'RFC 9110'},
      { 'code_value': 505, 'text':'HTTP Version Not Supported', 'memo':'RFC 9110'},
      { 'code_value': 506, 'text':'Variant Also Negotiates', 'memo':'RFC 2295'},
      { 'code_value': 507, 'text':'Insufficient Storage', 'memo':'WebDAV; RFC 4918'},
      { 'code_value': 508, 'text':'Loop Detected', 'memo':'WebDAV; RFC 5842'},
      { 'code_value': 509, 'text':'Bandwidth Limit Exceeded', 'memo':'Unofficial; Apache Web Server/cPanel'},
      { 'code_value': 510, 'text':'Not Extended', 'memo':'RFC 2774'},
      { 'code_value': 511, 'text':'Network Authentication Required', 'memo':'RFC 6585'},
      { 'code_value': 520, 'text':'Web Server Returned an Unknown Error', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 521, 'text':'Web Server Is Down', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 522, 'text':'Connection Timed Out', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 523, 'text':'Origin Is Unreachable', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 524, 'text':'A Timeout Occurred', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 525, 'text':'SSL Handshake Failed', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 526, 'text':'Invalid SSL Certificate', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 527, 'text':'Railgun Error', 'memo':'Obsolete; Cloudflare'},
      { 'code_value': 529, 'text':'Site is overloaded', 'memo':'Unofficial; Pantheon'},
      { 'code_value': 530, 'text':'Origin DNS Error', 'memo':'Unofficial; Shopify'},
      { 'code_value': 530, 'text':'See additonal 1xx code', 'memo':'Unofficial; Cloudflare'},
      { 'code_value': 530, 'text':'Site is frozen', 'memo':'Unofficial; Pantheon'},
      { 'code_value': 540, 'text':'Temporarily Disabled', 'memo':'Unofficial; Shopify'},
      { 'code_value': 598, 'text':'Network read timeout error', 'memo':'Unofficial; Informal convention'},
      { 'code_value': 599, 'text':'Network Connect Timeout Error', 'memo':'Unofficial'},
      { 'code_value': 783, 'text':'Unexpected Token', 'memo':'Unofficial; Shopify'},
    ]

    return (next(x for x in resp_code_info if x['code_value'] == code)) or False


def url_tracking(url, skip_flag):
    try:
        print(f'Initial URL: {url}')
        response = requests.get(url, verify=skip_flag)
        response.raise_for_status()

        if response.history:
            print('Request was redirected')

        for resp in response.history:
            extra_data = resp_code_info(resp.status_code)
            extra_data_string = f'{extra_data["text"]} ({extra_data["memo"]})'
            print(f'  {resp.url} -> {resp.status_code} {extra_data_string}')

        extra_data = resp_code_info(response.status_code)
        extra_data_string = f'{extra_data["text"]} ({extra_data["memo"]})'
        print(f'Final URL: {response.url} {response.status_code} {extra_data_string}')
        #print(f'Final URL: {response.url} {response.status_code}')

        return True

    except requests.exceptions.HTTPError as errh:
        print(f'An Http Error occurred: {errh}')
    except requests.exceptions.ConnectionError as errc:
        print(f'An Error Connecting to the API occurred: {errc}')
    except requests.exceptions.Timeout as errt:
        print(f'A Timeout Error occurred: {errt}')
    except requests.exceptions.RequestException as err:
        print(f'An Unknown Error occurred: {err}')

    return False


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('-u', '--url', help='Target URL', type=str, required=True)
    parser.add_argument('-s', '--skip', help='Skip SSL Verification', action='store_false')
    args = parser.parse_args()

    url = args.url

    if not (parsed_url := urlparse(url)).scheme or not parsed_url.netloc:
        print('Invalid URL Supplied')
        sys.exit(1)

    success = url_tracking(url, args.skip)
    sys.exit(0 if success else 2)
else:
    sys.exit(1)

# end of script
