# redirect-tracker
Show URL Redirection Sequence and Codes

## Description

This tool is used to preform URL redirection traces, showing the sequence of URL's and response code.

## Prerequisites

Requires Python 3.x (preferrably 3.10+) and uses the following (entirely standard) libraries:
* sys
* urllib3
* requests
* argparse
* urllib.parse


## How to Use

Clone this repo and run this one script contained within. There is no setup, installation or interconnect to anything else-- it's a self-contained program. A simple command line interface is present:

```
usage: redirect-tracker.py [-h] -u URL [-s]

options:
  -h, --help         show this help message and exit
  -u URL, --url URL  Target URL
  -s, --skip         Skip SSL Verification
```

Example:

```
Initial URL: http://events.desmoinesregister.com/
Request was redirected
  http://events.desmoinesregister.com/ -> 301 Moved Permanently or Forced SSL (RFC 9110)
  http://thingstodo.desmoinesregister.com/events -> 301 Moved Permanently or Forced SSL (RFC 9110)
  http://www.desmoinesregister.com/things-to-do/best-lists/ -> 301 Moved Permanently or Forced SSL (RFC 9110)
Final URL: https://www.desmoinesregister.com/things-to-do/best-lists/ 200 OK (RFC 9110)
```

## Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier** - [Gannett Co., Inc. (USA Today Network)](https://www.usatoday.com/)
