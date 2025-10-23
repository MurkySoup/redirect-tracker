# redirect-tracker
Show URL Redirection Sequence, Response Codes and Other Data

## Description

This Python-based command-line utility is a diagnostocs tool for tracing URL and HTTP/HTTPS redirects, validating secure upgrade behavior, and optionally outputting structured JSON suitable for automated analysis or CI/CD pipelines.

This utility is intended to be transparent and audit-friendly, adhering to the following design goals:
* Clarity — Human-readable output by default.
* Automation-ready — JSON output for integration in CI/CD or monitoring systems.
* Security-aware — Highlights weak redirect patterns or delayed HTTPS transitions.
* Clean, maintainable code — Fully type-annotated, modular, and standards-aligned.

Features:
- Full redirect chain tracing: Displays every hop from initial request to final destination.
- HTTPS upgrade verification: Warns when No upgrade from HTTP → HTTPS occurred, or when HTTPS upgrade occurred after the first redirect (suboptimal).
- HTTP header inspection: View headers for each step and the final response.
- Optional header redaction: Safely mask sensitive values.
- Machine-readable JSON output: Ideal for automated checks and security audits.
- Robust CLI interface: Simple, predictable command usage.

## Prerequisites

Requires Python 3.x (preferrably 3.11+) and uses the following libraries:
* annotations (future)
* argparse
* json
* sys
* dataclasses
* typing
* urllib.parse
* requests
* urllib3

## How to Use

Clone this repo and run this one script contained within. There is no setup, installation or interconnect to anything else-- it's a self-contained program. A simple command line interface is present:

```
usage: redirect-tracker.py [-h] -u URL [-k] [-j] [-r]

Trace HTTP redirects for a given URL.

options:
  -h, --help            show this help message and exit
  -u URL, --url URL     Target URL to trace.
  -k, --insecure        Skip SSL certificate verification (insecure).
  -j, --json            Output results in JSON format.
  -r, --redact-headers  Redact sensitive headers (safe for sharing).
```

Output can be test or JSON, can be trivially piped to a file, and includes the ability to redact an extensible list of "sensitive" headers:
* authorization
* proxy-authorization
* cookie
* set-cookie
* x-csrf-token
* x-xsrf-token
* x-api-key
* x-auth-token

## Built With

* [Python](https://www.python.org) designed by Guido van Rossum

## Author

**Rick Pelletier** - [Gannett Co., Inc. (USA Today Network)](https://www.usatoday.com/)
