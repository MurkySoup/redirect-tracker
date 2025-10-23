#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
URL Redirection Tracker, Version 0.9-Beta (Do Not Distribute)
By Rick Pelletier (galiagante@gmail.com), 04 July 2024
Last updated: 23 October 2024

Trace HTTP redirects for a given URL, detect HTTPS upgrades,
and optionally emit structured JSON output. Includes header inspection,
with optional redaction of sensitive header fields.

Example:
    python redirect_tracker.py -u "http://example.com"
    python redirect_tracker.py -u "http://example.com" --json
    python redirect_tracker.py -u "http://example.com" --json --redact-headers

Potential future feature upgrades:
- Timing metrics (per redirect and total elapsed time).
- TLS details (protocol version, cipher suite, certificate issuer).
- Custom output filters (e.g., only warnings, only redirect chain).
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import dataclass, asdict
from typing import Any
from urllib.parse import urlparse
import requests
from requests import Response
import urllib3
# Suppress insecure request warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ------------------------------------------------------------------------------
# HTTP Status Reference
# ------------------------------------------------------------------------------

@dataclass(frozen=True)
class HttpStatus:
    code: int
    text: str
    memo: str

# A comprehensive status code lookup table
HTTP_STATUS_MAP: dict[int, HttpStatus] = {
    100: HttpStatus(100, "Continue", "RFC 9110"),
    101: HttpStatus(101, "Switching Protocols", "RFC 9110"),
    102: HttpStatus(102, "Processing", "WebDAV: RFC 2518"),
    103: HttpStatus(103, "Early Hints",  "RFC 8297"),
    110: HttpStatus(110, "Response is Stale", "Obsolete"),
    111: HttpStatus(111, "Revalidation Failed", "Obsolete"),
    112: HttpStatus(112, "Disconnected Operation", "Obsolete"),
    113: HttpStatus(113, "Heuristic Expiration", "Obsolete"),
    199: HttpStatus(100, "Miscellaneous Warning", "Obsolete"),
    200: HttpStatus(200, "OK", "RFC 9110"),
    201: HttpStatus(201, "Created", "RFC 9110"),
    202: HttpStatus(202, "Accepted", "RFC 9110"),
    203: HttpStatus(203, "Non-Authoritative Information (since HTTP/1.1)", "RFC 9110"),
    204: HttpStatus(204, "No Content", "RFC 9110"),
    205: HttpStatus(205, "Reset Content", "RFC 9110"),
    206: HttpStatus(206, "Partial Content", "RFC 9110"),
    207: HttpStatus(207, "Multi-Status", "WebDAV: RFC 4918"),
    208: HttpStatus(208, "Already Reported", "WebDAV: RFC 5842"),
    214: HttpStatus(214, "Transformation Applied", "Obsolete"),
    218: HttpStatus(218, "This is fine", "Unofficial: Apache HTTP Server"),
    226: HttpStatus(226, "IM Used", "RFC 3229"),
    299: HttpStatus(200, "Miscellaneous Persistent Warning", "Obsolete"),
    300: HttpStatus(300, "Multiple Choices", "RFC 9110"),
    301: HttpStatus(301, "Moved Permanently or Forced SSL", "RFC 9110"),
    302: HttpStatus(302, "Found (Previously \"Moved temporarily\")", "RFC 9110"),
    303: HttpStatus(303, "See Other (since HTTP/1.1)", "RFC 9110"),
    304: HttpStatus(304, "Not Modified", "RFC 9110"),
    305: HttpStatus(305, "Use Proxy (since HTTP/1.1)", "RFC 9110, RFC 7231"),
    306: HttpStatus(306, "Switch Proxy", "RFC 9110"),
    307: HttpStatus(307, "Temporary Redirect (since HTTP/1.1)", "RFC 9110"),
    308: HttpStatus(308, "Permanent Redirect", "RFC 9110, RFC 7538"),
    400: HttpStatus(400, "Bad Request", "RFC 9110"),
    401: HttpStatus(401, "Unauthorized", "RFC 9110"),
    402: HttpStatus(402, "Payment Required", "RFC 9110"),
    403: HttpStatus(403, "Forbidden", "RFC 9110"),
    404: HttpStatus(404, "Not Found", "RFC 9110"),
    405: HttpStatus(405, "Method Not Allowed", "RFC 9110"),
    406: HttpStatus(406, "Not Acceptable", "RFC 9110"),
    407: HttpStatus(407, "Proxy Authentication Required", "RFC 9110"),
    408: HttpStatus(408, "Request Timeout", "RFC 9110"),
    409: HttpStatus(409, "Conflict", "RFC 9110"),
    410: HttpStatus(410, "Gone", "RFC 9110"),
    411: HttpStatus(411, "Length Required", "RFC 9110"),
    412: HttpStatus(412, "Precondition Failed", "RFC 9110"),
    413: HttpStatus(413, "Payload Too Large", "RFC 9110"),
    414: HttpStatus(414, "URI Too Long", "RFC 9110"),
    415: HttpStatus(415, "Unsupported Media Type", "RFC 9110"),
    416: HttpStatus(416, "Range Not Satisfiable", "RFC 9110"),
    417: HttpStatus(417, "Expectation Failed", "RFC 9110"),
    418: HttpStatus(418, "I'm a teapot", "RFC 2324, RFC 7168"),
    419: HttpStatus(410, "Page Expired", "Unofficial: Laravel Framework"),
    420: HttpStatus(420, "Method Failure", "Unofficial: Spring Framework"),
    421: HttpStatus(421, "Misdirected Request", "RFC 9110"),
    422: HttpStatus(422, "Unprocessable Content", "RFC 9110"),
    423: HttpStatus(423, "Locked", "WebDAV: RFC 4918"),
    424: HttpStatus(424, "Failed Dependency", "WebDAV: RFC 4918"),
    425: HttpStatus(425, "Too Early", "RFC 8470"),
    426: HttpStatus(426, "Upgrade Required", "RFC 9110"),
    428: HttpStatus(428, "Precondition Required", "RFC 6585"),
    429: HttpStatus(429, "Too Many Requests", "RFC 6585"),
    430: HttpStatus(430, "Shopify Security Rejection", "Unofficial: Shopify"),
    431: HttpStatus(431, "Request Header Fields Too Large", "RFC 6585"),
    440: HttpStatus(440, "Login Time-out", "Unofficial: IIS"),
    444: HttpStatus(444, "No Response", "Unofficial: NGinx"),
    449: HttpStatus(449, "Retry With", "Unofficial: IIS"),
    450: HttpStatus(450, "Blocked by Windows Parental Controls", "Unofficial: Microsoft"),
    451: HttpStatus(451, "Unavailable For Legal Reasons", "RFC 7725"),
    494: HttpStatus(494, "Request header too large", "Unofficial: NGinx"),
    495: HttpStatus(495, "SSL Certificate Error", "Unofficial: NGinx"),
    496: HttpStatus(496, "SSL Certificate Required", "Unofficial: NGinx"),
    497: HttpStatus(497, "HTTP Request Sent to HTTPS Port", "Unofficial: NGinx"),
    498: HttpStatus(498, "Invalid Token", "Unofficial: Esri"),
    499: HttpStatus(499, "Client Closed Request", "Unofficial: NGinx"),
    500: HttpStatus(500, "Internal Server Error", "RFC 9110"),
    501: HttpStatus(501, "Not Implemented", "RFC 9110"),
    502: HttpStatus(502, "Bad Gateway", "RFC 9110"),
    503: HttpStatus(503, "Service Unavailable", "RFC 9110"),
    504: HttpStatus(504, "Gateway Timeout", "RFC 9110"),
    505: HttpStatus(505, "HTTP Version Not Supported", "RFC 9110"),
    506: HttpStatus(506, "Variant Also Negotiates", "RFC 2295"),
    507: HttpStatus(507, "Insufficient Storage", "WebDAV: RFC 4918"),
    508: HttpStatus(508, "Loop Detected", "WebDAV: RFC 5842"),
    509: HttpStatus(509, "Bandwidth Limit Exceeded", "Unofficial: Apache Web Server/cPanel"),
    510: HttpStatus(510, "Not Extended", "RFC 2774"),
    511: HttpStatus(511, "Network Authentication Required", "RFC 6585"),
    520: HttpStatus(520, "Web Server Returned an Unknown Error", "Unofficial: Cloudflare"),
    521: HttpStatus(521, "Web Server Is Down", "Unofficial: Cloudflare"),
    522: HttpStatus(522, "Connection Timed Out", "Unofficial: Cloudflare"),
    523: HttpStatus(523, "Origin Is Unreachable", "Unofficial: Cloudflare"),
    524: HttpStatus(524, "A Timeout Occurred", "Unofficial: Cloudflare"),
    525: HttpStatus(525, "SSL Handshake Failed", "Unofficial: Cloudflare"),
    526: HttpStatus(526, "Invalid SSL Certificate", "Unofficial: Cloudflare"),
    527: HttpStatus(527, "Railgun Error", "Obsolete: Cloudflare"),
    529: HttpStatus(529, "Site is overloaded", "Unofficial: Pantheon"),
    530: HttpStatus(530, "See additonal 1xx code", "Unofficial: Cloudflare"),
    540: HttpStatus(540, "Temporarily Disabled", "Unofficial: Shopify"),
    598: HttpStatus(598, "Network read timeout error", "Unofficial: Informal convention"),
    599: HttpStatus(599, "Network Connect Timeout Error", "Unofficial"),
    783: HttpStatus(783, "Unexpected Token", "Unofficial: Shopify"),
}

def get_status_info(code: int) -> HttpStatus:
    """
    Retrieve HTTP status info for the given code.
    """

    return HTTP_STATUS_MAP.get(code, HttpStatus(code, "Unknown Status", "N/A"))

# ------------------------------------------------------------------------------
# Header Redaction
# ------------------------------------------------------------------------------

SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "x-xsrf-token",
    "x-api-key",
    "x-auth-token",
}

def redact_headers(headers: dict[str, str], enabled: bool = False) -> dict[str, str]:
    """
    Return a copy of headers with sensitive keys redacted if redaction is enabled.
    """

    if not enabled:
        return dict(headers)

    redacted = {}

    for k, v in headers.items():
        if k.lower() in SENSITIVE_HEADERS:
            redacted[k] = "<REDACTED>"
        else:
            redacted[k] = v

    return redacted


# ------------------------------------------------------------------------------
# Core Redirect Tracker
# ------------------------------------------------------------------------------

def track_redirects(url: str, verify_ssl: bool = True, redact: bool = False) -> dict[str, Any]:
    """
    Follow HTTP redirects for the given URL and return structured info.

    Includes:
        - Redirect chain with headers.
        - HTTPS upgrade detection.
        - Optional header redaction.

    Args:
        url (str): The starting URL.
        verify_ssl (bool): Whether to verify SSL certificates.
        redact (bool): Whether to redact sensitive headers.

    Returns:
        dict: Structured result data.
    """

    result: dict[str, Any] = {
        "initial_url": url,
        "redirects": [],
        "final_url": None,
        "final_status": None,
        "https_upgrade": None,
        "upgrade_step": None,
        "warnings": [],
        "success": False,
    }

    try:
        response: Response = requests.get(url, verify=verify_ssl, allow_redirects=True, timeout=10)
        response.raise_for_status()

        # --- No Redirect Case ---
        if not response.history:
            result["final_url"] = response.url
            result["final_status"] = asdict(get_status_info(response.status_code))
            result["final_headers"] = redact_headers(response.headers, redact)
            result["success"] = True

            if urlparse(url).scheme.lower() != "https":
                result["https_upgrade"] = False
                result["warnings"].append("No HTTPS upgrade occurred — connection remained insecure (HTTP).")
            else:
                result["https_upgrade"] = True

            return result

        # --- Redirect Chain Analysis ---
        chain_urls = [resp.url for resp in response.history] + [response.url]
        upgraded_to_https = False
        upgrade_step = None

        for i, resp in enumerate(response.history):
            status_info = get_status_info(resp.status_code)
            next_url = response.history[i + 1].url if i + 1 < len(response.history) else response.url
            redirect_entry = {
                "from": resp.url,
                "to": next_url,
                "status": asdict(status_info),
                "request_headers": redact_headers(resp.request.headers, redact),
                "response_headers": redact_headers(resp.headers, redact),
            }
            result["redirects"].append(redirect_entry)

            # Detect HTTP→HTTPS upgrade
            current_scheme = urlparse(resp.url).scheme.lower()
            next_scheme = urlparse(next_url).scheme.lower()

            if not upgraded_to_https and current_scheme == "http" and next_scheme == "https":
                upgraded_to_https = True
                upgrade_step = i

        # --- Final Target ---
        final_status = get_status_info(response.status_code)
        result["final_url"] = response.url
        result["final_status"] = asdict(final_status)
        result["final_headers"] = redact_headers(response.headers, redact)
        result["success"] = True

        # --- HTTPS Upgrade Logic ---
        initial_scheme = urlparse(chain_urls[0]).scheme.lower()
        final_scheme = urlparse(chain_urls[-1]).scheme.lower()

        if initial_scheme == "http" and final_scheme == "https":
            result["https_upgrade"] = True
            result["upgrade_step"] = upgrade_step
            if upgrade_step == 0:
                pass  # Ideal
            else:
                result["warnings"].append(
                    "HTTPS upgrade occurred after the first redirect (suboptimal chain)."
                )
        elif initial_scheme == "https":
            result["https_upgrade"] = True
        else:
            result["https_upgrade"] = False
            result["warnings"].append("No HTTPS upgrade occurred — chain remained insecure (HTTP).")

        return result

    except requests.exceptions.RequestException as exc:
        result["warnings"].append(f"Request failed: {exc}")

        return result

# ------------------------------------------------------------------------------
# Output Helpers
# ------------------------------------------------------------------------------

def print_human(result: dict[str, Any]) -> None:
    """
    Pretty-print results in human-readable form.
    """

    print(f"Initial URL: {result['initial_url']}")

    if not result["redirects"]:
        print("No redirects detected.")
    else:
        print("Redirect chain:")
        for i, step in enumerate(result["redirects"], 1):
            status = step["status"]
            print(f"{i}. {step['from']} -> {status['code']} {status["text"]}")
            print(f"   ↳ {step['to']}")
            print()
            print(f"Request headers: {json.dumps(step['request_headers'], indent=2)}")
            print()
            print(f"Response headers: {json.dumps(step['response_headers'], indent=2)}")
            print()

    final_status = result.get("final_status")
    if final_status:
        print(f"Final URL: {result['final_url']} -> {final_status['code']} {final_status['text']}")
        print()

    if "final_headers" in result:
        print(f"Final response headers: {json.dumps(result['final_headers'], indent=2)}")

    for warning in result.get("warnings", []):
        print(f"Warning: {warning}")

    if result.get("https_upgrade") and not result.get("warnings"):
        print("HTTPS upgrade confirmed or already secure.")

def print_json(result: dict[str, Any]) -> None:
    """
    Emit result as JSON with headers included.
    """

    print(json.dumps(result, indent=2, ensure_ascii=False))

# ------------------------------------------------------------------------------
# Command-Line Interface
# ------------------------------------------------------------------------------

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Trace HTTP redirects for a given URL."
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL to trace."
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Skip SSL certificate verification (insecure)."
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results in JSON format."
    )

    parser.add_argument(
        "-r",
        "--redact-headers",
        action="store_true",
        help="Redact sensitive headers (safe for sharing)."
    )

    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    url = args.url.strip()

    parsed = urlparse(url)

    if not parsed.scheme or not parsed.netloc:
        print(f"Invalid URL: {url}")

        return 1

    result = track_redirects(url, verify_ssl=not args.insecure, redact=args.redact_headers)

    if args.json:
        print_json(result)
    else:
        print_human(result)

    return 0 if result.get("success") else 2

if __name__ == "__main__":
    sys.exit(main())

# end of script
