#!/usr/bin/env python3

"""
URL Redirection Tracker, Version 1.0.2-Beta (Do Not Distribute)
By Rick Pelletier (galiagante@gmail.com), 04 July 2024
Last updated: 25 October 2025

Trace HTTP redirects for a given URL, detect HTTPS upgrades,
and optionally emit structured JSON output. Includes header inspection,
with optional redaction of sensitive header fields.

Example:
    python redirect_tracker.py -u "http://example.com"
    python redirect_tracker.py -u "http://example.com" --json
    python redirect_tracker.py -u "http://example.com" --json --redact-headers

Features:
- Uses :mod:`http.HTTPStatus` for robust status‑code handling.
- Explicit type hints and exhaustive docstrings.
- All user‑facing data wrapped in immutable dataclasses.
- No global state – the main logic is pure, making it trivial to unit‑test.
- Explicit request timeout and optional SSL verification.
- Output is available in human‑readable or JSON format.

Potential future feature upgrades:
- Timing metrics (per redirect and total elapsed time).
- TLS details (protocol version, cipher suite, certificate issuer).
- Custom output filters (e.g., only warnings, only redirect chain).
"""

from __future__ import annotations
import argparse
import json
import sys
from dataclasses import asdict, dataclass, field
from http import HTTPStatus
from typing import Any
from collections.abc import Mapping
import requests
from requests import Response, Session
from urllib.parse import urlparse

# --------------------------------------------------------------------------- #
# Types
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class StatusInfo:
    """A small wrapper around HTTP status codes."""

    code: int
    code_msg: str

    @classmethod
    def from_code(cls, code: int) -> StatusInfo:
        """
        Construct a :class:`StatusInfo` from an integer status code.
        Uses :class:`http.HTTPStatus` for the canonical phrase.
        """

        try:
            http_status = HTTPStatus(code)
            code_msg = http_status.phrase
        except ValueError:
            code_msg = "Unknown Status"

        return cls(code=code, code_msg=code_msg)

@dataclass(frozen=True)
class RedirectEntry:
    """A record of a single redirect step."""

    from_url: str
    to_url: str
    status: StatusInfo
    request_headers: dict[str, str]
    response_headers: dict[str, str]

@dataclass
class TraceResult:
    """Immutable container for the complete redirect trace."""

    initial_url: str
    redirects: list[RedirectEntry] = field(default_factory=list)
    final_url: str | None = None
    final_status: StatusInfo | None = None
    final_headers: dict[str, str] | None = None
    https_upgrade: bool | None = None
    upgrade_step: int | None = None
    warnings: list[str] = field(default_factory=list)
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a serialisable dictionary representation."""

        return {
            "initial_url": self.initial_url,
            "redirects": [
                {
                    "from": e.from_url,
                    "to": e.to_url,
                    "status": asdict(e.status),
                    "request_headers": e.request_headers,
                    "response_headers": e.response_headers,
                }
                for e in self.redirects
            ],
            "final_url": self.final_url,
            "final_status": asdict(self.final_status) if self.final_status else None,
            "final_headers": self.final_headers,
            "https_upgrade": self.https_upgrade,
            "upgrade_step": self.upgrade_step,
            "warnings": self.warnings,
            "success": self.success,
        }

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Headers that should be redacted when the user asks for it.
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

def redact_headers(
    headers: Mapping[str, str], *, enabled: bool = False) -> dict[str, str]:
    """
    Return a copy of *headers* with any sensitive keys replaced by ``<REDACTED>``.
    The function is case‑insensitive – header names are normalised to lower‑case
    for comparison.
    """

    if not enabled:
        return dict(headers)

    redacted: dict[str, str] = {}

    for key, value in headers.items():
        if key.lower() in SENSITIVE_HEADERS:
            redacted[key] = "<REDACTED>"
        else:
            redacted[key] = value

    return redacted

# --------------------------------------------------------------------------- #
# Core logic
# --------------------------------------------------------------------------- #

def track_redirects(url: str, *, verify_ssl: bool = True, redact: bool = False, timeout: float = 10.0) -> TraceResult:
    """
    Follow *url* until the final destination is reached, collecting
    information about every redirect step.

    Parameters
    ----------
    url : str
        Target URL.
    verify_ssl : bool, optional
        Whether to validate the server’s SSL certificate.
    redact : bool, optional
        Whether to replace sensitive headers with ``<REDACTED>``.
    timeout : float, optional
        Timeout (seconds) for each HTTP request.

    Returns
    -------
    TraceResult
        A data structure containing the entire trace.
    """

    result = TraceResult(initial_url=url)

    session = Session()
    session.verify = verify_ssl

    try:
        response: Response = session.get(
            url,
            allow_redirects=True,
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.exceptions.RequestException as exc:
        result.warnings.append(f"Request failed: {exc}")

        return result  # success remains False

    # Helper to convert requests.Response into a RedirectEntry
    def entry_from_resp(resp: Response, next_resp: Response | None = None) -> RedirectEntry:
        next_url = next_resp.url if next_resp else resp.url
        status = StatusInfo.from_code(resp.status_code)

        return RedirectEntry(
            from_url=resp.url,
            to_url=next_url,
            status=status,
            request_headers=redact_headers(resp.request.headers, enabled=redact),
            response_headers=redact_headers(resp.headers, enabled=redact),
        )

    # No redirect case
    if not response.history:
        result.final_url = response.url
        result.final_status = StatusInfo.from_code(response.status_code)
        result.final_headers = redact_headers(response.headers, enabled=redact)
        result.success = True

        scheme = urlparse(url).scheme.lower()
        result.https_upgrade = scheme == "https"

        if not result.https_upgrade:
            result.warnings.append(
                "No HTTPS upgrade – the initial connection was over HTTP."
            )

        return result

    # Build chain of RedirectEntry objects
    chain = list(response.history) + [response]

    for i, resp in enumerate(chain[:-1]):
        result.redirects.append(entry_from_resp(resp, chain[i + 1]))

    # Final target
    final_resp = chain[-1]
    result.final_url = final_resp.url
    result.final_status = StatusInfo.from_code(final_resp.status_code)
    result.final_headers = redact_headers(final_resp.headers, enabled=redact)
    result.success = True

    # HTTPS upgrade logic
    initial_scheme = urlparse(chain[0].url).scheme.lower()
    final_scheme = urlparse(final_resp.url).scheme.lower()
    result.https_upgrade = initial_scheme != "http" or final_scheme == "https"

    if initial_scheme == "http" and final_scheme == "https":
        # find first http → https transition
        for idx, resp in enumerate(chain[:-1]):
            if (
                urlparse(resp.url).scheme.lower() == "http"
                and urlparse(chain[idx + 1].url).scheme.lower() == "https"
            ):
                result.upgrade_step = idx
                break
        if result.upgrade_step and result.upgrade_step > 0:
            result.warnings.append(
                "HTTPS upgrade occurred after the first redirect "
                "(sub‑optimal chain)."
            )
    elif initial_scheme == "https":
        result.upgrade_step = None
    else:
        result.warnings.append(
            "No HTTPS upgrade – the entire chain remained over HTTP."
        )

    return result

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

def print_human(result: TraceResult) -> None:
    """Print a human‑friendly summary of *result*."""

    print(f"Initial URL: {result.initial_url}")

    if not result.redirects:
        print("No redirects detected.")
    else:
        print("Redirect chain:")
        for i, step in enumerate(result.redirects, 1):
            print(f"{i}. {step.from_url} -> {step.status.code} {step.status.code_msg}")
            print(f"   ↳ {step.to_url}\n")
            print(f"   Request headers: {json.dumps(step.request_headers, indent=2)}\n")
            print(f"   Response headers: {json.dumps(step.response_headers, indent=2)}\n")

    if result.final_status:
        print(
            f"Final URL: {result.final_url} -> "
            f"{result.final_status.code} {result.final_status.code_msg}\n"
        )

    if result.final_headers:
        print(
            f"Final response headers: "
            f"{json.dumps(result.final_headers, indent=2)}\n"
        )

    for warning in result.warnings:
        print(f"Warning: {warning}")

    if result.https_upgrade and not result.warnings:
        print("HTTPS upgrade confirmed or already secure.")


def print_json(result: TraceResult) -> None:
    """Emit the result as a JSON document."""
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

# --------------------------------------------------------------------------- #
# Command‑line interface
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command‑line arguments."""

    parser = argparse.ArgumentParser(
        description="Trace HTTP redirects for a given URL."
    )

    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="Target URL to trace.",
    )

    parser.add_argument(
        "-k",
        "--insecure",
        action="store_true",
        help="Skip SSL certificate verification (insecure).",
    )

    parser.add_argument(
        "-j",
        "--json",
        action="store_true",
        help="Output results in JSON format.",
    )

    parser.add_argument(
        "-r",
        "--redact-headers",
        action="store_true",
        help="Redact sensitive headers (safe for sharing).",
    )

    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    """Entry point for the script."""

    args = parse_args(argv)

    parsed = urlparse(args.url)

    if not parsed.scheme or not parsed.netloc:
        print(f"Invalid URL: {args.url}")

        return 1

    result = track_redirects(
        args.url,
        verify_ssl=not args.insecure,
        redact=args.redact_headers,
    )

    if args.json:
        print_json(result)
    else:
        print_human(result)

    return 0 if result.success else 2

# --------------------------------------------------------------------------- #
# Guard
# --------------------------------------------------------------------------- #

if __name__ == "__main__":
    sys.exit(main())

# end of script
