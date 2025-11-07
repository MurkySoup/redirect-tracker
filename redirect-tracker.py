#!/usr/bin/env python3

"""
URL Redirection Tracker, Version 1.1-Beta (Do Not Distribute)
By Rick Pelletier (galiagante@gmail.com), 04 July 2024
Last updated: 07 November 2025

Trace HTTP redirects for a given URL, detect HTTPS upgrades and downgrades,
and optionally emit structured JSON output. Includes header inspection,
with optional redaction of sensitive header fields.

Example:
    python redirect_tracker.py -u "http://example.com"
    python redirect_tracker.py -u "http://example.com" --json
    python redirect_tracker.py -u "http://example.com" --json --redact-headers
    python redirect_tracker.py -u "https://example.com" --downgrade-fatal

Linter: ruff check redirect-tracker.py --extend-select F,B,UP
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
    """Holds HTTP status code information."""
    code: int
    code_msg: str

    @classmethod
    def from_code(cls, code: int) -> StatusInfo:
        """Create a StatusInfo instance from a numeric code."""
        try:
            http_status = HTTPStatus(code)
            code_msg = http_status.phrase
        except ValueError:
            code_msg = "Unknown Status"

        return cls(code=code, code_msg=code_msg)

@dataclass(frozen=True)
class RedirectEntry:
    """Represents a single hop in a redirect chain."""
    from_url: str
    to_url: str
    status: StatusInfo
    request_headers: dict[str, str]
    response_headers: dict[str, str]

@dataclass
class TraceResult:
    """Contains the full results of a redirect trace."""
    initial_url: str
    redirects: list[RedirectEntry] = field(default_factory=list)
    final_url: str | None = None
    final_status: StatusInfo | None = None
    final_headers: dict[str, str] | None = None
    https_upgrade: bool | None = None
    upgrade_step: int | None = None
    https_downgrade: bool | None = None
    downgrade_step: int | None = None
    warnings: list[str] = field(default_factory=list)
    success: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Convert the result to a dictionary for JSON serialization."""
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
            "https_downgrade": self.https_downgrade,
            "downgrade_step": self.downgrade_step,
            "warnings": self.warnings,
            "success": self.success,
        }

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

# Extensible list of headers that should be redacted when the user asks for it.
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

def redact_headers(headers: Mapping[str, str], *, enabled: bool = False) -> dict[str, str]:
    """
    Redact sensitive values from a dictionary of headers.

    Args:
        headers: The original request or response headers.
        enabled: If True, redaction will be performed.

    Returns:
        A new dictionary of headers, potentially with redacted values.
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
    Traces all HTTP redirects from a starting URL.

    Args:
        url: The initial URL to trace.
        verify_ssl: Whether to verify SSL certificates.
        redact: Whether to redact sensitive headers in the output.
        timeout: Request timeout in seconds.

    Returns:
        A TraceResult object containing the full chain and analysis.
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
        # Note: We don't call raise_for_status() here, as a 4xx or 5xx
        # is a valid final state for a redirect chain. We'll capture
        # the final status code regardless.
    except requests.exceptions.RequestException as exc:
        result.warnings.append(f"Request failed: {exc}")
        return result  # success remains False

    # Helper to convert requests.Response into a RedirectEntry
    def entry_from_resp(resp: Response, next_resp: Response) -> RedirectEntry:
        """Create a RedirectEntry from two adjacent responses in the chain."""
        status = StatusInfo.from_code(resp.status_code)
        return RedirectEntry(
            from_url=resp.url,
            to_url=next_resp.url,
            status=status,
            request_headers=redact_headers(resp.request.headers, enabled=redact),
            response_headers=redact_headers(resp.headers, enabled=redact),
        )

    # --- Final state processing ---
    # The full chain is history (all but last) + response (last)
    chain = list(response.history) + [response]
    final_resp = chain[-1]
    result.final_url = final_resp.url
    result.final_status = StatusInfo.from_code(final_resp.status_code)
    result.final_headers = redact_headers(final_resp.headers, enabled=redact)
    result.success = True # We got a final response

    # --- No redirect case ---
    if not response.history:
        result.https_upgrade = False
        result.https_downgrade = False
        scheme = urlparse(result.final_url).scheme.lower()
        if scheme == "http":
            result.warnings.append(
                "No redirects – the connection remained over HTTP."
            )
        return result

    # --- Redirect case ---

    # Build chain of RedirectEntry objects
    for i, resp in enumerate(chain[:-1]):
        result.redirects.append(entry_from_resp(resp, chain[i + 1]))

    # --- Security analysis (Upgrade / Downgrade) ---
    result.https_upgrade = False
    result.https_downgrade = False

    found_upgrade = False
    found_downgrade = False

    for i in range(len(chain) - 1):
        from_scheme = urlparse(chain[i].url).scheme.lower()
        to_scheme = urlparse(chain[i+1].url).scheme.lower()

        # Check for first upgrade
        if from_scheme == "http" and to_scheme == "https" and not found_upgrade:
            result.https_upgrade = True
            result.upgrade_step = i
            found_upgrade = True

        # Check for first downgrade
        if from_scheme == "https" and to_scheme == "http" and not found_downgrade:
            result.https_downgrade = True
            result.downgrade_step = i
            found_downgrade = True

    # --- Add contextual warnings ---
    initial_scheme = urlparse(chain[0].url).scheme.lower()
    final_scheme = urlparse(final_resp.url).scheme.lower()

    if result.https_downgrade:
        result.warnings.append(
            f"SECURITY RISK: HTTPS to HTTP downgrade detected at step {result.downgrade_step}."
        )

    if result.https_upgrade:
        if result.upgrade_step is not None and result.upgrade_step > 0:
            result.warnings.append(
                "HTTPS upgrade occurred after the first redirect (sub-optimal chain)."
            )
    elif initial_scheme == "http" and final_scheme == "http":
        result.warnings.append(
            "No HTTPS upgrade – the entire chain remained over HTTP."
        )

    return result

# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #

def print_human(result: TraceResult) -> None:
    """Print the trace result in a human-readable format."""
    print(f"Initial URL: {result.initial_url}")

    if not result.redirects:
        print("No redirects detected.")
    else:
        print("Redirect chain:")
        for i, step in enumerate(result.redirects, 1):
            print(f"{i}. {step.from_url} -> {step.status.code} {step.status.code_msg}")
            print(f"    ↳ {step.to_url}")
            print(f"    Request headers: {json.dumps(step.request_headers, indent=2)}")
            print(f"    Response headers: {json.dumps(step.response_headers, indent=2)}")
            print() # Blank line for readability

    if result.final_status:
        print(
            f"Final URL: {result.final_url} -> "
            f"{result.final_status.code} {result.final_status.code_msg}"
        )
        print()

    if result.final_headers:
        print(
            f"Final response headers: "
            f"{json.dumps(result.final_headers, indent=2)}"
        )
        print()

    for warning in result.warnings:
        print(f"Warning: {warning}")

    # Print a final "good" status message only if no warnings were generated
    if not result.warnings and result.success:
        if result.https_upgrade:
            print("HTTPS upgrade confirmed (optimal chain).")
        else:
            # This covers https -> https (no redirect) and https -> https (redirects)
            print("Connection confirmed secure (HTTPS).")


def print_json(result: TraceResult) -> None:
    """Emit the result as a JSON document."""
    print(json.dumps(result.to_dict(), indent=2, ensure_ascii=False))

# --------------------------------------------------------------------------- #
# Command-line interface
# --------------------------------------------------------------------------- #

def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse command-line arguments."""
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

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=10.0,
        help="Request timeout in seconds (default: 10.0).",
    )

    return parser.parse_args(argv)

def main(argv: list[str] | None = None) -> int:
    """Main script entry point."""
    args = parse_args(argv)

    parsed = urlparse(args.url)

    if not parsed.scheme or not parsed.netloc:
        print(f"Invalid URL: {args.url}", file=sys.stderr)
        return 1

    result = track_redirects(
        args.url,
        verify_ssl=not args.insecure,
        redact=args.redact_headers,
        timeout=args.timeout,
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
