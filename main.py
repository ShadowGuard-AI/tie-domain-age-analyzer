import argparse
import logging
import re
import sys
from datetime import datetime, timezone

import requests
import whois

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

DOMAIN_RE = re.compile(
    r'^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$'
)


def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='tie-Domain-Age-Analyzer: Determines domain age and checks Wayback Machine.')
    parser.add_argument('domain', help='The domain name to analyze.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (DEBUG level).')
    parser.add_argument('--timeout', type=int, default=30, help='Timeout in seconds for the WHOIS query and the Wayback request (default: 30).')
    return parser


def _normalize_date(value):
    """Convert a creation date to a naive UTC datetime, or return None."""
    if isinstance(value, datetime):
        if value.tzinfo is not None:
            return value.astimezone(timezone.utc).replace(tzinfo=None)
        return value
    return None


def get_domain_age(domain, timeout=30):
    """
    Calculates the age of a domain in days using WHOIS information.

    Returns:
        tuple: (age_in_days, error) where exactly one element is set.
        error is one of "not_registered", "query_failed", "no_creation_date",
        or "future_creation_date".
    """
    try:
        domain_info = whois.whois(domain, timeout=timeout)
    except whois.parser.PywhoisError as e:
        logging.error(f"WHOIS query failed for {domain}: {e}")
        return None, "not_registered"
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching WHOIS data for {domain}: {e}")
        return None, "query_failed"

    raw = domain_info.creation_date
    if not raw:
        logging.warning(f"No creation date found in WHOIS data for {domain}.")
        return None, "no_creation_date"

    dates = raw if isinstance(raw, list) else [raw]
    normalized = [d for d in (_normalize_date(item) for item in dates) if d is not None]
    if not normalized:
        logging.warning(f"Could not parse creation date for {domain}: {raw!r}")
        return None, "no_creation_date"

    creation_date = min(normalized)
    now = datetime.now()
    if creation_date > now:
        logging.error(f"Creation date for {domain} is in the future: {creation_date}")
        return None, "future_creation_date"

    logging.info(f"Domain {domain} creation date: {creation_date}")
    return (now - creation_date).days, None


def check_wayback_machine(domain, timeout=30):
    """
    Returns the earliest archived URL for a domain from the Wayback CDX index.

    The CDX listing is ordered by capture time, so its first row is the
    earliest capture, not the snapshot closest to now.

    Returns:
        tuple: (url_or_none, failed) where failed is True only when the
        Wayback request itself could not be completed or parsed. A domain
        with no captures returns (None, False).
    """
    try:
        response = requests.get(
            "https://web.archive.org/cdx/search/cdx",
            params={"url": domain, "output": "json", "limit": 1, "fl": "timestamp,original"},
            timeout=timeout,
        )
    except requests.exceptions.RequestException as e:
        logging.error(f"Error accessing Wayback Machine for {domain}: {e}")
        return None, True

    if response.status_code != 200:
        logging.error(f"Wayback Machine request for {domain} returned HTTP {response.status_code}.")
        return None, True

    try:
        rows = response.json()
    except ValueError as e:
        logging.error(f"Error decoding Wayback Machine response for {domain}: {e}")
        return None, True

    if rows and rows[0] == ["timestamp", "original"]:
        rows = rows[1:]

    if not rows:
        logging.info(f"Domain {domain} has no captures in the Wayback Machine.")
        return None, False

    first = rows[0]
    if not isinstance(first, list) or len(first) < 2:
        logging.error(f"Malformed Wayback Machine response for {domain}.")
        return None, True
    timestamp, original = first[0], first[1]
    earliest_url = f"https://web.archive.org/web/{timestamp}/{original}"
    logging.info(f"Earliest Wayback Machine URL for {domain}: {earliest_url}")
    return earliest_url, False


def is_valid_domain(domain):
    """
    Validates the format of the input domain name against a strict
    domain pattern, rejecting query characters and other URL syntax.
    """
    if not isinstance(domain, str) or not domain:
        logging.error("Invalid input: Domain must be a non-empty string.")
        return False
    if not DOMAIN_RE.match(domain):
        logging.error(f"Invalid input: {domain!r} is not a valid domain name.")
        return False
    return True


def main():
    """
    Main function to execute the domain age analysis and Wayback Machine check.
    """
    parser = setup_argparse()
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Verbose logging enabled.")

    domain = args.domain

    if not is_valid_domain(domain):
        sys.exit(1)

    failed = False

    domain_age, age_error = get_domain_age(domain, timeout=args.timeout)
    if age_error == "not_registered":
        print(f"Domain {domain} does not appear to be registered (WHOIS returned no record).")
        failed = True
    elif age_error == "no_creation_date":
        print(f"WHOIS record for {domain} carries no creation date; the age of the domain could not be measured.")
        failed = True
    elif age_error == "future_creation_date":
        print(f"Invalid WHOIS data for {domain}: the creation date is in the future, so no age can be reported.")
        failed = True
    elif age_error is not None:
        print(f"WHOIS lookup failed for {domain}; the age of the domain could not be measured.")
        failed = True
    else:
        print(f"Domain {domain} is {domain_age} days old.")

    earliest_wayback_url, wayback_failed = check_wayback_machine(domain, timeout=args.timeout)
    if wayback_failed:
        print(f"Wayback Machine lookup failed for {domain}; no archive result was retrieved.")
        failed = True
    elif earliest_wayback_url:
        print(f"Earliest Wayback Machine URL for {domain}: {earliest_wayback_url}")
    else:
        print(f"Domain {domain} not found in the Wayback Machine.")

    if failed:
        sys.exit(1)


if __name__ == "__main__":
    main()
