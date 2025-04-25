import argparse
import logging
import sys
import time
import requests
import whois
from datetime import datetime
from urllib.parse import urljoin

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def setup_argparse():
    """
    Sets up the argument parser for the command-line interface.
    """
    parser = argparse.ArgumentParser(description='tie-Domain-Age-Analyzer: Determines domain age and checks Wayback Machine.')
    parser.add_argument('domain', help='The domain name to analyze.')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging (DEBUG level).')
    return parser

def get_domain_age(domain):
    """
    Calculates the age of a domain in days using WHOIS information.

    Args:
        domain (str): The domain name.

    Returns:
        int: The age of the domain in days, or None if an error occurs.
    """
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            # Handle cases where creation_date is a list
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            if creation_date:
                domain_age = (datetime.now() - creation_date).days
                logging.info(f"Domain {domain} creation date: {creation_date}")
                return domain_age
            else:
                logging.warning(f"Could not determine creation date for {domain}.")
                return None
        else:
            logging.warning(f"No creation date found in WHOIS data for {domain}.")
            return None
    except whois.parser.PywhoisError as e:
        logging.error(f"WHOIS query failed for {domain}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while fetching WHOIS data for {domain}: {e}")
        return None

def check_wayback_machine(domain):
    """
    Checks if a domain is listed in the Wayback Machine and returns the oldest archived URL.

    Args:
        domain (str): The domain name.

    Returns:
        str: The oldest archived URL, or None if not found.
    """
    try:
        url = f"http://archive.org/wayback/available?url={domain}"
        response = requests.get(url)
        response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)
        data = response.json()

        if data and 'archived_snapshots' in data and data['archived_snapshots']:
            if 'closest' in data['archived_snapshots']:
                oldest_url = data['archived_snapshots']['closest']['url']
                logging.info(f"Oldest Wayback Machine URL for {domain}: {oldest_url}")
                return oldest_url
            else:
                 logging.warning(f"No archived snapshots found for {domain} in wayback machine")
                 return None
        else:
            logging.info(f"Domain {domain} not found in the Wayback Machine.")
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error accessing Wayback Machine for {domain}: {e}")
        return None
    except Exception as e:
        logging.error(f"An unexpected error occurred while checking the Wayback Machine for {domain}: {e}")
        return None

def is_valid_domain(domain):
    """
    Validates the format of the input domain name.
    Simple check; consider more robust validation if needed.

    Args:
        domain (str): The domain name.

    Returns:
        bool: True if the domain is valid, False otherwise.
    """
    if not isinstance(domain, str):
        logging.error("Invalid input: Domain must be a string.")
        return False

    if not domain:
        logging.error("Invalid input: Domain cannot be empty.")
        return False

    if " " in domain:
        logging.error("Invalid input: Domain cannot contain spaces.")
        return False

    # Add more sophisticated validation here if needed (e.g., regex)
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

    domain_age = get_domain_age(domain)
    if domain_age is not None:
        print(f"Domain {domain} is {domain_age} days old.")
    else:
        print(f"Could not determine the age of domain {domain}.")

    oldest_wayback_url = check_wayback_machine(domain)
    if oldest_wayback_url:
        print(f"Oldest Wayback Machine URL for {domain}: {oldest_wayback_url}")
    else:
        print(f"Domain {domain} not found in the Wayback Machine.")


if __name__ == "__main__":
    main()