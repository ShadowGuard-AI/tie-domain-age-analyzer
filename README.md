# tie-Domain-Age-Analyzer
A command-line tool that takes a domain name as input and determines its age using WHOIS information. Outputs the domain age in days and also checks if the domain is listed in the Wayback Machine, providing the earliest archived URL if available. The earliest capture is taken from the Wayback CDX index listing, whose first row is the earliest capture. - Focused on Automates the process of gathering and correlating threat intelligence data from various open-source sources. Allows users to input indicators (e.g., IP addresses, domain names, hashes) and enrich them with information from WHOIS records, public threat feeds, and other relevant sources, facilitating quicker threat assessments and incident response.

## Install
`git clone https://github.com/ShadowStrikeHQ/tie-domain-age-analyzer`

## Usage
`./tie-domain-age-analyzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-v`: Enable verbose logging (DEBUG level).
- `--timeout`: Timeout in seconds for the WHOIS query and the Wayback request (default: 30).

## Notes
A failed WHOIS query, an unregistered domain, a WHOIS record with no creation date, a creation date in the future, and a failed Wayback request are each reported in their own words and exit non-zero; none of them is printed as a measured age or as a simple not-found result. Creation dates with a timezone offset are converted to UTC before the age is computed, and a list of creation dates uses the earliest one. Domain input must match a strict domain pattern; URL or query characters are rejected.

## License
Copyright (c) ShadowStrikeHQ
