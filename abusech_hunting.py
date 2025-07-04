################################################
## Author: Nico Thelen                        ##
## MIT License                                ##
## www.linkedin.com/in/nico-thelen-5bbb6a289  ##
################################################

import re
import sys
import json
import argparse
import requests
import logging
import os

# Define the Abuse.ch API endpoints
MALWAREBAZAAR_API   = 'https://mb-api.abuse.ch/api/v1/'         # MalwareBazaar hash reporting API
YARAIFY_API         = 'https://yaraify-api.abuse.ch/api/v1/'    # Yaraify rule generation API
URLHAUS_API         = 'https://urlhaus-api.abuse.ch/v1/'        # URLhaus IOC lookup API
THREATFOX_API       = 'https://threatfox-api.abuse.ch/api/v1/'  # ThreatFox IOC search API

# Regular expressions to detect IOC type
IOC_PATTERNS = {
    'ipv4': re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'),   # Valid IPv4 addresses
    'domain': re.compile(r'^(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,}$'),    # Domains
    'url': re.compile(r'^(?:http|https)://'),                       # URLs
    'md5': re.compile(r'^[A-Fa-f0-9]{32}$'),                        # MD5 hashes
    'sha256': re.compile(r'^[A-Fa-f0-9]{64}$'),                     # SHA256 hashes
}


# Replace dots in IOCs to defang for logging
def defang_ioc(ioc):
    return ioc.replace('.', '[.]')


# Determine IOC type by matching regex patterns
def detect_ioc_type(ioc):
    for ioc_type, pattern in IOC_PATTERNS.items():
        if pattern.match(ioc):
            return ioc_type
    return None


# Query MalwareBazaar, ioc: MD5 or SHA256 hash, headers: authentication header
def query_malwarebazaar(ioc, headers):
    payload = {'query': 'get_info', 'hash': ioc}

    try:
        response = requests.post(MALWAREBAZAAR_API, headers=headers, data=payload)
        response.raise_for_status()
        return response.json()
    
    except requests.RequestException as error:
        logging.error(f"MalwareBazaar query failed for {defang_ioc(ioc)}: {error}")
        return {'error': f'MalwareBazaar query failed: {error}'}


# Query Yaraify, ioc: MD5 or SHA256 hash, headers: authentication header
def query_yaraify(ioc, headers):
    payload = {'query': 'lookup_hash', 'search_term': ioc}
    try:
        response = requests.post(YARAIFY_API, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    
    except requests.RequestException as error:
        logging.error(f"Yaraify lookup_hash query failed for {defang_ioc(ioc)}: {error}")
        return {'error': f"Yaraify lookup_hash query failed: {error}"}
    

# Query URLhaus, ioc: IOC string, ioc_type: type from detect_ioc_type, headers: auth header
def query_urlhaus(ioc, ioc_type, headers):
    # Select endpoint based on IOC type
    if ioc_type == 'url':
        endpoint = URLHAUS_API + 'url/'
        data = {'url': ioc}

    elif ioc_type in ('domain', 'ipv4'):
        endpoint = URLHAUS_API + 'host/'
        data = {'host': ioc}

    else:
        endpoint = URLHAUS_API + 'payload/'
        if len(ioc) == 32:  # Use MD5 or SHA256 parameter
            data = {'md5_hash': ioc}
        else:
            data = {'sha256_hash': ioc}

    try:
        response = requests.post(endpoint, headers=headers, data=data)
        response.raise_for_status()
        return response.json()
    
    except requests.RequestException as error:
        logging.error(f"URLhaus query failed for {defang_ioc(ioc)} ({ioc_type}): {error}")
        return {'error': f'URLhaus query failed: {error}'}


# Query ThreatFox, ioc: IOC string, ioc_type: detected type, headers: auth header
def query_threatfox(ioc, ioc_type, headers):
    # Build JSON payload for search
    if ioc_type in ('ipv4', 'domain', 'url'):
        payload = {'query': 'search_ioc', 'search_term': ioc, 'exact_match': True}
    else:
        payload = {'query': 'search_hash', 'hash': ioc}
    try:
        response = requests.post(THREATFOX_API, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()
    
    except requests.RequestException as error:
        logging.error(f"ThreatFox query failed for {defang_ioc(ioc)}: {error}")
        return {'error': f'ThreatFox query failed: {error}'}

    
# Aggregate all platform queries for a single IOC, ioc: IOC string, headers: auth header
def aggregate_ioc(ioc, headers):
    ioc_type = detect_ioc_type(ioc)

    if not ioc_type:
        logging.warning(f"Unsupported IOC type: {defang_ioc(ioc)}")
        return {'error': 'Unsupported IOC type'}
    result = {'type': ioc_type}

    # Query MalwareBazaar for file hashes
    if ioc_type in ('md5', 'sha256'):
        result['malwarebazaar'] = query_malwarebazaar(ioc, headers)
        result['yaraify'] = query_yaraify(ioc, headers)

    # Always query URLhaus and ThreatFox
    result['urlhaus'] = query_urlhaus(ioc, ioc_type, headers)
    result['threatfox'] = query_threatfox(ioc, ioc_type, headers)

    return result


# Load IOCs from a file, one per line, ignore blank/comments, file_path: path to IOC list file
def load_iocs(file_path):
    ioc_list = []
    
    with open(file_path, 'r') as file_content:
        for line in file_content:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith('#'):
                ioc_list.append(cleaned)
    return ioc_list


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Aggregate IOC information across Abuse.ch platforms')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', help='File path containing IOCs, one per line')
    group.add_argument('-i', '--ioc',  help='Single IOC string to process')
    parser.add_argument('-t', '--token', help='Abuse.ch API token (required if not in env var "ABUSE_CH_API_TOKEN")')
    parser.add_argument('-o', '--output', help='Output JSON file path', default='abusech_intel.json')
    args = vars(parser.parse_args())

    # Parse arguments
    file = bool(args['file'])
    bulk_ioc = args['file'] if file else None
    single_ioc = args['ioc'].strip() if not file else None
    api_token = os.environ.get('ABUSE_CH_API_TOKEN', args["token"]) # Retrieve API Token from env or given argument
    output = args["output"]

    # Set up headers for authentication
    headers = {'Auth-Key': api_token}

    # Determine list of IOCs to process
    if file:
        ioc_items = load_iocs(bulk_ioc)
    else:
        ioc_items = [single_ioc]

    # Configure logging and running directory
    running_dir = os.path.dirname(os.path.realpath(__file__))
    logging.basicConfig(filename=os.path.join(running_dir, 'abusech_intel.log'), format='%(asctime)s - %(levelname)s - %(message)s', datefmt='%d.%m.%Y %H:%M:%S', level=logging.INFO)

    # Process each IOC and collect results
    aggregated_results = {}
    for ioc_value in ioc_items:
        logging.info(f"Processing IOC: {defang_ioc(ioc_value)}")
        aggregated_results[ioc_value] = aggregate_ioc(ioc_value, headers)

    # Write output to JSON file
    try:
        with open(os.path.join(running_dir, output), 'w') as o:
            o.write(json.dumps(aggregated_results, indent="\t"))
        logging.info(f"Results written to {output}")

    except IOError as error:
        logging.error(f"Error writing to file {output}: {error}")
        sys.exit(1)
