# # CSV input (header row will be skipped)
# python script.py input_hostnames.csv

# # Plain text input (no header, one hostname per line)
# python script.py input_hostnames.txt

# # Plain text input with no extension at all
# python script.py hostnames_list

# # Optionally specify a custom output file
# python script.py input_hostnames.csv -o my_results.csv


import argparse
import csv
import json
import os
import requests
from akamai.edgegrid import EdgeGridAuth
from urllib.parse import urljoin

# Akamai EdgeGrid credentials configuration
AKAMAI_HOST = "https://akaa-baseurl-xxxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net"
AKAMAI_ACCESS_TOKEN = "akaa-access-token-xxx-xxx"
AKAMAI_CLIENT_TOKEN = "akaa-client-token-xxx-xxx"
AKAMAI_CLIENT_SECRET = "client-secret-xxx-xxx"


# API endpoint
CERT_CHALLENGE_ENDPOINT = "/papi/v1/hostnames/certificate-challenges"

# Query parameters for the API request
CONTRACT_ID = "YOUR-CONTRACT-ID"
GROUP_ID = "YOUR-GROUP-ID"
ACCOUNT_SWITCH_KEY = "YOUR-ACCOUNT-SWITHKEY"  # Your account switch key


def setup_akamai_session():
    """Setup and return an Akamai EdgeGrid authenticated session."""
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=AKAMAI_CLIENT_TOKEN,
        client_secret=AKAMAI_CLIENT_SECRET,
        access_token=AKAMAI_ACCESS_TOKEN
    )
    return session


def read_hostnames(input_file):
    """
    Read hostnames and zones from the input file.

    - If the file has a .csv extension, treat it as CSV with a header row
      (the first line is a column name and is skipped; reads both hostname
      and zone columns).
    - Otherwise, treat it as a plain text file with comma-separated values
      (no header, one hostname,zone pair per line).
    """
    hostnames = []
    zones = []
    _, ext = os.path.splitext(input_file)

    if ext.lower() == '.csv':
        with open(input_file, newline='') as f:
            reader = csv.reader(f)
            rows = list(reader)
            if not rows:
                return hostnames, zones
            # Skip header row
            for row in rows[1:]:
                if row and row[0].strip():
                    hostnames.append(row[0].strip())
                    zone = row[1].strip() if len(row) > 1 else ""
                    zones.append(zone)
    else:
        with open(input_file) as f:
            for line in f:
                line = line.strip()
                if line:
                    parts = line.split(',')
                    hostnames.append(parts[0].strip())
                    zone = parts[1].strip() if len(parts) > 1 else ""
                    zones.append(zone)

    return hostnames, zones


def get_sbd_certificate_challenges(session, hostnames):
    """
    POST a request to Akamai PAPI to generate Secure by Default
    certificate challenges for the given list of hostnames.

    Request body format:
        {"cnamesFrom": ["www.example1.com", "www.example2.com"]}

    Query parameters:
        - contractId
        - groupId
        - accountSwitchKey
    """
    url = urljoin(AKAMAI_HOST, CERT_CHALLENGE_ENDPOINT)

    params = {
        "contractId": CONTRACT_ID,
        "groupId": GROUP_ID,
        "accountSwitchKey": ACCOUNT_SWITCH_KEY
    }

    payload = {
        "cnamesFrom": hostnames
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = session.post(url, params=params, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    return response.json()


def parse_challenge_response(data):
    """
    Parse the API response into a list of (hostname, cname_challenge, cname_target) tuples,
    based on the confirmed response structure:

    {
      "accountId": "...",
      "hostnames": {
        "items": [
          {
            "cnameFrom": "www.example1.com",
            "validationCname": {
              "hostname": "_acme-challenge.www.example1.com",
              "target": "ac.xxxx.www.example1.com.validate-akdv.net"
            }
          },
          ...
        ]
      }
    }
    """
    results = []

    items = data.get("hostnames", {}).get("items", [])

    for item in items:
        hostname = item.get("cnameFrom", "n/a")
        validation_cname = item.get("validationCname", {})
        cname_challenge = validation_cname.get("hostname", "n/a")
        cname_target = validation_cname.get("target", "n/a")

        results.append((hostname, cname_challenge, cname_target))

    return results


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate Akamai Secure by Default certificate challenges for a list of hostnames."
    )
    parser.add_argument(
        "input_file",
        help="Path to the input file. If it has a .csv extension, it is "
             "treated as CSV with a header row. Otherwise, it is treated "
             "as a plain text file with one hostname per line."
    )
    parser.add_argument(
        "-o", "--output",
        default="output_sbd_cname_challenges.csv",
        help="Path to the output CSV file (default: output_sbd_cname_challenges.csv)"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_file = args.input_file
    output_file = args.output

    if not os.path.isfile(input_file):
        print(f"Error: input file '{input_file}' not found.")
        return

    session = setup_akamai_session()

    hostnames, zones = read_hostnames(input_file)  # Now returns both

    if not hostnames:
        print("No hostnames found in input file.")
        return

    try:
        print(f"Requesting certificate challenges for {len(hostnames)} hostname(s)...")
        data = get_sbd_certificate_challenges(session, hostnames)
        results = parse_challenge_response(data)
        print(f"Successfully retrieved {len(results)} challenge(s).")
    except requests.exceptions.HTTPError as e:
        print(f"HTTP Error: {e.response.status_code} - {e.response.text}")
        return
    except Exception as e:
        print(f"Error: {e}")
        return

    with open(output_file, 'w', newline='') as csvfile_out:
        writer = csv.writer(csvfile_out)
        writer.writerow(['hostname', 'zone', 'cname_challenge', 'cname_target'])
        for i, (hostname, cname_challenge, cname_target) in enumerate(results):
            writer.writerow([hostname, zones[i], cname_challenge, cname_target])

    print(f"Done. Results written to {output_file}")

if __name__ == "__main__":
    main()
