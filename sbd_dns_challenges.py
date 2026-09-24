import argparse
import csv
import json
import os
import sys
import requests
from akamai.edgegrid import EdgeGridAuth
from urllib.parse import urljoin

# Akamai EdgeGrid credentials configuration
AKAMAI_HOST = "https://akaa-baseurl-xxxxxxxxxxxx-xxxxxxxxxxxxx.luna.akamaiapis.net"
AKAMAI_ACCESS_TOKEN = "akaa-access-token-xxx-xxx"
AKAMAI_CLIENT_TOKEN = "akaa-client-token-xxx-xxx"
AKAMAI_CLIENT_SECRET = "client-secret-xxx-xxx"


# Query parameters — same as used for PAPI calls
CONTRACT_ID = "YOUR-CONTRACT-ID"
GROUP_ID = "YOUR-GROUP-ID"
ACCOUNT_SWITCH_KEY = "YOUR-ACCOUNT-SWITHKEY"  # Your account switch key

DNS_API_BASE = "/config-dns/v2"

# TTL to use when creating/updating CNAME recordsets
DEFAULT_TTL = 300


def setup_akamai_session():
    """Setup and return an Akamai EdgeGrid authenticated session."""
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=AKAMAI_CLIENT_TOKEN,
        client_secret=AKAMAI_CLIENT_SECRET,
        access_token=AKAMAI_ACCESS_TOKEN
    )
    return session


def zone_exists(session, zone):
    """
    Check if a zone exists in Edge DNS.
    GET /config-dns/v2/zones/{zone}
    Returns True if 200, False if 404, raises on other errors.
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones/{zone}")
    params = {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}
    headers = {"accept": "application/json"}

    response = session.get(url, params=params, headers=headers)
    if response.status_code == 200:
        return True
    elif response.status_code == 404:
        return False
    else:
        response.raise_for_status()


def create_zone(session, zone):
    """
    Create a new primary zone in Edge DNS.
    POST /config-dns/v2/zones

    NOTE: Verify the required payload fields against the docs.
    Assumed minimal payload for a PRIMARY zone below.
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones")
    params = {"contractId": CONTRACT_ID}
    if GROUP_ID:
        params["gid"] = GROUP_ID
    if ACCOUNT_SWITCH_KEY:
        params["accountSwitchKey"] = ACCOUNT_SWITCH_KEY

    payload = {
        "zone": zone,
        "type": "PRIMARY",
        "comment": "Auto-created for SBD certificate CNAME validation"
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = session.post(url, params=params, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    return response.json() if response.text else {}


def get_recordset(session, zone, record_name, record_type="CNAME"):
    """
    Get an existing recordset.
    GET /config-dns/v2/zones/{zone}/names/{name}/types/{type}
    Returns the JSON body if found (200), None if not found (404),
    raises on other errors.
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones/{zone}/names/{record_name}/types/{record_type}")
    params = {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}
    headers = {"accept": "application/json"}

    response = session.get(url, params=params, headers=headers)
    if response.status_code == 200:
        return response.json()
    elif response.status_code == 404:
        return None
    else:
        response.raise_for_status()


def create_recordset(session, zone, record_name, target, record_type="CNAME", ttl=DEFAULT_TTL):
    """
    Create a new recordset.
    POST /config-dns/v2/zones/{zone}/names/{name}/types/{type}
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones/{zone}/names/{record_name}/types/{record_type}")
    params = {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}

    payload = {
        "name": record_name,
        "type": record_type,
        "ttl": ttl,
        "rdata": [normalize_target(target)]
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = session.post(url, params=params, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    return response.json() if response.text else {}


def update_recordset(session, zone, record_name, target, record_type="CNAME", ttl=DEFAULT_TTL):
    """
    Update an existing recordset.
    PUT /config-dns/v2/zones/{zone}/names/{name}/types/{type}
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones/{zone}/names/{record_name}/types/{record_type}")
    params = {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}

    payload = {
        "name": record_name,
        "type": record_type,
        "ttl": ttl,
        "rdata": [normalize_target(target)]
    }

    headers = {
        "accept": "application/json",
        "content-type": "application/json"
    }

    response = session.put(url, params=params, headers=headers, data=json.dumps(payload))
    response.raise_for_status()
    return response.json() if response.text else {}


def normalize_target(target):
    """Ensure the CNAME target ends with a trailing dot (FQDN format)."""
    target = target.strip()
    return target if target.endswith(".") else target + "."


def prompt_yes_no(question):
    """Simple interactive yes/no prompt. Defaults to 'no' on empty input."""
    while True:
        answer = input(f"{question} [y/N]: ").strip().lower()
        if answer in ("y", "yes"):
            return True
        if answer in ("", "n", "no"):
            return False
        print("Please answer 'y' or 'n'.")


def read_challenge_rows(input_file):
    """
    Read the input file with columns: zone, hostname, cname_challenge, cname_target
    """
    rows = []
    with open(input_file, newline='') as f:
        reader = csv.DictReader(f)

        required_columns = {"zone", "hostname", "cname_challenge", "cname_target"}
        if not required_columns.issubset(set(reader.fieldnames or [])):
            missing = required_columns - set(reader.fieldnames or [])
            raise ValueError(f"Input file is missing required column(s): {', '.join(missing)}")

        for row in reader:
            zone = row.get("zone", "").strip()
            hostname = row.get("hostname", "").strip()
            cname_challenge = row.get("cname_challenge", "").strip()
            cname_target = row.get("cname_target", "").strip()
            if zone and hostname and cname_challenge and cname_target:
                rows.append({
                    "zone": zone,
                    "hostname": hostname,
                    "cname_challenge": cname_challenge,
                    "cname_target": cname_target
                })
    return rows


def ensure_zone(session, zone, skip_zones, known_good_zones):
    """
    Ensure the zone exists, prompting to create it if missing.
    Returns True if the zone is usable (exists or was created),
    False if it should be skipped.
    """
    if zone in skip_zones:
        return False
    if zone in known_good_zones:
        return True

    try:
        exists = zone_exists(session, zone)
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Failed to check zone '{zone}': {e.response.status_code} - {e.response.text}")
        return False

    if exists:
        known_good_zones.add(zone)
        return True

    print(f"Zone '{zone}' does not exist in Edge DNS.")
    if prompt_yes_no(f"Create zone '{zone}'?"):
        try:
            create_zone(session, zone)
            print(f"[CREATED] Zone '{zone}' created.")
            known_good_zones.add(zone)
            return True
        except requests.exceptions.HTTPError as e:
            print(f"[ERROR] Failed to create zone '{zone}': {e.response.status_code} - {e.response.text}")
            return False
    else:
        print(f"[SKIP] User chose not to create zone '{zone}'.")
        skip_zones.add(zone)
        return False


def process_record(session, row, skip_zones, known_good_zones):
    """
    Process a single CNAME challenge record within its specified zone:
    - Ensure the zone exists (prompt to create if not)
    - Create or update the CNAME record as needed
    """
    zone = row["zone"]
    hostname = row["hostname"]
    record_name = row["cname_challenge"]
    target = row["cname_target"]

    if not ensure_zone(session, zone, skip_zones, known_good_zones):
        print(f"[SKIP] Skipping record '{record_name}' for hostname '{hostname}' (zone '{zone}' unavailable).")
        return

    try:
        existing = get_recordset(session, zone, record_name, "CNAME")
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Failed to check record '{record_name}' in zone '{zone}': {e.response.status_code} - {e.response.text}")
        return

    normalized_target = normalize_target(target)

    try:
        if existing is None:
            create_recordset(session, zone, record_name, target, "CNAME")
            print(f"[CREATED] {record_name} -> {normalized_target} (zone: {zone})")
        else:
            existing_rdata = existing.get("rdata", [])
            if existing_rdata == [normalized_target]:
                print(f"[UNCHANGED] {record_name} already points to {normalized_target} (zone: {zone})")
            else:
                update_recordset(session, zone, record_name, target, "CNAME")
                print(f"[UPDATED] {record_name} -> {normalized_target} (zone: {zone}, was: {existing_rdata})")
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Failed to create/update record '{record_name}' in zone '{zone}': {e.response.status_code} - {e.response.text}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create or update CNAME validation records in Akamai Edge DNS."
    )
    parser.add_argument(
        "input_file",
        help="CSV file with columns: zone, hostname, cname_challenge, cname_target"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_file = args.input_file

    if not os.path.isfile(input_file):
        print(f"Error: input file '{input_file}' not found.")
        sys.exit(1)

    try:
        rows = read_challenge_rows(input_file)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)

    if not rows:
        print("No valid rows found in input file.")
        return

    session = setup_akamai_session()

    skip_zones = set()        # zones the user chose not to create
    known_good_zones = set()  # zones confirmed to exist or just created

    for row in rows:
        print(f"\nProcessing hostname '{row['hostname']}' (record: {row['cname_challenge']}, zone: {row['zone']})...")
        process_record(session, row, skip_zones, known_good_zones)

    print("\nDone.")


if __name__ == "__main__":
    main()
