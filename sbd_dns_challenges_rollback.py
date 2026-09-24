import argparse
import csv
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
ACCOUNT_SWITCH_KEY = "YOUR-ACCOUNT-SWITHKEY"

DNS_API_BASE = "/config-dns/v2"


def setup_akamai_session():
    """Setup and return an Akamai EdgeGrid authenticated session."""
    session = requests.Session()
    session.auth = EdgeGridAuth(
        client_token=AKAMAI_CLIENT_TOKEN,
        client_secret=AKAMAI_CLIENT_SECRET,
        access_token=AKAMAI_ACCESS_TOKEN
    )
    return session


def delete_recordset(session, zone, record_name, record_type="CNAME"):
    """
    Delete a recordset from Edge DNS.
    DELETE /config-dns/v2/zones/{zone}/names/{name}/types/{type}
    Returns True if successful (204 No Content), raises on errors.
    """
    url = urljoin(AKAMAI_HOST, f"{DNS_API_BASE}/zones/{zone}/names/{record_name}/types/{record_type}")
    params = {"accountSwitchKey": ACCOUNT_SWITCH_KEY} if ACCOUNT_SWITCH_KEY else {}
    headers = {"accept": "application/json"}

    response = session.delete(url, params=params, headers=headers)
    if response.status_code == 204:
        return True
    elif response.status_code == 404:
        # Record doesn't exist, nothing to delete
        return False
    else:
        response.raise_for_status()


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


def rollback_record(session, row):
    """
    Delete a single CNAME challenge record.
    """
    zone = row["zone"]
    hostname = row["hostname"]
    record_name = row["cname_challenge"]

    try:
        deleted = delete_recordset(session, zone, record_name, "CNAME")
        if deleted:
            print(f"[DELETED] {record_name} from zone '{zone}'")
        else:
            print(f"[NOT FOUND] {record_name} in zone '{zone}' (already deleted or doesn't exist)")
    except requests.exceptions.HTTPError as e:
        print(f"[ERROR] Failed to delete record '{record_name}' from zone '{zone}': {e.response.status_code} - {e.response.text}")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Rollback CNAME validation records from Akamai Edge DNS."
    )
    parser.add_argument(
        "input_file",
        help="CSV file with columns: zone, hostname, cname_challenge, cname_target "
             "(same input file used with create_dns_challenges.py)"
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Skip confirmation prompt and delete all records immediately"
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_file = args.input_file
    force = args.force

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

    print(f"Found {len(rows)} record(s) to delete:")
    for row in rows:
        print(f"  - {row['cname_challenge']} (zone: {row['zone']})")

    if not force and not prompt_yes_no("\nProceed with deletion?"):
        print("Rollback cancelled.")
        return

    session = setup_akamai_session()

    for row in rows:
        print(f"\nRolling back hostname '{row['hostname']}' (record: {row['cname_challenge']}, zone: {row['zone']})...")
        rollback_record(session, row)

    print("\nRollback complete.")


if __name__ == "__main__":
    main()
