##### Needs work 

import argparse
import json
import dns.resolver
import time
from alive_progress import alive_it
from collections import Counter

def parse_bloodhound_computers(file_path):
    """
    Parses the BloodHound JSON file and extracts computer names.
    Handles JSON arrays, single JSON objects, and newline-delimited JSON (NDJSON).
    Args:
        file_path (str): Path to the BloodHound JSON file.
    Returns:
        list: List of computer names.
    """
    computer_names = []

    with open(file_path, 'r') as file:
        try:
            # Try to load the entire file as a JSON structure
            bloodhound_data = json.load(file)

            # If the JSON contains a "data" key with a list of objects
            if isinstance(bloodhound_data, dict) and "data" in bloodhound_data:
                for entry in bloodhound_data["data"]:
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
            # If it's a list of objects
            elif isinstance(bloodhound_data, list):
                for entry in bloodhound_data:
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
            # If it's a single dictionary object
            elif isinstance(bloodhound_data, dict):
                properties = bloodhound_data.get("Properties", {})
                if "name" in properties:
                    computer_names.append(properties["name"])
            else:
                print("Unexpected JSON structure: Could not parse.")
        except json.JSONDecodeError:
            # Handle JSON decoding errors
            print("DEBUG: JSON decoding failed. Trying NDJSON parsing...")
            file.seek(0)  # Reset file pointer
            for line in file:
                try:
                    entry = json.loads(line.strip())
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
                except json.JSONDecodeError:
                    pass  # Skip invalid JSON lines

    return computer_names



def resolve_ips(computer_names, domain_controller):
    """
    Resolves IPs for a list of computer names using a specific domain controller.
    Args:
        computer_names (list): List of computer names to resolve.
        domain_controller (str): Domain controller to use for DNS queries.
    Returns:
        list: List of resolved IP addresses.
    """
    resolver = dns.resolver.Resolver()
    domain_controller_ip = socket.gethostbyname(domain_controller)
    resolver.nameservers = ['10.8.16.1'] ## ADD NAMESERVER!!!
    print(f"DEBUG: Resolver using nameservers: {resolver.nameservers}")

    #print(f"DEBUG: Resolving domain controller: {domain_controller}")
    #print(f"DEBUG: Domain controller resolved to: {socket.gethostbyname(domain_controller)}")


    try:
        answers = resolver.resolve("KNOWNHOST", 'A')
        for rdata in answers:
            print(rdata.address)
    except Exception as e:
        print(f"Test failed: {e}")


    # Increase the DNS resolver timeout
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    ips = []
    for name in alive_it(computer_names):  # Shows progress during resolution
        if name:  # Ignore empty or None names
            try:
                answers = resolver.resolve(str(name), 'A')
                for rdata in answers:
                    ips.append(str(rdata.address))
            except dns.resolver.NXDOMAIN:
                pass  # No such domain, skip
            except dns.resolver.NoAnswer:
                pass  # No answer received, skip
            except dns.resolver.NoNameservers:
                #print(f"All nameservers failed to answer the query: {name}")
                pass
            except dns.exception.Timeout:
                #print(f"Query timed out for {name}")
                pass
            time.sleep(1)  # Add a delay to avoid overwhelming the server
    return ips

def consolidate_ips(ips):
    """
    Consolidates a list of IP addresses into unique /24 CIDRs.
    Args:
        ips (list): List of IP addresses.
    Returns:
        list: Unique /24 CIDRs.
    """
    # Strip the last octet and add /24
    cidrs = ['.'.join(ip.split('.')[:-1]) + '.0/24' for ip in ips]

    # Count occurrences of each /24 block (optional for debugging or optimization)
    cidr_counter = Counter(cidrs)

    # Keep only unique /24 blocks
    unique_cidrs = list(cidr_counter.keys())

    return unique_cidrs


def main():
    # Determine if BloodHound JSON or AD query is needed
    parser = argparse.ArgumentParser(description="Resolve IPs for AD computer names.")
    parser.add_argument("--bloodhoundcomputers", help="Path to BloodHound computers JSON file.", required=true)
    args = parser.parse_args()

    # Parse computer names from the BloodHound JSON file
    computer_names = parse_bloodhound_computers(args.bloodhoundcomputers)

    # Resolve IPs
    ips = resolve_ips(computer_names, domain_controller)

    # Consolidate IPs into /24 CIDRs
    cidrs = consolidate_ips(ips)

    # Print results
    print("Resolved /24 CIDRs:")
    for cidr in cidrs:
        print(cidr)


if __name__ == "__main__":
    main()
