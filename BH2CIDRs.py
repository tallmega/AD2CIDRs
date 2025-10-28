import argparse
import json
import dns.resolver
import time
from alive_progress import alive_it
from collections import Counter


def parse_bloodhound_computers(file_path):
    """Parse BloodHound JSON and extract computer names."""
    computer_names = []
    with open(file_path, 'r') as file:
        try:
            bloodhound_data = json.load(file)

            # Handle different BloodHound export formats
            if isinstance(bloodhound_data, dict) and "data" in bloodhound_data:
                for entry in bloodhound_data["data"]:
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
            elif isinstance(bloodhound_data, list):
                for entry in bloodhound_data:
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
            elif isinstance(bloodhound_data, dict):
                properties = bloodhound_data.get("Properties", {})
                if "name" in properties:
                    computer_names.append(properties["name"])
            else:
                print("Unexpected JSON structure: Could not parse.")
        except json.JSONDecodeError:
            # Fallback to NDJSON format
            file.seek(0)
            for line in file:
                try:
                    entry = json.loads(line.strip())
                    properties = entry.get("Properties", {})
                    if "name" in properties:
                        computer_names.append(properties["name"])
                except json.JSONDecodeError:
                    pass
    return computer_names


def resolve_ips(computer_names, nameserver_ip):
    """
    Resolves IPs for a list of computer names using the provided DNS server.
    Args:
        computer_names (list): List of computer names to resolve.
        nameserver_ip (str): IP of the DNS server to query.
    Returns:
        list: List of resolved IP addresses.
    """
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [nameserver_ip]
    resolver.timeout = 2.0
    resolver.lifetime = 2.0

    print(f"Using DNS nameserver: {resolver.nameservers[0]}")

    ips = []
    for name in alive_it(computer_names, title="Resolving"):
        if name:
            try:
                answers = resolver.resolve(name, 'A')
                for rdata in answers:
                    ips.append(str(rdata.address))
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
                    dns.resolver.NoNameservers, dns.exception.Timeout):
                pass
            time.sleep(0.1)  # prevent flooding
    return ips


def consolidate_ips(ips):
    """Consolidate IPs into unique /24 CIDRs."""
    cidrs = ['.'.join(ip.split('.')[:-1]) + '.0/24' for ip in ips]
    cidr_counter = Counter(cidrs)
    return list(cidr_counter.keys())


def main():
    parser = argparse.ArgumentParser(description="Resolve IPs for BloodHound computer names.")
    parser.add_argument("--bloodhoundcomputers", help="Path to BloodHound computers JSON file.", required=True)
    parser.add_argument("--nameserver", help="IP address of the DNS server to use.", required=True)
    args = parser.parse_args()

    computer_names = parse_bloodhound_computers(args.bloodhoundcomputers)
    ips = resolve_ips(computer_names, args.nameserver)
    cidrs = consolidate_ips(ips)

    print("\nResolved /24 CIDRs:")
    for cidr in cidrs:
        print(cidr)


if __name__ == "__main__":
    main()
