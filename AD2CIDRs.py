import argparse
from getpass import getpass
from ldap3 import Server, Connection, ALL
from ldap3.core.exceptions import LDAPKeyError
import dns.resolver
import socket
import time
from collections import Counter
from netaddr import IPNetwork, cidr_merge
from netaddr import IPSet

def get_credentials():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_controller", help="Domain controller address")
    parser.add_argument("domain", help="Domain name")
    parser.add_argument("username", help="Username for domain")
    parser.add_argument("password", help="Password for domain")
    args = parser.parse_args()

    print("DEBUG INFO:")
    print(f"Domain Controller: {args.domain_controller}")
    print(f"Domain: {args.domain}")
    print(f"Username: {args.username}")
    print(f"Password: {args.password}")  # Only for debugging purposes. Do not print passwords in production.

    return args.domain_controller, args.domain, args.username, args.password

def get_computers(domain_controller, domain, username, password):
    base_dn = ','.join('dc=' + part for part in domain.split('.'))
    server = Server(domain_controller, use_ssl=False)
    conn = Connection(server, user=username, password=password, auto_bind=True)
    conn.search(base_dn, '(objectclass=computer)', attributes=['dNSHostName'])
    computer_names = []
    for entry in conn.entries:
        try:
            computer_names.append(entry['dNSHostName'])
        except LDAPKeyError:
            print(f"No 'dNSHostName' attribute for entry {entry.entry_dn}")
    return computer_names

def resolve_ips(computer_names, domain_controller):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [socket.gethostbyname(domain_controller)]
    ips = []
    for name in computer_names:
        if name:  # Ignore if name is empty or None
            try:
                print(f"Resolving {name}")
                answers = resolver.resolve(str(name), 'A')
                for rdata in answers:
                    ips.append(str(rdata.address))
            except dns.resolver.NXDOMAIN:
                print(f"Could not resolve IP for {name}")
            time.sleep(1)  # Add a one second delay between each request
        else:
            print("Encountered an empty DNS name, skipping...")
    return ips

def consolidate_ips(ips):
    # strip last octet and add /24
    cidrs = ['.'.join(ip.split('.')[:-1]) + '.0/24' for ip in ips]

    # count occurrence of each /24 block
    cidr_counter = Counter(cidrs)

    # keep only unique /24 blocks
    unique_cidrs = list(cidr_counter.keys())

    return unique_cidrs

def main():
    domain_controller, domain, username, password = get_credentials()
    computer_names = get_computers(domain_controller, domain, username, password)
    ips = resolve_ips(computer_names, domain_controller)
    cidrs = consolidate_ips(ips)
    for cidr in cidrs:
        print(cidr)

if __name__ == "__main__":
    main()
