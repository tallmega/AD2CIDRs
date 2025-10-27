import argparse
import dns.resolver
import socket
import time
import ssl
from art import *
from getpass import getpass
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, SUBTREE, Tls
from ldap3.extend.standard import PagedSearch
from ldap3.core.exceptions import LDAPKeyError
from datetime import datetime
from collections import Counter
from netaddr import IPNetwork, cidr_merge, IPSet
from alive_progress import alive_it

def get_credentials():
    parser = argparse.ArgumentParser()
    parser.add_argument("domain_controller", help="Domain controller address")
    parser.add_argument("domain", help="Domain name")
    parser.add_argument("username", help="Username for domain - username@domain.com")
    parser.add_argument("password", help="Password for domain")
    args = parser.parse_args()
    tprint("AD2CIDRs.py \n", font="random")
    print("Collecting and resolving AD computers using the following inputs:")
    print(f"Domain Controller: {args.domain_controller}")
    print(f"Domain: {args.domain}")
    print(f"Username: {args.username}")
    #print(f"Password: {args.password}")  # Only for debugging purposes. Do not print passwords in production.

    return args.domain_controller, args.domain, args.username, args.password

def get_computers(domain_controller, domain, username, password):
    base_dn = ','.join('dc=' + part for part in domain.split('.'))

    # Configure TLS for LDAPS (LDAP over SSL)
    tls_configuration = Tls(validate=ssl.CERT_NONE)  # For testing purposes only
    # Note: For production, use validate=ssl.CERT_REQUIRED and specify a valid CA certificate

    # Initialize the Server
    server = Server(
        domain_controller,
        port=636,  # LDAPS port
        use_ssl=True,
        tls=tls_configuration,
        get_info=ALL
    )

    # Adjust the username format for the LDAP connection
    user_dn = f'{domain}\\{username.split("@")[0]}'

    print(f"Attempting to connect to the server with the user: {user_dn}")

    # Create the LDAP Connection
    try:
        conn = Connection(
            server,
            user=user_dn,
            password=password,
            authentication=NTLM,
            auto_bind=True,
            receive_timeout=60,
            sasl_mechanism='GSSAPI',  # Enable LDAP signing through SASL
            auto_referrals=False      # Avoid referral issues
        )
        print("Bind successful")
    except Exception as e:
        print(f"Failed to bind to server: {e}")
        return []

    computer_names = []
    entries = 0
    cookie = None

    while True:
        conn.search(search_base=base_dn,
                    search_filter='(objectclass=computer)',
                    search_scope=SUBTREE,
                    attributes=['dNSHostName'],
                    paged_size=1000,
                    paged_cookie=cookie)

        for entry in conn.entries:
            entries += 1
            try:
                computer_names.append(entry['dNSHostName'])
            except LDAPKeyError:
                print(f"No 'dNSHostName' attribute for entry {entry.entry_dn}")

        cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')

        # Break while loop if no more pages
        if not cookie:
            break

    print(f"Total entries returned: {entries}")
    return computer_names

    return computer_names

def resolve_ips(computer_names, domain_controller):
    resolver = dns.resolver.Resolver()
    resolver.nameservers = [socket.gethostbyname(domain_controller)]

    # Increase the DNS resolver timeout
    resolver.timeout = 10.0
    resolver.lifetime = 10.0

    ips = []
    for name in alive_it(computer_names):
        if name:  # Ignore if name is empty or None
            try:
                #print(f"Resolving {name}")
                answers = resolver.resolve(str(name), 'A')
                for rdata in answers:
                    ips.append(str(rdata.address))
            except dns.resolver.NXDOMAIN:
                #print(f"Could not resolve IP for {name}")
                pass
            except dns.resolver.NoAnswer:
                #print(f"No answer to the question: {name}")
                pass
            except dns.resolver.NoNameservers:
                print(f"All nameservers failed to answer the query: {name}")
                pass
            except dns.exception.Timeout:
                print(f"Query timed out for {name}")
                pass
            time.sleep(1)  # Add a one second delay between each request
        else:
            #print("Encountered an empty DNS name, skipping...")
            pass
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
