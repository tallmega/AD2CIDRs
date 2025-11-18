import argparse
import dns.resolver
import socket
import time
import ssl
from art import *
from getpass import getpass
from ldap3 import Server, Connection, ALL, NTLM, ALL_ATTRIBUTES, SUBTREE, Tls
from ldap3.extend.standard import PagedSearch
from ldap3.core.exceptions import LDAPKeyError, LDAPSocketOpenError
from datetime import datetime
from collections import Counter
from netaddr import IPNetwork, cidr_merge, IPSet
from alive_progress import alive_it

def is_valid_hostname(hostname):
    """Return True for hostnames with labels <=63 characters."""
    if not hostname:
        return False
    hostname = hostname.rstrip('.')  # allow trailing dot
    if len(hostname) > 253:
        return False
    for label in hostname.split('.'):
        if not label or len(label) > 63:
            return False
    return True

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

def _bind_connection(domain_controller, user_dn, password):
    tls_configuration = Tls(validate=ssl.CERT_NONE)  # For testing; tighten validation in production
    for protocol, use_ssl in (("LDAPS", True), ("LDAP", False)):
        try:
            server = Server(
                domain_controller,
                use_ssl=use_ssl,
                tls=tls_configuration if use_ssl else None,
                get_info=ALL,
            )
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_bind=True,
                auto_referrals=False,
                receive_timeout=15,
            )
            print(f"Bind successful over {protocol}")
            return conn
        except Exception as exc:
            print(f"{protocol} bind failed: {exc}")
    print("Failed to bind over LDAPS and LDAP")
    return None

def _derive_base_dn(domain, conn):
    if conn and conn.server:
        server_info = getattr(conn.server, "info", None)
        if server_info:
            info_other = getattr(server_info, "other", {}) or {}
            default_context = info_other.get('defaultNamingContext')
            if default_context:
                derived_dn = default_context[0]
                if derived_dn:
                    print(f"Using default naming context from server: {derived_dn}")
                    return derived_dn
        naming_contexts = getattr(server_info, "naming_contexts", None)
        if naming_contexts:
            derived_dn = naming_contexts[0]
            if derived_dn:
                print(f"Using first naming context from server: {derived_dn}")
                return derived_dn

    if '.' in domain:
        base_dn = ','.join('dc=' + part for part in domain.split('.'))
        print(f"Falling back to domain-derived base DN: {base_dn}")
        return base_dn

    print("Unable to derive base DN automatically. Please provide the fully qualified domain name.")
    return None


def get_computers(domain_controller, domain, username, password):
    user_dn = f'{domain}\\{username.split("@")[0]}'

    print(f"Attempting to connect to the server with the user: {user_dn}")

    conn = _bind_connection(domain_controller, user_dn, password)
    if not conn:
        return []

    base_dn = _derive_base_dn(domain, conn)
    if not base_dn:
        return []

    computer_names = []
    entries = 0
    cookie = None

    while True:
        try:
            conn.search(search_base=base_dn,
                        search_filter='(objectclass=computer)',
                        search_scope=SUBTREE,
                        attributes=['dNSHostName'],
                        paged_size=1000,
                        paged_cookie=cookie)
        except LDAPSocketOpenError as err:
            print(f"Ignoring referral with invalid server address: {err}")
            break

        for entry in conn.entries:
            entries += 1
            try:
                dns_value = entry['dNSHostName'].value
                if dns_value:
                    computer_names.append(dns_value)
                else:
                    print(f"'dNSHostName' attribute empty for entry {entry.entry_dn}")
            except LDAPKeyError:
                print(f"No 'dNSHostName' attribute for entry {entry.entry_dn}")

        cookie = conn.result.get('controls', {}).get('1.2.840.113556.1.4.319', {}).get('value', {}).get('cookie')

        # Break while loop if no more pages
        if not cookie:
            break

    print(f"Total entries returned: {entries}")
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
                if not is_valid_hostname(name):
                    print(f"Skipping invalid hostname (label too long): {name}")
                    continue
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
