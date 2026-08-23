import argparse
import dns.resolver
import socket
import time
import ssl
import sys
from art import *
from getpass import getpass
from ldap3 import Server, Connection, NONE, NTLM, SUBTREE, Tls
from ldap3.extend.standard import PagedSearch
from ldap3.core.exceptions import LDAPKeyError, LDAPSocketOpenError
from datetime import datetime
from collections import Counter
from netaddr import IPNetwork, cidr_merge, IPSet
from alive_progress import alive_it


_UNICODE_PROGRESS_SAMPLE = "▏▎▍▌▋▊▉█⠋"


def iter_with_progress(items, total=None, **options):
    stream = getattr(sys, "stdout", None)
    encoding = getattr(stream, "encoding", None) if stream else None

    if encoding:
        try:
            _UNICODE_PROGRESS_SAMPLE.encode(encoding)
            return alive_it(items, total=total, **options)
        except (LookupError, UnicodeEncodeError):
            pass

    title = options.get("title")
    if title:
        if total is None and hasattr(items, "__len__"):
            total = len(items)
        count_suffix = f" ({total} items)" if total is not None else ""
        print(f"{title}{count_suffix} without live progress; stdout encoding is {encoding or 'unknown'}.")

    return items

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

def _ldap_error(conn):
    """Return the useful part of ldap3's otherwise terse failure state."""
    result = getattr(conn, "result", None)
    if isinstance(result, dict):
        parts = []
        for key in ("description", "message"):
            value = result.get(key)
            if value:
                parts.append(str(value))
        if parts:
            return ": ".join(parts)
    return getattr(conn, "last_error", None) or "server returned no LDAP error"


def _bind_connection(domain_controller, user_dn, password):
    tls_configuration = Tls(validate=ssl.CERT_NONE)  # For testing; tighten validation in production
    attempts = (
        ("STARTTLS", False, 389),
        ("LDAPS", True, 636),
    )

    for protocol, use_ssl, port in attempts:
        conn = None
        try:
            server = Server(
                domain_controller,
                port=port,
                use_ssl=use_ssl,
                tls=tls_configuration,
                get_info=NONE,
                connect_timeout=10,
            )
            conn = Connection(
                server,
                user=user_dn,
                password=password,
                authentication=NTLM,
                auto_referrals=False,
                receive_timeout=15,
                raise_exceptions=False,
            )

            # RootDSE discovery can hang on filtered LDAP connections.  Neither
            # binding nor this script's domain-derived search base requires it.
            conn.open(read_server_info=False)
            if conn.closed:
                print(f"{protocol} socket open failed: {_ldap_error(conn)}")
                continue

            if protocol == "STARTTLS" and not conn.start_tls(read_server_info=False):
                print(f"STARTTLS negotiation failed: {_ldap_error(conn)}")
                conn.unbind()
                continue

            if not conn.bind(read_server_info=False):
                print(f"{protocol} NTLM bind failed: {_ldap_error(conn)}")
                conn.unbind()
                continue

            print(f"Bind successful over {protocol}")
            return conn
        except Exception as exc:
            print(f"{protocol} bind failed: {exc}")
            if conn:
                conn.unbind()
    print("Failed to bind over STARTTLS and LDAPS")
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
    if "\\" in username:
        user_dn = username
    else:
        # NTLM requires DOMAIN\\user.  In the usual AD configuration the
        # NetBIOS domain is the first label of the DNS domain.
        netbios_domain = domain.split(".", 1)[0].upper()
        user_dn = f'{netbios_domain}\\{username.split("@", 1)[0]}'

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
    for name in iter_with_progress(computer_names, title="Resolving"):
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
