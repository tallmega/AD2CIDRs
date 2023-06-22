# AD2CIDRs
Resolve AD Computers to rough CIDR blocks.

Useful for finding active CIDRs for further discovery - massscan, nmap, etc.

**Setup:**
pip install art ldap3 datetime netaddr alive_progress

**Usage:**
python3 ADtoCIDRs.py <Domain Controller IP> <domain> <user@domain.com> <password>
