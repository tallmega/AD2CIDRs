# AD2CIDRs Project Guide for AI Agents

## Project Overview
AD2CIDRs is a network reconnaissance tool that resolves Active Directory computer objects to their IP addresses and consolidates them into CIDR blocks. The project consists of two main components:

- `AD2CIDRs.py`: Queries Active Directory directly via LDAP to get computer objects
- `BH2CIDRs.py`: Processes BloodHound JSON output to extract computer information

## Key Dependencies
Required Python packages:
```
art ldap3 datetime netaddr alive_progress dns.resolver
```

## Main Components and Data Flow

### AD2CIDRs.py Workflow
1. Authenticates to domain controller using NTLM
2. Queries AD for computer objects via LDAP
3. Resolves DNS names to IP addresses using the domain controller
4. Consolidates IPs into CIDR blocks

### BH2CIDRs.py Workflow
1. Parses BloodHound JSON exports (supports array, single object, and NDJSON formats)
2. Extracts computer names from the Properties.name field
3. Performs DNS resolution
4. Generates CIDR blocks

## Project Conventions

### Error Handling
- DNS resolution failures are silently skipped to maintain progress
- LDAP connection issues are logged but don't halt execution
- BloodHound JSON parsing attempts multiple formats before failing

### Security Considerations
- TLS validation is disabled by default (for testing)
- Production deployments should enable proper certificate validation
- Credential handling via command line arguments (no interactive input)

## Common Development Tasks

### Adding Support for New BloodHound Export Formats
Modify the parse_bloodhound_computers() function in BH2CIDRs.py to handle new JSON structures.

### Modifying LDAP Query Behavior
Adjust the search_filter and attributes in get_computers() function of AD2CIDRs.py.

### Testing Changes
Test with small AD environments or BloodHound exports first, as DNS resolution can be time-consuming with large datasets.