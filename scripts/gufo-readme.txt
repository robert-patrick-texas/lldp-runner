Gufo SNMP diagnostic scripts
============================

Run these scripts in the same Python/uv environment, under the same
operating-system account, and on the same Linux host as LLDP-Runner. They bypass
LLDP-Runner so an operator can distinguish Gufo transport behavior from
scheduler, identity, retry, and collector behavior.

Do not place credentials on the command line. Set only the environment variables
required for the selected SNMP version, for example through a protected
scripts/.private file.

IPv6 bracket comparison
-----------------------

The focused IPv6 test accepts an unbracketed IPv6 literal or a hostname with at
least one IPv6 result. IPv4 is intentionally rejected. For each IPv6 address it
passes the same destination to Gufo first without brackets and then with brackets
at the transport boundary.

    export SNMPCOMM='your-community'
    ./gufo-ipv6-test.py 2001:db8:130f::9c0:876a:130b
    ./gufo-ipv6-test.py switch.example.net

A successful diagnostic reports either "brackets required" or "brackets not
required". Exit status 1 means the comparison was inconclusive; exit status 2
means usage, resolution, credential, or Gufo import/configuration failed; 130
means the operator interrupted the test.

Detailed SNMP diagnostic
------------------------

The detailed script supports direct IPv4/IPv6 literals, DNS names, SNMPv2c,
SNMPv3 authPriv, repeated fresh sessions, multiple OIDs, address-family
selection, phase-specific failures, Gufo/Python/platform metadata, optional
tracebacks, and credential-value redaction.

SNMPv2c examples:

    export SNMPCOMM='your-community'
    ./gufo-snmp-diag.py switch.example.net -6 --traceback
    ./gufo-snmp-diag.py 2001:db8::10 -6 --repeat 3 --delay 2 --traceback
    ./gufo-snmp-diag.py switch.example.net -4 --traceback

SNMPv3 authPriv example:

    export SNMPUSER='diagnostic-user'
    export SNMPAUTH='authentication-password'
    export SNMPPRIV='privacy-password'

    ./gufo-snmp-diag.py switch.example.net \
      --snmp-version 3 \
      -6 \
      --auth-protocol sha1 \
      --priv-protocol aes128 \
      --traceback

Without -4 or -6, all unique IPv4 and IPv6 destinations returned by the resolver
are queried sequentially. Add --first-address to test only the resolver's first
applicable result. sysDescr.0 is queried by default; repeat --oid to select other
numeric OIDs.

Detailed-script exit status:

    0  every attempted query succeeded
    1  a Gufo session or query failed
    2  usage, resolution, credential, or import failure
    130 operator interruption

Gufo SNMP documentation: https://docs.gufolabs.com/gufo_snmp/
