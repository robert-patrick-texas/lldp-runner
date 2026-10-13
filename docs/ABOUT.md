# About LLDP-Runner

LLDP-Runner is an operator-focused, SNMP-driven network topology discovery
engine that turns a small set of seed devices into a structured map of the
network using LLDP, LLDPv2, and CDP neighbor intelligence.

It safely scales discovery through concurrent workers while centrally
controlling credentials, policy boundaries, recursion, adaptive SNMP pacing,
and resumable SQLite state. Raw protocol advertisements and typed claims are
retained before reasoning, and a deterministic graph separates physical
chassis, logical systems, interfaces, advertisements, and observed
relationships.

Its defining value is controlled, policy-aware topology discovery with
reversible conclusions and explainable uncertainty. Operational JSON/CSV
results, graph-aware diff, stored-discovery viewing, and single-device
inspection make it both a network-mapping platform and a practical
troubleshooting and review tool.
