# Sample Incident: Internal Port Scan

## Summary

A host generated connections to more than 30 destination ports on a single internal server. The behavior matches network service discovery and is mapped to MITRE ATT&CK T1046.

## Evidence

- Source: `10.10.10.50`
- Destination: `10.10.10.30`
- Unique destination ports: 35
- Supporting IDS alert: Nmap scan signature

## Analyst Action

Verify whether `10.10.10.50` is an authorized vulnerability scanner. If not, investigate the endpoint for unauthorized scanning tools or compromise.
