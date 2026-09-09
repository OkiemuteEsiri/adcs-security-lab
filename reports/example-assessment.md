# Example AD CS Security Assessment

**Environment:** Synthetic lab  
**Assessment type:** Defensive configuration review  
**Data classification:** Fictional / non-production

## Executive Summary

The synthetic inventory contains one certificate template with a high-risk combination of authentication capability, broad enrollment rights, requester-controlled subject data, long validity, and exportable private keys. The sample certification authority also exposes web enrollment without HTTPS-only enforcement and has auditing disabled.

These conditions would represent material identity assurance and monitoring weaknesses if observed in a real authorized environment.

## Example Priority Findings

| Priority | Control | Object | Risk |
|---|---|---|---|
| 1 | ADCS-001 | UserAuthentication | Critical |
| 2 | ADCS-002 | UserAuthentication | High |
| 3 | ADCS-004 | UserAuthentication | High |
| 4 | ADCS-101 | LAB-ROOT-CA01 | High |
| 5 | ADCS-003 | UserAuthentication | Medium |
| 6 | ADCS-102 | LAB-ROOT-CA01 | Medium |
| 7 | ADCS-005 | LegacyVPNCertificate | Low |

## Remediation Priorities

1. Remove requester-controlled identity fields from the broadly enrollable authentication template or strictly scope enrollment.
2. Introduce issuance approval or authorized-signature controls for sensitive authentication templates.
3. Disable private-key export for authentication certificates unless a formally approved exception exists.
4. Enforce protected enrollment transport.
5. Enable CA auditing and validate event collection.
6. Reduce long certificate lifetimes and assign ownership to legacy templates.

## Validation Strategy

After remediation, update the synthetic inventory to represent the approved target state and re-run the assessment. Critical and high findings should no longer be present unless an explicitly documented exception remains.

## Important Note

This report is generated from fictional data for portfolio demonstration. It does not represent an assessment of any employer, client, customer, or production Active Directory environment.
