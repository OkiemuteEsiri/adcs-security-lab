# Remediation and Validation Playbook

## Template Findings

### Requester-controlled subject information
**Remediation:** remove requester-controlled subject/SAN behavior unless a documented application requirement exists; narrow enrollment permissions to explicitly approved principals.

**Validation:** export or review the effective template configuration after change and confirm the risky flag/permission combination no longer exists. Re-run the lab assessment against an updated representation.

### Broad authentication-certificate enrollment
**Remediation:** replace broad groups with role-specific groups and introduce issuance approval for sensitive templates.

**Validation:** verify the effective ACL and approval settings, then confirm no broad principal is granted enrollment.

### Exportable authentication keys
**Remediation:** enforce non-exportable private keys except where formally approved.

**Validation:** verify the effective template setting and confirm a benign newly issued certificate follows the protected-key policy.

### Excessive certificate lifetime
**Remediation:** adopt a documented validity period aligned with authentication risk and renewal capability.

**Validation:** confirm the template value and inspect a benign newly issued certificate for the expected validity period.

## CA Findings

### Unprotected web enrollment
**Remediation:** enforce HTTPS and disable unnecessary legacy enrollment endpoints.

**Validation:** confirm plain HTTP is unavailable or safely redirected and that the approved TLS certificate chain is presented.

### Missing CA auditing
**Remediation:** enable relevant CA audit categories and forward events to the approved monitoring platform.

**Validation:** perform a benign certificate issuance workflow and verify expected audit telemetry is generated and retained.

## Closure Criteria

A finding is considered validated only when:

1. the effective configuration has changed;
2. the relevant risky condition no longer matches the control logic;
3. evidence is retained with owner and timestamp;
4. dependent identity/security controls are checked for regression; and
5. any exception has an accountable owner, justification, expiry date, and compensating controls.
