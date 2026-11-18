# Security Policy

## Reporting a vulnerability in vulnhound

Please report privately via GitHub Security Advisories on this repository
(Security tab, "Report a vulnerability"). Do not open public issues for
undisclosed vulnerabilities. Expect an acknowledgement within a few days;
we will coordinate a fix and disclosure timeline with you.

## Using vulnhound responsibly

- Scan only code you own or are explicitly authorized to test.
- Proof-of-concept scripts are never run directly on the host. They must be run
  through `vulnhound prove`, which executes them in a sandbox.
- vulnhound is pre-alpha: findings are leads to verify, not guarantees.
