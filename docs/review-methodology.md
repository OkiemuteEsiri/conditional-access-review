# Review Methodology

## Assessment objectives
The lab evaluates whether synthetic Conditional Access policy coverage protects privileged identities, general users, risky sign-ins, sensitive applications, and legacy authentication paths without relying on unsafe testing.

## Review sequence
1. Inventory policy state, scope, controls, exclusions, and application sensitivity.
2. Verify privileged-role MFA coverage.
3. Verify broad user MFA coverage or an explicitly documented equivalent control strategy.
4. Verify legacy authentication blocking.
5. Review risky sign-in controls and sensitive-application device requirements.
6. Review exclusions for breadth, ownership, expiry, and emergency-access governance.
7. Identify disabled policies that are expected to enforce baseline controls.
8. Document remediation evidence and repeat the policy evaluation.

## Risk principles
Critical findings represent direct weakening of privileged identity controls. High findings represent broad control gaps or exclusions that materially increase account misuse risk. Medium findings reduce assurance for sensitive application access or governance quality.

## ATT&CK context
Valid Accounts (T1078) is the primary defensive mapping because Conditional Access is an important control against misuse of valid credentials. No credential attack or MFA-bypass testing is included.
