# Remediation and Validation

## Safe implementation sequence
1. Confirm business ownership and affected user/application scope.
2. Use report-only or equivalent impact-analysis mode before enforcement where supported.
3. Validate emergency-access accounts and exclusions independently.
4. Pilot with a controlled population, review sign-in impact, then expand scope.
5. Record change approval, implementation evidence, and rollback criteria.

## Validation requirements
- Privileged roles are covered by strong authentication policy.
- Legacy authentication is blocked where technically supported.
- Risky sign-ins receive step-up authentication or blocking.
- Sensitive applications enforce documented device-trust requirements where applicable.
- Exclusions are narrow, owned, reviewed, and time-bound where possible.
- Expected baseline policies are enabled after impact validation.

A finding is closed only after the configuration change is verified and the policy engine no longer reports the gap. No tenant secrets, tokens, or identifiable production exports should be committed as evidence.
