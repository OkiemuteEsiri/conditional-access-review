# Example Conditional Access Review

## Executive summary
The synthetic policy set demonstrates a partially mature identity-control baseline with two meaningful gaps: legacy authentication blocking is disabled and a sensitive-application policy contains a broad contractor exclusion. Risky sign-in protection is also absent.

| Control | Severity | Example observation | Recommended action |
|---|---|---|---|
| CA-03 | High | Legacy-auth block policy disabled | Validate compatibility and enable blocking |
| CA-04 | High | No risky-sign-in step-up control | Require stronger authentication or block elevated-risk sign-ins |
| CA-06 | High | Broad contractor exclusion | Reduce to narrowly approved identities/groups |
| CA-07 | High | Expected baseline policy disabled | Use report-only validation, then enable through change control |

## Validation plan
Re-run the policy engine after remediation and confirm expected controls are enabled with only documented emergency-access exclusions. This report is synthetic and does not represent a real tenant.
