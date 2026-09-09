# Conditional Access Review Lab

Identity-security engineering project for reviewing synthetic Microsoft Entra ID-style Conditional Access policies against a defined control baseline.

## Problem statement
Conditional Access is a critical identity control plane. Weak coverage, broad exclusions, legacy-auth allowance, missing MFA requirements, or incomplete privileged-role protection can leave valid accounts exposed even when authentication controls exist elsewhere. This lab models those gaps using synthetic policy metadata and produces explainable findings with remediation evidence.

## Architecture
```text
Synthetic policy inventory + identity baseline
                  |
                  v
          src/policy_review.py
            - scope analysis
            - control checks
            - severity scoring
                  |
                  +--> prioritized findings
                  +--> remediation plan
                  +--> validation evidence
```

## Controls implemented
- Require MFA for privileged administrative roles.
- Require MFA for all users or an explicitly governed equivalent scope.
- Block legacy authentication.
- Protect risky sign-ins with step-up or blocking controls.
- Require compliant/managed device controls for sensitive applications.
- Flag broad user/group exclusions.
- Detect disabled policies that are expected to enforce baseline controls.
- Require emergency-access account exclusions to be explicit and narrowly governed.

## ATT&CK context
The project maps primarily to **Valid Accounts (T1078)** and **Account Access Removal / Identity controls defensive context**. It does not perform credential attacks, MFA bypass, session theft, or live tenant interaction.

## Repository structure
- `src/policy_review.py` — defensive Conditional Access policy engine.
- `data/synthetic_policies.json` — fictional policy inventory.
- `tests/test_policy_review.py` — unit tests.
- `docs/review-methodology.md` — governance and assessment approach.
- `docs/remediation-validation.md` — implementation and re-test workflow.
- `reports/example-review.md` — example recruiter-facing assessment.
- `.github/workflows/tests.yml` — CI unit-test workflow.

## Usage
```bash
python -m unittest discover -s tests -v
python src/policy_review.py data/synthetic_policies.json
```

## Skills demonstrated
Identity security, Microsoft Entra ID control design, Conditional Access governance, policy-as-code, Python, unit testing, risk classification, ATT&CK mapping, remediation validation, and CI/CD.

## Limitations
This repository evaluates synthetic policy metadata only. Production reviews additionally require tenant context, sign-in logs, identity protection data, break-glass governance, application sensitivity, device-compliance posture, and authorized change-control evidence.

## Roadmap
- Add coverage matrix by user population and application tier.
- Add policy-conflict and overlap detection.
- Add risk-based sign-in simulation using synthetic events.
- Add machine-readable findings and control IDs for dashboard ingestion.
