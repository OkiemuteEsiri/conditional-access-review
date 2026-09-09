from __future__ import annotations
import json, sys
from dataclasses import dataclass, asdict
from pathlib import Path

WEIGHTS={"critical":10,"high":7,"medium":4,"low":1}

@dataclass(frozen=True)
class Finding:
    control_id: str
    severity: str
    policy: str
    message: str
    remediation: str


def review(policies: list[dict]) -> list[Finding]:
    findings=[]
    enabled=[p for p in policies if p.get("state")=="enabled"]

    def any_control(name):
        return any(name in p.get("controls",[]) for p in enabled)

    if not any(p.get("scope")=="privileged_roles" and "mfa" in p.get("controls",[]) for p in enabled):
        findings.append(Finding("CA-01","critical","tenant","No enabled MFA policy protects privileged roles.","Require MFA for privileged roles with tightly governed emergency-access exclusions."))
    if not any(p.get("scope")=="all_users" and "mfa" in p.get("controls",[]) for p in enabled):
        findings.append(Finding("CA-02","high","tenant","No enabled broad MFA baseline was found.","Deploy a governed MFA baseline covering the intended user population."))
    if not any_control("block_legacy_auth"):
        findings.append(Finding("CA-03","high","tenant","Legacy authentication is not explicitly blocked.","Block legacy authentication protocols and validate application compatibility."))
    if not any_control("risky_signin_stepup"):
        findings.append(Finding("CA-04","high","tenant","Risky sign-ins are not protected by step-up or block policy.","Require stronger authentication or blocking for elevated sign-in risk."))
    if not any(p.get("application_tier")=="sensitive" and ("compliant_device" in p.get("controls",[]) or "managed_device" in p.get("controls",[])) for p in enabled):
        findings.append(Finding("CA-05","medium","tenant","Sensitive applications lack managed/compliant-device enforcement.","Require device trust for sensitive application access where supported."))

    for p in policies:
        exclusions=p.get("excluded_groups",[])
        if "All Contractors" in exclusions or "All Guests" in exclusions or len(exclusions)>3:
            findings.append(Finding("CA-06","high",p.get("name","unnamed"),"Policy contains broad or excessive exclusions.","Reduce exclusions to narrowly defined, approved identities and document ownership."))
        if p.get("expected_baseline",False) and p.get("state")!="enabled":
            findings.append(Finding("CA-07","high",p.get("name","unnamed"),"Expected baseline policy is not enabled.","Enable after impact assessment, report-only validation, and change approval."))
    return findings


def score(findings): return min(100,sum(WEIGHTS[f.severity] for f in findings))

def main(path):
    policies=json.loads(Path(path).read_text(encoding="utf-8"))
    findings=review(policies)
    print(json.dumps({"risk_score":score(findings),"findings":[asdict(f) for f in findings]},indent=2))
    return 0

if __name__=="__main__":
    if len(sys.argv)!=2: raise SystemExit("usage: python src/policy_review.py <policies.json>")
    raise SystemExit(main(sys.argv[1]))
