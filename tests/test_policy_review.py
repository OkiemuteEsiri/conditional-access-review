import importlib.util
import pathlib
import unittest

MODULE = pathlib.Path(__file__).parents[1] / "src" / "policy_review.py"
spec = importlib.util.spec_from_file_location("policy_review", MODULE)
policy_review = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy_review)

SECURE=[
 {"name":"Priv","state":"enabled","scope":"privileged_roles","controls":["mfa"],"excluded_groups":["Emergency Access Accounts"],"application_tier":"all","expected_baseline":True},
 {"name":"Users","state":"enabled","scope":"all_users","controls":["mfa","block_legacy_auth","risky_signin_stepup"],"excluded_groups":[],"application_tier":"all","expected_baseline":True},
 {"name":"Sensitive","state":"enabled","scope":"all_users","controls":["compliant_device"],"excluded_groups":[],"application_tier":"sensitive","expected_baseline":True}
]

class Tests(unittest.TestCase):
    def test_secure_baseline_has_no_findings(self):
        self.assertEqual(policy_review.review(SECURE),[])
    def test_missing_privileged_mfa_is_critical(self):
        findings=policy_review.review([])
        self.assertTrue(any(f.control_id=="CA-01" and f.severity=="critical" for f in findings))
    def test_disabled_expected_policy_is_detected(self):
        p=SECURE+[{'name':'Legacy','state':'disabled','scope':'all_users','controls':['block_legacy_auth'],'excluded_groups':[],'application_tier':'all','expected_baseline':True}]
        self.assertTrue(any(f.control_id=="CA-07" for f in policy_review.review(p)))
    def test_broad_exclusion_is_high(self):
        p=[dict(SECURE[0], excluded_groups=['All Contractors'])]+SECURE[1:]
        self.assertTrue(any(f.control_id=="CA-06" and f.severity=="high" for f in policy_review.review(p)))
    def test_score_cap(self):
        f=policy_review.Finding('x','critical','p','m','r')
        self.assertEqual(policy_review.score([f]*20),100)

if __name__=="__main__": unittest.main()
