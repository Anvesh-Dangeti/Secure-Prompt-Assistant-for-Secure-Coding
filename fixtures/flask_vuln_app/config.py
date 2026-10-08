"""
DELIBERATELY VULNERABLE CODE -- TEST FIXTURE ONLY.

CWE-798 hard-coded credentials. The value is a fabricated Stripe *test-mode*
style string; it has never been a real credential. It is shaped so that two
independent tools (Bandit by variable name, Gitleaks by token format) can both
detect it -- the project's cross-scanner corroboration case.
"""

API_TOKEN = "sk_test_4eC39HqLyjWDarjtT1zdp7dcFAKE00"
