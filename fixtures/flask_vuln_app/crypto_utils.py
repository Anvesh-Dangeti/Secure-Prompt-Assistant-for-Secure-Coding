"""
DELIBERATELY VULNERABLE CODE -- TEST FIXTURE ONLY.

Weak cryptography helpers used by app.py.
"""

import hashlib
import random


def hash_password(password):
    """CWE-327 broken hash: MD5 is unsuitable for password storage."""
    return hashlib.md5(password.encode("utf-8")).hexdigest()


def make_reset_token():
    """CWE-330 insufficiently random values: `random` is not a CSPRNG."""
    return "%06d" % random.randint(0, 999999)
