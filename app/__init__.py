"""Secure Prompt Assistant for Secure Coding.

Scan a Python repository with independent open-source security tools, track
each finding's identity across commits, and (later phases) generate measured
remediation prompts whose fixes are verified by re-scanning -- never by the LLM.
"""

__version__ = "0.1.0"
