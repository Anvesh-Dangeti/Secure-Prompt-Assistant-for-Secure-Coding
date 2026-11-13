"""spa-connect: connect a project folder to a shared Secure Prompt Assistant server.

The scanners, the prompt builder and the verification checks all run on the
server. This package only packs the folder, sends it over HTTPS with the
developer's own access token, and prints what comes back. It has no
dependencies outside the standard library.
"""

__version__ = "1.0.0"
