"""xdr_response: approval-gated incident response framework for Cisco XDR.

Investigation and recommendation are automatic. Every state-changing action
needs a deterministic, human approval token that the execution guard
(:mod:`xdr_response.guard`) re-verifies before any vendor write.

This module deliberately imports nothing else so importing the package has
no side effects and no import cycles.
"""

__version__ = "0.1.0"
FRAMEWORK_VERSION = __version__

__all__ = ["FRAMEWORK_VERSION", "__version__"]
