"""MailScope: a local, privacy-preserving first-pass email triage tool."""
from .risk_assessment import analyze_bytes, INDICATOR_MEANING

__all__ = ["analyze_bytes", "INDICATOR_MEANING"]
__version__ = "1.0.0"
