"""Conservative email verification primitives."""

from .engine import VerificationConfig, VerificationEngine
from .models import VerificationResult

__all__ = ["VerificationConfig", "VerificationEngine", "VerificationResult"]
