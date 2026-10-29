"""Local synthetic services for financial-app security regression tests.

These modules never contact FYERS or any production trading system.
"""

from .auth_service import SyntheticAuthService
from .financial_api import SyntheticFinancialAPI

__all__ = ["SyntheticAuthService", "SyntheticFinancialAPI"]
