"""Synthetic multi-account financial API for authorization regression tests.

Local only. Does not contact FYERS. Transaction endpoints are disabled unless a
test explicitly enables them. Findings from this mock must not be attributed to FYERS.
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from .auth_service import SyntheticAuthService


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_accounts() -> dict[str, dict[str, Any]]:
    return {
        "TEST_ACCOUNT_A": {
            "profile": {"account_id": "TEST_ACCOUNT_A", "display_name": "Synthetic A", "role": "trader"},
            "balance": {"currency": "INR", "available": 100000.0, "collateral": 25000.0},
            "holdings": [{"symbol": "SYN-AAA", "qty": 10, "avg_price": 100.0}],
            "orders": [{"order_id": "ORD-A-1", "symbol": "SYN-AAA", "side": "BUY", "qty": 1, "status": "COMPLETE"}],
        },
        "TEST_ACCOUNT_B": {
            "profile": {"account_id": "TEST_ACCOUNT_B", "display_name": "Synthetic B", "role": "trader"},
            "balance": {"currency": "INR", "available": 5555.0, "collateral": 100.0},
            "holdings": [{"symbol": "SYN-BBB", "qty": 3, "avg_price": 50.0}],
            "orders": [{"order_id": "ORD-B-9", "symbol": "SYN-BBB", "side": "SELL", "qty": 2, "status": "COMPLETE"}],
        },
    }


READONLY_ROLE = "readonly"
TRADER_ROLE = "trader"


@dataclass
class SyntheticFinancialAPI:
    auth: SyntheticAuthService = field(default_factory=SyntheticAuthService)
    allow_transactions: bool = False
    _accounts: dict[str, dict[str, Any]] = field(default_factory=_seed_accounts)
    _roles: dict[str, str] = field(
        default_factory=lambda: {"TEST_ACCOUNT_A": TRADER_ROLE, "TEST_ACCOUNT_B": TRADER_ROLE}
    )
    _idempotency: dict[str, dict[str, Any]] = field(default_factory=dict)
    _cache: dict[str, Any] = field(default_factory=dict)
    _evidence_bags: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    def set_role(self, account_id: str, role: str) -> None:
        if account_id not in self._accounts:
            raise KeyError(account_id)
        self._roles[account_id] = role
        self._accounts[account_id]["profile"]["role"] = role

    def _require_auth(self, access_token: str | None) -> dict[str, Any]:
        if not access_token:
            return {"ok": False, "status": 401, "error": "authentication_required"}
        auth = self.auth.authenticate(access_token)
        if not auth.get("ok"):
            return {"ok": False, "status": 401, "error": "authentication_required"}
        return {"ok": True, "status": 200, **auth}

    def _forbid_cross_account(self, auth_account: str, requested_account: str | None) -> dict[str, Any] | None:
        if requested_account and requested_account != auth_account:
            return {
                "ok": False,
                "status": 403,
                "error": "forbidden",
                "message": "Object identifier does not match authenticated account",
            }
        return None

    def _cache_key(self, account_id: str, resource: str) -> str:
        return f"{account_id}::{resource}"

    def get_profile(self, access_token: str | None, account_id: str | None = None) -> dict[str, Any]:
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        denied = self._forbid_cross_account(auth["account_id"], account_id)
        if denied:
            return denied
        data = deepcopy(self._accounts[auth["account_id"]]["profile"])
        self._cache[self._cache_key(auth["account_id"], "profile")] = data
        return {"ok": True, "status": 200, "data": data}

    def get_balance(self, access_token: str | None, account_id: str | None = None) -> dict[str, Any]:
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        denied = self._forbid_cross_account(auth["account_id"], account_id)
        if denied:
            return denied
        data = deepcopy(self._accounts[auth["account_id"]]["balance"])
        self._cache[self._cache_key(auth["account_id"], "balance")] = data
        return {"ok": True, "status": 200, "data": data}

    def get_holdings(self, access_token: str | None, account_id: str | None = None) -> dict[str, Any]:
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        denied = self._forbid_cross_account(auth["account_id"], account_id)
        if denied:
            return denied
        data = deepcopy(self._accounts[auth["account_id"]]["holdings"])
        self._cache[self._cache_key(auth["account_id"], "holdings")] = data
        return {"ok": True, "status": 200, "data": data}

    def get_orders(self, access_token: str | None, account_id: str | None = None) -> dict[str, Any]:
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        denied = self._forbid_cross_account(auth["account_id"], account_id)
        if denied:
            return denied
        data = deepcopy(self._accounts[auth["account_id"]]["orders"])
        self._cache[self._cache_key(auth["account_id"], "orders")] = data
        return {"ok": True, "status": 200, "data": data}

    def get_order(
        self,
        access_token: str | None,
        order_id: str,
        *,
        account_id_in_body: str | None = None,
    ) -> dict[str, Any]:
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        # Body/account override must never win over authenticated identity.
        denied = self._forbid_cross_account(auth["account_id"], account_id_in_body)
        if denied:
            return denied
        for account_id, payload in self._accounts.items():
            for order in payload["orders"]:
                if order["order_id"] == order_id:
                    if account_id != auth["account_id"]:
                        return {"ok": False, "status": 403, "error": "forbidden"}
                    return {"ok": True, "status": 200, "data": deepcopy(order)}
        return {"ok": False, "status": 404, "error": "not_found"}

    def place_order(
        self,
        access_token: str | None,
        order: dict[str, Any],
        *,
        idempotency_key: str | None = None,
    ) -> dict[str, Any]:
        if not self.allow_transactions:
            return {
                "ok": False,
                "status": 403,
                "error": "transactions_disabled",
                "message": "Transaction-capable operations are disabled for ordinary assessments",
            }
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        if self._roles.get(auth["account_id"]) == READONLY_ROLE:
            return {"ok": False, "status": 403, "error": "readonly_role"}
        # Ignore spoofed account_id in body.
        if order.get("account_id") and order["account_id"] != auth["account_id"]:
            return {"ok": False, "status": 403, "error": "forbidden"}
        status = str(order.get("status") or "NEW").upper()
        if status not in {"NEW", "PENDING"}:
            return {"ok": False, "status": 409, "error": "invalid_state_transition"}
        if idempotency_key:
            cached = self._idempotency.get(idempotency_key)
            if cached:
                return deepcopy(cached)
        created = {
            "order_id": f"ORD-{uuid4().hex[:8]}",
            "symbol": order.get("symbol", "SYN-AAA"),
            "side": order.get("side", "BUY"),
            "qty": int(order.get("qty") or 1),
            "status": "NEW",
            "account_id": auth["account_id"],
            "created_at": _utcnow(),
        }
        self._accounts[auth["account_id"]]["orders"].append(deepcopy(created))
        response = {"ok": True, "status": 201, "data": created}
        if idempotency_key:
            self._idempotency[idempotency_key] = deepcopy(response)
        return response

    def cancel_order(self, access_token: str | None, order_id: str) -> dict[str, Any]:
        if not self.allow_transactions:
            return {"ok": False, "status": 403, "error": "transactions_disabled"}
        auth = self._require_auth(access_token)
        if not auth.get("ok"):
            return auth
        if self._roles.get(auth["account_id"]) == READONLY_ROLE:
            return {"ok": False, "status": 403, "error": "readonly_role"}
        for order in self._accounts[auth["account_id"]]["orders"]:
            if order["order_id"] == order_id:
                if order["status"] in {"COMPLETE", "CANCELLED"}:
                    return {"ok": False, "status": 409, "error": "invalid_state_transition"}
                order["status"] = "CANCELLED"
                return {"ok": True, "status": 200, "data": deepcopy(order)}
        return {"ok": False, "status": 404, "error": "not_found"}

    def evidence_append(self, assessment_id: str, account_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
        """Evidence bags are partitioned by assessment and account; no cross-account merge."""
        key = f"{assessment_id}::{account_id}"
        bag = self._evidence_bags.setdefault(key, [])
        # Strip obviously sensitive transaction detail fields.
        cleaned = {
            k: v
            for k, v in evidence.items()
            if k not in {"access_token", "refresh_token", "authorization", "full_response"}
        }
        bag.append(cleaned)
        return {"ok": True, "count": len(bag)}

    def evidence_export(self, assessment_id: str, account_id: str) -> dict[str, Any]:
        key = f"{assessment_id}::{account_id}"
        return {"ok": True, "assessment_id": assessment_id, "account_id": account_id, "items": deepcopy(self._evidence_bags.get(key, []))}

    def cache_is_isolated(self, account_a: str, account_b: str, resource: str) -> bool:
        return self._cache_key(account_a, resource) != self._cache_key(account_b, resource)
