"""受保护身份流程的后台接口测试：登录边界、越权、停用吊销、审计链与幂等。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from power_dispatch.api import JsonApplication
from power_dispatch.clock import FrozenClock
from power_dispatch.service import SupplyService


def json_body(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class IdentityBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = SupplyService(
            self.connection, FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        )
        self.app = JsonApplication(self.service)
        self.service.bootstrap_admin("admin", "调度管理员", "admin-pass")
        self.admin_token = self._login("admin", "admin-pass")
        for user_id, role in (("plan", "planner"), ("dispatch", "dispatcher"), ("risk", "risk"), ("audit", "auditor")):
            self._invite(user_id, role, f"{user_id}-pass")

    def tearDown(self) -> None:
        self.connection.close()

    def _request(self, method: str, path: str, token: str | None = None, payload: dict | None = None,
                 headers: dict | None = None) -> object:
        merged = dict(headers or {})
        if token is not None:
            merged["Authorization"] = f"Bearer {token}"
        return self.app.handle(method, path, merged, b"" if payload is None else json_body(payload))

    def _login(self, user_id: str, password: str) -> str:
        response = self.app.handle("POST", "/auth/login", body=json_body(
            {"user_id": user_id, "password": password}))
        assert response.status == 200, response.body
        return response.body["token"]

    def _invite(self, user_id: str, role: str, password: str, token: str | None = None,
                idempotency_key: str | None = None) -> object:
        headers = {"Idempotency-Key": idempotency_key} if idempotency_key else None
        return self._request("POST", "/users", token or self.admin_token, {
            "user_id": user_id, "display_name": user_id, "role": role, "password": password,
        }, headers)

    def _audit_events(self) -> list[sqlite3.Row]:
        return self.connection.execute(
            "SELECT * FROM supply_audit_events ORDER BY event_id"
        ).fetchall()

    # -- 未登录 ----------------------------------------------------------

    def test_health_is_public_but_everything_else_requires_login(self) -> None:
        self.assertEqual(self.app.handle("GET", "/health").status, 200)
        for method, path in (
            ("POST", "/users"),
            ("GET", "/audit/chain"),
            ("POST", "/quotes"),
            ("POST", "/nominations"),
        ):
            response = self._request(method, path, None, {} if method == "POST" else None)
            self.assertEqual(response.status, 401, path)
            self.assertEqual(response.body["error"]["code"], "unauthenticated")

    def test_self_declared_actor_header_is_ignored(self) -> None:
        response = self.app.handle(
            "GET", "/audit/chain", {"X-Actor-Id": "admin"})
        self.assertEqual(response.status, 401)

    def test_malformed_authorization_is_rejected(self) -> None:
        response = self._request("GET", "/audit/chain", None, None,
                                 {"Authorization": "Basic abc"})
        self.assertEqual(response.status, 401)
        response = self._request("GET", "/audit/chain", None, None,
                                 {"Authorization": "Bearer not-a-real-token"})
        self.assertEqual(response.status, 401)

    def test_login_wrong_password_and_deactivated_account(self) -> None:
        response = self.app.handle("POST", "/auth/login", body=json_body(
            {"user_id": "admin", "password": "wrong"}))
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthenticated")
        self._request("POST", "/users/risk/deactivate", self.admin_token, {})
        response = self.app.handle("POST", "/auth/login", body=json_body(
            {"user_id": "risk", "password": "risk-pass"}))
        self.assertEqual(response.status, 401)

    # -- 越权 ------------------------------------------------------------

    def test_non_admin_cannot_invite_change_role_or_deactivate(self) -> None:
        invite = self._invite("intruder", "dispatcher", "pw", token=self._login("plan", "plan-pass"))
        self.assertEqual(invite.status, 403)
        self.assertEqual(invite.body["error"]["code"], "forbidden")
        change = self._request("POST", "/users/risk/role",
                               self._login("dispatch", "dispatch-pass"), {"role": "admin"})
        self.assertEqual(change.status, 403)
        deactivate = self._request("POST", "/users/risk/deactivate",
                                   self._login("risk", "risk-pass"), {})
        self.assertEqual(deactivate.status, 403)
        self.assertIsNone(self.connection.execute(
            "SELECT * FROM supply_users WHERE user_id='intruder'").fetchone())

    def test_role_permission_still_enforced_for_dispatch_operations(self) -> None:
        response = self._request("POST", "/scenarios/restart/approve",
                                 self._login("plan", "plan-pass"), {"expected_revision": 1})
        self.assertEqual(response.status, 403)

    def test_admin_cannot_self_deactivate_or_change_own_role(self) -> None:
        self.assertEqual(
            self._request("POST", "/users/admin/deactivate", self.admin_token, {}).status, 403)
        self.assertEqual(
            self._request("POST", "/users/admin/role", self.admin_token, {"role": "auditor"}).status,
            403)

    # -- 停用即失效 ------------------------------------------------------

    def test_deactivation_revokes_existing_sessions_immediately(self) -> None:
        token = self._login("audit", "audit-pass")
        working = self._request("GET", "/audit/chain", token)
        self.assertEqual(working.status, 200)
        result = self._request("POST", "/users/audit/deactivate", self.admin_token, {})
        self.assertEqual(result.status, 200)
        self.assertFalse(result.body["active"])
        self.assertGreaterEqual(result.body["sessions_revoked"], 1)
        blocked = self._request("GET", "/audit/chain", token)
        self.assertEqual(blocked.status, 401)
        self.assertEqual(blocked.body["error"]["code"], "unauthenticated")

    def test_logout_revokes_token(self) -> None:
        token = self._login("audit", "audit-pass")
        self.assertEqual(self._request("POST", "/auth/logout", token, {}).status, 200)
        self.assertEqual(self._request("GET", "/audit/chain", token).status, 401)

    # -- 合法管理员操作与审计 --------------------------------------------

    def test_admin_invite_role_change_and_reactivation(self) -> None:
        invited = self._invite("ops-7", "dispatcher", "initial-pass")
        self.assertEqual(invited.status, 201)
        self.assertEqual(invited.body, {"user_id": "ops-7", "role": "dispatcher", "active": True})
        token = self._login("ops-7", "initial-pass")
        self.assertEqual(
            self._request("POST", "/nominations", token, {}).status, 422)

        changed = self._request("POST", "/users/ops-7/role", self.admin_token, {"role": "risk"})
        self.assertEqual(changed.status, 200)
        self.assertEqual(changed.body["role"], "risk")
        self.assertEqual(self._request("GET", "/audit/chain", token).status, 403)

        self._request("POST", "/users/ops-7/deactivate", self.admin_token, {})
        self.assertEqual(self._request("GET", "/audit/chain", token).status, 401)
        reactivated = self._request("POST", "/users/ops-7/activate", self.admin_token, {})
        self.assertEqual(reactivated.status, 200)
        self.assertTrue(reactivated.body["active"])
        # 旧会话仍处于吊销状态，必须重新登录
        self.assertEqual(self._request("GET", "/audit/chain", token).status, 401)
        new_token = self._login("ops-7", "initial-pass")
        # 角色已变更为 risk：可通过鉴权，但目标线路不存在
        denied_route = self._request("POST", "/routes/pipe-x/outages", new_token, {
            "starts_at": "2026-09-25T00:00:00Z", "ends_at": None,
            "capacity_percent": "50", "reason": "检修"})
        self.assertEqual(denied_route.status, 404)

    def test_account_lifecycle_events_land_in_immutable_chain(self) -> None:
        self._invite("ops-8", "planner", "pw")
        self._request("POST", "/users/ops-8/role", self.admin_token, {"role": "risk"})
        self._request("POST", "/users/ops-8/deactivate", self.admin_token, {})
        events = self._audit_events()
        lifecycle = [row["event_type"] for row in events if row["entity_id"] == "ops-8"]
        self.assertEqual(lifecycle, ["user.invited", "user.role_changed", "user.deactivated"])
        role_event = next(row for row in events if row["event_type"] == "user.role_changed")
        self.assertEqual(role_event["actor_id"], "admin")
        payload = json.loads(role_event["payload_json"])
        self.assertEqual(payload, {"from_role": "planner", "to_role": "risk"})
        deactivated = next(row for row in events if row["event_type"] == "user.deactivated")
        self.assertGreaterEqual(json.loads(deactivated["payload_json"])["sessions_revoked"], 0)
        chain = self.service.audit_chain("audit")
        self.assertTrue(chain["valid"])
        self.connection.execute(
            "UPDATE supply_audit_events SET payload_json='{}' WHERE event_id=?",
            (role_event["event_id"],))
        self.assertFalse(self.service.audit_chain("audit")["valid"])

    # -- 重复请求 --------------------------------------------------------

    def test_repeated_invite_with_same_idempotency_key_creates_one_account(self) -> None:
        payload = {"user_id": "ops-9", "display_name": "运维九号", "role": "dispatcher", "password": "pw"}
        headers = {"Authorization": f"Bearer {self.admin_token}", "Idempotency-Key": "invite-9"}
        first = self.app.handle("POST", "/users", headers, json_body(payload))
        second = self.app.handle("POST", "/users", headers, json_body(payload))
        self.assertEqual(first.status, 201)
        self.assertEqual(second.status, 201)
        self.assertEqual(first.body, second.body)
        count = self.connection.execute(
            "SELECT COUNT(*) c FROM supply_users WHERE user_id='ops-9'").fetchone()["c"]
        self.assertEqual(count, 1)
        invites = [row for row in self._audit_events()
                   if row["entity_id"] == "ops-9" and row["event_type"] == "user.invited"]
        self.assertEqual(len(invites), 1)

    def test_idempotency_key_reused_with_different_payload_conflicts(self) -> None:
        base = {"user_id": "ops-10", "display_name": "十号", "role": "dispatcher", "password": "pw"}
        headers = {"Authorization": f"Bearer {self.admin_token}", "Idempotency-Key": "invite-10"}
        self.assertEqual(self.app.handle("POST", "/users", headers, json_body(base)).status, 201)
        other = dict(base, role="risk")
        response = self.app.handle("POST", "/users", headers, json_body(other))
        self.assertEqual(response.status, 409)

    def test_duplicate_invite_without_idempotency_key_is_conflict(self) -> None:
        first = self._invite("ops-11", "planner", "pw")
        second = self._invite("ops-11", "planner", "pw")
        self.assertEqual(first.status, 201)
        self.assertEqual(second.status, 409)
        self.assertEqual(second.body["error"]["code"], "conflict")

    def test_bootstrap_admin_twice_is_rejected(self) -> None:
        with self.assertRaises(Exception):
            self.service.bootstrap_admin("admin2", "第二管理员", "pw")


class DispatchFlowStillWorksTests(unittest.TestCase):
    """身份改造后，调度主流程必须保持可用。"""

    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.service = SupplyService(
            self.connection, FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc)))
        self.app = JsonApplication(self.service)
        self.service.bootstrap_admin("admin", "管理员", "admin-pass")
        admin = self._login("admin", "admin-pass")
        for user_id, role in (("plan", "planner"), ("dispatch", "dispatcher"), ("risk", "risk"), ("audit", "auditor")):
            response = self._request("POST", "/users", admin, {
                "user_id": user_id, "display_name": user_id, "role": role, "password": f"{user_id}-pass"})
            assert response.status == 201
        self.plan = self._login("plan", "plan-pass")
        self.dispatch = self._login("dispatch", "dispatch-pass")
        self.risk = self._login("risk", "risk-pass")
        self.audit = self._login("audit", "audit-pass")

    def tearDown(self) -> None:
        self.connection.close()

    def _request(self, method: str, path: str, token: str, payload: dict | None = None) -> object:
        return self.app.handle(method, path, {"Authorization": f"Bearer {token}"},
                               b"" if payload is None else json_body(payload))

    def _login(self, user_id: str, password: str) -> str:
        response = self.app.handle("POST", "/auth/login", body=json_body(
            {"user_id": user_id, "password": password}))
        assert response.status == 200
        return response.body["token"]

    def test_full_schedule_flow_over_http_with_bearer_tokens(self) -> None:
        self.assertEqual(self._request("POST", "/facilities", self.plan, {
            "facility_id": "field-a", "name": "北部电厂", "kind": "storage",
            "timezone": "Asia/Shanghai", "capacity_mwh": "500000"}).status, 201)
        self.assertEqual(self._request("POST", "/facilities", self.plan, {
            "facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal",
            "timezone": "Asia/Shanghai", "capacity_mwh": "800000"}).status, 201)
        self.assertEqual(self._request("POST", "/routes", self.plan, {
            "route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b",
            "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25,
            "transit_hours": 36}).status, 201)
        self.assertEqual(self._request("POST", "/quotes", self.plan, {
            "market_index": "PEAK_VALLEY", "trade_date": "2026-09-23", "close_cny": "98",
            "source_revision": "r-23", "observed_at": "2026-09-23T21:00:00Z"}).status, 201)
        self.assertEqual(self._request("POST", "/routes/pipe-a-b/outages", self.risk, {
            "starts_at": "2026-09-25T00:00:00Z", "ends_at": "2026-09-25T23:59:59Z",
            "capacity_percent": "50", "reason": "检修"}).status, 201)
        self.assertEqual(self._request("POST", "/nominations", self.dispatch, {
            "nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "refinery",
            "service_date": "2026-09-25", "requested_mwh": "40000", "priority": 10,
            "idempotency_key": "key-1"}).status, 201)
        allocation = self._request("POST", "/routes/pipe-a-b/allocate", self.dispatch,
                                   {"service_date": "2026-09-25"})
        self.assertEqual(allocation.status, 200)
        self.assertEqual(allocation.body["available_capacity"], "50000.000")
        self.assertEqual(self._request("POST", "/inventory/lots", self.dispatch, {
            "lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "PV",
            "quantity_mwh": "60000", "unit_cost_cny": "91",
            "received_at": "2026-09-24T06:00:00Z"}).status, 201)
        transfer = self._request("POST", "/transfers", self.dispatch, {
            "transfer_id": "transfer-1", "nomination_id": "nom-1", "lot_id": "lot-1",
            "expected_revision": 2})
        self.assertEqual(transfer.status, 201)
        self.assertEqual(transfer.body["state"], "in_transit")
        chain = self._request("GET", "/audit/chain", self.audit)
        self.assertEqual(chain.status, 200)
        self.assertTrue(chain.body["valid"])
        self.assertGreater(chain.body["events"], 5)


if __name__ == "__main__":
    unittest.main()
