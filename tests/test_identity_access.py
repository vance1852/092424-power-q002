"""通过后台 JSON 接口验证账号开通的登录、授权、停用与审计边界。"""

from __future__ import annotations

import json
import sqlite3
import unittest
from datetime import datetime, timezone

from power_dispatch.api import JsonApplication
from power_dispatch.clock import FrozenClock
from power_dispatch.service import SupplyService


def json_body(payload: dict[str, object]) -> bytes:
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


class IdentityBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.connection = sqlite3.connect(":memory:", isolation_level=None)
        self.connection.row_factory = sqlite3.Row
        self.clock = FrozenClock(datetime(2026, 9, 24, 8, 0, tzinfo=timezone.utc))
        self.service = SupplyService(self.connection, self.clock)
        self.service.bootstrap_user("root", "系统管理员", "admin", "admin-secret")
        self.app = JsonApplication(self.service)
        self.admin_token = self.login("root", "admin-secret")
        # 管理员通过受保护的邀请流程开通四个业务角色，后续用例直接复用。
        self.invite("plan", "计划员", "planner", "pw-plan", "invite-plan")
        self.invite("dispatch", "调度员", "dispatcher", "pw-dispatch", "invite-dispatch")
        self.invite("risk", "风险员", "risk", "pw-risk", "invite-risk")
        self.invite("audit", "审计员", "auditor", "pw-audit", "invite-audit")
        self.plan_token = self.login("plan", "pw-plan")
        self.dispatch_token = self.login("dispatch", "pw-dispatch")
        self.risk_token = self.login("risk", "pw-risk")
        self.audit_token = self.login("audit", "pw-audit")

    def tearDown(self) -> None:
        self.connection.close()

    def request(self, method: str, target: str, token: str | None = None, payload: dict[str, object] | None = None) -> object:
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        body = json_body(payload) if payload is not None else b""
        return self.app.handle(method, target, headers, body)

    def login(self, user_id: str, secret: str) -> str:
        response = self.app.handle("POST", "/login", body=json_body({"user_id": user_id, "secret": secret}))
        assert response.status == 200, response.body
        return response.body["token"]

    def invite(self, user_id: str, name: str, role: str, secret: str, key: str) -> object:
        return self.request(
            "POST", "/users", self.admin_token,
            {"user_id": user_id, "display_name": name, "role": role, "secret": secret, "idempotency_key": key},
        )

    def audit_items(self) -> list[dict[str, object]]:
        response = self.request("GET", "/audit/chain", self.audit_token)
        assert response.status == 200, response.body
        return response.body["items"]

    # ---- 未登录 -------------------------------------------------------

    def test_anonymous_cannot_reach_protected_endpoints(self) -> None:
        for method, target, payload in (
            ("POST", "/users", {"user_id": "x", "display_name": "x", "role": "planner", "secret": "s", "idempotency_key": "k"}),
            ("POST", "/quotes", {"market_index": "X"}),
            ("POST", "/nominations", {"nomination_id": "n1"}),
            ("GET", "/audit/chain", None),
        ):
            response = self.request(method, target, None, payload)
            self.assertEqual(response.status, 401, (method, target, response.body))
            self.assertEqual(response.body["error"]["code"], "unauthorized")
        # 健康检查仍是唯一的匿名入口。
        self.assertEqual(self.app.handle("GET", "/health").status, 200)

    def test_forged_or_malformed_token_is_rejected(self) -> None:
        self.assertEqual(self.request("GET", "/audit/chain", "not-a-real-token").status, 401)
        response = self.app.handle(
            "GET", "/audit/chain", {"Authorization": "Basic abc"}, b""
        )
        self.assertEqual(response.status, 401)

    def test_login_with_wrong_secret_is_unauthorized(self) -> None:
        response = self.app.handle("POST", "/login", body=json_body({"user_id": "plan", "secret": "wrong"}))
        self.assertEqual(response.status, 401)
        self.assertEqual(response.body["error"]["code"], "unauthorized")

    # ---- 越权 ---------------------------------------------------------

    def test_non_admin_cannot_invite_change_or_deactivate(self) -> None:
        invite_payload = {"user_id": "intruder", "display_name": "闯入者", "role": "risk", "secret": "pw", "idempotency_key": "k-1"}
        self.assertEqual(self.request("POST", "/users", self.plan_token, invite_payload).status, 403)
        self.assertEqual(self.request("POST", "/users", self.dispatch_token, invite_payload).status, 403)
        self.assertEqual(self.request("POST", "/users/plan/role", self.risk_token, {"role": "risk"}).status, 403)
        self.assertEqual(self.request("POST", "/users/plan/deactivate", self.audit_token, {"reason": "越权"}).status, 403)

    def test_admin_cannot_touch_business_operations(self) -> None:
        # 管理权与业务调度权双向隔离。
        self.assertEqual(self.request("POST", "/quotes", self.admin_token, {"market_index": "X"}).status, 403)
        self.assertEqual(self.request("POST", "/nominations", self.admin_token, {"nomination_id": "n1"}).status, 403)
        self.assertEqual(self.request("GET", "/audit/chain", self.admin_token).status, 403)

    def test_cross_role_business_permissions_still_enforced(self) -> None:
        self.assertEqual(self.request("POST", "/quotes", self.dispatch_token, {"market_index": "X"}).status, 403)
        self.assertEqual(self.request("GET", "/audit/chain", self.risk_token).status, 403)

    def test_invite_cannot_create_another_admin(self) -> None:
        response = self.request(
            "POST", "/users", self.admin_token,
            {"user_id": "evil", "display_name": "提权", "role": "admin", "secret": "pw", "idempotency_key": "k-admin"},
        )
        self.assertEqual(response.status, 422)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM supply_users WHERE role='admin'").fetchone()[0], 1)

    # ---- 合法管理员操作与审计内容 -------------------------------------

    def test_admin_invite_is_audited_and_login_works(self) -> None:
        response = self.invite("newbie", "新调度", "dispatcher", "pw-newbie", "invite-newbie")
        self.assertEqual(response.status, 201)
        self.assertEqual(response.body, {"user_id": "newbie", "role": "dispatcher", "state": "invited"})
        token = self.login("newbie", "pw-newbie")
        # 密钥只以 PBKDF2 哈希落库，库内查不到明文。
        stored = self.connection.execute("SELECT credential_secret FROM supply_users WHERE user_id='newbie'").fetchone()[0]
        self.assertTrue(stored.startswith("pbkdf2_sha256$"))
        self.assertNotIn("pw-newbie", stored)
        invited = [e for e in self.audit_items() if e["event_type"] == "user.invited"]
        self.assertEqual(len(invited), 5)  # setUp 的 4 个 + 本用例 1 个
        event = invited[-1]
        self.assertEqual(event["actor_id"], "root")
        self.assertEqual(event["entity_type"], "user")
        self.assertEqual(event["entity_id"], "newbie")
        self.assertEqual(event["payload"]["role"], "dispatcher")
        self.assertTrue(token)

    def test_duplicate_invite_request_does_not_create_second_account(self) -> None:
        payload = {"user_id": "dup", "display_name": "重复邀请", "role": "risk", "secret": "pw-dup", "idempotency_key": "invite-dup"}
        first = self.request("POST", "/users", self.admin_token, payload)
        second = self.request("POST", "/users", self.admin_token, payload)
        self.assertEqual(first.status, 201)
        self.assertEqual(second.status, 201)
        self.assertEqual(first.body, second.body)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM supply_users WHERE user_id='dup'").fetchone()[0], 1)
        self.assertEqual(
            len([e for e in self.audit_items() if e["event_type"] == "user.invited" and e["entity_id"] == "dup"]),
            1,
        )

    def test_same_idempotency_key_with_other_payload_conflicts(self) -> None:
        payload = {"user_id": "a1", "display_name": "甲", "role": "risk", "secret": "p1", "idempotency_key": "same-key"}
        changed = dict(payload, user_id="a2")
        self.assertEqual(self.request("POST", "/users", self.admin_token, payload).status, 201)
        response = self.request("POST", "/users", self.admin_token, changed)
        self.assertEqual(response.status, 409)
        self.assertEqual(self.connection.execute("SELECT count(*) FROM supply_users WHERE user_id='a2'").fetchone()[0], 0)

    def test_role_change_is_audited_and_takes_effect_on_next_request(self) -> None:
        response = self.request("POST", "/users/plan/role", self.admin_token, {"role": "risk"})
        self.assertEqual(response.status, 200)
        self.assertEqual(response.body["role"], "risk")
        # 原计划员权限立即丧失。
        quote = {
            "market_index": "PEAK_VALLEY", "trade_date": "2026-09-23", "close_cny": "98",
            "source_revision": "r1", "observed_at": "2026-09-23T21:00:00Z",
        }
        self.assertEqual(self.request("POST", "/quotes", self.plan_token, quote).status, 403)
        # 新风险角色权限立即生效。
        self.assertEqual(
            self.request("POST", "/routes/pipe-a-b/outages", self.plan_token,
                         {"starts_at": "2026-09-25T00:00:00Z", "capacity_percent": "50", "reason": "检修"}).status,
            404,  # 线路尚不存在，说明已通过授权进入业务校验
        )
        events = [e for e in self.audit_items() if e["event_type"] == "user.role_changed"]
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["actor_id"], "root")
        self.assertEqual(events[0]["entity_id"], "plan")
        self.assertEqual(events[0]["payload"], {"from_role": "planner", "to_role": "risk"})

    def test_audit_chain_is_contiguous_and_cryptographically_valid(self) -> None:
        self.request("POST", "/users/plan/role", self.admin_token, {"role": "auditor"})
        self.request("POST", "/users/plan/deactivate", self.admin_token, {"reason": "审计验证后停用"})
        chain = self.request("GET", "/audit/chain", self.audit_token).body
        self.assertTrue(chain["valid"])
        items = chain["items"]
        self.assertEqual(items[0]["previous_hash"], "0" * 64)
        for previous, current in zip(items, items[1:]):
            self.assertEqual(current["previous_hash"], previous["event_hash"])
        types = {item["event_type"] for item in items}
        self.assertIn("user.invited", types)
        self.assertIn("user.role_changed", types)
        self.assertIn("user.deactivated", types)

    # ---- 停用后访问 ---------------------------------------------------

    def test_deactivation_revokes_existing_sessions_immediately(self) -> None:
        victim_token = self.login("risk", "pw-risk")
        # 停用前该会话可以通过授权（路由不存在返回 404）。
        self.assertEqual(
            self.request("POST", "/routes/r-x/outages", victim_token,
                         {"starts_at": "2026-09-25T00:00:00Z", "capacity_percent": "50", "reason": "检修"}).status,
            404,
        )
        response = self.request("POST", "/users/risk/deactivate", self.admin_token, {"reason": "违规操作"})
        self.assertEqual(response.status, 200)
        self.assertGreaterEqual(response.body["sessions_revoked"], 2)  # setUp 与本用例各一个会话
        # 旧会话立即失效。
        self.assertEqual(self.request("GET", "/audit/chain", victim_token).status, 401)
        self.assertEqual(self.request("GET", "/audit/chain", self.risk_token).status, 401)
        # 已停用账号无法重新登录换取新会话。
        blocked = self.app.handle("POST", "/login", body=json_body({"user_id": "risk", "secret": "pw-risk"}))
        self.assertEqual(blocked.status, 403)
        event = [e for e in self.audit_items() if e["event_type"] == "user.deactivated"][-1]
        self.assertEqual(event["actor_id"], "root")
        self.assertEqual(event["entity_id"], "risk")
        self.assertEqual(event["payload"]["reason"], "违规操作")
        self.assertEqual(event["payload"]["sessions_revoked"], response.body["sessions_revoked"])

    def test_last_active_admin_cannot_be_deactivated(self) -> None:
        response = self.request("POST", "/users/root/deactivate", self.admin_token, {"reason": "自锁"})
        self.assertEqual(response.status, 409)
        self.assertEqual(response.body["error"]["code"], "invalid_state")

    # ---- 现有调度流程在新身份边界下保持可用 ---------------------------

    def test_full_dispatch_flow_works_with_bearer_sessions(self) -> None:
        # 计划员建档。
        self.assertEqual(self.request("POST", "/facilities", self.plan_token, {
            "facility_id": "field-a", "name": "北部电厂", "kind": "storage",
            "timezone": "Asia/Shanghai", "capacity_mwh": "500000",
        }).status, 201)
        self.assertEqual(self.request("POST", "/facilities", self.plan_token, {
            "facility_id": "terminal-b", "name": "沿海终端", "kind": "terminal",
            "timezone": "Asia/Shanghai", "capacity_mwh": "800000",
        }).status, 201)
        self.assertEqual(self.request("POST", "/routes", self.plan_token, {
            "route_id": "pipe-a-b", "origin_id": "field-a", "destination_id": "terminal-b",
            "product": "crude", "daily_capacity": "100000", "loss_basis_points": 25, "transit_hours": 36,
        }).status, 201)
        # 调度员完成提名、入账、分配和送电。
        nomination = {
            "nomination_id": "nom-1", "route_id": "pipe-a-b", "shipper_id": "refinery-1",
            "service_date": "2026-09-25", "requested_mwh": "80000", "priority": 10, "idempotency_key": "key-1",
        }
        self.assertEqual(self.request("POST", "/nominations", self.dispatch_token, nomination).status, 201)
        self.assertEqual(self.request("POST", "/inventory/lots", self.dispatch_token, {
            "lot_id": "lot-1", "facility_id": "field-a", "product": "crude", "grade": "PV",
            "quantity_mwh": "120000", "unit_cost_cny": "91", "received_at": "2026-09-24T06:00:00Z",
        }).status, 201)
        allocation = self.request("POST", "/routes/pipe-a-b/allocate", self.dispatch_token, {"service_date": "2026-09-25"})
        self.assertEqual(allocation.status, 200)
        self.assertEqual(allocation.body["available_capacity"], "100000.000")
        transfer = self.request("POST", "/transfers", self.dispatch_token, {
            "transfer_id": "transfer-1", "nomination_id": "nom-1", "lot_id": "lot-1", "expected_revision": 2,
        })
        self.assertEqual(transfer.status, 201)
        self.assertEqual(transfer.body["state"], "in_transit")
        # 业务写操作同样进入审计链，且整条链校验通过。
        chain = self.request("GET", "/audit/chain", self.audit_token).body
        self.assertTrue(chain["valid"])
        self.assertIn("transfer.dispatched", {item["event_type"] for item in chain["items"]})


if __name__ == "__main__":
    unittest.main()
