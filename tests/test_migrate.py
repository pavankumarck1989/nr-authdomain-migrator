import json, os, sys, tempfile, unittest
from unittest import mock
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import migrate, nrgql

SRC = {"domain": {"id": "src"}, "users": [
    {"id": "1", "email": "a@x.com", "name": "A", "tier": "FULL_USER_TIER"},
    {"id": "2", "email": "b@x.com", "name": "B", "tier": "BASIC_USER_TIER"}],
 "groups": [{"name": "G1", "members": ["a@x.com", "b@x.com"], "grants": [
    {"roleId": "10", "roleName": "Standard User", "accountId": "111", "organizationId": None},
    {"roleId": "11", "roleName": "Scheduled Search Access", "accountId": "111", "organizationId": None},
    {"roleId": "12", "roleName": "Billing User", "accountId": None, "organizationId": "org1"}]}]}


class T(unittest.TestCase):
    def run_apply(self, execute, **kw):
        calls = []
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", side_effect=lambda c, d, n: calls.append(("group", n)) or "g1"), \
             mock.patch.object(nrgql, "create_user", side_effect=lambda c, d, e, n, t: calls.append(("user", e, t)) or "u" + e[0]), \
             mock.patch.object(nrgql, "add_members", side_effect=lambda c, g, ids: calls.append(("members", g, sorted(ids)))), \
             mock.patch.object(nrgql, "grant", side_effect=lambda c, g, account_grants=None, org_grants=None, group_grants=None: calls.append(("grant", g, account_grants, org_grants, group_grants))):
            stats, fails, _w = migrate.apply(None, "dst", SRC, execute, True, kw.get("exclude", []), set())
        return stats, fails, calls

    def test_dry_run_writes_nothing(self):
        stats, fails, calls = self.run_apply(False)
        self.assertEqual(calls, [])
        self.assertEqual(stats, dict(groups=1, grants=3, users=2, memberships=2))

    def test_execute_and_exclude(self):
        stats, fails, calls = self.run_apply(True, exclude=["Scheduled Search Access"])
        self.assertEqual(stats["grants"], 2)
        self.assertIn(("grant", "g1", [{"accountId": 111, "roleId": "10"}], None, None), calls)
        self.assertIn(("grant", "g1", None, [{"roleId": "12"}], None), calls)
        self.assertIn(("members", "g1", ["ua", "ub"]), calls)

    def test_idempotent(self):
        with mock.patch.object(nrgql, "read_users", return_value=[{"id": "9", "email": "A@x.com"}, {"id": "8", "email": "b@x.com"}]), \
             mock.patch.object(nrgql, "read_groups", return_value=[{"id": "g9", "displayName": "G1"}]), \
             mock.patch.object(nrgql, "read_members", return_value=[{"email": "a@x.com"}, {"email": "b@x.com"}]), \
             mock.patch.object(nrgql, "read_grants", return_value=[
                 {"roleId": "10", "accountId": "111"}, {"roleId": "11", "accountId": "111"},
                 {"roleId": "12", "organizationId": "org1"}]):
            stats, fails, _w = migrate.apply(None, "dst", SRC, True, True, [], set())
            self.assertEqual(stats, dict(groups=0, grants=0, users=0, memberships=0))
            self.assertEqual(migrate.verify(None, "dst", SRC, True, []), [])

    def test_single_user(self):
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="g1"), \
             mock.patch.object(nrgql, "create_user", side_effect=lambda c, d, e, n, t: "u" + e[0]) as cu, \
             mock.patch.object(nrgql, "add_members") as am, \
             mock.patch.object(nrgql, "grant"):
            stats, _, _w = migrate.apply(None, "dst", SRC, True, True, [], set(), {"a@x.com"})
        self.assertEqual(stats["users"], 1)
        self.assertEqual(stats["memberships"], 1)
        cu.assert_called_once()
        am.assert_called_once_with(None, "g1", ["ua"])

    def test_warns_on_unscoped_grant(self):
        src = {**SRC, "groups": [{**SRC["groups"][0], "grants": [
            {"roleId": "99", "roleName": "Odd Role", "accountId": None, "organizationId": None}]}]}
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]):
            stats, _, warns = migrate.apply(None, "dst", src, False, False, [], set())
        self.assertEqual(stats["grants"], 0)
        self.assertEqual(len(warns), 1)
        self.assertIn("Odd Role", warns[0])

    def test_group_scoped_grant_remapped_by_name(self):
        src = {**SRC, "groups": [
            {"name": "TSM", "members": ["a@x.com"], "grants": [
                {"roleId": "14516", "roleName": "Group Admin", "accountId": None, "organizationId": None,
                 "groupName": "TSM", "groupId": "old-id", "dataAccessPolicyId": None}]}]}
        calls = []
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="new-id"), \
             mock.patch.object(nrgql, "grant", side_effect=lambda c, g, account_grants=None, org_grants=None, group_grants=None: calls.append((g, group_grants))):
            stats, _, warns = migrate.apply(None, "dst", src, True, False, [], set())
        self.assertEqual(calls, [("new-id", [{"groupId": "new-id", "roleId": "14516"}])])
        self.assertEqual(warns, [])
        self.assertEqual(stats["grants"], 1)

    def test_rollback_reverses_only_manifest_in_reverse_order(self):
        import tempfile, os
        path = os.path.join(tempfile.mkdtemp(), "m.jsonl")
        m = migrate.Manifest(path, "dst")
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="g1"), \
             mock.patch.object(nrgql, "create_user", side_effect=lambda c, d, e, n, t: "u" + e[0]), \
             mock.patch.object(nrgql, "add_members"), mock.patch.object(nrgql, "grant"):
            migrate.apply(None, "dst", SRC, True, True, [], set(), frozenset(), m)
        calls = []
        with mock.patch.object(nrgql, "check_rollback_schema", return_value=[]), \
             mock.patch.object(nrgql, "revoke", side_effect=lambda c, g, a, o, gr: calls.append("revoke")), \
             mock.patch.object(nrgql, "remove_members", side_effect=lambda c, g, ids: calls.append("members")), \
             mock.patch.object(nrgql, "delete_user", side_effect=lambda c, i: calls.append("user")), \
             mock.patch.object(nrgql, "delete_group", side_effect=lambda c, i: calls.append("group")):
            dry, _ = migrate.rollback(None, "dst", path, False)
            self.assertEqual(calls, [])
            stats, fails = migrate.rollback(None, "dst", path, True)
            self.assertEqual(calls[0], "members")
            self.assertEqual(calls[-1], "group")
            self.assertLess(calls.index("user"), calls.index("revoke"))
            self.assertEqual(stats, dry)
            again, _ = migrate.rollback(None, "dst", path, True)
        self.assertEqual(again, dict(grants=0, memberships=0, users=0, groups=0))
        with self.assertRaises(SystemExit):
            migrate.rollback(None, "other-domain", path, False)

    def test_failure_attributed_to_user(self):
        errors = {}
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="g1"), \
             mock.patch.object(nrgql, "grant"), mock.patch.object(nrgql, "add_members"), \
             mock.patch.object(nrgql, "create_user", side_effect=lambda c, d, e, n, t: (_ for _ in ()).throw(nrgql.NerdGraphError("nope")) if e.startswith("a") else "ub"):
            stats, fails, _w = migrate.apply(None, "dst", SRC, True, True, [], set(), frozenset(), None, errors)
        self.assertIn("a@x.com", errors)
        self.assertNotIn("b@x.com", errors)
        self.assertEqual(len(fails), 1)

    def test_selective_rollback_only_removes_created_users(self):
        import tempfile, os
        path = os.path.join(tempfile.mkdtemp(), "m.jsonl")
        m = migrate.Manifest(path, "dst")
        m.add(op="group", id="g1", name="G1")
        m.add(op="user", id="ua", email="a@x.com")
        m.add(op="user", id="ub", email="b@x.com")
        m.add(op="member", groupId="g1", userIds=["ua", "ub"])
        calls = []
        with mock.patch.object(nrgql, "check_rollback_schema", return_value=[]), \
             mock.patch.object(nrgql, "remove_members", side_effect=lambda c, g, ids: calls.append(("rm", g, ids))), \
             mock.patch.object(nrgql, "delete_user", side_effect=lambda c, i: calls.append(("del", i))), \
             mock.patch.object(nrgql, "delete_group", side_effect=lambda c, i: calls.append(("delg", i))):
            stats, fails, skipped = migrate.rollback_users(None, "dst", path, {"a@x.com", "pre@x.com"}, False)
            self.assertEqual(calls, [])
            self.assertEqual((stats, skipped), (dict(users=1, memberships=1), ["pre@x.com"]))
            stats, fails, skipped = migrate.rollback_users(None, "dst", path, {"a@x.com", "pre@x.com"}, True)
            self.assertEqual(calls, [("rm", "g1", ["ua"]), ("del", "ua")])
            # a second run finds nothing left to remove for a@x.com
            stats2, _, skipped2 = migrate.rollback_users(None, "dst", path, {"a@x.com"}, True)
            self.assertEqual((stats2["users"], skipped2), (0, ["a@x.com"]))
            # full rollback afterwards leaves b alone being removed with the group, and does not touch ua again
            calls.clear()
            migrate.rollback(None, "dst", path, True)
        self.assertNotIn(("del", "ua"), calls)
        self.assertIn(("del", "ub"), calls)
        self.assertIn(("rm", "g1", ["ub"]), calls)
        with self.assertRaises(SystemExit):
            migrate.rollback_users(None, "other", path, {"a@x.com"}, False)

    def test_skip_empty_and_no_access_groups(self):
        src = {**SRC, "groups": SRC["groups"] + [{"name": "Empty", "members": [], "grants": SRC["groups"][0]["grants"]},
                                                 {"name": "NoAccess", "members": ["a@x.com"], "grants": []}]}
        self.assertEqual([g["name"] for g in migrate.drop_groups(src, True, False)["groups"]], ["G1", "NoAccess"])
        self.assertEqual([g["name"] for g in migrate.drop_groups(src, False, True)["groups"]], ["G1", "Empty"])
        self.assertEqual([g["name"] for g in migrate.drop_groups(src, True, True)["groups"]], ["G1"])

    def test_tier(self):
        self.assertEqual(migrate.tier_of("Full platform"), "FULL_USER_TIER")
        self.assertEqual(migrate.tier_of("Basic"), "BASIC_USER_TIER")


class Scale(unittest.TestCase):
    def many(self, n):
        return {"domain": {"id": "src"},
                "users": [{"id": str(i), "email": f"u{i}@x.com", "name": f"U{i}", "tier": "BASIC_USER_TIER"} for i in range(n)],
                "groups": [{"name": f"G{k}", "members": [f"u{i}@x.com" for i in range(k, n, 7)],
                            "grants": [{"roleId": "10", "roleName": "R", "accountId": str(a), "organizationId": None}
                                       for a in range(100, 135)]} for k in range(7)]}

    def patches(self, **over):
        created = {"u": 0}
        def cu(c, d, e, n, t):
            created["u"] += 1
            return "id-" + e
        base = dict(read_users=mock.DEFAULT, read_groups=mock.DEFAULT)
        return created, cu

    def test_two_thousand_users_dry_run_and_execute(self):
        src = self.many(2000)
        calls = {"user": 0, "members": 0, "grant": 0, "group": 0}
        def cnt(k):
            return lambda *a, **kw: calls.__setitem__(k, calls[k] + 1) or ("g-" + str(calls[k]) if k == "group" else None)
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", side_effect=cnt("group")), \
             mock.patch.object(nrgql, "create_user", side_effect=lambda c, d, e, n, t: calls.__setitem__("user", calls["user"] + 1) or "id-" + e), \
             mock.patch.object(nrgql, "add_members", side_effect=cnt("members")), \
             mock.patch.object(nrgql, "grant", side_effect=cnt("grant")):
            stats, fails, warns = migrate.apply(None, "dst", src, False, True, [], set())
            self.assertEqual(calls, {"user": 0, "members": 0, "grant": 0, "group": 0})
            self.assertEqual((stats["groups"], stats["users"], stats["grants"]), (7, 2000, 7 * 35))
            self.assertIn("write calls", migrate.estimate(stats))
            stats, fails, warns = migrate.apply(None, "dst", src, True, True, [], set())
        self.assertEqual((calls["user"], calls["group"], fails), (2000, 7, []))
        self.assertEqual(calls["grant"], 7)            # 35 grants per group fit in one 50-grant batch
        self.assertEqual(stats["memberships"], 2000)   # every user is in exactly one group

    def test_stops_after_consecutive_failures(self):
        src = self.many(100)
        def boom(*a, **k):
            raise nrgql.NerdGraphError("HTTP 401: bad key")
        with mock.patch.object(nrgql, "read_users", return_value=[]), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="g"), mock.patch.object(nrgql, "grant"), \
             mock.patch.object(nrgql, "add_members"), \
             mock.patch.object(nrgql, "create_user", side_effect=boom) as cu:
            stats, fails, warns = migrate.apply(None, "dst", src, True, True, [], set(), frozenset(), None, {}, 5)
        self.assertEqual(cu.call_count, 5)
        self.assertTrue(stats["aborted"])
        self.assertTrue(any(w.startswith("ABORTED") for w in warns))

    def test_ambiguous_create_is_recovered_not_duplicated(self):
        src = {**SRC, "groups": [], "users": SRC["users"][:1]}
        state = {"n": 0}
        def read_users(c, d):
            state["n"] += 1
            return [{"id": "real-id", "email": "A@x.com"}] if state["n"] > 1 else []
        errors = {}
        m_events = []
        class M:
            def add(self, **e): m_events.append(e)
        with mock.patch.object(nrgql, "read_users", side_effect=read_users), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_user", side_effect=nrgql.NerdGraphError("HTTP 504 (outcome unknown; check)")):
            stats, fails, _ = migrate.apply(None, "dst", src, True, True, [], set(), frozenset(), M(), errors)
        self.assertEqual(fails, [])
        self.assertEqual(m_events, [{"op": "user", "id": "real-id", "email": "a@x.com"}])
        self.assertEqual(stats["users"], 1)

    def test_export_tolerates_bad_records(self):
        users = [{"id": "1", "email": None, "name": "x", "type": {"displayName": "Basic"}},
                 {"id": "2", "email": "B@X.com", "name": None, "type": {"displayName": "Weird"}},
                 {"id": "3", "email": "c@x.com", "name": "C", "type": {"displayName": "Full platform"}}]
        with mock.patch.object(nrgql, "list_domains", return_value=[{"id": "d", "name": "D"}]), \
             mock.patch.object(nrgql, "read_users", return_value=users), \
             mock.patch.object(nrgql, "read_groups", return_value=[{"id": "g1", "displayName": "G"}, {"id": "g2", "displayName": "G"}]), \
             mock.patch.object(nrgql, "read_members", return_value=[{"email": "c@x.com"}, {"email": None}]), \
             mock.patch.object(nrgql, "read_grants", return_value=[]):
            data = migrate.export(None, "d")
        self.assertEqual([u["email"] for u in data["users"]], ["b@x.com", "c@x.com"])
        self.assertIsNone(data["users"][0]["tier"])
        self.assertEqual(data["groups"][0]["members"], ["c@x.com"])
        # a user with an unsupported type is reported, not created
        with mock.patch.object(nrgql, "read_users", return_value=[]), mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "create_group", return_value="g"), mock.patch.object(nrgql, "grant"), \
             mock.patch.object(nrgql, "add_members"), mock.patch.object(nrgql, "create_user") as cu:
            errors = {}
            _, _, warns = migrate.apply(None, "dst", data, True, True, [], set(), frozenset(), None, errors)
        self.assertEqual([c.args[3] for c in cu.call_args_list], ["C"])
        self.assertIn("b@x.com", errors)


class ClientRetry(unittest.TestCase):
    def setUp(self):
        import urllib.error, io
        self.ue = urllib.error
        self.io = io

    def client(self):
        return nrgql.Client(api_key="k", region="US", retries=2)

    def test_read_retries_timeout_but_write_does_not(self):
        c = self.client()
        with mock.patch("urllib.request.urlopen", side_effect=TimeoutError("slow")) as uo, mock.patch("time.sleep"):
            with self.assertRaises(nrgql.NerdGraphError):
                c.query("query { a }")
            self.assertEqual(uo.call_count, 3)
            uo.reset_mock()
            with self.assertRaises(nrgql.NerdGraphError) as cm:
                c.query("mutation { userManagementCreateUser }")
            self.assertEqual(uo.call_count, 1)
            self.assertIn("outcome unknown", str(cm.exception))

    def test_write_retried_on_429_only(self):
        c = self.client()
        def http(code):
            return self.ue.HTTPError("u", code, "x", {}, self.io.BytesIO(b"{}"))
        class R:
            def __enter__(s): return s
            def __exit__(s, *a): pass
            def read(s, *a): return b'{"data": {"ok": 1}}'
        with mock.patch("urllib.request.urlopen", side_effect=[http(429), R()]) as uo, mock.patch("time.sleep"):
            self.assertEqual(c.query("mutation { x }"), {"ok": 1})
            self.assertEqual(uo.call_count, 2)
        with mock.patch("urllib.request.urlopen", side_effect=[http(503), R()]) as uo, mock.patch("time.sleep"):
            with self.assertRaises(nrgql.NerdGraphError) as cm:
                c.query("mutation { x }")
            self.assertEqual(uo.call_count, 1)
            self.assertIn("outcome unknown", str(cm.exception))

    def test_pagination_loop_guard(self):
        page = {"actor": {"organization": {"userManagement": {"authenticationDomains": {"authenticationDomains": [
            {"users": {"nextCursor": "same", "users": [{"id": "1"}]}}]}}}}}
        class C:
            def query(s, *a, **k): return page
        with self.assertRaises(nrgql.NerdGraphError):
            nrgql.read_users(C(), "d")


class V(unittest.TestCase):
    def test_verify_limited_to_selected_users(self):
        with mock.patch.object(nrgql, "read_users", return_value=[{"id": "9", "email": "a@x.com"}]), \
             mock.patch.object(nrgql, "read_groups", return_value=[{"id": "g9", "displayName": "G1"}]), \
             mock.patch.object(nrgql, "read_members", return_value=[{"email": "a@x.com"}]), \
             mock.patch.object(nrgql, "read_grants", return_value=[
                 {"roleId": "10", "accountId": "111"}, {"roleId": "11", "accountId": "111"},
                 {"roleId": "12", "organizationId": "org1"}]):
            self.assertEqual(migrate.verify(None, "dst", SRC, True, [], frozenset({"a@x.com"})), [])
            self.assertNotEqual(migrate.verify(None, "dst", SRC, True, []), [])


class W(unittest.TestCase):
    def test_worksheet_roundtrip(self):
        import tempfile, userlist
        src = {**SRC, "users": SRC["users"] + [{"id": "3", "email": "c@x.com", "name": "=cmd", "tier": "CORE_USER_TIER"}]}
        rows = userlist.build_rows(src, {"a@x.com"}, {"b@x.com": "yes"}, "no")
        by = {r["email"]: r for r in rows}
        self.assertEqual(by["a@x.com"]["in_new_domain"], "yes")
        self.assertEqual(by["b@x.com"]["in_new_domain"], "no")
        self.assertEqual((by["a@x.com"]["migrate"], by["b@x.com"]["migrate"]), ("no", "yes"))
        self.assertEqual(by["a@x.com"]["account_count"], 1)
        self.assertEqual(by["a@x.com"]["groups"], "G1")
        self.assertTrue(by["c@x.com"]["name"].startswith("'="))
        path = os.path.join(tempfile.mkdtemp(), "u.csv")
        userlist.write_csv(path, rows)
        choices, errors = userlist.read_choices(path)
        self.assertEqual(errors, [])
        self.assertEqual(choices["b@x.com"], "yes")

    def test_status_values(self):
        import userlist
        src = {**SRC, "users": SRC["users"] + [{"id": "3", "email": "c@x.com", "name": "C", "tier": "BASIC_USER_TIER"}]}
        src["groups"] = [{**SRC["groups"][0], "members": ["a@x.com", "b@x.com"]}]
        choices = {"a@x.com": "yes", "b@x.com": "yes", "c@x.com": "no"}
        rows = userlist.build_rows(src, {"a@x.com", "b@x.com"}, choices, "no", {"G1": {"a@x.com"}},
                                   {"zz@x.com": "ignored"}, "now")
        st = {r["email"]: (r["status"], r["note"]) for r in rows}
        self.assertEqual(st["a@x.com"][0], "migrated")
        self.assertEqual(st["b@x.com"], ("partial", "missing from groups: G1"))
        self.assertEqual(st["c@x.com"][0], "not selected")
        rows = userlist.build_rows(src, set(), {"a@x.com": "yes"}, "no", {}, {"a@x.com": "boom"}, "now")
        st = {r["email"]: r["status"] for r in rows}
        self.assertEqual((st["a@x.com"], st["b@x.com"]), ("failed", "not selected"))
        rows = userlist.build_rows(src, set(), {"b@x.com": "yes"}, "no", {}, {}, "now")
        self.assertEqual({r["email"]: r["status"] for r in rows}["b@x.com"], "pending")

    def test_invalid_choice_reported(self):
        import tempfile, userlist
        path = os.path.join(tempfile.mkdtemp(), "u.csv")
        with open(path, "w") as f:
            f.write("email,migrate\na@x.com,Yes\nb@x.com,maybe\n")
        choices, errors = userlist.read_choices(path)
        self.assertEqual(choices, {"a@x.com": "yes"})
        self.assertEqual(len(errors), 1)
        self.assertIn("line 3", errors[0])



class Safety(unittest.TestCase):
    DOMS = [{"id": "s", "name": "Old", "provisioningType": "MANUAL"}, {"id": "t", "name": "New", "provisioningType": "SCIM"}]

    def test_load_export_messages(self):
        d = tempfile.mkdtemp()
        with self.assertRaises(SystemExit) as c:
            migrate.load_export(os.path.join(d, "nope.json"))
        self.assertIn("not found", str(c.exception))
        bad = os.path.join(d, "bad.json")
        with open(bad, "w") as f:
            f.write("{oops")
        with self.assertRaises(SystemExit) as c:
            migrate.load_export(bad)
        self.assertIn("not a valid export", str(c.exception))
        wrong = os.path.join(d, "wrong.json")
        with open(wrong, "w") as f:
            json.dump({"hello": 1}, f)
        with self.assertRaises(SystemExit):
            migrate.load_export(wrong)
        ok = os.path.join(d, "ok.json")
        with open(ok, "w") as f:
            json.dump(SRC, f)
        self.assertEqual(migrate.load_export(ok)["domain"]["id"], "src")

    def test_confirm_requires_typed_name_or_yes(self):
        with mock.patch.object(nrgql, "list_domains", return_value=self.DOMS):
            migrate.confirm_execute(None, "t", "x", True)
            with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="Old"):
                with self.assertRaises(SystemExit):
                    migrate.confirm_execute(None, "t", "x", False)
            with mock.patch("sys.stdin.isatty", return_value=True), mock.patch("builtins.input", return_value="New"):
                migrate.confirm_execute(None, "t", "x", False)
            with mock.patch("sys.stdin.isatty", return_value=False):
                with self.assertRaises(SystemExit):
                    migrate.confirm_execute(None, "t", "x", False)

    def test_scim_detection(self):
        self.assertTrue(migrate.is_scim(self.DOMS[1]))
        self.assertFalse(migrate.is_scim(self.DOMS[0]))

    def test_preflight(self):
        with mock.patch.object(nrgql, "list_domains", return_value=self.DOMS), \
             mock.patch.object(nrgql, "read_groups", return_value=[]), \
             mock.patch.object(nrgql, "check_rollback_schema", return_value=[]):
            self.assertEqual(migrate.preflight(None, "s", "t"), 0)
            self.assertEqual(migrate.preflight(None, "s", "zzz"), 1)
            self.assertEqual(migrate.preflight(None, "s", "s"), 1)
        with mock.patch.object(nrgql, "list_domains", side_effect=nrgql.NerdGraphError("HTTP 401")):
            self.assertEqual(migrate.preflight(None, "s", "t"), 1)


if __name__ == "__main__":
    unittest.main()
