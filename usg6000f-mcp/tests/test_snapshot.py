"""snapshot.py 单元测试"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestSnapshot(unittest.TestCase):
    def setUp(self) -> None:
        self.tmpdir = tempfile.mkdtemp(prefix="usg-action-test-")
        os.environ["USG_ACTION_DIR"] = self.tmpdir
        # 重新导入以应用新的环境变量
        if "snapshot" in sys.modules:
            del sys.modules["snapshot"]
        import snapshot
        self.snap = snapshot

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_new_action_id_format(self) -> None:
        aid = self.snap.new_action_id()
        self.assertTrue(aid.startswith("act-"))
        parts = aid.split("-")
        self.assertEqual(len(parts), 4)  # act, YYYYMMDD, HHMMSS, hex

    def test_save_load(self) -> None:
        aid = self.snap.new_action_id()
        rec = {
            "action_id": aid,
            "ip": "1.2.3.4",
            "action_type": "block",
            "status": "applied",
        }
        self.snap.save(rec)
        loaded = self.snap.load(aid)
        self.assertEqual(loaded["ip"], "1.2.3.4")

    def test_load_nonexistent(self) -> None:
        self.assertIsNone(self.snap.load("act-nonexistent"))

    def test_update(self) -> None:
        aid = self.snap.new_action_id()
        self.snap.save({"action_id": aid, "ip": "1.2.3.4", "status": "applied"})
        updated = self.snap.update(aid, {"status": "unblocked", "unblocked_at": "2026-04-20"})
        self.assertEqual(updated["status"], "unblocked")
        self.assertEqual(updated["ip"], "1.2.3.4")  # 原字段保留
        # 二次读
        reloaded = self.snap.load(aid)
        self.assertEqual(reloaded["unblocked_at"], "2026-04-20")

    def test_list_recent_order(self) -> None:
        ids = []
        for i in range(3):
            aid = self.snap.new_action_id()
            ids.append(aid)
            self.snap.save({
                "action_id": aid, "ip": f"1.2.3.{i}",
                "action_type": "block", "status": "applied",
            })
            time.sleep(0.01)  # 保证 mtime 不同
        items = self.snap.list_recent(limit=10)
        self.assertEqual(len(items), 3)
        # 最新的应该排第一
        self.assertEqual(items[0]["action_id"], ids[-1])

    def test_list_filter_by_ip(self) -> None:
        for ip in ["1.1.1.1", "2.2.2.2", "1.1.1.1"]:
            self.snap.save({
                "action_id": self.snap.new_action_id(),
                "ip": ip, "action_type": "block", "status": "applied",
            })
            time.sleep(0.01)
        items = self.snap.list_recent(limit=10, ip="1.1.1.1")
        self.assertEqual(len(items), 2)
        for it in items:
            self.assertEqual(it["ip"], "1.1.1.1")

    def test_list_filter_by_status(self) -> None:
        self.snap.save({
            "action_id": self.snap.new_action_id(), "ip": "1.1.1.1",
            "action_type": "block", "status": "applied",
        })
        time.sleep(0.01)
        self.snap.save({
            "action_id": self.snap.new_action_id(), "ip": "2.2.2.2",
            "action_type": "block", "status": "unblocked",
        })
        applied = self.snap.list_recent(limit=10, status="applied")
        unblocked = self.snap.list_recent(limit=10, status="unblocked")
        self.assertEqual(len(applied), 1)
        self.assertEqual(len(unblocked), 1)

    def test_now_iso(self) -> None:
        s = self.snap.now_iso()
        self.assertRegex(s, r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")


if __name__ == "__main__":
    unittest.main(verbosity=2)
