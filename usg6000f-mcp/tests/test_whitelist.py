"""白名单引擎单元测试"""
import os
import sys
import unittest
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from whitelist import WhitelistEngine, _domain_match, _check_biz_hour  # noqa: E402

# 测试固定时间：2026-04-19 周日 10:00（周末，保证 L5 biz_hour 不命中）
WEEKEND = datetime(2026, 4, 19, 10, 0, 0)


SAMPLE = {
    "ip": [
        {"cidr": "10.0.0.0/8", "comment": "内网核心"},
        {"cidr": "192.168.0.0/16", "comment": "办公段"},
        {"cidr": "203.0.113.5/32", "comment": "办公出口"},
    ],
    "asn": [
        {"asn": 4134, "comment": "中国电信"},
        {"asn": 4837, "comment": "中国联通"},
    ],
    "domain": [
        {"pattern": "*.cmhk.com", "comment": "甲方主域"},
        {"pattern": "trusted.example.com", "comment": "精确域名"},
    ],
    "tag": [
        {"tag": "core_business", "action": "block", "comment": "核心业务"},
        {"tag": "office", "action": "warn", "comment": "办公"},
    ],
    "biz_hour": {
        "workdays": ["mon", "tue", "wed", "thu", "fri"],
        "work_hours": {"start": "09:00", "end": "18:00"},
        "action": "warn",
        "holidays": ["2026-05-01"],
    },
}


class TestL1IPCIDR(unittest.TestCase):
    def setUp(self) -> None:
        self.e = WhitelistEngine()
        self.e.load_from_dict(SAMPLE)

    def test_in_cidr(self) -> None:
        r = self.e.check("10.80.0.91", now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L1_ip")
        self.assertEqual(r.action, "block")

    def test_office_cidr(self) -> None:
        r = self.e.check("192.168.1.100", now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L1_ip")

    def test_single_ip(self) -> None:
        r = self.e.check("203.0.113.5", now=WEEKEND)
        self.assertTrue(r.hit)

    def test_not_hit(self) -> None:
        r = self.e.check("8.8.8.8", now=WEEKEND)
        self.assertFalse(r.hit)
        self.assertIn("L1_ip", r.checked_layers)

    def test_invalid_ip_skips_l1(self) -> None:
        r = self.e.check("not-an-ip", now=WEEKEND)
        # L1 会跳过（IP 非法），但没其他维度入参，最终 not hit
        self.assertFalse(r.hit)


class TestL2ASN(unittest.TestCase):
    def setUp(self) -> None:
        self.e = WhitelistEngine()
        self.e.load_from_dict(SAMPLE)

    def test_hit_asn(self) -> None:
        r = self.e.check("8.8.8.8", asn=4134, now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L2_asn")

    def test_miss_asn(self) -> None:
        r = self.e.check("8.8.8.8", asn=99999, now=WEEKEND)
        self.assertFalse(r.hit)


class TestL3Domain(unittest.TestCase):
    def setUp(self) -> None:
        self.e = WhitelistEngine()
        self.e.load_from_dict(SAMPLE)

    def test_wildcard_match(self) -> None:
        r = self.e.check("8.8.8.8", domain="api.cmhk.com", now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L3_domain")

    def test_exact_match(self) -> None:
        r = self.e.check("8.8.8.8", domain="trusted.example.com", now=WEEKEND)
        self.assertTrue(r.hit)

    def test_miss(self) -> None:
        r = self.e.check("8.8.8.8", domain="evil.com", now=WEEKEND)
        self.assertFalse(r.hit)

    def test_case_insensitive(self) -> None:
        r = self.e.check("8.8.8.8", domain="API.CMHK.COM", now=WEEKEND)
        self.assertTrue(r.hit)


class TestL4Tag(unittest.TestCase):
    def setUp(self) -> None:
        self.e = WhitelistEngine()
        self.e.load_from_dict(SAMPLE)

    def test_core_business_block(self) -> None:
        r = self.e.check("8.8.8.8", tags=["core_business"], now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.action, "block")

    def test_office_warn(self) -> None:
        r = self.e.check("8.8.8.8", tags=["office"], now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.action, "warn")


class TestL5BizHour(unittest.TestCase):
    def setUp(self) -> None:
        self.e = WhitelistEngine()
        self.e.load_from_dict(SAMPLE)

    def test_in_biz_hour(self) -> None:
        # 2026-04-20 是周一，10:00 在工作时段
        now = datetime(2026, 4, 20, 10, 0, 0)
        r = self.e.check("8.8.8.8", now=now)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L5_biz_hour")

    def test_weekend_no_hit(self) -> None:
        # 2026-04-19 周日
        now = datetime(2026, 4, 19, 10, 0, 0)
        r = self.e.check("8.8.8.8", now=now)
        self.assertFalse(r.hit)

    def test_after_hours_no_hit(self) -> None:
        # 周一 23:00
        now = datetime(2026, 4, 20, 23, 0, 0)
        r = self.e.check("8.8.8.8", now=now)
        self.assertFalse(r.hit)

    def test_holiday_no_hit(self) -> None:
        # 2026-05-01 节假日（虽然是周五）
        now = datetime(2026, 5, 1, 10, 0, 0)
        r = self.e.check("8.8.8.8", now=now)
        self.assertFalse(r.hit)


class TestPriorityL1First(unittest.TestCase):
    def test_l1_hit_short_circuits(self) -> None:
        # 即使 ASN 也在白名单，也只返 L1（顺序 L1→L2→L3→L4→L5）
        e = WhitelistEngine()
        e.load_from_dict(SAMPLE)
        r = e.check("10.0.0.1", asn=4134, now=WEEKEND)
        self.assertTrue(r.hit)
        self.assertEqual(r.layer, "L1_ip")


class TestStats(unittest.TestCase):
    def test_stats_tracking(self) -> None:
        e = WhitelistEngine()
        e.load_from_dict(SAMPLE)
        e.check("10.0.0.1", now=WEEKEND)  # hit L1
        e.check("10.0.0.2", now=WEEKEND)  # hit L1
        e.check("8.8.8.8", now=WEEKEND)   # miss（周末 + 非白名单 IP）
        s = e.stats.to_dict()
        self.assertEqual(s["total_checks"], 3)
        self.assertEqual(s["total_hits"], 2)
        self.assertEqual(s["hits_by_layer"]["L1_ip"], 2)


class TestDomainMatch(unittest.TestCase):
    def test_wildcard(self) -> None:
        self.assertTrue(_domain_match("api.cmhk.com", "*.cmhk.com"))
        self.assertTrue(_domain_match("www.api.cmhk.com", "*.cmhk.com"))
        self.assertTrue(_domain_match("cmhk.com", "*.cmhk.com"))
        self.assertFalse(_domain_match("cmhk.org", "*.cmhk.com"))

    def test_exact(self) -> None:
        self.assertTrue(_domain_match("trusted.example.com", "trusted.example.com"))
        self.assertFalse(_domain_match("other.example.com", "trusted.example.com"))


class TestEngineNotLoaded(unittest.TestCase):
    def test_skip_when_not_loaded(self) -> None:
        e = WhitelistEngine()
        r = e.check("10.0.0.1")
        self.assertFalse(r.hit)
        self.assertIn("未加载", r.comment)


if __name__ == "__main__":
    unittest.main(verbosity=2)
