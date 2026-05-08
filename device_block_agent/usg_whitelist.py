from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from typing import Any

try:
    import yaml  # type: ignore

    _HAS_YAML = True
except ImportError:
    _HAS_YAML = False


@dataclass
class CheckResult:
    hit: bool
    layer: str = ""
    rule_id: str = ""
    comment: str = ""
    action: str = "block"
    checked_layers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "hit": self.hit,
            "layer": self.layer,
            "rule_id": self.rule_id,
            "comment": self.comment,
            "action": self.action,
            "checked_layers": self.checked_layers,
        }


@dataclass
class WhitelistStats:
    total_checks: int = 0
    total_hits: int = 0
    hits_by_layer: dict[str, int] = field(default_factory=dict)

    def record(self, result: CheckResult) -> None:
        self.total_checks += 1
        if result.hit:
            self.total_hits += 1
            self.hits_by_layer[result.layer] = self.hits_by_layer.get(result.layer, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        hit_rate = round(self.total_hits / self.total_checks, 4) if self.total_checks else 0.0
        return {
            "total_checks": self.total_checks,
            "total_hits": self.total_hits,
            "hit_rate": hit_rate,
            "hits_by_layer": dict(self.hits_by_layer),
        }


class WhitelistEngine:
    def __init__(self) -> None:
        self._l1_ips: list[tuple[ipaddress._BaseNetwork, str, str]] = []
        self._l2_asns: dict[int, str] = {}
        self._l3_domains: list[tuple[str, str]] = []
        self._l4_tags: dict[str, tuple[str, str]] = {}
        self._l5_biz: dict[str, Any] = {}
        self._source_path: str | None = None
        self._loaded = False
        self.stats = WhitelistStats()

    def load(self, path: str) -> None:
        if not _HAS_YAML:
            raise RuntimeError("PyYAML 未安装，无法加载 YAML 白名单。请先安装 pyyaml")
        if not os.path.exists(path):
            raise FileNotFoundError(f"白名单文件不存在: {path}")
        with open(path, encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        self.load_from_dict(data)
        self._source_path = path

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._l1_ips.clear()
        self._l2_asns.clear()
        self._l3_domains.clear()
        self._l4_tags.clear()
        self._l5_biz.clear()

        for index, row in enumerate(data.get("ip", []) or []):
            cidr = row.get("cidr") or row.get("ip")
            if not cidr:
                continue
            try:
                network = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            self._l1_ips.append((network, f"ip[{index}]={cidr}", str(row.get("comment", ""))))

        for row in data.get("asn", []) or []:
            asn = row.get("asn")
            if isinstance(asn, int):
                self._l2_asns[asn] = str(row.get("comment", ""))

        for row in data.get("domain", []) or []:
            pattern = row.get("pattern") or row.get("domain")
            if pattern:
                self._l3_domains.append((str(pattern).lower(), str(row.get("comment", ""))))

        for row in data.get("tag", []) or []:
            tag = row.get("tag")
            if tag:
                self._l4_tags[str(tag)] = (str(row.get("action", "block")), str(row.get("comment", "")))

        self._l5_biz = dict(data.get("biz_hour", {}) or {})
        self._loaded = True

    def reload(self) -> None:
        if not self._source_path:
            raise RuntimeError("没有历史加载路径可供 reload")
        self.load(self._source_path)

    def is_loaded(self) -> bool:
        return self._loaded

    def check(
        self,
        ip: str,
        *,
        asn: int | None = None,
        domain: str | None = None,
        tags: list[str] | None = None,
        now: datetime | None = None,
    ) -> CheckResult:
        if not self._loaded:
            result = CheckResult(hit=False, comment="白名单未加载，跳过校验")
            self.stats.record(result)
            return result

        checked_layers: list[str] = []

        try:
            address = ipaddress.ip_address(ip)
            checked_layers.append("L1_ip")
            for network, rule_id, comment in self._l1_ips:
                if address in network:
                    result = CheckResult(True, "L1_ip", rule_id, comment, "block", checked_layers)
                    self.stats.record(result)
                    return result
        except ValueError:
            pass

        if asn is not None:
            checked_layers.append("L2_asn")
            if asn in self._l2_asns:
                result = CheckResult(True, "L2_asn", f"asn={asn}", self._l2_asns[asn], "block", checked_layers)
                self.stats.record(result)
                return result

        if domain:
            checked_layers.append("L3_domain")
            normalized_domain = domain.lower()
            for pattern, comment in self._l3_domains:
                if _domain_match(normalized_domain, pattern):
                    result = CheckResult(True, "L3_domain", f"domain={pattern}", comment, "block", checked_layers)
                    self.stats.record(result)
                    return result

        if tags:
            checked_layers.append("L4_tag")
            for tag in tags:
                if tag in self._l4_tags:
                    action, comment = self._l4_tags[tag]
                    result = CheckResult(True, "L4_tag", f"tag={tag}", comment, action, checked_layers)
                    self.stats.record(result)
                    return result

        if self._l5_biz:
            checked_layers.append("L5_biz_hour")
            if _check_biz_hour(self._l5_biz, now or datetime.now()):
                action = str(self._l5_biz.get("action", "warn"))
                result = CheckResult(True, "L5_biz_hour", "biz_hour", "当前处于业务时段", action, checked_layers)
                self.stats.record(result)
                return result

        result = CheckResult(hit=False, checked_layers=checked_layers)
        self.stats.record(result)
        return result

    def summary(self) -> dict[str, Any]:
        return {
            "loaded": self._loaded,
            "source": self._source_path,
            "counts": {
                "L1_ip": len(self._l1_ips),
                "L2_asn": len(self._l2_asns),
                "L3_domain": len(self._l3_domains),
                "L4_tag": len(self._l4_tags),
                "L5_biz_hour": 1 if self._l5_biz else 0,
            },
            "stats": self.stats.to_dict(),
        }

    def list_all(self) -> dict[str, Any]:
        return {
            "ip": [{"cidr": str(network), "rule_id": rule_id, "comment": comment} for network, rule_id, comment in self._l1_ips],
            "asn": [{"asn": asn, "comment": comment} for asn, comment in self._l2_asns.items()],
            "domain": [{"pattern": pattern, "comment": comment} for pattern, comment in self._l3_domains],
            "tag": [{"tag": tag, "action": action, "comment": comment} for tag, (action, comment) in self._l4_tags.items()],
            "biz_hour": dict(self._l5_biz),
        }


def _domain_match(domain: str, pattern: str) -> bool:
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return domain.endswith(suffix) or domain == suffix[1:]
    return False


def _check_biz_hour(config: dict[str, Any], now: datetime) -> bool:
    workdays = config.get("workdays") or []
    work_hours = config.get("work_hours") or {}
    holidays = config.get("holidays") or []

    today_string = now.strftime("%Y-%m-%d")
    if today_string in holidays:
        return False

    weekday_names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    current_weekday = weekday_names[now.weekday()]
    if workdays and current_weekday not in [day.lower() for day in workdays]:
        return False

    start_string = work_hours.get("start", "00:00")
    end_string = work_hours.get("end", "23:59")
    try:
        start_hour, start_minute = map(int, str(start_string).split(":"))
        end_hour, end_minute = map(int, str(end_string).split(":"))
        current_time = now.time()
        return dtime(start_hour, start_minute) <= current_time <= dtime(end_hour, end_minute)
    except (ValueError, AttributeError):
        return False


_GLOBAL = WhitelistEngine()


def get_engine() -> WhitelistEngine:
    return _GLOBAL


def auto_load_default() -> str | None:
    env_path = os.environ.get("USG_WHITELIST_PATH", "").strip()
    workspace_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    candidates = [
        env_path,
        os.path.join(workspace_root, "config", "usg-whitelist.yaml"),
        os.path.join(workspace_root, "usg6000f-mcp", "whitelist.yaml"),
        os.path.join(workspace_root, "usg6000f-mcp", "whitelist.sample.yaml"),
    ]
    for path in candidates:
        if path and os.path.exists(path):
            try:
                _GLOBAL.load(path)
                return path
            except Exception:
                continue
    return None