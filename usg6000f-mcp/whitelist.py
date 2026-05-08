"""
USG6000F 白名单校验引擎（五层强校验）

覆盖招标指标：
  - 白名单校验（多级强校验）：核心业务 IP / 运维网段 / 办公出口 / 第三方链路
  - 白名单覆盖率 100%

五层：
  L1 IP/CIDR   — 精确 IP 或 CIDR 段匹配
  L2 ASN       — 合作伙伴 / 运营商 ASN 匹配
  L3 Domain    — 域名 PTR 反查（本地不做 DNS 反查，依赖上层传入）
  L4 Tag       — 资产标签匹配（core_business / dr_site / ops_segment）
  L5 BizHour   — 业务时段（工作时段办公段降权或禁止自动封禁）

接口：
  WhitelistEngine.load(path) -> None
  WhitelistEngine.check(ip, asn=None, domain=None, tags=None, now=None) -> CheckResult
"""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from datetime import datetime, time as dtime
from typing import Any

try:
    import yaml  # type: ignore
    _HAS_YAML = True
except ImportError:  # pragma: no cover
    _HAS_YAML = False


# ----------------------------------------------------------------------------
# 数据类
# ----------------------------------------------------------------------------

@dataclass
class CheckResult:
    """白名单校验结果。hit=True 表示命中白名单，封禁应被拒绝。"""
    hit: bool
    layer: str = ""            # L1_ip / L2_asn / L3_domain / L4_tag / L5_biz_hour
    rule_id: str = ""          # 规则标识（如 cidr=10.0.0.0/8）
    comment: str = ""          # 规则备注
    action: str = "block"      # block(拒绝封禁) / warn(仅警告) / allow(允许封禁)
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
    """白名单命中统计（监控用）。"""
    total_checks: int = 0
    total_hits: int = 0
    hits_by_layer: dict[str, int] = field(default_factory=dict)

    def record(self, result: CheckResult) -> None:
        self.total_checks += 1
        if result.hit:
            self.total_hits += 1
            self.hits_by_layer[result.layer] = self.hits_by_layer.get(result.layer, 0) + 1

    def to_dict(self) -> dict[str, Any]:
        cov = round(self.total_hits / self.total_checks, 4) if self.total_checks else 0.0
        return {
            "total_checks": self.total_checks,
            "total_hits": self.total_hits,
            "hit_rate": cov,
            "hits_by_layer": dict(self.hits_by_layer),
        }


# ----------------------------------------------------------------------------
# 白名单引擎
# ----------------------------------------------------------------------------

class WhitelistEngine:
    """
    从 YAML 文件加载白名单，提供 check() 校验。
    支持 reload() 热更新；支持编程式 add/remove。
    """

    def __init__(self) -> None:
        self._l1_ips: list[tuple[ipaddress._BaseNetwork, str, str]] = []  # (net, rule_id, comment)
        self._l2_asns: dict[int, str] = {}
        self._l3_domains: list[tuple[str, str]] = []     # (pattern, comment)
        self._l4_tags: dict[str, tuple[str, str]] = {}   # tag -> (action, comment)
        self._l5_biz: dict[str, Any] = {}
        self._source_path: str | None = None
        self._loaded = False
        self.stats = WhitelistStats()

    # -------- 加载 ----------
    def load(self, path: str) -> None:
        if not _HAS_YAML:
            raise RuntimeError("PyYAML 未安装，无法加载 YAML 白名单。请 pip install pyyaml")
        if not os.path.exists(path):
            raise FileNotFoundError(f"白名单文件不存在: {path}")
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
        self.load_from_dict(data)
        self._source_path = path

    def load_from_dict(self, data: dict[str, Any]) -> None:
        self._l1_ips.clear()
        self._l2_asns.clear()
        self._l3_domains.clear()
        self._l4_tags.clear()
        self._l5_biz.clear()

        # L1 IP/CIDR
        for i, row in enumerate(data.get("ip", []) or []):
            cidr = row.get("cidr") or row.get("ip")
            if not cidr:
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                continue
            self._l1_ips.append((net, f"ip[{i}]={cidr}", str(row.get("comment", ""))))

        # L2 ASN
        for row in data.get("asn", []) or []:
            asn = row.get("asn")
            if isinstance(asn, int):
                self._l2_asns[asn] = str(row.get("comment", ""))

        # L3 Domain（支持通配 *.example.com）
        for row in data.get("domain", []) or []:
            pat = row.get("pattern") or row.get("domain")
            if pat:
                self._l3_domains.append((pat.lower(), str(row.get("comment", ""))))

        # L4 Tag
        for row in data.get("tag", []) or []:
            tag = row.get("tag")
            if tag:
                self._l4_tags[tag] = (
                    str(row.get("action", "block")),
                    str(row.get("comment", "")),
                )

        # L5 BizHour
        self._l5_biz = dict(data.get("biz_hour", {}) or {})

        self._loaded = True

    def reload(self) -> None:
        if not self._source_path:
            raise RuntimeError("没有历史加载路径可供 reload")
        self.load(self._source_path)

    def is_loaded(self) -> bool:
        return self._loaded

    # -------- 校验 ----------
    def check(
        self,
        ip: str,
        *,
        asn: int | None = None,
        domain: str | None = None,
        tags: list[str] | None = None,
        now: datetime | None = None,
    ) -> CheckResult:
        """
        五层校验，任一命中立即返回 hit=True。
        """
        if not self._loaded:
            r = CheckResult(hit=False, comment="白名单未加载，跳过校验")
            self.stats.record(r)
            return r

        checked: list[str] = []

        # L1 IP/CIDR
        try:
            addr = ipaddress.ip_address(ip)
            checked.append("L1_ip")
            for net, rule_id, cmt in self._l1_ips:
                if addr in net:
                    r = CheckResult(
                        hit=True, layer="L1_ip", rule_id=rule_id,
                        comment=cmt, action="block", checked_layers=checked,
                    )
                    self.stats.record(r)
                    return r
        except ValueError:
            pass  # ip 非法，跳过 L1

        # L2 ASN
        if asn is not None:
            checked.append("L2_asn")
            if asn in self._l2_asns:
                r = CheckResult(
                    hit=True, layer="L2_asn", rule_id=f"asn={asn}",
                    comment=self._l2_asns[asn], action="block",
                    checked_layers=checked,
                )
                self.stats.record(r)
                return r

        # L3 Domain
        if domain:
            checked.append("L3_domain")
            dlow = domain.lower()
            for pat, cmt in self._l3_domains:
                if _domain_match(dlow, pat):
                    r = CheckResult(
                        hit=True, layer="L3_domain", rule_id=f"domain={pat}",
                        comment=cmt, action="block", checked_layers=checked,
                    )
                    self.stats.record(r)
                    return r

        # L4 Tag
        if tags:
            checked.append("L4_tag")
            for t in tags:
                if t in self._l4_tags:
                    act, cmt = self._l4_tags[t]
                    r = CheckResult(
                        hit=True, layer="L4_tag", rule_id=f"tag={t}",
                        comment=cmt, action=act, checked_layers=checked,
                    )
                    self.stats.record(r)
                    return r

        # L5 BizHour
        if self._l5_biz:
            checked.append("L5_biz_hour")
            hit = _check_biz_hour(self._l5_biz, now or datetime.now())
            if hit:
                act = str(self._l5_biz.get("action", "warn"))
                r = CheckResult(
                    hit=True, layer="L5_biz_hour",
                    rule_id="biz_hour",
                    comment="当前处于业务时段",
                    action=act,
                    checked_layers=checked,
                )
                self.stats.record(r)
                return r

        r = CheckResult(hit=False, checked_layers=checked)
        self.stats.record(r)
        return r

    # -------- 查询/编辑 ----------
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
            "ip": [{"cidr": str(n), "rule_id": rid, "comment": c}
                   for n, rid, c in self._l1_ips],
            "asn": [{"asn": a, "comment": c} for a, c in self._l2_asns.items()],
            "domain": [{"pattern": p, "comment": c} for p, c in self._l3_domains],
            "tag": [{"tag": t, "action": a, "comment": c}
                    for t, (a, c) in self._l4_tags.items()],
            "biz_hour": dict(self._l5_biz),
        }


# ----------------------------------------------------------------------------
# 辅助函数
# ----------------------------------------------------------------------------

def _domain_match(domain: str, pattern: str) -> bool:
    """
    域名匹配，支持 *.example.com（子域通配）。
    """
    if pattern == domain:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]  # ".example.com"
        return domain.endswith(suffix) or domain == suffix[1:]
    return False


def _check_biz_hour(cfg: dict[str, Any], now: datetime) -> bool:
    """
    判定 now 是否落在业务时段内。
    """
    workdays = cfg.get("workdays") or []
    work_hours = cfg.get("work_hours") or {}
    holidays = cfg.get("holidays") or []

    # 节假日判定
    today_str = now.strftime("%Y-%m-%d")
    if today_str in holidays:
        return False  # 节假日不算业务时段

    # 工作日判定
    wd_names = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]
    today_wd = wd_names[now.weekday()]
    if workdays and today_wd not in [d.lower() for d in workdays]:
        return False

    # 工作时段判定
    start_s = work_hours.get("start", "00:00")
    end_s = work_hours.get("end", "23:59")
    try:
        sh, sm = map(int, start_s.split(":"))
        eh, em = map(int, end_s.split(":"))
        nt = now.time()
        return dtime(sh, sm) <= nt <= dtime(eh, em)
    except (ValueError, AttributeError):
        return False


# ----------------------------------------------------------------------------
# 模块级单例（便于从 server.py 导入使用）
# ----------------------------------------------------------------------------

_GLOBAL = WhitelistEngine()


def get_engine() -> WhitelistEngine:
    return _GLOBAL


def auto_load_default() -> str | None:
    """
    尝试从默认路径加载白名单（插件目录 whitelist.yaml 或 同名环境变量）。
    返回实际加载路径或 None。
    """
    env_path = os.environ.get("USG_WHITELIST_PATH", "").strip()
    candidates = [
        env_path,
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.yaml"),
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "whitelist.sample.yaml"),
    ]
    for p in candidates:
        if p and os.path.exists(p):
            try:
                _GLOBAL.load(p)
                return p
            except Exception:
                continue
    return None
