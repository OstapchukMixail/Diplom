"""
╔══════════════════════════════════════════════════════════════════╗
║   Алгоритм планирования адресного пространства SRv6             ║
║   для многодатацентровой инфраструктуры облачного провайдера    ║
║                                                                  ║
║   Автор: Остапчук М.Ю., МФТИ 2026                               ║
╚══════════════════════════════════════════════════════════════════╝

Использование:
    python sid_planner.py                  — интерактивный режим
    python sid_planner.py --example 1      — запустить пример 1
    python sid_planner.py --example 2      — запустить пример 2
    python sid_planner.py --example 3      — пример с ошибкой
    python sid_planner.py --example 1 --csv — пример 1 + CSV
"""

import math, ipaddress, csv, sys, os, argparse
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Dict


# ── Структуры данных ──────────────────────────────────────────────────

@dataclass
class SRv6SID:
    address:  ipaddress.IPv6Address
    locator:  ipaddress.IPv6Network
    function: int
    dc_id:    int
    leaf_id:  int
    vrf_id:   int
    behavior: str

@dataclass
class LeafLocator:
    dc_id:    int
    leaf_id:  int
    prefix:   ipaddress.IPv6Network
    loopback: ipaddress.IPv6Address
    sids:     List[SRv6SID] = field(default_factory=list)

@dataclass
class PlanningResult:
    success:                 bool
    error:                   Optional[str]
    fix_suggestions:         List[str]
    locators:                List[LeafLocator]
    total_locator_space:     int
    used_locators:           int
    total_sid_space:         int
    used_sids_per_leaf:      int
    utilization_locators_pct: float
    utilization_sids_pct:    float
    growth_reserve_locators: int
    growth_reserve_vrfs:     int
    dc_bits:   int
    leaf_bits: int
    func_bits: int
    block_len: int
    node_len:  int
    provider_prefix:   str
    num_dc:            int
    max_leafs_per_dc:  int
    max_vrfs_per_leaf: int
    behaviors:         List[str]


BEHAVIORS_MAP = {
    'dt4': 'End.DT4',
    'dt6': 'End.DT6',
    'dx4': 'End.DX4',
    'end': 'End',
}

# ── ULA (Unique Local Addresses, RFC 4193) ────────────────────────────
#
# Используются ТОЛЬКО для физических стыков коммутатор↔сервер.
# За пределы коммутатора не маршрутизируются.
# Глобальный пул SID и ULA не пересекаются по определению:
#   SID берутся из глобального блока провайдера (например 2001:db8::/32)
#   ULA лежат в fc00::/7 — принципиально разные диапазоны.

@dataclass
class ULAEntry:
    """ULA-адрес для физического стыка коммутатор↔сервер."""
    dc_id:         int
    leaf_id:       int
    server_id:     int
    switch_addr:   ipaddress.IPv6Address   # адрес на интерфейсе коммутатора
    server_addr:   ipaddress.IPv6Address   # адрес на интерфейсе сервера
    link_prefix:   ipaddress.IPv6Network   # /127 линк между ними


class ULAPlanner:
    """
    Генератор ULA-адресов для физических стыков.

    Схема адресации (RFC 4193):
        fc00::/7  — ULA диапазон
        fd<провайдер>/48 — глобально уникальный ULA-префикс провайдера
                           (fd = fc00::/7 с L-битом = 1)

    Внутри /48:
        следующие 16 бит — номер DC
        следующие 16 бит — номер leaf
        следующие 16 бит — номер сервера
        /127 на каждый линк: ::0 = коммутатор, ::1 = сервер
    """

    # Стандартный ULA-префикс с L=1 (fd00::/8)
    # Провайдер выбирает случайные 40 бит глобального ID (RFC 4193 §3.2.2)
    # Для определённости используем фиксированный псевдослучайный ID
    ULA_BASE = "fd00::/8"

    def __init__(
        self,
        num_dc:           int,
        max_leafs_per_dc: int,
        max_servers_per_leaf: int,
        ula_global_id:    str = "fd12:3456:789a",  # 40-бит ID провайдера
    ):
        self.num_dc               = num_dc
        self.max_leafs_per_dc     = max_leafs_per_dc
        self.max_servers_per_leaf = max_servers_per_leaf
        # Базовый /48 провайдера в ULA-пространстве
        self.ula_base = ipaddress.IPv6Network(
            f"{ula_global_id}::/48", strict=False)

    def _make_link(self, dc: int, leaf: int,
                   server: int) -> ipaddress.IPv6Network:
        """Формирует /127 линк для пары коммутатор↔сервер."""
        base = int(self.ula_base.network_address)
        # fd<id>:<dc>:<leaf>:<server>::/127
        addr = (base
                | (dc     << 64)
                | (leaf   << 48)
                | (server << 32))
        return ipaddress.IPv6Network(
            f"{ipaddress.IPv6Address(addr)}/127", strict=False)

    def generate(self) -> List[ULAEntry]:
        """Генерирует таблицу ULA-адресов для всех стыков."""
        entries = []
        for dc in range(1, self.num_dc + 1):
            for leaf in range(1, self.max_leafs_per_dc + 1):
                for srv in range(1, self.max_servers_per_leaf + 1):
                    link = self._make_link(dc, leaf, srv)
                    hosts = list(link.hosts())
                    # /127 даёт ровно два адреса: ::0 и ::1
                    sw_addr  = ipaddress.IPv6Address(
                        int(link.network_address))
                    srv_addr = ipaddress.IPv6Address(
                        int(link.network_address) + 1)
                    entries.append(ULAEntry(
                        dc_id=dc, leaf_id=leaf, server_id=srv,
                        switch_addr=sw_addr,
                        server_addr=srv_addr,
                        link_prefix=link,
                    ))
        return entries

    def check_overlap_with_global(
        self,
        global_prefix: str,
    ) -> bool:
        """
        Проверяет что ULA-пространство не пересекается
        с глобальным пулом SID.
        Всегда False (ULA fd::/8 и глобальные 2000::/3
        не пересекаются по определению RFC 4291),
        но проверка явная для документирования гарантии.
        """
        try:
            gnet = ipaddress.IPv6Network(global_prefix, strict=False)
            return self.ula_base.overlaps(gnet)
        except Exception:
            return False


def print_ula_report(entries: List[ULAEntry],
                     global_prefix: str,
                     ula_planner: ULAPlanner):
    """Выводит отчёт по ULA-адресам."""
    print()
    print("═"*68)
    print("  ULA-АДРЕСА ДЛЯ ФИЗИЧЕСКИХ СТЫКОВ (RFC 4193)")
    print("  Используются ТОЛЬКО коммутатор↔сервер,")
    print("  за пределы коммутатора не маршрутизируются.")
    print("═"*68)

    overlap = ula_planner.check_overlap_with_global(global_prefix)
    print(f"\n  Пересечение с глобальным пулом SID: "
          f"{'ДА — КОНФЛИКТ!' if overlap else 'нет ✓'}")
    print(f"  ULA-база провайдера: {ula_planner.ula_base}")
    print(f"  Глобальный пул SID:  {global_prefix}")

    n_show = min(6, len(entries))
    print(f"\n  ТАБЛИЦА СТЫКОВ (показано {n_show} из {len(entries)})")
    print(_sep())
    print(f"  {'DC':>3}  {'Leaf':>4}  {'Srv':>3}  "
          f"{'Коммутатор (::0)':38}  {'Сервер (::1)'}")
    print("  " + "─"*64)
    for e in entries[:n_show]:
        print(f"  {e.dc_id:>3}  {e.leaf_id:>4}  {e.server_id:>3}  "
              f"{str(e.switch_addr):38}  {e.server_addr}")
    if len(entries) > n_show:
        print(f"  ... ещё {len(entries)-n_show} стыков")
    print("═"*68)


def export_ula_csv(entries: List[ULAEntry], base: str):
    """Экспортирует ULA-таблицу в CSV."""
    path = base + "_ula_links.csv"
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dc_id", "leaf_id", "server_id",
                    "link_prefix", "switch_addr", "server_addr"])
        for e in entries:
            w.writerow([e.dc_id, e.leaf_id, e.server_id,
                        str(e.link_prefix),
                        str(e.switch_addr),
                        str(e.server_addr)])
    print(f"  ULA-таблица стыков → {path}  ({len(entries):,} записей)")




# ── Вспомогательные функции ───────────────────────────────────────────

def _max_dc_leaf_table(available_bits: int) -> str:
    lines = []
    for dc_b in range(1, available_bits):
        leaf_b   = available_bits - dc_b
        max_dc   = 2**dc_b   - 1
        max_leaf = 2**leaf_b - 1
        if max_dc < 1 or max_leaf < 1:
            continue
        lines.append(
            f"      {dc_b} бит DC → max {max_dc:4d} DC,  "
            f"{leaf_b} бит leaf → max {max_leaf:5d} leaf/DC"
        )
    return "\n".join(lines) if lines else "    (нет допустимых комбинаций)"

def _sep(char="─", w=68):
    return char * w


# ── Ядро алгоритма ────────────────────────────────────────────────────

class SRv6AddressPlanner:

    def __init__(self, provider_prefix, num_dc, max_leafs_per_dc,
                 max_vrfs_per_leaf, block_len=40, node_len=24,
                 behaviors=None):
        self.provider_prefix   = ipaddress.IPv6Network(
                                     provider_prefix, strict=False)
        self.num_dc            = num_dc
        self.max_leafs_per_dc  = max_leafs_per_dc
        self.max_vrfs_per_leaf = max_vrfs_per_leaf
        self.block_len         = block_len
        self.node_len          = node_len
        self.behaviors         = behaviors or ['dt4']

    def _check_constraints(self):
        pfx      = self.provider_prefix.prefixlen
        dc_bits  = math.ceil(math.log2(self.num_dc + 1))
        lf_bits  = math.ceil(math.log2(self.max_leafs_per_dc + 1))
        fn_need  = math.ceil(
            math.log2(self.max_vrfs_per_leaf * len(self.behaviors) + 1))
        fn_avail = 128 - self.block_len - self.node_len

        if self.block_len + self.node_len > 64:
            fixes = [
                f"Уменьшите node_len до {64 - self.block_len} "
                f"(block_len + node_len должно быть ≤ 64).",
                f"Или уменьшите block_len до {64 - self.node_len}.",
            ]
            return False, (
                f"block_len ({self.block_len}) + node_len "
                f"({self.node_len}) = "
                f"{self.block_len+self.node_len} > 64.\n"
                f"  Локатор должен укладываться в /64 (RFC 8754)."
            ), fixes

        bits_needed = pfx + dc_bits + lf_bits
        if bits_needed > self.block_len:
            deficit   = bits_needed - self.block_len
            min_pfx   = self.block_len - dc_bits - lf_bits
            min_block = bits_needed
            fn_after  = 128 - min_block - self.node_len
            fixes = [
                (
                    f"Расширьте блок провайдера: используйте "
                    f"/{min_pfx} вместо /{pfx}.\n"
                    f"    Это освобождает {deficit} дополнительных "
                    f"бит внутри Block.\n"
                    f"    Почему нельзя сразу: провайдер получает "
                    f"IPv6-блок от регионального регистратора\n"
                    f"    (RIPE NCC для России/Европы). Размер блока "
                    f"определяется заявкой и политикой\n"
                    f"    регистратора. В лабораторных условиях "
                    f"используйте 2001:db8::/{min_pfx}."
                ),
                (
                    f"Увеличьте block_len до {min_block} "
                    f"(сейчас {self.block_len}).\n"
                    f"    Тогда Function-часть: "
                    f"128 - {min_block} - {self.node_len} "
                    f"= {fn_after} бит.\n"
                    f"    Нужно для VRF: {fn_need} бит — "
                    + ("достаточно ✓"
                       if fn_after >= fn_need
                       else f"недостаточно! Также уменьшите node_len.")
                ),
                (
                    f"Уменьшите масштаб инфраструктуры.\n"
                    f"    При block_len={self.block_len} и "
                    f"префиксе /{pfx} доступно "
                    f"{self.block_len - pfx} бит.\n"
                    f"    Допустимые комбинации DC × leaf:\n"
                    + _max_dc_leaf_table(self.block_len - pfx)
                ),
            ]
            return False, (
                f"Недостаточно бит в Block-части.\n"
                f"  Провайдерский префикс : /{pfx}\n"
                f"  Нужно бит для {self.num_dc} DC   : {dc_bits}\n"
                f"  Нужно бит для {self.max_leafs_per_dc} "
                f"leaf/DC: {lf_bits}\n"
                f"  Итого нужно            : {bits_needed} бит\n"
                f"  Доступно в Block       : {self.block_len} бит\n"
                f"  Дефицит                : {deficit} бит"
            ), fixes

        if fn_need > fn_avail:
            fixes = [
                f"Уменьшите max_vrfs_per_leaf.\n"
                f"    При fn_bits={fn_avail} максимум VRF/поведение: "
                f"{2**fn_avail // len(self.behaviors)}",
                f"Уменьшите node_len (сейчас {self.node_len}).\n"
                f"    Нужно node_len ≤ "
                f"{128 - self.block_len - fn_need}",
                f"Сократите список behaviors.\n"
                f"    Сейчас: {self.behaviors}  "
                f"→ оставьте только ['dt4'].",
            ]
            return False, (
                f"Недостаточно бит для Function-части.\n"
                f"  Нужно бит: {fn_need}\n"
                f"  Доступно (128-{self.block_len}-"
                f"{self.node_len}): {fn_avail} бит"
            ), fixes

        return True, None, []

    def _layout(self):
        pfx     = self.provider_prefix.prefixlen
        dc_bits = math.ceil(math.log2(self.num_dc + 1))
        lf_bits = math.ceil(math.log2(self.max_leafs_per_dc + 1))
        return dict(
            dc_bits=dc_bits, leaf_bits=lf_bits,
            func_bits=128 - self.block_len - self.node_len,
            dc_shift=128 - pfx - dc_bits,
            leaf_shift=128 - pfx - dc_bits - lf_bits,
        )

    def _make_locator(self, L, dc, leaf):
        base = int(self.provider_prefix.network_address)
        addr = base | (dc << L['dc_shift']) | (leaf << L['leaf_shift'])
        return ipaddress.IPv6Network(
            f"{ipaddress.IPv6Address(addr)}"
            f"/{self.block_len + self.node_len}", strict=False)

    def _make_sid(self, locator, vrf, b_off):
        fn = vrf * len(self.behaviors) + b_off
        return ipaddress.IPv6Address(
            int(locator.network_address) | fn)

    def _check_conflicts(self, locators):
        seen_l, seen_s = set(), set()
        for loc in locators:
            k = str(loc.prefix)
            if k in seen_l:
                return f"Конфликт локаторов: {loc.prefix}"
            seen_l.add(k)
            for sid in loc.sids:
                ks = str(sid.address)
                if ks in seen_s:
                    return f"Конфликт SID: {sid.address}"
                seen_s.add(ks)
                if sid.address not in loc.prefix:
                    return f"SID {sid.address} вне локатора {loc.prefix}"
        return None

    def plan(self) -> PlanningResult:
        def _empty(err=None, fixes=None):
            return PlanningResult(
                success=False, error=err,
                fix_suggestions=fixes or [],
                locators=[], total_locator_space=0, used_locators=0,
                total_sid_space=0, used_sids_per_leaf=0,
                utilization_locators_pct=0, utilization_sids_pct=0,
                growth_reserve_locators=0, growth_reserve_vrfs=0,
                dc_bits=0, leaf_bits=0, func_bits=0,
                block_len=self.block_len, node_len=self.node_len,
                provider_prefix=str(self.provider_prefix),
                num_dc=self.num_dc,
                max_leafs_per_dc=self.max_leafs_per_dc,
                max_vrfs_per_leaf=self.max_vrfs_per_leaf,
                behaviors=self.behaviors)

        ok, err, fixes = self._check_constraints()
        if not ok:
            return _empty(err=err, fixes=fixes)

        L        = self._layout()
        locators = []
        for dc in range(1, self.num_dc + 1):
            for leaf in range(1, self.max_leafs_per_dc + 1):
                net = self._make_locator(L, dc, leaf)
                lo  = ipaddress.IPv6Address(
                          int(net.network_address) | 1)
                ll  = LeafLocator(dc_id=dc, leaf_id=leaf,
                                  prefix=net, loopback=lo)
                for vrf in range(1, self.max_vrfs_per_leaf + 1):
                    for b_off, b_key in enumerate(self.behaviors):
                        ll.sids.append(SRv6SID(
                            address=self._make_sid(net, vrf, b_off),
                            locator=net, function=vrf*len(self.behaviors)+b_off,
                            dc_id=dc, leaf_id=leaf, vrf_id=vrf,
                            behavior=BEHAVIORS_MAP.get(b_key, b_key)))
                locators.append(ll)

        conflict = self._check_conflicts(locators)
        if conflict:
            return _empty(err=conflict)

        pfx  = self.provider_prefix.prefixlen
        tloc = 2 ** (self.block_len - pfx)
        uloc = self.num_dc * self.max_leafs_per_dc
        tsid = 2 ** L['func_bits']
        usid = self.max_vrfs_per_leaf * len(self.behaviors)
        return PlanningResult(
            success=True, error=None, fix_suggestions=[],
            locators=locators,
            total_locator_space=tloc, used_locators=uloc,
            total_sid_space=tsid,    used_sids_per_leaf=usid,
            utilization_locators_pct=uloc/tloc*100,
            utilization_sids_pct=usid/tsid*100,
            growth_reserve_locators=tloc-uloc,
            growth_reserve_vrfs=tsid-usid,
            dc_bits=L['dc_bits'], leaf_bits=L['leaf_bits'],
            func_bits=L['func_bits'],
            block_len=self.block_len, node_len=self.node_len,
            provider_prefix=str(self.provider_prefix),
            num_dc=self.num_dc,
            max_leafs_per_dc=self.max_leafs_per_dc,
            max_vrfs_per_leaf=self.max_vrfs_per_leaf,
            behaviors=self.behaviors)


# ── Вывод в консоль ───────────────────────────────────────────────────

def print_report(r: PlanningResult):
    print(); print("═"*68)
    print("  ОТЧЁТ: Планирование адресного пространства SRv6")
    print("═"*68)
    print()
    print("  ВХОДНЫЕ ПАРАМЕТРЫ")
    print(_sep())
    print(f"  Провайдерский префикс : {r.provider_prefix}")
    print(f"  Число DC              : {r.num_dc}")
    print(f"  Max leaf/DC           : {r.max_leafs_per_dc}")
    print(f"  Max VRF/leaf          : {r.max_vrfs_per_leaf}")
    print(f"  Поведения SID         : {r.behaviors}")
    print(f"  block_len / node_len  : {r.block_len} / {r.node_len} бит")

    if not r.success:
        print(); print("  ОШИБКА"); print(_sep())
        for line in r.error.split("\n"):
            print(f"  {line}")
        print(); print("  ЧТО МОЖНО СДЕЛАТЬ"); print(_sep())
        for i, fix in enumerate(r.fix_suggestions, 1):
            print(f"  Вариант {i}:")
            for line in fix.split("\n"):
                print(f"    {line}")
            print()
        print("═"*68); return

    pfx = ipaddress.IPv6Network(r.provider_prefix).prefixlen
    print(); print("  СХЕМА РАЗБИЕНИЯ"); print(_sep())
    print(f"  {'Провайдер-префикс':<24} {pfx:3d} бит")
    print(f"  {'DC-идентификатор':<24} {r.dc_bits:3d} бит")
    print(f"  {'Leaf-идентификатор':<24} {r.leaf_bits:3d} бит")
    pad = r.block_len - pfx - r.dc_bits - r.leaf_bits
    if pad > 0:
        print(f"  {'Выравнивание (pad)':<24} {pad:3d} бит")
    print(f"  {'Node (locator)':<24} {r.node_len:3d} бит")
    print(f"  {'Function (VRF+behavior)':<24} {r.func_bits:3d} бит")
    print(f"  {'ИТОГО':<24} 128 бит")

    print(); print("  УТИЛИЗАЦИЯ ПРОСТРАНСТВА"); print(_sep())
    print(f"  Локаторов: {r.used_locators:,} / "
          f"{r.total_locator_space:,}  "
          f"({r.utilization_locators_pct:.2f}%)")
    print(f"  SID/leaf : {r.used_sids_per_leaf:,} / "
          f"{r.total_sid_space:,}  "
          f"({r.utilization_sids_pct:.6f}%)")
    print(f"  Резерв локаторов : {r.growth_reserve_locators:,}  "
          f"(можно добавить leaf)")
    print(f"  Резерв SID/leaf  : {r.growth_reserve_vrfs:,}  "
          f"(можно добавить VRF)")

    n_loc = min(6, len(r.locators))
    print(); print(f"  ТАБЛИЦА ЛОКАТОРОВ (показано {n_loc} "
                   f"из {len(r.locators)})"); print(_sep())
    print(f"  {'DC':>4}  {'Leaf':>4}  {'Локатор':<38}  Loopback")
    print("  " + "─"*62)
    for loc in r.locators[:n_loc]:
        print(f"  {loc.dc_id:>4}  {loc.leaf_id:>4}  "
              f"{str(loc.prefix):<38}  {loc.loopback}")
    if len(r.locators) > n_loc:
        print(f"  ... ещё {len(r.locators)-n_loc} локаторов")

    first  = r.locators[0]
    nb     = len(r.behaviors)
    n_sid  = min(3 * nb, len(first.sids))
    print(); print(f"  ПРИМЕРЫ SID  "
                   f"(первые 3 VRF, DC={first.dc_id} leaf={first.leaf_id})")
    print(_sep())
    print(f"  Локатор: {first.prefix}")
    print(f"  {'VRF':>6}  {'Поведение':<10}  SID")
    print("  " + "─"*58)
    for sid in first.sids[:n_sid]:
        print(f"  {sid.vrf_id:>6}  {sid.behavior:<10}  {sid.address}")
    print()
    print("  ✓ Проверка конфликтов пройдена: все SID уникальны")
    print("═"*68)


# ── Экспорт в CSV ─────────────────────────────────────────────────────

def export_csv(r: PlanningResult, base: str):
    loc_path = base + "_locators.csv"
    sid_path = base + "_sids.csv"
    with open(loc_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dc_id","leaf_id","locator_prefix","loopback"])
        for loc in r.locators:
            w.writerow([loc.dc_id, loc.leaf_id,
                        str(loc.prefix), str(loc.loopback)])
    total = sum(len(loc.sids) for loc in r.locators)
    with open(sid_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dc_id","leaf_id","locator_prefix",
                    "vrf_id","behavior","sid_address"])
        for loc in r.locators:
            for sid in loc.sids:
                w.writerow([loc.dc_id, loc.leaf_id, str(loc.prefix),
                            sid.vrf_id, sid.behavior, str(sid.address)])
    print(f"  Таблица локаторов  → {loc_path}")
    print(f"  Полная таблица SID → {sid_path}  ({total:,} записей)")


# ── Интерактивный режим ───────────────────────────────────────────────

def ask(prompt, default, cast=str):
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            return cast(raw)
        except Exception:
            print("  ✗ Некорректный ввод, попробуйте ещё раз.")

def ask_behaviors():
    print()
    print("  Доступные поведения SID:")
    print("    dt4 — End.DT4  L3VPN IPv4  (рекомендуется)")
    print("    dt6 — End.DT6  L3VPN IPv6")
    print("    dx4 — End.DX4  L2 IPv4")
    print("    end — End      базовый")
    raw = input("  Введите через запятую [dt4,dt6]: ").strip()
    if not raw:
        return ["dt4","dt6"]
    result = [b.strip() for b in raw.split(",")
              if b.strip() in BEHAVIORS_MAP]
    return result if result else ["dt4"]

def ask_mode():
    print()
    print("  Режим вывода:")
    print("    1 — краткий отчёт в консоль")
    print("    2 — полные таблицы в CSV-файлы")
    while True:
        raw = input("  Выберите [1]: ").strip()
        if raw in ("","1"): return "console"
        if raw == "2":      return "csv"
        print("  ✗ Введите 1 или 2.")

def interactive_mode():
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Планировщик адресного пространства SRv6           ║")
    print("║   Нажмите Enter для принятия значения по умолчанию  ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    prefix    = ask("Провайдерский IPv6-префикс", "2001:db8::/32")
    num_dc    = ask("Число дата-центров (DC)", 3, int)
    max_leafs = ask("Максимум leaf-узлов в одном DC", 20, int)
    max_vrfs  = ask("Максимум VRF (арендаторов) на leaf", 500, int)
    block_len = ask("block_len (бит, рекомендуется 40)", 40, int)
    node_len  = ask("node_len  (бит, рекомендуется 24)", 24, int)
    behaviors = ask_behaviors()
    print()
    print("  ULA-адреса для физических стыков коммутатор<->сервер (RFC 4193):")
    gen_ula = ask("Генерировать ULA-адреса? (да/нет)", "да")
    ula_entries = []
    ula_planner = None
    if gen_ula.lower() in ("да", "y", "yes", "д"):
        max_srvs = ask("Максимум серверов на leaf", 10, int)
        ula_id   = ask("ULA Global ID провайдера", "fd12:3456:789a")
        ula_planner = ULAPlanner(num_dc=num_dc,
            max_leafs_per_dc=max_leafs,
            max_servers_per_leaf=max_srvs,
            ula_global_id=ula_id)
        ula_entries = ula_planner.generate()
    mode = ask_mode()
    planner = SRv6AddressPlanner(
        provider_prefix=prefix, num_dc=num_dc,
        max_leafs_per_dc=max_leafs, max_vrfs_per_leaf=max_vrfs,
        block_len=block_len, node_len=node_len, behaviors=behaviors)
    result = planner.plan()
    print_report(result)
    if ula_entries and ula_planner:
        print_ula_report(ula_entries, prefix, ula_planner)
    if result.success and mode == "csv":
        print(); print("  Сохранение CSV...")
        base = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "srv6_plan")
        export_csv(result, base)
        if ula_entries:
            export_ula_csv(ula_entries, base)


# ── Встроенные примеры ────────────────────────────────────────────────

EXAMPLES = {
    1: dict(
        title="Малый провайдер: 2 DC × 10 leaf × 200 VRF",
        desc=(
            "Небольшая IaaS-платформа.\n"
            "  Провайдерский блок /32 (стандартная выдача RIPE NCC).\n"
            "  2 ЦОД, по 10 leaf в каждом, до 200 арендаторов на leaf.\n"
            "  Поддержка IPv4 и IPv6 VPN арендаторов."
        ),
        params=dict(provider_prefix="2001:db8::/32",
                    num_dc=2, max_leafs_per_dc=10,
                    max_vrfs_per_leaf=200, block_len=40, node_len=24,
                    behaviors=["dt4","dt6"]),
    ),
    2: dict(
        title="Средний провайдер: 4 DC × 30 leaf × 500 VRF",
        desc=(
            "Региональный провайдер с четырьмя площадками.\n"
            "  Блок /30 (запрашивается для среднего провайдера).\n"
            "  Показывает как больший блок снимает ограничения."
        ),
        params=dict(provider_prefix="2001:db8::/30",
                    num_dc=4, max_leafs_per_dc=30,
                    max_vrfs_per_leaf=500, block_len=40, node_len=24,
                    behaviors=["dt4","dt6"]),
    ),
    3: dict(
        title="Нарушение ограничений: диагностика и советы",
        desc=(
            "Провайдер с блоком /32 пытается разместить\n"
            "  10 DC × 100 leaf — не хватает бит в Block.\n"
            "  Алгоритм выявляет проблему и предлагает варианты решения."
        ),
        params=dict(provider_prefix="2001:db8::/32",
                    num_dc=10, max_leafs_per_dc=100,
                    max_vrfs_per_leaf=500, block_len=40, node_len=24,
                    behaviors=["dt4"]),
    ),
}

def run_example(n: int, csv_mode: bool):
    if n not in EXAMPLES:
        print(f"Пример {n} не найден. Доступны: 1, 2, 3."); return
    ex = EXAMPLES[n]
    print(); print("▶"*68)
    print(f"  ПРИМЕР {n}: {ex['title']}")
    print("▶"*68); print()
    for line in ex["desc"].split("\n"):
        print(f"  {line}")
    planner = SRv6AddressPlanner(**ex["params"])
    result  = planner.plan()
    print_report(result)
    # ULA для примеров 1 и 2 (не для примера 3 — там ошибка)
    if result.success and n in (1, 2):
        p = ex["params"]
        ula_planner = ULAPlanner(
            num_dc=p["num_dc"],
            max_leafs_per_dc=p["max_leafs_per_dc"],
            max_servers_per_leaf=4)
        ula_entries = ula_planner.generate()
        print_ula_report(ula_entries, p["provider_prefix"], ula_planner)
        if csv_mode:
            print(); print("  Сохранение CSV...")
            base = os.path.join(
                os.path.dirname(os.path.abspath(__file__)),
                f"srv6_plan_example{n}")
            export_csv(result, base)
            export_ula_csv(ula_entries, base)
    elif csv_mode and result.success:
        print(); print("  Сохранение CSV...")
        base = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"srv6_plan_example{n}")
        export_csv(result, base)


# ── Точка входа ───────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(
        description="Планировщик адресного пространства SRv6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--example", type=int, choices=[1,2,3],
                   help="Запустить встроенный пример")
    p.add_argument("--csv", action="store_true",
                   help="Сохранить результат в CSV-файлы")
    args = p.parse_args()
    if args.example:
        run_example(args.example, csv_mode=args.csv)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()

    loopback: ipaddress.IPv6Address
    sids:     List[SRv6SID] = field(default_factory=list)

@dataclass
class PlanningResult:
    success:                 bool
    error:                   Optional[str]
    fix_suggestions:         List[str]
    locators:                List[LeafLocator]
    total_locator_space:     int
    used_locators:           int
    total_sid_space:         int
    used_sids_per_leaf:      int
    utilization_locators_pct: float
    utilization_sids_pct:    float
    growth_reserve_locators: int
    growth_reserve_vrfs:     int
    dc_bits:   int
    leaf_bits: int
    func_bits: int
    block_len: int
    node_len:  int
    provider_prefix:   str
    num_dc:            int
    max_leafs_per_dc:  int
    max_vrfs_per_leaf: int
    behaviors:         List[str]


BEHAVIORS_MAP = {
    'dt4': 'End.DT4',
    'dt6': 'End.DT6',
    'dx4': 'End.DX4',
    'end': 'End',
}


def _max_dc_leaf_table(available_bits: int) -> str:
    lines = []
    for dc_b in range(1, available_bits):
        leaf_b   = available_bits - dc_b
        max_dc   = 2**dc_b   - 1
        max_leaf = 2**leaf_b - 1
        if max_dc < 1 or max_leaf < 1:
            continue
        lines.append(
            f"      {dc_b} бит DC → max {max_dc:4d} DC,  "
            f"{leaf_b} бит leaf → max {max_leaf:5d} leaf/DC"
        )
    return "\n".join(lines) if lines else "    (нет допустимых комбинаций)"

def _sep(char="─", w=68):
    return char * w


class SRv6AddressPlanner:

    def __init__(self, provider_prefix, num_dc, max_leafs_per_dc,
                 max_vrfs_per_leaf, block_len=40, node_len=24,
                 behaviors=None):
        self.provider_prefix   = ipaddress.IPv6Network(
                                     provider_prefix, strict=False)
        self.num_dc            = num_dc
        self.max_leafs_per_dc  = max_leafs_per_dc
        self.max_vrfs_per_leaf = max_vrfs_per_leaf
        self.block_len         = block_len
        self.node_len          = node_len
        self.behaviors         = behaviors or ['dt4']

    def _check_constraints(self):
        pfx      = self.provider_prefix.prefixlen
        dc_bits  = math.ceil(math.log2(self.num_dc + 1))
        lf_bits  = math.ceil(math.log2(self.max_leafs_per_dc + 1))
        fn_need  = math.ceil(
            math.log2(self.max_vrfs_per_leaf * len(self.behaviors) + 1))
        fn_avail = 128 - self.block_len - self.node_len

        if self.block_len + self.node_len > 64:
            fixes = [
                f"Уменьшите node_len до {64 - self.block_len} "
                f"(block_len + node_len должно быть ≤ 64).",
                f"Или уменьшите block_len до {64 - self.node_len}.",
            ]
            return False, (
                f"block_len ({self.block_len}) + node_len "
                f"({self.node_len}) = "
                f"{self.block_len+self.node_len} > 64.\n"
                f"  Локатор должен укладываться в /64 (RFC 8754)."
            ), fixes

        bits_needed = pfx + dc_bits + lf_bits
        if bits_needed > self.block_len:
            deficit   = bits_needed - self.block_len
            min_pfx   = self.block_len - dc_bits - lf_bits
            min_block = bits_needed
            fn_after  = 128 - min_block - self.node_len
            fixes = [
                (
                    f"Расширьте блок провайдера: используйте "
                    f"/{min_pfx} вместо /{pfx}.\n"
                    f"    Это освобождает {deficit} дополнительных "
                    f"бит внутри Block.\n"
                    f"    Почему нельзя сразу: провайдер получает "
                    f"IPv6-блок от регионального регистратора\n"
                    f"    (RIPE NCC для России/Европы). Размер блока "
                    f"определяется заявкой и политикой\n"
                    f"    регистратора. В лабораторных условиях "
                    f"используйте 2001:db8::/{min_pfx}."
                ),
                (
                    f"Увеличьте block_len до {min_block} "
                    f"(сейчас {self.block_len}).\n"
                    f"    Тогда Function-часть: "
                    f"128 - {min_block} - {self.node_len} "
                    f"= {fn_after} бит.\n"
                    f"    Нужно для VRF: {fn_need} бит — "
                    + ("достаточно ✓"
                       if fn_after >= fn_need
                       else f"недостаточно! Также уменьшите node_len.")
                ),
                (
                    f"Уменьшите масштаб инфраструктуры.\n"
                    f"    При block_len={self.block_len} и "
                    f"префиксе /{pfx} доступно "
                    f"{self.block_len - pfx} бит.\n"
                    f"    Допустимые комбинации DC × leaf:\n"
                    + _max_dc_leaf_table(self.block_len - pfx)
                ),
            ]
            return False, (
                f"Недостаточно бит в Block-части.\n"
                f"  Провайдерский префикс : /{pfx}\n"
                f"  Нужно бит для {self.num_dc} DC   : {dc_bits}\n"
                f"  Нужно бит для {self.max_leafs_per_dc} "
                f"leaf/DC: {lf_bits}\n"
                f"  Итого нужно            : {bits_needed} бит\n"
                f"  Доступно в Block       : {self.block_len} бит\n"
                f"  Дефицит                : {deficit} бит"
            ), fixes

        if fn_need > fn_avail:
            fixes = [
                f"Уменьшите max_vrfs_per_leaf.\n"
                f"    При fn_bits={fn_avail} максимум VRF/поведение: "
                f"{2**fn_avail // len(self.behaviors)}",
                f"Уменьшите node_len (сейчас {self.node_len}).\n"
                f"    Нужно node_len ≤ "
                f"{128 - self.block_len - fn_need}",
                f"Сократите список behaviors.\n"
                f"    Сейчас: {self.behaviors}  "
                f"→ оставьте только ['dt4'].",
            ]
            return False, (
                f"Недостаточно бит для Function-части.\n"
                f"  Нужно бит: {fn_need}\n"
                f"  Доступно (128-{self.block_len}-"
                f"{self.node_len}): {fn_avail} бит"
            ), fixes

        return True, None, []

    def _layout(self):
        pfx     = self.provider_prefix.prefixlen
        dc_bits = math.ceil(math.log2(self.num_dc + 1))
        lf_bits = math.ceil(math.log2(self.max_leafs_per_dc + 1))
        return dict(
            dc_bits=dc_bits, leaf_bits=lf_bits,
            func_bits=128 - self.block_len - self.node_len,
            dc_shift=128 - pfx - dc_bits,
            leaf_shift=128 - pfx - dc_bits - lf_bits,
        )

    def _make_locator(self, L, dc, leaf):
        base = int(self.provider_prefix.network_address)
        addr = base | (dc << L['dc_shift']) | (leaf << L['leaf_shift'])
        return ipaddress.IPv6Network(
            f"{ipaddress.IPv6Address(addr)}"
            f"/{self.block_len + self.node_len}", strict=False)

    def _make_sid(self, locator, vrf, b_off):
        fn = vrf * len(self.behaviors) + b_off
        return ipaddress.IPv6Address(
            int(locator.network_address) | fn)

    def _check_conflicts(self, locators):
        seen_l, seen_s = set(), set()
        for loc in locators:
            k = str(loc.prefix)
            if k in seen_l:
                return f"Конфликт локаторов: {loc.prefix}"
            seen_l.add(k)
            for sid in loc.sids:
                ks = str(sid.address)
                if ks in seen_s:
                    return f"Конфликт SID: {sid.address}"
                seen_s.add(ks)
                if sid.address not in loc.prefix:
                    return f"SID {sid.address} вне локатора {loc.prefix}"
        return None

    def plan(self) -> PlanningResult:
        def _empty(err=None, fixes=None):
            return PlanningResult(
                success=False, error=err,
                fix_suggestions=fixes or [],
                locators=[], total_locator_space=0, used_locators=0,
                total_sid_space=0, used_sids_per_leaf=0,
                utilization_locators_pct=0, utilization_sids_pct=0,
                growth_reserve_locators=0, growth_reserve_vrfs=0,
                dc_bits=0, leaf_bits=0, func_bits=0,
                block_len=self.block_len, node_len=self.node_len,
                provider_prefix=str(self.provider_prefix),
                num_dc=self.num_dc,
                max_leafs_per_dc=self.max_leafs_per_dc,
                max_vrfs_per_leaf=self.max_vrfs_per_leaf,
                behaviors=self.behaviors)

        ok, err, fixes = self._check_constraints()
        if not ok:
            return _empty(err=err, fixes=fixes)

        L        = self._layout()
        locators = []
        for dc in range(1, self.num_dc + 1):
            for leaf in range(1, self.max_leafs_per_dc + 1):
                net = self._make_locator(L, dc, leaf)
                lo  = ipaddress.IPv6Address(
                          int(net.network_address) | 1)
                ll  = LeafLocator(dc_id=dc, leaf_id=leaf,
                                  prefix=net, loopback=lo)
                for vrf in range(1, self.max_vrfs_per_leaf + 1):
                    for b_off, b_key in enumerate(self.behaviors):
                        ll.sids.append(SRv6SID(
                            address=self._make_sid(net, vrf, b_off),
                            locator=net, function=vrf*len(self.behaviors)+b_off,
                            dc_id=dc, leaf_id=leaf, vrf_id=vrf,
                            behavior=BEHAVIORS_MAP.get(b_key, b_key)))
                locators.append(ll)

        conflict = self._check_conflicts(locators)
        if conflict:
            return _empty(err=conflict)

        pfx  = self.provider_prefix.prefixlen
        tloc = 2 ** (self.block_len - pfx)
        uloc = self.num_dc * self.max_leafs_per_dc
        tsid = 2 ** L['func_bits']
        usid = self.max_vrfs_per_leaf * len(self.behaviors)
        return PlanningResult(
            success=True, error=None, fix_suggestions=[],
            locators=locators,
            total_locator_space=tloc, used_locators=uloc,
            total_sid_space=tsid,    used_sids_per_leaf=usid,
            utilization_locators_pct=uloc/tloc*100,
            utilization_sids_pct=usid/tsid*100,
            growth_reserve_locators=tloc-uloc,
            growth_reserve_vrfs=tsid-usid,
            dc_bits=L['dc_bits'], leaf_bits=L['leaf_bits'],
            func_bits=L['func_bits'],
            block_len=self.block_len, node_len=self.node_len,
            provider_prefix=str(self.provider_prefix),
            num_dc=self.num_dc,
            max_leafs_per_dc=self.max_leafs_per_dc,
            max_vrfs_per_leaf=self.max_vrfs_per_leaf,
            behaviors=self.behaviors)


def print_report(r: PlanningResult):
    print(); print("═"*68)
    print("  ОТЧЁТ: Планирование адресного пространства SRv6")
    print("═"*68)
    print()
    print("  ВХОДНЫЕ ПАРАМЕТРЫ")
    print(_sep())
    print(f"  Провайдерский префикс : {r.provider_prefix}")
    print(f"  Число DC              : {r.num_dc}")
    print(f"  Max leaf/DC           : {r.max_leafs_per_dc}")
    print(f"  Max VRF/leaf          : {r.max_vrfs_per_leaf}")
    print(f"  Поведения SID         : {r.behaviors}")
    print(f"  block_len / node_len  : {r.block_len} / {r.node_len} бит")

    if not r.success:
        print(); print("  ОШИБКА"); print(_sep())
        for line in r.error.split("\n"):
            print(f"  {line}")
        print(); print("  ЧТО МОЖНО СДЕЛАТЬ"); print(_sep())
        for i, fix in enumerate(r.fix_suggestions, 1):
            print(f"  Вариант {i}:")
            for line in fix.split("\n"):
                print(f"    {line}")
            print()
        print("═"*68); return

    pfx = ipaddress.IPv6Network(r.provider_prefix).prefixlen
    print(); print("  СХЕМА РАЗБИЕНИЯ"); print(_sep())
    print(f"  {'Провайдер-префикс':<24} {pfx:3d} бит")
    print(f"  {'DC-идентификатор':<24} {r.dc_bits:3d} бит")
    print(f"  {'Leaf-идентификатор':<24} {r.leaf_bits:3d} бит")
    pad = r.block_len - pfx - r.dc_bits - r.leaf_bits
    if pad > 0:
        print(f"  {'Выравнивание (pad)':<24} {pad:3d} бит")
    print(f"  {'Node (locator)':<24} {r.node_len:3d} бит")
    print(f"  {'Function (VRF+behavior)':<24} {r.func_bits:3d} бит")
    print(f"  {'ИТОГО':<24} 128 бит")

    print(); print("  УТИЛИЗАЦИЯ ПРОСТРАНСТВА"); print(_sep())
    print(f"  Локаторов: {r.used_locators:,} / "
          f"{r.total_locator_space:,}  "
          f"({r.utilization_locators_pct:.2f}%)")
    print(f"  SID/leaf : {r.used_sids_per_leaf:,} / "
          f"{r.total_sid_space:,}  "
          f"({r.utilization_sids_pct:.6f}%)")
    print(f"  Резерв локаторов : {r.growth_reserve_locators:,}  "
          f"(можно добавить leaf)")
    print(f"  Резерв SID/leaf  : {r.growth_reserve_vrfs:,}  "
          f"(можно добавить VRF)")

    n_loc = min(6, len(r.locators))
    print(); print(f"  ТАБЛИЦА ЛОКАТОРОВ (показано {n_loc} "
                   f"из {len(r.locators)})"); print(_sep())
    print(f"  {'DC':>4}  {'Leaf':>4}  {'Локатор':<38}  Loopback")
    print("  " + "─"*62)
    for loc in r.locators[:n_loc]:
        print(f"  {loc.dc_id:>4}  {loc.leaf_id:>4}  "
              f"{str(loc.prefix):<38}  {loc.loopback}")
    if len(r.locators) > n_loc:
        print(f"  ... ещё {len(r.locators)-n_loc} локаторов")

    first  = r.locators[0]
    nb     = len(r.behaviors)
    n_sid  = min(3 * nb, len(first.sids))
    print(); print(f"  ПРИМЕРЫ SID  "
                   f"(первые 3 VRF, DC={first.dc_id} leaf={first.leaf_id})")
    print(_sep())
    print(f"  Локатор: {first.prefix}")
    print(f"  {'VRF':>6}  {'Поведение':<10}  SID")
    print("  " + "─"*58)
    for sid in first.sids[:n_sid]:
        print(f"  {sid.vrf_id:>6}  {sid.behavior:<10}  {sid.address}")
    print()
    print("  ✓ Проверка конфликтов пройдена: все SID уникальны")
    print("═"*68)


def export_csv(r: PlanningResult, base: str):
    loc_path = base + "_locators.csv"
    sid_path = base + "_sids.csv"
    with open(loc_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dc_id","leaf_id","locator_prefix","loopback"])
        for loc in r.locators:
            w.writerow([loc.dc_id, loc.leaf_id,
                        str(loc.prefix), str(loc.loopback)])
    total = sum(len(loc.sids) for loc in r.locators)
    with open(sid_path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["dc_id","leaf_id","locator_prefix",
                    "vrf_id","behavior","sid_address"])
        for loc in r.locators:
            for sid in loc.sids:
                w.writerow([loc.dc_id, loc.leaf_id, str(loc.prefix),
                            sid.vrf_id, sid.behavior, str(sid.address)])
    print(f"  Таблица локаторов  → {loc_path}")
    print(f"  Полная таблица SID → {sid_path}  ({total:,} записей)")


def ask(prompt, default, cast=str):
    while True:
        raw = input(f"  {prompt} [{default}]: ").strip()
        if not raw:
            return default
        try:
            return cast(raw)
        except Exception:
            print("  ✗ Некорректный ввод, попробуйте ещё раз.")

def ask_behaviors():
    print()
    print("  Доступные поведения SID:")
    print("    dt4 — End.DT4  L3VPN IPv4  (рекомендуется)")
    print("    dt6 — End.DT6  L3VPN IPv6")
    print("    dx4 — End.DX4  L2 IPv4")
    print("    end — End      базовый")
    raw = input("  Введите через запятую [dt4,dt6]: ").strip()
    if not raw:
        return ["dt4","dt6"]
    result = [b.strip() for b in raw.split(",")
              if b.strip() in BEHAVIORS_MAP]
    return result if result else ["dt4"]

def ask_mode():
    print()
    print("  Режим вывода:")
    print("    1 — краткий отчёт в консоль")
    print("    2 — полные таблицы в CSV-файлы")
    while True:
        raw = input("  Выберите [1]: ").strip()
        if raw in ("","1"): return "console"
        if raw == "2":      return "csv"
        print("  ✗ Введите 1 или 2.")

def interactive_mode():
    print()
    print("╔══════════════════════════════════════════════════════╗")
    print("║   Планировщик адресного пространства SRv6           ║")
    print("║   Нажмите Enter для принятия значения по умолчанию  ║")
    print("╚══════════════════════════════════════════════════════╝")
    print()
    prefix    = ask("Провайдерский IPv6-префикс", "2001:db8::/32")
    num_dc    = ask("Число дата-центров (DC)", 3, int)
    max_leafs = ask("Максимум leaf-узлов в одном DC", 20, int)
    max_vrfs  = ask("Максимум VRF (арендаторов) на leaf", 500, int)
    block_len = ask("block_len (бит, рекомендуется 40)", 40, int)
    node_len  = ask("node_len  (бит, рекомендуется 24)", 24, int)
    behaviors = ask_behaviors()
    mode      = ask_mode()
    planner = SRv6AddressPlanner(
        provider_prefix=prefix, num_dc=num_dc,
        max_leafs_per_dc=max_leafs, max_vrfs_per_leaf=max_vrfs,
        block_len=block_len, node_len=node_len, behaviors=behaviors)
    result = planner.plan()
    print_report(result)
    if result.success and mode == "csv":
        print(); print("  Сохранение CSV...")
        base = os.path.join(
            os.path.dirname(os.path.abspath(__file__)), "srv6_plan")
        export_csv(result, base)


EXAMPLES = {
    1: dict(
        title="Малый провайдер: 2 DC × 10 leaf × 200 VRF",
        desc=(
            "Небольшая IaaS-платформа.\n"
            "  Провайдерский блок /32 (стандартная выдача RIPE NCC).\n"
            "  2 ЦОД, по 10 leaf в каждом, до 200 арендаторов на leaf.\n"
            "  Поддержка IPv4 и IPv6 VPN арендаторов."
        ),
        params=dict(provider_prefix="2001:db8::/32",
                    num_dc=2, max_leafs_per_dc=10,
                    max_vrfs_per_leaf=200, block_len=40, node_len=24,
                    behaviors=["dt4","dt6"]),
    ),
    2: dict(
        title="Средний провайдер: 4 DC × 30 leaf × 500 VRF",
        desc=(
            "Региональный провайдер с четырьмя площадками.\n"
            "  Блок /30 (запрашивается для среднего провайдера).\n"
            "  Показывает как больший блок снимает ограничения."
        ),
        params=dict(provider_prefix="2001:db8::/30",
                    num_dc=4, max_leafs_per_dc=30,
                    max_vrfs_per_leaf=500, block_len=40, node_len=24,
                    behaviors=["dt4","dt6"]),
    ),
    3: dict(
        title="Нарушение ограничений: диагностика и советы",
        desc=(
            "Провайдер с блоком /32 пытается разместить\n"
            "  10 DC × 100 leaf — не хватает бит в Block.\n"
            "  Алгоритм выявляет проблему и предлагает варианты решения."
        ),
        params=dict(provider_prefix="2001:db8::/32",
                    num_dc=10, max_leafs_per_dc=100,
                    max_vrfs_per_leaf=500, block_len=40, node_len=24,
                    behaviors=["dt4"]),
    ),
}

def run_example(n: int, csv_mode: bool):
    if n not in EXAMPLES:
        print(f"Пример {n} не найден. Доступны: 1, 2, 3."); return
    ex = EXAMPLES[n]
    print(); print("▶"*68)
    print(f"  ПРИМЕР {n}: {ex['title']}")
    print("▶"*68); print()
    for line in ex["desc"].split("\n"):
        print(f"  {line}")
    planner = SRv6AddressPlanner(**ex["params"])
    result  = planner.plan()
    print_report(result)
    if result.success and csv_mode:
        print(); print("  Сохранение CSV...")
        base = os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f"srv6_plan_example{n}")
        export_csv(result, base)


def main():
    p = argparse.ArgumentParser(
        description="Планировщик адресного пространства SRv6",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    p.add_argument("--example", type=int, choices=[1,2,3],
                   help="Запустить встроенный пример")
    p.add_argument("--csv", action="store_true",
                   help="Сохранить результат в CSV-файлы")
    args = p.parse_args()
    if args.example:
        run_example(args.example, csv_mode=args.csv)
    else:
        interactive_mode()

if __name__ == "__main__":
    main()
