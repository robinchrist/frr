#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
test_bgp_evpn_reexport_imported.py: RT-rewriting EVPN gateway via
re-export-imported (scope external).

    r1 ---- [s1, default-VRF underlay] ---- r2

- r1 tenant blue (L3VNI 100) originates 10.1.1.0/24 as a type-5 with
  RT 65000:100.
- r2 tenant blue (L3VNI 200) imports 65000:100 and re-originates the
  imported prefix as its OWN type-5 - r2's RD, VTEP and L3VNI - with the
  rewritten RT set 65000:999 (mode override, scope external-only).
- r1 tenant red imports 65000:999 (import-only, no L3VNI) and must
  receive 10.1.1.0/24 solely through r2's re-originated route.

Also verifies that dropping 'external' from the scope withdraws the
re-originated type-5 again.
"""

import functools
import json
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]

PFX = "10.1.1.0/24"


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    s1 = tgen.add_switch("s1")
    s1.add_link(r1)  # r1-eth0
    s1.add_link(r2)  # r2-eth0


def _setup_dataplane(router, local_ip, vni, extra=None):
    """Tenant VRF blue with an L3VNI (SVD-style: vxlan under a bridge that
    is enslaved to the VRF)."""
    cmds = [
        "ip link add blue type vrf table 1001",
        "ip link set blue up",
        "ip link add br{vni} type bridge",
        "ip link set br{vni} master blue",
        "ip link add vxlan{vni} type vxlan id {vni} dstport 4789 local "
        + local_ip
        + " dev {r}-eth0 nolearning",
        "ip link set vxlan{vni} master br{vni}",
        "ip link set vxlan{vni} up",
        "ip link set br{vni} up",
    ]
    for cmd in cmds:
        router.cmd_raises(cmd.format(r=router.name, vni=vni))
    for cmd in extra or []:
        router.cmd_raises(cmd)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _setup_dataplane(
        tgen.gears["r1"],
        "192.168.1.1",
        100,
        extra=[
            # the prefix r1's tenant blue originates
            "ip link add d-blue type dummy",
            "ip link set d-blue master blue",
            "ip addr add 10.1.1.1/24 dev d-blue",
            "ip link set d-blue up",
            # import-only tenant red on r1
            "ip link add red type vrf table 1002",
            "ip link set red up",
        ],
    )
    _setup_dataplane(tgen.gears["r2"], "192.168.1.2", 200)

    for rname in ("r1", "r2"):
        tgen.gears[rname].load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_session(router, peer):
    output = router.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
    peers = output.get("peers", {})
    if peer not in peers:
        return "{}: peer {} missing".format(router.name, peer)
    if peers[peer].get("state") != "Established":
        return "{}: peer {} not Established".format(router.name, peer)
    return None


def test_sessions_established():
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    for rname, peer in (("r1", "192.168.1.2"), ("r2", "192.168.1.1")):
        test_func = functools.partial(_check_session, tgen.gears[rname], peer)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


def _vrf_has_prefix(router, vrf, prefix, expect):
    output = router.vtysh_cmd(
        "show bgp vrf {} ipv4 unicast {} json".format(vrf, prefix), isjson=True
    )
    paths = output.get("paths", [])
    if expect and not paths:
        return "{}: {} missing in vrf {}".format(router.name, prefix, vrf)
    if not expect and paths:
        return "{}: unexpected {} in vrf {}".format(router.name, prefix, vrf)
    return None


def test_import_on_r2():
    """r2 tenant blue imports r1's type-5 via RT 65000:100."""
    tgen = get_topogen()
    test_func = functools.partial(
        _vrf_has_prefix, tgen.gears["r2"], "blue", PFX, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def _r1_sees_reoriginated_type5(router, expect):
    """Look for r2's re-originated type-5 (nexthop 192.168.1.2) carrying the
    rewritten RT 65000:999 and NOT the original 65000:100."""
    output = router.vtysh_cmd(
        "show bgp l2vpn evpn route type prefix json", isjson=True
    )
    found = None
    for rd, rd_data in (output or {}).items():
        if not isinstance(rd_data, dict):
            continue
        for prefix, pdata in rd_data.items():
            if PFX not in prefix or not isinstance(pdata, dict):
                continue
            for path in pdata.get("paths", []):
                # paths may be nested lists depending on the format
                entries = path if isinstance(path, list) else [path]
                for entry in entries:
                    nhs = entry.get("nexthops", [])
                    if not any(nh.get("ip") == "192.168.1.2" for nh in nhs):
                        continue
                    found = entry
    if not expect:
        if found:
            return "r2's re-originated type-5 still present"
        return None
    if not found:
        return "no type-5 for {} from r2 in r1's EVPN table".format(PFX)

    ecom = found.get("extendedCommunity", {})
    ecom_str = ecom.get("string", "") if isinstance(ecom, dict) else str(ecom)
    if "65000:999" not in ecom_str:
        return "rewritten RT 65000:999 missing: {}".format(ecom_str)
    if "65000:100" in ecom_str:
        return "original RT 65000:100 not overridden: {}".format(ecom_str)
    return None


def test_reoriginated_type5_with_rewritten_rt():
    tgen = get_topogen()
    test_func = functools.partial(
        _r1_sees_reoriginated_type5, tgen.gears["r1"], True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_r1_red_receives_via_rewritten_rt():
    """r1 tenant red (imports 65000:999 only) gets the prefix through r2's
    re-origination."""
    tgen = get_topogen()
    test_func = functools.partial(
        _vrf_has_prefix, tgen.gears["r1"], "red", PFX, True
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_scope_change_withdraws_type5():
    """Narrowing the scope to local-only must withdraw the re-originated
    type-5 and empty r1's red VRF again."""
    tgen = get_topogen()
    r2 = tgen.gears["r2"]

    r2.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65002 vrf blue\n"
        "address-family l2vpn evpn\n"
        "re-export-imported\n"
        "scope local-only\n"
    )

    test_func = functools.partial(
        _r1_sees_reoriginated_type5, tgen.gears["r1"], False
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result

    test_func = functools.partial(
        _vrf_has_prefix, tgen.gears["r1"], "red", PFX, False
    )
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
