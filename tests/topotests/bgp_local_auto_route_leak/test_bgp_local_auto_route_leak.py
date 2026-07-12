#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
test_bgp_local_auto_route_leak.py: Local auto route leak (Juniper
auto-export style) on a single router with three tenant VRFs:

  blue:  route-target both   65000:100     (exports 100, imports 100)
  red:   route-target import 65000:100, export 65000:200
  green: route-target import 65000:200, local-auto-route-leak-import disable

Process-wide defaults enable both directions; no underlay, no L3VNI, no
peers - leaking is matched purely on the EVPN route-target config.

Verifies:
- blue's connected route is auto-leaked into red (RT 65000:100 match)
- no reverse leak into blue (red only exports 65000:200)
- green receives nothing while its per-VRF import override is 'disable';
  flipping it to 'enable' at runtime pulls red's route in
- re-export-imported (scope local-only) on red re-leaks blue's imported
  route onward to green with the rewritten RT set; provenance shows the
  blue -> red traversal chain
- a deliberate RT cycle (green re-exports with blue's import RT) does NOT
  return blue's own route to blue (traversal-chain loop guard), while
  red's route legitimately reaches blue via the green hop
"""

import functools
import os
import sys
import pytest

CWD = os.path.dirname(os.path.realpath(__file__))
sys.path.append(os.path.join(CWD, "../"))

# pylint: disable=C0413
from lib import topotest
from lib.topogen import Topogen, get_topogen
from lib.topolog import logger

pytestmark = [pytest.mark.bgpd]

BLUE_PFX = "10.0.1.0/24"
RED_PFX = "10.0.2.0/24"
GREEN_PFX = "10.0.3.0/24"


def build_topo(tgen):
    tgen.add_router("r1")


def _setup_dataplane(router):
    cmds = [
        # three tenant VRFs, one dummy interface with a connected subnet each
        "ip link add blue type vrf table 1001",
        "ip link set blue up",
        "ip link add red type vrf table 1002",
        "ip link set red up",
        "ip link add green type vrf table 1003",
        "ip link set green up",
        "ip link add d-blue type dummy",
        "ip link set d-blue master blue",
        "ip addr add 10.0.1.1/24 dev d-blue",
        "ip link set d-blue up",
        "ip link add d-red type dummy",
        "ip link set d-red master red",
        "ip addr add 10.0.2.1/24 dev d-red",
        "ip link set d-red up",
        "ip link add d-green type dummy",
        "ip link set d-green master green",
        "ip addr add 10.0.3.1/24 dev d-green",
        "ip link set d-green up",
    ]
    for cmd in cmds:
        router.cmd_raises(cmd)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _setup_dataplane(tgen.gears["r1"])
    tgen.gears["r1"].load_frr_config(os.path.join(CWD, "r1", "frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _vrf_has_prefix(router, vrf, prefix, expect, origin_vrf=None, chain=None):
    """None when the VRF's unicast table matches the expectation."""
    output = router.vtysh_cmd(
        "show bgp vrf {} ipv4 unicast {} json".format(vrf, prefix), isjson=True
    )
    paths = output.get("paths", [])

    if not expect:
        if paths:
            return "{}: unexpected {} in vrf {}".format(router.name, prefix, vrf)
        return None

    if not paths:
        return "{}: {} missing in vrf {}".format(router.name, prefix, vrf)

    if origin_vrf is None and chain is None:
        return None

    for path in paths:
        if origin_vrf and path.get("localLeakOriginVrf") != origin_vrf:
            continue
        if chain and path.get("localLeakPath") != chain:
            continue
        return None

    return "{}: {} in vrf {} lacks expected leak provenance (origin {}, chain {})".format(
        router.name, prefix, vrf, origin_vrf, chain
    )


def _expect(vrf, prefix, expect, origin_vrf=None, chain=None, count=30):
    tgen = get_topogen()
    router = tgen.gears["r1"]
    test_func = functools.partial(
        _vrf_has_prefix, router, vrf, prefix, expect, origin_vrf, chain
    )
    _, result = topotest.run_and_expect(test_func, None, count=count, wait=1)
    assert result is None, result


def test_basic_leak_by_rt_match():
    """blue (export 65000:100) -> red (import 65000:100)."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    _expect("red", BLUE_PFX, True, origin_vrf="blue", chain=["blue"])
    # no RT match in the reverse direction
    _expect("blue", RED_PFX, False)


def test_tristate_import_override():
    """green's 'disable' override beats the process-wide default; flipping
    it to 'enable' pulls red's route (export 65000:200) in."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    # red exports 65000:200 which green imports - but green's import is off
    _expect("green", RED_PFX, False)

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf green\n"
        "address-family l2vpn evpn\n"
        "local-auto-route-leak-import enable\n"
    )
    _expect("green", RED_PFX, True, origin_vrf="red", chain=["red"])


def test_leak_matrix_show():
    """Sanity of the adjacency show command."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    output = r1.vtysh_cmd(
        "show bgp l2vpn evpn local-auto-route-leak json", isjson=True
    )
    assert output.get("exportDefault") is True
    assert output.get("importDefault") is True

    vrfs = output.get("vrfs", {})
    blue = next((v for k, v in vrfs.items() if "blue" in k), None)
    assert blue is not None, "blue missing in leak matrix"
    assert blue.get("exportEffective") is True
    assert any("red" in dest for dest in blue.get("leaksTo", [])), (
        "blue does not list red as leak destination: %s" % blue
    )


def test_reexport_local_chain():
    """red re-exports its imported routes with RT 65000:200 (override,
    local-only): blue's route continues to green as blue -> red."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    # without re-export, imported routes never propagate onward
    _expect("green", BLUE_PFX, False)

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf red\n"
        "address-family l2vpn evpn\n"
        "re-export-imported\n"
        "route-target 65000:200\n"
        "mode override\n"
        "scope local-only\n"
    )
    _expect("green", BLUE_PFX, True, origin_vrf="blue", chain=["blue", "red"])


def test_reexport_cycle_is_loop_free():
    """Close the RT cycle: green re-exports with 65000:100, which blue
    imports. blue's own route must NOT come back (chain guard), but red's
    route legitimately reaches blue via green (red -> green)."""
    tgen = get_topogen()
    r1 = tgen.gears["r1"]

    r1.vtysh_cmd(
        "configure terminal\n"
        "router bgp 65000 vrf green\n"
        "address-family l2vpn evpn\n"
        "re-export-imported\n"
        "route-target 65000:100\n"
        "mode override\n"
        "scope local-only\n"
    )

    # red's prefix travels red -> green -> blue (no cycle: blue not revisited)
    _expect("blue", RED_PFX, True, origin_vrf="red", chain=["red", "green"])

    # blue's own prefix must never return to blue as an imported path
    def _blue_own_pfx_clean(router):
        output = router.vtysh_cmd(
            "show bgp vrf blue ipv4 unicast {} json".format(BLUE_PFX), isjson=True
        )
        for path in output.get("paths", []):
            if path.get("localLeakOriginVrf"):
                return "blue received its own prefix back via local leak"
        return None

    # give the engine a moment, then require stability
    test_func = functools.partial(_blue_own_pfx_clean, r1)
    _, result = topotest.run_and_expect(test_func, None, count=5, wait=1)
    assert result is None, result


def test_memory_leak():
    tgen = get_topogen()
    if not tgen.is_memleak_enabled():
        pytest.skip("Memory leak test/report is disabled")
    tgen.report_memory_leaks()


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
