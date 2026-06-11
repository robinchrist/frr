#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
test_bgp_evpn_multi_underlay.py: Two PEs connected through TWO underlay VRFs
(underlay-red, underlay-blue), each hosting one VXLAN VNI:

    r1 ---- [s1, underlay-red,  VNI 100] ---- r2
    r1 ---- [s2, underlay-blue, VNI 200] ---- r2

Verifies the multi-underlay EVPN model:
- both underlay instances peer and exchange EVPN routes independently
- origination is scoped to the EVI's bound underlay: the IMET route for
  VNI 100 must only appear in underlay-red's EVPN RIB, VNI 200 only in
  underlay-blue's (send anywhere / receive only via your own underlay)
- the EVPN route table is logically shared: an EVI without any VNI/underlay
  imports routes received via BOTH underlays purely through its manual RTs
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

pytestmark = [pytest.mark.bgpd, pytest.mark.evpn]


def build_topo(tgen):
    r1 = tgen.add_router("r1")
    r2 = tgen.add_router("r2")

    s1 = tgen.add_switch("s1")
    s1.add_link(r1)  # r1-eth0
    s1.add_link(r2)  # r2-eth0

    s2 = tgen.add_switch("s2")
    s2.add_link(r1)  # r1-eth1
    s2.add_link(r2)  # r2-eth1


def _setup_dataplane(router, red_local, blue_local):
    """Two underlay VRFs, each with one VXLAN device whose link (and thus
    derived underlay VRF) lives in that VRF."""
    cmds = [
        "ip link add underlay-red type vrf table 1001",
        "ip link set underlay-red up",
        "ip link add underlay-blue type vrf table 1002",
        "ip link set underlay-blue up",
        "ip link set {r}-eth0 master underlay-red",
        "ip link set {r}-eth1 master underlay-blue",
        # VNI 100 over underlay-red
        "ip link add br100 type bridge",
        "ip link set br100 up",
        "ip link add vxlan100 type vxlan id 100 dstport 4789 local "
        + red_local
        + " dev {r}-eth0 nolearning",
        "ip link set vxlan100 master br100",
        "ip link set vxlan100 up",
        # VNI 200 over underlay-blue
        "ip link add br200 type bridge",
        "ip link set br200 up",
        "ip link add vxlan200 type vxlan id 200 dstport 4789 local "
        + blue_local
        + " dev {r}-eth1 nolearning",
        "ip link set vxlan200 master br200",
        "ip link set vxlan200 up",
    ]
    for cmd in cmds:
        router.cmd_raises(cmd.format(r=router.name))


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    _setup_dataplane(tgen.gears["r1"], "192.168.1.1", "192.168.2.1")
    _setup_dataplane(tgen.gears["r2"], "192.168.1.2", "192.168.2.2")

    for rname in ("r1", "r2"):
        router = tgen.gears[rname]
        router.load_frr_config(os.path.join(CWD, rname, "frr.conf"))

    tgen.start_router()


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def _check_sessions(router, vrf, peer):
    output = router.vtysh_cmd(
        "show bgp vrf {} l2vpn evpn summary json".format(vrf), isjson=True
    )
    peers = output.get("peers", {})
    if peer not in peers:
        return "{}: peer {} missing in vrf {}".format(router.name, peer, vrf)
    if peers[peer].get("state") != "Established":
        return "{}: peer {} in vrf {} not Established".format(router.name, peer, vrf)
    return None


def test_underlay_sessions_established():
    """Both underlay instances must establish their EVPN session."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    for rname, peers in (
        ("r1", (("underlay-red", "192.168.1.2"), ("underlay-blue", "192.168.2.2"))),
        ("r2", (("underlay-red", "192.168.1.1"), ("underlay-blue", "192.168.2.1"))),
    ):
        router = tgen.gears[rname]
        for vrf, peer in peers:
            test_func = functools.partial(_check_sessions, router, vrf, peer)
            _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
            assert result is None, result


def _underlay_has_imet(router, vrf, vtep_ip, expect):
    output = router.vtysh_cmd(
        "show bgp vrf {} l2vpn evpn route type multicast json".format(vrf),
        isjson=True,
    )
    found = False
    for rd_data in (output or {}).values():
        if not isinstance(rd_data, dict):
            continue
        for prefix in rd_data:
            if vtep_ip in prefix:
                found = True
    if expect and not found:
        return "{}: IMET for VTEP {} missing in vrf {}".format(
            router.name, vtep_ip, vrf
        )
    if not expect and found:
        return "{}: IMET for VTEP {} must NOT be in vrf {}".format(
            router.name, vtep_ip, vrf
        )
    return None


def test_origination_scoped_to_bound_underlay():
    """
    r1's IMET route for VNI 100 (VTEP 192.168.1.1) must arrive in r2's
    underlay-red RIB only; the one for VNI 200 (VTEP 192.168.2.1) in
    underlay-blue only - origination goes only into the bound underlay.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    r2 = tgen.gears["r2"]

    for vrf, vtep, expect in (
        ("underlay-red", "192.168.1.1", True),
        ("underlay-blue", "192.168.2.1", True),
        ("underlay-red", "192.168.2.1", False),
        ("underlay-blue", "192.168.1.1", False),
    ):
        test_func = functools.partial(_underlay_has_imet, r2, vrf, vtep, expect)
        _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
        assert result is None, result


# TODO (diagnostics stage): once `show bgp l2vpn evpn evi NAME` exists, assert
# that r2's VNI-less "import-both" EVI imported the IMET/MAC-IP routes from
# BOTH underlays (cross-underlay shared-table import). Until then this is only
# covered indirectly via the irt machinery.


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))
