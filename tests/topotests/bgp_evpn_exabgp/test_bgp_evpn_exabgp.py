#!/usr/bin/env python3
# SPDX-License-Identifier: ISC

"""
test_bgp_evpn_exabgp.py: Simple EVPN debugging topology with 2 ExaBGP peers and 1 FRR router.

Topology:

   peer1 (ExaBGP, AS 65002, 192.0.2.2) ---+
                                            +--- [s1] --- r1 (FRR, AS 65001, 192.0.2.1)
   peer2 (ExaBGP, AS 65003, 192.0.2.3) ---+

Each ExaBGP peer announces a handful of EVPN Type-2 (MAC/IP) and Type-3 (IMET) routes
with its own route-target, giving FRR routes to process in the L2VPN EVPN table.

Interactive debugging
---------------------
Run with --topology-only to get an interactive CLI where you can open a vtysh:

    sudo -E pytest -s --topology-only bgp_evpn_exabgp/test_bgp_evpn_exabgp.py
    unet> vtysh r1

Or launch vtysh automatically on start:

    sudo -E pytest -s --topology-only --vtysh=r1 bgp_evpn_exabgp/test_bgp_evpn_exabgp.py
"""

import functools
import os
import sys
from time import sleep
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

    peer1 = tgen.add_exabgp_peer(
        "peer1", ip="192.0.2.2", defaultRoute="via 192.0.2.1"
    )
    peer2 = tgen.add_exabgp_peer(
        "peer2", ip="192.0.2.3", defaultRoute="via 192.0.2.1"
    )

    switch = tgen.add_switch("s1")
    switch.add_link(r1)
    switch.add_link(peer1)
    switch.add_link(peer2)


def setup_module(mod):
    tgen = Topogen(build_topo, mod.__name__)
    tgen.start_topology()

    router = tgen.gears["r1"]

    # Bare VRF device for the import-only tenant VRF "blue". Deliberately NO
    # VXLAN interface / bridge / SVI: the whole point is that the control
    # plane (import via route targets) works without any EVPN dataplane.
    router.cmd_raises("ip link add blue type vrf table 1001")
    router.cmd_raises("ip link set blue up")

    router.load_frr_config(os.path.join(CWD, "r1/frr.conf"))
    tgen.start_router()

    env_file = os.path.join(CWD, "exabgp.env")
    for pname in ("peer1", "peer2"):
        peer = tgen.gears[pname]
        peer.start(os.path.join(CWD, pname), env_file)
        logger.info("started ExaBGP peer %s", pname)


def teardown_module(mod):
    tgen = get_topogen()
    tgen.stop_topology()


def test_bgp_evpn_peers_established():
    """Both ExaBGP peers must reach Established state in the L2VPN EVPN AFI."""
    tgen = get_topogen()

    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    r1 = tgen.gears["r1"]

    def _check_established():
        output = r1.vtysh_cmd("show bgp l2vpn evpn summary json", isjson=True)
        peers = output.get("peers", {})
        not_up = [
            addr
            for addr, data in peers.items()
            if data.get("state") != "Established"
        ]
        if not_up:
            return "peers not established: {}".format(not_up)
        if len(peers) < 2:
            return "expected 2 peers, have {}".format(len(peers))
        return None

    test_func = functools.partial(_check_established)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_bgp_evpn_routes_received():
    """The announced type-2/type-3 routes must be present in the global EVPN table."""
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    r1 = tgen.gears["r1"]

    def _check_routes():
        output = r1.vtysh_cmd("show bgp l2vpn evpn route json", isjson=True)
        num = output.get("numPrefix", 0)
        # peer1: 1x IMET + 2x MAC/IP, peer2: 1x IMET + 1x MAC/IP
        if num < 5:
            return "expected >= 5 EVPN prefixes, have {}".format(num)
        return None

    test_func = functools.partial(_check_routes)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_import_only_vrf_imports_host_routes():
    """
    Decoupling proof (control plane independent of dataplane):

    VRF "blue" has only a manual import RT - no origination-l3vni, no
    vxlan-underlay anywhere, no VXLAN dataplane constructs. The MAC/IP
    routes' host prefixes with the matching RT (65000:100, from peer1) must
    be imported into its BGP RIB; the ones with the non-matching RT
    (65000:200, from peer2) must not.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    r1 = tgen.gears["r1"]

    def _check_vrf_import():
        output = r1.vtysh_cmd("show bgp vrf blue ipv4 unicast json", isjson=True)
        routes = output.get("routes", {})
        for want in ("10.0.1.10/32", "10.0.1.11/32"):
            if want not in routes:
                return "expected {} in VRF blue BGP RIB, have {}".format(
                    want, list(routes.keys())
                )
        if "10.0.2.10/32" in routes:
            return "10.0.2.10/32 (RT 65000:200) must NOT be imported into VRF blue"
        return None

    test_func = functools.partial(_check_vrf_import)
    _, result = topotest.run_and_expect(test_func, None, count=60, wait=1)
    assert result is None, result


def test_import_only_vrf_not_programmed_to_zebra():
    """
    Without a live L3VNI, the imported routes must stay a pure control-plane
    matter: nothing may be programmed into zebra / the kernel for VRF blue.
    """
    tgen = get_topogen()
    if tgen.routers_have_failure():
        pytest.skip("routers have failure: {}".format(tgen.errors))

    r1 = tgen.gears["r1"]

    output = r1.vtysh_cmd("show ip route vrf blue json", isjson=True)
    for prefix in ("10.0.1.10/32", "10.0.1.11/32"):
        assert prefix not in output, (
            "{} must not be announced to zebra without a live L3VNI".format(prefix)
        )


if __name__ == "__main__":
    args = ["-s"] + sys.argv[1:]
    sys.exit(pytest.main(args))