// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp CLI northbound wiring table and bgp_cli_init() entry point.
 *
 * Split out of bgpd/bgp_cli.c (bgpd-yang-conversion intermezzo). The
 * proteus_bgp_cli_info table is pure code motion (unchanged). bgp_cli_init()
 * is NOT byte-identical to the original: DEFPY_YANG() bakes each generated
 * "cmd_element" as `static`, so install_element() call sites for a command
 * can only live in the same translation unit as its DEFPY. bgp_cli_init()
 * therefore now delegates to bgp_cli_instance_init()/bgp_cli_process_init()/
 * bgp_cli_neighbor_init(), one per split file, each doing exactly the
 * install_node()/install_element() calls that original bgp_cli_init() did
 * for that file's commands, in the same order. See bgp_cli_local.h.
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"
#include "vrf.h"
#include "asn.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"

const struct frr_yang_module_info proteus_bgp_cli_info = {
	.name = "proteus-bgp",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp:instance",
			.cbs = {
				.cli_show = instance_cli_write,
				.cli_show_end = instance_cli_write_end,
			}
		},
		/* M5 B0: address-family block header/trailer for the nine
		 * instance afi-safis containers. cli_show fires only once a
		 * per-AF leaf materializes the non-presence container (B1+),
		 * wrapping the converted leaves in an 'address-family <...>'
		 * block byte-identical to bgp_config_write_family(). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		/* M6 B1: 'vni N' ... 'exit-vni' list-entry frame. Gated to stay
		 * silent while the entry has no converted sub-leaf (bgpd's
		 * write_vni_config still owns the whole block during the M6
		 * coexistence window). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni",
			.cbs = {
				.cli_show = instance_evpn_vni_cli_write,
				.cli_show_end = instance_evpn_vni_cli_write_end,
			}
		},
		/* M6 B2: instance-level l2vpn-evpn advertise-flag leaves. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-all-vni",
			.cbs = {
				.cli_show = instance_evpn_advertise_all_vni_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-default-gw",
			.cbs = {
				.cli_show = instance_evpn_advertise_default_gw_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-svi-ip",
			.cbs = {
				.cli_show = instance_evpn_advertise_svi_ip_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/enable-resolve-overlay-index",
			.cbs = {
				.cli_show = instance_evpn_enable_resolve_overlay_index_cli_write,
			}
		},
		/* M6 B3: instance-level l2vpn-evpn mac-vrf-soo + flooding.
		 * mac-vrf-soo's cli_show is registered on each choice case's
		 * local-admin leaf, mirroring M5 B3's per-AF soo registration
		 * (the one point reached regardless of which case is set). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as2/local-admin",
			.cbs = {
				.cli_show = instance_evpn_mac_vrf_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as4/local-admin",
			.cbs = {
				.cli_show = instance_evpn_mac_vrf_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/ipv4/local-admin",
			.cbs = {
				.cli_show = instance_evpn_mac_vrf_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/flooding",
			.cbs = {
				.cli_show = instance_evpn_flooding_cli_write,
			}
		},
		/* M6 B4: instance-level l2vpn-evpn dup-addr-detection max-moves/
		 * time/freeze; 'enabled' is printed by the still-native legacy
		 * emitter (bgp_config_write_evpn_info), not through mgmtd. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection",
			.cbs = {
				.cli_show = instance_evpn_dup_addr_detection_cli_write,
			}
		},
		/* M6 B5: instance-level l2vpn-evpn multihoming
		 * ead-es-frag-evi-limit + ead-es-route-target-export; the
		 * latter's three case lists each fire once per configured
		 * RT, same shape as the 'network' lists below.
		 * use-es-l3nhg/disable-ead-evi-rx/-tx follow (M6 B9b, Tier A
		 * toggles). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit",
			.cbs = {
				.cli_show = instance_evpn_multihoming_ead_es_frag_evi_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as2",
			.cbs = {
				.cli_show = instance_evpn_ead_es_route_target_export_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as4",
			.cbs = {
				.cli_show = instance_evpn_ead_es_route_target_export_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/ipv4",
			.cbs = {
				.cli_show = instance_evpn_ead_es_route_target_export_ipv4_cli_write,
			}
		},
		/* M6 B9b: Tier A multihoming toggles. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg",
			.cbs = {
				.cli_show = instance_evpn_multihoming_use_es_l3nhg_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx",
			.cbs = {
				.cli_show = instance_evpn_multihoming_disable_ead_evi_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx",
			.cbs = {
				.cli_show = instance_evpn_multihoming_disable_ead_evi_tx_cli_write,
			}
		},
		/* M6 B9b: VRF-level and per-VNI route-target trees. One
		 * cli_show per direction container renders the manual +
		 * wildcard RT lines in legacy's sorted order; the auto
		 * leaves render behind it via the DFS. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import",
			.cbs = {
				.cli_show = instance_evpn_rt_direction_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/auto/mode",
			.cbs = {
				.cli_show = instance_evpn_rt_auto_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/auto/rfc8365-compatible",
			.cbs = {
				.cli_show = instance_evpn_rt_auto_rfc8365_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export",
			.cbs = {
				.cli_show = instance_evpn_rt_direction_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/auto/mode",
			.cbs = {
				.cli_show = instance_evpn_rt_auto_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/auto/rfc8365-compatible",
			.cbs = {
				.cli_show = instance_evpn_rt_auto_rfc8365_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import",
			.cbs = {
				.cli_show = instance_evpn_vni_rt_direction_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/auto/mode",
			.cbs = {
				.cli_show = instance_evpn_vni_rt_auto_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export",
			.cbs = {
				.cli_show = instance_evpn_vni_rt_direction_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export/auto/mode",
			.cbs = {
				.cli_show = instance_evpn_vni_rt_auto_mode_cli_write,
			}
		},
		/* M6 B9b: advertise <ipv4|ipv6> unicast, advertise-pip and
		 * the type-5 'network' list. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast",
			.cbs = {
				.cli_show = instance_evpn_advertise_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast",
			.cbs = {
				.cli_show = instance_evpn_advertise_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip",
			.cbs = {
				.cli_show = instance_evpn_advertise_pip_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network",
			.cbs = {
				.cli_show = instance_evpn_network_cli_write,
			}
		},
		/* M6 B6: per-VNI 'rd'/'flooding'/'advertise-default-gw'/
		 * 'advertise-svi-ip'/'advertise-subnet'. 'rd's cli_show is
		 * registered on each choice case's assigned-number leaf, the
		 * same "one point reached regardless of which case is set"
		 * idiom as mac-vrf-soo above. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_vni_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_vni_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_vni_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/flooding",
			.cbs = {
				.cli_show = instance_evpn_vni_flooding_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-default-gw",
			.cbs = {
				.cli_show = instance_evpn_vni_advertise_default_gw_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-svi-ip",
			.cbs = {
				.cli_show = instance_evpn_vni_advertise_svi_ip_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-subnet",
			.cbs = {
				.cli_show = instance_evpn_vni_advertise_subnet_cli_write,
			}
		},
		/* M6 B7: instance-level (per-VRF-instance role) 'rd'/
		 * 'default-originate'. 'rd's cli_show is registered on each
		 * choice case's assigned-number leaf, same idiom as the
		 * per-VNI form above. 'advertise ipv4/ipv6 unicast'
		 * converted in M6 B9b (its containers' rows below). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4/assigned-number",
			.cbs = {
				.cli_show = instance_evpn_rd_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv4",
			.cbs = {
				.cli_show = instance_evpn_default_originate_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv6",
			.cbs = {
				.cli_show = instance_evpn_default_originate_ipv6_cli_write,
			}
		},
		/* M5 B9: instance-AF 'network' list (ipv4/ipv6 x
		 * unicast/multicast/labeled-unicast); ipv4/ipv6-vpn use the
		 * separate RD-keyed af-network-vpn-* grouping (M7). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv6_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv6_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/network",
			.cbs = {
				.cli_show = afi_safis_network_ipv6_cli_write,
			}
		},
		/* M5 B10: instance-AF 'aggregate-address' list, same six AFs;
		 * ipv4/ipv6 share one emitter (identical option leaves). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address",
			.cbs = {
				.cli_show = afi_safis_aggregate_address_cli_write,
			}
		},
		/* M5 B11: instance-AF 'redistribute' list, ipv4-unicast/
		 * ipv6-unicast only (af-redistribute is unicast-only). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/redistribute",
			.cbs = {
				.cli_show = afi_safis_redistribute_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/redistribute",
			.cbs = {
				.cli_show = afi_safis_redistribute_cli_write,
			}
		},
		/* M7 B1: instance-AF VPN leaking simple knobs (af-vpn-leaking's
		 * export-vpn/import-vpn/import-vrf/import-vrf-route-map),
		 * ipv4-unicast/ipv6-unicast only. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/export-vpn",
			.cbs = {
				.cli_show = afi_safis_export_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vpn",
			.cbs = {
				.cli_show = afi_safis_import_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vrf",
			.cbs = {
				.cli_show = afi_safis_import_vrf_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vrf-route-map",
			.cbs = {
				.cli_show = afi_safis_import_vrf_route_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/export-vpn",
			.cbs = {
				.cli_show = afi_safis_export_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vpn",
			.cbs = {
				.cli_show = afi_safis_import_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vrf",
			.cbs = {
				.cli_show = afi_safis_import_vrf_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vrf-route-map",
			.cbs = {
				.cli_show = afi_safis_import_vrf_route_map_cli_write,
			}
		},
		/* M7 B2: instance-AF VPN leaking, detailed vpn-policy block
		 * (af-vpn-leaking's 'vpn' container), ipv4-unicast/
		 * ipv6-unicast only. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/route-map-import",
			.cbs = {
				.cli_show = afi_safis_vpn_route_map_import_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/route-map-export",
			.cbs = {
				.cli_show = afi_safis_vpn_route_map_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/value",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_value_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/auto",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_auto_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/allocation-mode",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_allocation_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as2/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as4/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/ipv4/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/nexthop-export",
			.cbs = {
				.cli_show = afi_safis_vpn_nexthop_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-import",
			.cbs = {
				.cli_show = afi_safis_vpn_route_map_import_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-export",
			.cbs = {
				.cli_show = afi_safis_vpn_route_map_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/value",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_value_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/auto",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_auto_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/allocation-mode",
			.cbs = {
				.cli_show = afi_safis_vpn_label_export_allocation_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4/assigned-number",
			.cbs = {
				.cli_show = afi_safis_vpn_rd_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/nexthop-export",
			.cbs = {
				.cli_show = afi_safis_vpn_nexthop_export_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_import_ipv4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_rt_export_ipv4_cli_write,
			}
		},
		/* M5 B12: instance-AF 'maximum-paths'/'table-map'/'bgp
		 * dampening', all eight instance AFs that 'uses'
		 * af-route-selection (ipv4/ipv6 x
		 * unicast/multicast/labeled-unicast/vpn). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		/* M7 B3: MPLS-VPN static 'network' statements, RD-encoding
		 * split (as2/ipv4/as4); 'raw' has no legacy parser and stays
		 * reject-stubbed. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_network_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_network_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_network_ipv4_cli_write,
			}
		},
		/* M7: default-on 'bgp retain route-target all'; only the 'no'
		 * form ever renders. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/retain-route-target-all",
			.cbs = {
				.cli_show = afi_safis_retain_route_target_all_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/maximum-paths",
			.cbs = {
				.cli_show = afi_safis_maximum_paths_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/table-map",
			.cbs = {
				.cli_show = afi_safis_table_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening",
			.cbs = {
				.cli_show = afi_safis_dampening_cli_write,
			}
		},
		/* M7 B3: MPLS-VPN static 'network' statements, RD-encoding
		 * split (as2/ipv4/as4); 'raw' has no legacy parser and stays
		 * reject-stubbed. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2",
			.cbs = {
				.cli_show = afi_safis_vpn_network_as2_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4",
			.cbs = {
				.cli_show = afi_safis_vpn_network_as4_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4",
			.cbs = {
				.cli_show = afi_safis_vpn_network_ipv4_cli_write,
			}
		},
		/* M7: default-on 'bgp retain route-target all'; only the 'no'
		 * form ever renders. */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/retain-route-target-all",
			.cbs = {
				.cli_show = afi_safis_retain_route_target_all_cli_write,
			}
		},
		/* M5 B13: instance-AF 'distance bgp ...' + per-prefix
		 * 'distance (1-255) PREFIX [ACCESSLIST]', all eight instance
		 * AFs that 'uses' af-distance-ipv4/-ipv6 (ipv4/ipv6 x
		 * unicast/multicast/labeled-unicast/vpn). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		/* M5 B14: instance-AF 'nexthop prefer-global', ipv6-unicast
		 * only (proteus-bgp.yang models the leaf under ipv6-unicast
		 * alone, even though the legacy DEFUN is also installed on
		 * BGP_IPV6M_NODE/BGP_IPV6L_NODE -- those two stay native). */
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/nexthop-prefer-global",
			.cbs = {
				.cli_show = afi_safis_ipv6_unicast_nexthop_prefer_global_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance",
			.cbs = {
				.cli_show = afi_safis_distance_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/prefix",
			.cbs = {
				.cli_show = afi_safis_distance_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/router-id",
			.cbs = {
				.cli_show = instance_router_id_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/log-neighbor-changes",
			.cbs = {
				.cli_show = instance_log_neighbor_changes_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/write-quanta",
			.cbs = {
				.cli_show = instance_write_quanta_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/read-quanta",
			.cbs = {
				.cli_show = instance_read_quanta_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/coalesce-time",
			.cbs = {
				.cli_show = instance_coalesce_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers",
			.cbs = {
				.cli_show = instance_timers_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/minimum-holdtime",
			.cbs = {
				.cli_show = instance_timers_minimum_holdtime_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/conditional-advertisement",
			.cbs = {
				.cli_show = instance_timers_conditional_advertisement_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/default-originate",
			.cbs = {
				.cli_show = instance_timers_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/cluster-id",
			.cbs = {
				.cli_show = instance_cluster_id_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/fast-external-failover",
			.cbs = {
				.cli_show = instance_fast_external_failover_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ipv6-auto-ra",
			.cbs = {
				.cli_show = instance_ipv6_auto_ra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-fib-pending",
			.cbs = {
				.cli_show = instance_suppress_fib_pending_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/update-delay",
			.cbs = {
				.cli_show = instance_update_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/advertisement-delay",
			.cbs = {
				.cli_show = instance_advertisement_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-shutdown",
			.cbs = {
				.cli_show = instance_graceful_shutdown_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/always-compare-med",
			.cbs = {
				.cli_show = instance_always_compare_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/labeled-unicast-explicit-null",
			.cbs = {
				.cli_show = instance_labeled_unicast_explicit_null_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/reject-as-sets",
			.cbs = {
				.cli_show = instance_reject_as_sets_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/client-to-client-reflection",
			.cbs = {
				.cli_show = instance_client_to_client_reflection_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/disable-ebgp-connected-route-check",
			.cbs = {
				.cli_show = instance_disable_ebgp_connected_route_check_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-ignore",
			.cbs = {
				.cli_show = instance_bestpath_as_path_ignore_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-confed",
			.cbs = {
				.cli_show = instance_bestpath_as_path_confed_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-multipath-relax",
			.cbs = {
				.cli_show = instance_bestpath_as_path_multipath_relax_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/compare-routerid",
			.cbs = {
				.cli_show = instance_bestpath_compare_routerid_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/use-imported-attributes",
			.cbs = {
				.cli_show = instance_bestpath_use_imported_attributes_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/med",
			.cbs = {
				.cli_show = instance_bestpath_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/peer-type-multipath-relax",
			.cbs = {
				.cli_show = instance_bestpath_peer_type_multipath_relax_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/bandwidth",
			.cbs = {
				.cli_show = instance_bestpath_bandwidth_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-unicast",
			.cbs = {
				.cli_show = instance_default_ipv4_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-multicast",
			.cbs = {
				.cli_show = instance_default_ipv4_multicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-labeled-unicast",
			.cbs = {
				.cli_show = instance_default_ipv4_labeled_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-vpn",
			.cbs = {
				.cli_show = instance_default_ipv4_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-flowspec",
			.cbs = {
				.cli_show = instance_default_ipv4_flowspec_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-unicast",
			.cbs = {
				.cli_show = instance_default_ipv6_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-multicast",
			.cbs = {
				.cli_show = instance_default_ipv6_multicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-labeled-unicast",
			.cbs = {
				.cli_show = instance_default_ipv6_labeled_unicast_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-vpn",
			.cbs = {
				.cli_show = instance_default_ipv6_vpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-flowspec",
			.cbs = {
				.cli_show = instance_default_ipv6_flowspec_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/l2vpn-evpn",
			.cbs = {
				.cli_show = instance_default_l2vpn_evpn_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/local-preference",
			.cbs = {
				.cli_show = instance_default_local_preference_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/subgroup-pkt-queue-max",
			.cbs = {
				.cli_show = instance_default_subgroup_pkt_queue_max_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/on-startup",
			.cbs = {
				.cli_show = instance_max_med_on_startup_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/administrative",
			.cbs = {
				.cli_show = instance_max_med_administrative_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier",
			.cbs = {
				.cli_show = instance_confederation_identifier_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/peers",
			.cbs = {
				.cli_show = instance_confederation_peers_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/tcp-keepalive",
			.cbs = {
				.cli_show = instance_tcp_keepalive_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/long-lived-graceful-restart-stale-time",
			.cbs = {
				.cli_show = instance_long_lived_graceful_restart_stale_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/notification",
			.cbs = {
				.cli_show = instance_graceful_restart_notification_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/mode",
			.cbs = {
				.cli_show = instance_graceful_restart_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/preserve-fw-state",
			.cbs = {
				.cli_show = instance_graceful_restart_preserve_fw_state_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/restart-time",
			.cbs = {
				.cli_show = instance_graceful_restart_restart_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/stalepath-time",
			.cbs = {
				.cli_show = instance_graceful_restart_stalepath_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/select-defer-time",
			.cbs = {
				.cli_show = instance_graceful_restart_select_defer_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/rib-stale-time",
			.cbs = {
				.cli_show = instance_graceful_restart_rib_stale_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/disable-eor",
			.cbs = {
				.cli_show = instance_graceful_restart_disable_eor_cli_write,
			}
		},
		/* M7 B5: instance administrative shutdown; 'enabled' renders the
		 * whole 'bgp shutdown [message MSG...]' line (the 'message' leaf
		 * has no cli_show of its own). */
		{
			.xpath = "/proteus-bgp:instance/administrative-shutdown/enabled",
			.cbs = {
				.cli_show = instance_administrative_shutdown_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/allow-martian-nexthop",
			.cbs = {
				.cli_show = instance_allow_martian_nexthop_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/use-underlays-nexthop-weight",
			.cbs = {
				.cli_show = instance_use_underlays_nexthop_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/fast-convergence",
			.cbs = {
				.cli_show = instance_fast_convergence_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ebgp-requires-policy",
			.cbs = {
				.cli_show = instance_ebgp_requires_policy_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/enforce-first-as",
			.cbs = {
				.cli_show = instance_enforce_first_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-duplicates",
			.cbs = {
				.cli_show = instance_suppress_duplicates_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/hard-administrative-reset",
			.cbs = {
				.cli_show = instance_hard_administrative_reset_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/deterministic-med",
			.cbs = {
				.cli_show = instance_deterministic_med_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/network-import-check",
			.cbs = {
				.cli_show = instance_network_import_check_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/aigp",
			.cbs = {
				.cli_show = instance_bestpath_aigp_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-hostname",
			.cbs = {
				.cli_show = instance_default_show_hostname_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-nexthop-hostname",
			.cbs = {
				.cli_show = instance_default_show_nexthop_hostname_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/software-version-capability",
			.cbs = {
				.cli_show = instance_default_software_version_capability_cli_write,
			}
		},
		{
			.xpath =
				"/proteus-bgp:instance/default/software-version-capability-latest-encoding",
			.cbs = {
				.cli_show =
					instance_default_software_version_capability_latest_encoding_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/link-local-capability",
			.cbs = {
				.cli_show = instance_default_link_local_capability_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/dynamic-capability",
			.cbs = {
				.cli_show = instance_default_dynamic_capability_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/route-reflector-allow-outbound-policy",
			.cbs = {
				.cli_show = instance_route_reflector_allow_outbound_policy_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/route-map-delay-timer",
			.cbs = {
				.cli_show = process_route_map_delay_timer_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/session-dscp",
			.cbs = {
				.cli_show = process_session_dscp_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/input-queue-limit",
			.cbs = {
				.cli_show = process_input_queue_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/output-queue-limit",
			.cbs = {
				.cli_show = process_output_queue_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/no-rib",
			.cbs = {
				.cli_show = process_no_rib_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/send-extra-data-zebra",
			.cbs = {
				.cli_show = process_send_extra_data_zebra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/ipv6-auto-ra",
			.cbs = {
				.cli_show = process_ipv6_auto_ra_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/suppress-fib-pending",
			.cbs = {
				.cli_show = process_suppress_fib_pending_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/update-delay",
			.cbs = {
				.cli_show = process_update_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/advertisement-delay",
			.cbs = {
				.cli_show = process_advertisement_delay_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-shutdown",
			.cbs = {
				.cli_show = process_graceful_shutdown_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/mode",
			.cbs = {
				.cli_show = process_graceful_restart_mode_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/preserve-fw-state",
			.cbs = {
				.cli_show = process_graceful_restart_preserve_fw_state_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/restart-time",
			.cbs = {
				.cli_show = process_graceful_restart_restart_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/stalepath-time",
			.cbs = {
				.cli_show = process_graceful_restart_stalepath_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/select-defer-time",
			.cbs = {
				.cli_show = process_graceful_restart_select_defer_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/rib-stale-time",
			.cbs = {
				.cli_show = process_graceful_restart_rib_stale_time_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group",
			.cbs = {
				.cli_show = peer_group_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/listen-range",
			.cbs = {
				.cli_show = peer_group_listen_range_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor",
			.cbs = {
				.cli_show = neighbor_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/listen-limit",
			.cbs = {
				.cli_show = instance_listen_limit_cli_write,
			}
		},
		/* M5 B1: per-AF activate for neighbor and peer-group. The
		 * shared afi_safi_cli_write() header/trailer (M5 B0) opens the
		 * address-family block around the converted activate leaf. */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn",
			.cbs = {
				.cli_show = afi_safi_cli_write,
				.cli_show_end = afi_safi_cli_write_end,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/activate",
			.cbs = {
				.cli_show = neighbor_af_activate_cli_write,
			}
		},
		/* M5 B2: per-AF policy attachments (route-map/prefix-list/filter-list/
		 * distribute-list in|out, unsuppress-map) for neighbor and peer-group. */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		/* M5 batch B3: per-AF conditional-advertisement + site-of-origin
		 * (neighbor). */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		/* M5 batch B4: per-AF plain PEER_FLAG_* booleans (neighbor scope). */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/route-map-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/route-map-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/prefix-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/prefix-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/filter-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/filter-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/distribute-list-in",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/distribute-list-out",
			.cbs = {
				.cli_show = neighbor_af_filter_dir_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/unsuppress-map",
			.cbs = {
				.cli_show = neighbor_af_unsuppress_map_cli_write,
			}
		},
		/* M5 batch B3: per-AF conditional-advertisement + site-of-origin
		 * (peer-group). */
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.cli_show = neighbor_af_advertise_map_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as2/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/ipv4/local-admin",
			.cbs = {
				.cli_show = neighbor_af_soo_cli_write,
			}
		},
		/* M5 batch B4: per-AF plain PEER_FLAG_* booleans (peer-group scope). */
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/route-reflector-client",
			.cbs = {
				.cli_show = neighbor_af_route_reflector_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/route-server-client",
			.cbs = {
				.cli_show = neighbor_af_route_server_client_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/as-override",
			.cbs = {
				.cli_show = neighbor_af_as_override_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/next-hop-self/enabled",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_enabled_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/next-hop-self/force",
			.cbs = {
				.cli_show = neighbor_af_next_hop_self_force_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/nexthop-local-unchanged",
			.cbs = {
				.cli_show = neighbor_af_nexthop_local_unchanged_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soft-reconfiguration-inbound",
			.cbs = {
				.cli_show = neighbor_af_soft_reconfiguration_inbound_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/accept-own",
			.cbs = {
				.cli_show = neighbor_af_accept_own_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/attribute-unchanged",
			.cbs = {
				.cli_show = neighbor_af_attribute_unchanged_cli_write,
			}
		},
		/* M5 batch B5: per-AF send-community + remove-private-as + capability
		 * orf prefix-list (neighbor scope). */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		/* M5 batch B5: per-AF send-community + remove-private-as + capability
		 * orf prefix-list (peer-group scope). */
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/orf-prefix-list",
			.cbs = {
				.cli_show = neighbor_af_orf_prefix_list_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/remove-private-as",
			.cbs = {
				.cli_show = neighbor_af_remove_private_as_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/send-community",
			.cbs = {
				.cli_show = neighbor_af_send_community_cli_write,
			}
		},
		/* M5 batch B6: per-AF default-originate + maximum-prefix (+opts) +
		 * maximum-prefix-out + allowas-in + weight (neighbor scope). */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		/* M5 batch B6 (peer-group scope). */
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/default-originate",
			.cbs = {
				.cli_show = neighbor_af_default_originate_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix-out",
			.cbs = {
				.cli_show = neighbor_af_maximum_prefix_out_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/allowas-in",
			.cbs = {
				.cli_show = neighbor_af_allowas_in_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/weight",
			.cbs = {
				.cli_show = neighbor_af_weight_cli_write,
			}
		},
		/* M5 batch B7: per-AF addpath tx/tx-best-selected/disable-rx/
		 * rx-paths-limit emitters (neighbor scope). */
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		/* M5 batch B7 (peer-group scope). */
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath",
			.cbs = {
				.cli_show = neighbor_af_addpath_tx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/disable-rx",
			.cbs = {
				.cli_show = neighbor_af_addpath_disable_rx_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/rx-paths-limit",
			.cbs = {
				.cli_show = neighbor_af_addpath_rx_paths_limit_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening",
			.cbs = {
				.cli_show = neighbor_af_dampening_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};


void bgp_cli_init(void)
{
	bgp_cli_instance_init();
	bgp_cli_process_init();
	bgp_cli_neighbor_init();
	bgp_cli_interface_init();
	bgp_cli_filter_init();
}
