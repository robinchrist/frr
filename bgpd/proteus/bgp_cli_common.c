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
}
