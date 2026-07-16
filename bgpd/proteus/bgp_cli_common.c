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
			.xpath = "/proteus-bgp:instance/neighbor",
			.cbs = {
				.cli_show = neighbor_cli_write,
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
