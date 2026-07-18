// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp northbound callback dispatch table (frr_yang_module_info).
 * The callbacks themselves live in bgpd/proteus/bgp_nb_*.c.
 */
#include <zebra.h>

#include "lib/northbound.h"

#include "bgpd/bgp_nb.h"

const struct frr_yang_module_info proteus_bgp_nb_info = {
	.name = "proteus-bgp",
	.nodes = {
		{
			.xpath = "/proteus-bgp:process/route-map-delay-timer",
			.cbs = {
				.modify = process_route_map_delay_timer_modify,
				.destroy = process_route_map_delay_timer_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/update-delay/delay",
			.cbs = {
				.modify = process_update_delay_delay_modify,
				.destroy = process_update_delay_delay_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/update-delay/establish-wait",
			.cbs = {
				.modify = process_update_delay_establish_wait_modify,
				.destroy = process_update_delay_establish_wait_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/advertisement-delay",
			.cbs = {
				.modify = process_advertisement_delay_modify,
				.destroy = process_advertisement_delay_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/suppress-fib-pending/enabled",
			.cbs = {
				.modify = process_suppress_fib_pending_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/suppress-fib-pending/advertisement-delay",
			.cbs = {
				.modify = process_suppress_fib_pending_advertisement_delay_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/mode",
			.cbs = {
				.modify = process_graceful_restart_mode_modify,
				.destroy = process_graceful_restart_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/preserve-fw-state",
			.cbs = {
				.modify = process_graceful_restart_preserve_fw_state_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/restart-time",
			.cbs = {
				.modify = process_graceful_restart_restart_time_modify,
				.destroy = process_graceful_restart_restart_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/stalepath-time",
			.cbs = {
				.modify = process_graceful_restart_stalepath_time_modify,
				.destroy = process_graceful_restart_stalepath_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/select-defer-time",
			.cbs = {
				.modify = process_graceful_restart_select_defer_time_modify,
				.destroy = process_graceful_restart_select_defer_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = process_graceful_restart_rib_stale_time_modify,
				.destroy = process_graceful_restart_rib_stale_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/graceful-shutdown",
			.cbs = {
				.modify = process_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/no-rib",
			.cbs = {
				.modify = process_no_rib_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/send-extra-data-zebra",
			.cbs = {
				.modify = process_send_extra_data_zebra_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/ipv6-auto-ra",
			.cbs = {
				.modify = process_ipv6_auto_ra_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:process/session-dscp",
			.cbs = {
				.modify = process_session_dscp_modify,
				.destroy = process_session_dscp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/input-queue-limit",
			.cbs = {
				.modify = process_input_queue_limit_modify,
				.destroy = process_input_queue_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:process/output-queue-limit",
			.cbs = {
				.modify = process_output_queue_limit_modify,
				.destroy = process_output_queue_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance",
			.cbs = {
				.create = instance_create,
				.destroy = instance_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/instance-type",
			.cbs = {
				.modify = instance_instance_type_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/autonomous-system/plain",
			.cbs = {
				.modify = instance_autonomous_system_plain_modify,
				.destroy = instance_autonomous_system_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/autonomous-system/asdot",
			.cbs = {
				.create = instance_autonomous_system_asdot_create,
				.destroy = instance_autonomous_system_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/autonomous-system/asdot/high",
			.cbs = {
				.modify = instance_autonomous_system_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/autonomous-system/asdot/low",
			.cbs = {
				.modify = instance_autonomous_system_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/as-notation",
			.cbs = {
				.modify = instance_as_notation_modify,
				.destroy = instance_as_notation_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/router-id",
			.cbs = {
				.modify = instance_router_id_modify,
				.destroy = instance_router_id_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/cluster-id",
			.cbs = {
				.modify = instance_cluster_id_modify,
				.destroy = instance_cluster_id_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/fast-external-failover",
			.cbs = {
				.modify = instance_fast_external_failover_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ipv6-auto-ra",
			.cbs = {
				.modify = instance_ipv6_auto_ra_modify,
				.destroy = instance_ipv6_auto_ra_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-fib-pending/enabled",
			.cbs = {
				.modify = instance_suppress_fib_pending_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-fib-pending/advertisement-delay",
			.cbs = {
				.modify = instance_suppress_fib_pending_advertisement_delay_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/log-neighbor-changes",
			.cbs = {
				.modify = instance_log_neighbor_changes_modify,
				.destroy = instance_log_neighbor_changes_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/always-compare-med",
			.cbs = {
				.modify = instance_always_compare_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/ebgp-requires-policy",
			.cbs = {
				.modify = instance_ebgp_requires_policy_modify,
				.destroy = instance_ebgp_requires_policy_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/enforce-first-as",
			.cbs = {
				.modify = instance_enforce_first_as_modify,
				.destroy = instance_enforce_first_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/labeled-unicast-explicit-null",
			.cbs = {
				.modify = instance_labeled_unicast_explicit_null_modify,
				.destroy = instance_labeled_unicast_explicit_null_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/reject-as-sets",
			.cbs = {
				.modify = instance_reject_as_sets_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/suppress-duplicates",
			.cbs = {
				.modify = instance_suppress_duplicates_modify,
				.destroy = instance_suppress_duplicates_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/hard-administrative-reset",
			.cbs = {
				.modify = instance_hard_administrative_reset_modify,
				.destroy = instance_hard_administrative_reset_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-unicast",
			.cbs = {
				.modify = instance_default_ipv4_unicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-multicast",
			.cbs = {
				.modify = instance_default_ipv4_multicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-labeled-unicast",
			.cbs = {
				.modify = instance_default_ipv4_labeled_unicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-vpn",
			.cbs = {
				.modify = instance_default_ipv4_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv4-flowspec",
			.cbs = {
				.modify = instance_default_ipv4_flowspec_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-unicast",
			.cbs = {
				.modify = instance_default_ipv6_unicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-multicast",
			.cbs = {
				.modify = instance_default_ipv6_multicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-labeled-unicast",
			.cbs = {
				.modify = instance_default_ipv6_labeled_unicast_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-vpn",
			.cbs = {
				.modify = instance_default_ipv6_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/ipv6-flowspec",
			.cbs = {
				.modify = instance_default_ipv6_flowspec_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/l2vpn-evpn",
			.cbs = {
				.modify = instance_default_l2vpn_evpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/local-preference",
			.cbs = {
				.modify = instance_default_local_preference_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-hostname",
			.cbs = {
				.modify = instance_default_show_hostname_modify,
				.destroy = instance_default_show_hostname_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/show-nexthop-hostname",
			.cbs = {
				.modify = instance_default_show_nexthop_hostname_modify,
				.destroy = instance_default_show_nexthop_hostname_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/software-version-capability",
			.cbs = {
				.modify = instance_default_software_version_capability_modify,
				.destroy = instance_default_software_version_capability_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/software-version-capability-latest-encoding",
			.cbs = {
				.modify = instance_default_software_version_capability_latest_encoding_modify,
				.destroy = instance_default_software_version_capability_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/link-local-capability",
			.cbs = {
				.modify = instance_default_link_local_capability_modify,
				.destroy = instance_default_link_local_capability_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/dynamic-capability",
			.cbs = {
				.modify = instance_default_dynamic_capability_modify,
				.destroy = instance_default_dynamic_capability_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/subgroup-pkt-queue-max",
			.cbs = {
				.modify = instance_default_subgroup_pkt_queue_max_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/default/shutdown",
			.cbs = {
				.modify = instance_default_shutdown_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/client-to-client-reflection",
			.cbs = {
				.modify = instance_client_to_client_reflection_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/disable-ebgp-connected-route-check",
			.cbs = {
				.modify = instance_disable_ebgp_connected_route_check_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier/plain",
			.cbs = {
				.modify = instance_confederation_identifier_plain_modify,
				.destroy = instance_confederation_identifier_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier/asdot",
			.cbs = {
				.create = instance_confederation_identifier_asdot_create,
				.destroy = instance_confederation_identifier_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier/asdot/high",
			.cbs = {
				.modify = instance_confederation_identifier_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/identifier/asdot/low",
			.cbs = {
				.modify = instance_confederation_identifier_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/peers/plain",
			.cbs = {
				.create = instance_confederation_peers_plain_create,
				.destroy = instance_confederation_peers_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/confederation/peers/asdot",
			.cbs = {
				.create = instance_confederation_peers_asdot_create,
				.destroy = instance_confederation_peers_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/deterministic-med",
			.cbs = {
				.modify = instance_deterministic_med_modify,
				.destroy = instance_deterministic_med_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/update-delay/delay",
			.cbs = {
				.modify = instance_update_delay_delay_modify,
				.destroy = instance_update_delay_delay_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/update-delay/establish-wait",
			.cbs = {
				.modify = instance_update_delay_establish_wait_modify,
				.destroy = instance_update_delay_establish_wait_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/advertisement-delay",
			.cbs = {
				.modify = instance_advertisement_delay_modify,
				.destroy = instance_advertisement_delay_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/on-startup/period",
			.cbs = {
				.modify = instance_max_med_on_startup_period_modify,
				.destroy = instance_max_med_on_startup_period_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/on-startup/med",
			.cbs = {
				.modify = instance_max_med_on_startup_med_modify,
				.destroy = instance_max_med_on_startup_med_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/administrative/enabled",
			.cbs = {
				.modify = instance_max_med_administrative_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/max-med/administrative/med",
			.cbs = {
				.modify = instance_max_med_administrative_med_modify,
				.destroy = instance_max_med_administrative_med_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/write-quanta",
			.cbs = {
				.modify = instance_write_quanta_modify,
				.destroy = instance_write_quanta_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/read-quanta",
			.cbs = {
				.modify = instance_read_quanta_modify,
				.destroy = instance_read_quanta_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/coalesce-time",
			.cbs = {
				.modify = instance_coalesce_time_modify,
				.destroy = instance_coalesce_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-shutdown",
			.cbs = {
				.modify = instance_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/long-lived-graceful-restart-stale-time",
			.cbs = {
				.modify = instance_long_lived_graceful_restart_stale_time_modify,
				.destroy = instance_long_lived_graceful_restart_stale_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/mode",
			.cbs = {
				.modify = instance_graceful_restart_mode_modify,
				.destroy = instance_graceful_restart_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/notification",
			.cbs = {
				.modify = instance_graceful_restart_notification_modify,
				.destroy = instance_graceful_restart_notification_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/preserve-fw-state",
			.cbs = {
				.modify = instance_graceful_restart_preserve_fw_state_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/restart-time",
			.cbs = {
				.modify = instance_graceful_restart_restart_time_modify,
				.destroy = instance_graceful_restart_restart_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/stalepath-time",
			.cbs = {
				.modify = instance_graceful_restart_stalepath_time_modify,
				.destroy = instance_graceful_restart_stalepath_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/select-defer-time",
			.cbs = {
				.modify = instance_graceful_restart_select_defer_time_modify,
				.destroy = instance_graceful_restart_select_defer_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/rib-stale-time",
			.cbs = {
				.modify = instance_graceful_restart_rib_stale_time_modify,
				.destroy = instance_graceful_restart_rib_stale_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/graceful-restart/disable-eor",
			.cbs = {
				.modify = instance_graceful_restart_disable_eor_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/tcp-keepalive/idle",
			.cbs = {
				.modify = instance_tcp_keepalive_idle_modify,
				.destroy = instance_tcp_keepalive_idle_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/tcp-keepalive/interval",
			.cbs = {
				.modify = instance_tcp_keepalive_interval_modify,
				.destroy = instance_tcp_keepalive_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/tcp-keepalive/probes",
			.cbs = {
				.modify = instance_tcp_keepalive_probes_modify,
				.destroy = instance_tcp_keepalive_probes_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-ignore",
			.cbs = {
				.modify = instance_bestpath_as_path_ignore_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-confed",
			.cbs = {
				.modify = instance_bestpath_as_path_confed_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-multipath-relax/enabled",
			.cbs = {
				.modify = instance_bestpath_as_path_multipath_relax_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/as-path-multipath-relax/as-set",
			.cbs = {
				.modify = instance_bestpath_as_path_multipath_relax_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/compare-routerid",
			.cbs = {
				.modify = instance_bestpath_compare_routerid_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/use-imported-attributes",
			.cbs = {
				.modify = instance_bestpath_use_imported_attributes_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/aigp",
			.cbs = {
				.modify = instance_bestpath_aigp_modify,
				.destroy = instance_bestpath_aigp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/med/confed",
			.cbs = {
				.modify = instance_bestpath_med_confed_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/med/missing-as-worst",
			.cbs = {
				.modify = instance_bestpath_med_missing_as_worst_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/peer-type-multipath-relax",
			.cbs = {
				.modify = instance_bestpath_peer_type_multipath_relax_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/bestpath/bandwidth",
			.cbs = {
				.modify = instance_bestpath_bandwidth_modify,
				.destroy = instance_bestpath_bandwidth_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/route-reflector-allow-outbound-policy",
			.cbs = {
				.modify = instance_route_reflector_allow_outbound_policy_modify,
				.destroy = instance_route_reflector_allow_outbound_policy_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/network-import-check",
			.cbs = {
				.modify = instance_network_import_check_modify,
				.destroy = instance_network_import_check_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/keepalive",
			.cbs = {
				.modify = instance_timers_keepalive_modify,
				.destroy = instance_timers_keepalive_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/holdtime",
			.cbs = {
				.modify = instance_timers_holdtime_modify,
				.destroy = instance_timers_holdtime_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/minimum-holdtime",
			.cbs = {
				.modify = instance_timers_minimum_holdtime_modify,
				.destroy = instance_timers_minimum_holdtime_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/conditional-advertisement",
			.cbs = {
				.modify = instance_timers_conditional_advertisement_modify,
				.destroy = instance_timers_conditional_advertisement_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/timers/default-originate",
			.cbs = {
				.modify = instance_timers_default_originate_modify,
				.destroy = instance_timers_default_originate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group",
			.cbs = {
				.create = instance_peer_group_create,
				.destroy = instance_peer_group_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/remote-as/plain",
			.cbs = {
				.modify = instance_peer_group_remote_as_plain_modify,
				.destroy = instance_peer_group_remote_as_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/remote-as/asdot",
			.cbs = {
				.create = instance_peer_group_remote_as_asdot_create,
				.destroy = instance_peer_group_remote_as_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/remote-as/asdot/high",
			.cbs = {
				.modify = instance_peer_group_remote_as_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/remote-as/asdot/low",
			.cbs = {
				.modify = instance_peer_group_remote_as_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/remote-as/type",
			.cbs = {
				.modify = instance_peer_group_remote_as_type_modify,
				.destroy = instance_peer_group_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/plain",
			.cbs = {
				.modify = instance_peer_group_local_as_plain_modify,
				.destroy = instance_peer_group_local_as_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/asdot",
			.cbs = {
				.create = instance_peer_group_local_as_asdot_create,
				.destroy = instance_peer_group_local_as_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/asdot/high",
			.cbs = {
				.modify = instance_peer_group_local_as_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/asdot/low",
			.cbs = {
				.modify = instance_peer_group_local_as_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/no-prepend",
			.cbs = {
				.modify = instance_peer_group_local_as_no_prepend_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/replace-as",
			.cbs = {
				.modify = instance_peer_group_local_as_replace_as_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-as/dual-as",
			.cbs = {
				.modify = instance_peer_group_local_as_dual_as_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/description",
			.cbs = {
				.modify = instance_peer_group_description_modify,
				.destroy = instance_peer_group_description_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/administrative-shutdown/enabled",
			.cbs = {
				.modify = instance_peer_group_administrative_shutdown_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/administrative-shutdown/message",
			.cbs = {
				.modify = instance_peer_group_administrative_shutdown_message_modify,
				.destroy = instance_peer_group_administrative_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/administrative-shutdown/rtt/threshold",
			.cbs = {
				.modify = instance_peer_group_administrative_shutdown_rtt_threshold_modify,
				.destroy = instance_peer_group_administrative_shutdown_rtt_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/administrative-shutdown/rtt/count",
			.cbs = {
				.modify = instance_peer_group_administrative_shutdown_rtt_count_modify,
				.destroy = instance_peer_group_administrative_shutdown_rtt_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/enabled",
			.cbs = {
				.modify = instance_peer_group_bfd_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/detect-multiplier",
			.cbs = {
				.modify = instance_peer_group_bfd_detect_multiplier_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/min-rx",
			.cbs = {
				.modify = instance_peer_group_bfd_min_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/min-tx",
			.cbs = {
				.modify = instance_peer_group_bfd_min_tx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/check-control-plane-failure",
			.cbs = {
				.modify = instance_peer_group_bfd_check_control_plane_failure_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/profile",
			.cbs = {
				.modify = instance_peer_group_bfd_profile_modify,
				.destroy = instance_peer_group_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/strict",
			.cbs = {
				.modify = instance_peer_group_bfd_strict_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/bfd/strict-hold-time",
			.cbs = {
				.modify = instance_peer_group_bfd_strict_hold_time_modify,
				.destroy = instance_peer_group_bfd_strict_hold_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/password",
			.cbs = {
				.modify = instance_peer_group_password_modify,
				.destroy = instance_peer_group_password_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/solo",
			.cbs = {
				.modify = instance_peer_group_solo_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/port",
			.cbs = {
				.modify = instance_peer_group_port_modify,
				.destroy = instance_peer_group_port_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/source-interface",
			.cbs = {
				.modify = instance_peer_group_source_interface_modify,
				.destroy = instance_peer_group_source_interface_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/tcp-mss",
			.cbs = {
				.modify = instance_peer_group_tcp_mss_modify,
				.destroy = instance_peer_group_tcp_mss_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/passive",
			.cbs = {
				.modify = instance_peer_group_passive_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/ebgp-multihop",
			.cbs = {
				.modify = instance_peer_group_ebgp_multihop_modify,
				.destroy = instance_peer_group_ebgp_multihop_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/aigp",
			.cbs = {
				.modify = instance_peer_group_aigp_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/graceful-shutdown",
			.cbs = {
				.modify = instance_peer_group_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-role/role",
			.cbs = {
				.modify = instance_peer_group_local_role_role_modify,
				.destroy = instance_peer_group_local_role_role_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/local-role/strict-mode",
			.cbs = {
				.modify = instance_peer_group_local_role_strict_mode_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/oad",
			.cbs = {
				.modify = instance_peer_group_oad_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/ttl-security-hops",
			.cbs = {
				.modify = instance_peer_group_ttl_security_hops_modify,
				.destroy = instance_peer_group_ttl_security_hops_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/disable-connected-check",
			.cbs = {
				.modify = instance_peer_group_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/enforce-first-as",
			.cbs = {
				.modify = instance_peer_group_enforce_first_as_modify,
				.destroy = instance_peer_group_enforce_first_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/update-source",
			.cbs = {
				.modify = instance_peer_group_update_source_modify,
				.destroy = instance_peer_group_update_source_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/ip-transparent",
			.cbs = {
				.modify = instance_peer_group_ip_transparent_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/advertisement-interval",
			.cbs = {
				.modify = instance_peer_group_advertisement_interval_modify,
				.destroy = instance_peer_group_advertisement_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/timers/keepalive",
			.cbs = {
				.modify = instance_peer_group_timers_keepalive_modify,
				.destroy = instance_peer_group_timers_keepalive_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/timers/holdtime",
			.cbs = {
				.modify = instance_peer_group_timers_holdtime_modify,
				.destroy = instance_peer_group_timers_holdtime_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/timers/connect",
			.cbs = {
				.modify = instance_peer_group_timers_connect_modify,
				.destroy = instance_peer_group_timers_connect_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/timers/delayopen",
			.cbs = {
				.modify = instance_peer_group_timers_delayopen_modify,
				.destroy = instance_peer_group_timers_delayopen_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/dynamic",
			.cbs = {
				.modify = instance_peer_group_capabilities_dynamic_modify,
				.destroy = instance_peer_group_capabilities_dynamic_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/extended-nexthop",
			.cbs = {
				.modify = instance_peer_group_capabilities_extended_nexthop_modify,
				.destroy = instance_peer_group_capabilities_extended_nexthop_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/software-version",
			.cbs = {
				.modify = instance_peer_group_capabilities_software_version_modify,
				.destroy = instance_peer_group_capabilities_software_version_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/software-version-latest-encoding",
			.cbs = {
				.modify = instance_peer_group_capabilities_software_version_latest_encoding_modify,
				.destroy = instance_peer_group_capabilities_software_version_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/link-local",
			.cbs = {
				.modify = instance_peer_group_capabilities_link_local_modify,
				.destroy = instance_peer_group_capabilities_link_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/fqdn",
			.cbs = {
				.modify = instance_peer_group_capabilities_fqdn_modify,
				.destroy = instance_peer_group_capabilities_fqdn_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/dont-capability-negotiate",
			.cbs = {
				.modify = instance_peer_group_capabilities_dont_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/override-capability",
			.cbs = {
				.modify = instance_peer_group_capabilities_override_capability_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/capabilities/strict-capability-match",
			.cbs = {
				.modify = instance_peer_group_capabilities_strict_capability_match_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/rpki-strict",
			.cbs = {
				.modify = instance_peer_group_rpki_strict_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/sender-as-path-loop-detection",
			.cbs = {
				.modify = instance_peer_group_sender_as_path_loop_detection_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/path-attribute-discard",
			.cbs = {
				.create = instance_peer_group_path_attribute_discard_create,
				.destroy = instance_peer_group_path_attribute_discard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/path-attribute-treat-as-withdraw",
			.cbs = {
				.create = instance_peer_group_path_attribute_treat_as_withdraw_create,
				.destroy = instance_peer_group_path_attribute_treat_as_withdraw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/graceful-restart-mode",
			.cbs = {
				.modify = instance_peer_group_graceful_restart_mode_modify,
				.destroy = instance_peer_group_graceful_restart_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/send-nexthop-characteristics",
			.cbs = {
				.modify = instance_peer_group_send_nexthop_characteristics_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = instance_peer_group_disable_link_bw_encoding_ieee_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/extended-link-bandwidth",
			.cbs = {
				.modify = instance_peer_group_extended_link_bandwidth_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/extended-optional-parameters",
			.cbs = {
				.modify = instance_peer_group_extended_optional_parameters_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/listen-range",
			.cbs = {
				.create = instance_peer_group_listen_range_create,
				.destroy = instance_peer_group_listen_range_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_unicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_unicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_unicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_unicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_multicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_multicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_multicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_multicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_vpn_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_vpn_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_vpn_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv4_vpn_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_unicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_unicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_unicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_unicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_multicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_multicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_multicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_multicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_activate_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_vpn_soo_create,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_vpn_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_vpn_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_ipv6_vpn_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_weight_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/activate",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_activate_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/tx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_addpath_tx_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_addpath_tx_best_selected_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_addpath_rx_paths_limit_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/orf-prefix-list",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_orf_prefix_list_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/route-reflector-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/next-hop-self/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/remove-private-as",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_remove_private_as_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/as-override",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/send-community/standard",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_send_community_standard_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/send-community/extended",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_send_community_extended_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/send-community/large",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_send_community_large_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/default-originate/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/default-originate/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_default_originate_route_map_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_count_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_threshold_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_out_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/route-server-client",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/allowas-in/count",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_count_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/allowas-in/origin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_route_map_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/accept-own",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo",
			.cbs = {
				.create = instance_peer_group_afi_safis_l2vpn_evpn_soo_create,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as2",
			.cbs = {
				.create = instance_peer_group_afi_safis_l2vpn_evpn_soo_as2_create,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as4",
			.cbs = {
				.create = instance_peer_group_afi_safis_l2vpn_evpn_soo_as4_create,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/ipv4",
			.cbs = {
				.create = instance_peer_group_afi_safis_l2vpn_evpn_soo_ipv4_create,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/weight",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_weight_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening/enabled",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening/half-life",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_dampening_half_life_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_dampening_reuse_threshold_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_dampening_suppress_threshold_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_dampening_max_suppress_time_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_distribute_list_in_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_distribute_list_out_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_prefix_list_in_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_prefix_list_out_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_filter_list_in_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_filter_list_out_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/route-map-in",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_route_map_in_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/route-map-out",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_route_map_out_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_unsuppress_map_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/peer-group/afi-safis/l2vpn-evpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_peer_group_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor",
			.cbs = {
				.create = instance_neighbor_create,
				.destroy = instance_neighbor_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/interface-peer",
			.cbs = {
				.modify = instance_neighbor_interface_peer_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/v6only",
			.cbs = {
				.modify = instance_neighbor_v6only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/peer-group",
			.cbs = {
				.modify = instance_neighbor_peer_group_modify,
				.destroy = instance_neighbor_peer_group_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/remote-as/plain",
			.cbs = {
				.modify = instance_neighbor_remote_as_plain_modify,
				.destroy = instance_neighbor_remote_as_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/remote-as/asdot",
			.cbs = {
				.create = instance_neighbor_remote_as_asdot_create,
				.destroy = instance_neighbor_remote_as_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/remote-as/asdot/high",
			.cbs = {
				.modify = instance_neighbor_remote_as_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/remote-as/asdot/low",
			.cbs = {
				.modify = instance_neighbor_remote_as_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/remote-as/type",
			.cbs = {
				.modify = instance_neighbor_remote_as_type_modify,
				.destroy = instance_neighbor_remote_as_type_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/plain",
			.cbs = {
				.modify = instance_neighbor_local_as_plain_modify,
				.destroy = instance_neighbor_local_as_plain_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/asdot",
			.cbs = {
				.create = instance_neighbor_local_as_asdot_create,
				.destroy = instance_neighbor_local_as_asdot_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/asdot/high",
			.cbs = {
				.modify = instance_neighbor_local_as_asdot_high_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/asdot/low",
			.cbs = {
				.modify = instance_neighbor_local_as_asdot_low_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/no-prepend",
			.cbs = {
				.modify = instance_neighbor_local_as_no_prepend_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/replace-as",
			.cbs = {
				.modify = instance_neighbor_local_as_replace_as_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-as/dual-as",
			.cbs = {
				.modify = instance_neighbor_local_as_dual_as_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/description",
			.cbs = {
				.modify = instance_neighbor_description_modify,
				.destroy = instance_neighbor_description_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/administrative-shutdown/enabled",
			.cbs = {
				.modify = instance_neighbor_administrative_shutdown_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/administrative-shutdown/message",
			.cbs = {
				.modify = instance_neighbor_administrative_shutdown_message_modify,
				.destroy = instance_neighbor_administrative_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/administrative-shutdown/rtt/threshold",
			.cbs = {
				.modify = instance_neighbor_administrative_shutdown_rtt_threshold_modify,
				.destroy = instance_neighbor_administrative_shutdown_rtt_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/administrative-shutdown/rtt/count",
			.cbs = {
				.modify = instance_neighbor_administrative_shutdown_rtt_count_modify,
				.destroy = instance_neighbor_administrative_shutdown_rtt_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/enabled",
			.cbs = {
				.modify = instance_neighbor_bfd_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/detect-multiplier",
			.cbs = {
				.modify = instance_neighbor_bfd_detect_multiplier_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/min-rx",
			.cbs = {
				.modify = instance_neighbor_bfd_min_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/min-tx",
			.cbs = {
				.modify = instance_neighbor_bfd_min_tx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/check-control-plane-failure",
			.cbs = {
				.modify = instance_neighbor_bfd_check_control_plane_failure_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/profile",
			.cbs = {
				.modify = instance_neighbor_bfd_profile_modify,
				.destroy = instance_neighbor_bfd_profile_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/strict",
			.cbs = {
				.modify = instance_neighbor_bfd_strict_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/bfd/strict-hold-time",
			.cbs = {
				.modify = instance_neighbor_bfd_strict_hold_time_modify,
				.destroy = instance_neighbor_bfd_strict_hold_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/password",
			.cbs = {
				.modify = instance_neighbor_password_modify,
				.destroy = instance_neighbor_password_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/solo",
			.cbs = {
				.modify = instance_neighbor_solo_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/port",
			.cbs = {
				.modify = instance_neighbor_port_modify,
				.destroy = instance_neighbor_port_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/source-interface",
			.cbs = {
				.modify = instance_neighbor_source_interface_modify,
				.destroy = instance_neighbor_source_interface_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/tcp-mss",
			.cbs = {
				.modify = instance_neighbor_tcp_mss_modify,
				.destroy = instance_neighbor_tcp_mss_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/passive",
			.cbs = {
				.modify = instance_neighbor_passive_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/ebgp-multihop",
			.cbs = {
				.modify = instance_neighbor_ebgp_multihop_modify,
				.destroy = instance_neighbor_ebgp_multihop_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/aigp",
			.cbs = {
				.modify = instance_neighbor_aigp_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/graceful-shutdown",
			.cbs = {
				.modify = instance_neighbor_graceful_shutdown_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-role/role",
			.cbs = {
				.modify = instance_neighbor_local_role_role_modify,
				.destroy = instance_neighbor_local_role_role_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/local-role/strict-mode",
			.cbs = {
				.modify = instance_neighbor_local_role_strict_mode_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/oad",
			.cbs = {
				.modify = instance_neighbor_oad_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/ttl-security-hops",
			.cbs = {
				.modify = instance_neighbor_ttl_security_hops_modify,
				.destroy = instance_neighbor_ttl_security_hops_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/disable-connected-check",
			.cbs = {
				.modify = instance_neighbor_disable_connected_check_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/enforce-first-as",
			.cbs = {
				.modify = instance_neighbor_enforce_first_as_modify,
				.destroy = instance_neighbor_enforce_first_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/update-source",
			.cbs = {
				.modify = instance_neighbor_update_source_modify,
				.destroy = instance_neighbor_update_source_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/ip-transparent",
			.cbs = {
				.modify = instance_neighbor_ip_transparent_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/advertisement-interval",
			.cbs = {
				.modify = instance_neighbor_advertisement_interval_modify,
				.destroy = instance_neighbor_advertisement_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/timers/keepalive",
			.cbs = {
				.modify = instance_neighbor_timers_keepalive_modify,
				.destroy = instance_neighbor_timers_keepalive_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/timers/holdtime",
			.cbs = {
				.modify = instance_neighbor_timers_holdtime_modify,
				.destroy = instance_neighbor_timers_holdtime_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/timers/connect",
			.cbs = {
				.modify = instance_neighbor_timers_connect_modify,
				.destroy = instance_neighbor_timers_connect_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/timers/delayopen",
			.cbs = {
				.modify = instance_neighbor_timers_delayopen_modify,
				.destroy = instance_neighbor_timers_delayopen_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/dynamic",
			.cbs = {
				.modify = instance_neighbor_capabilities_dynamic_modify,
				.destroy = instance_neighbor_capabilities_dynamic_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/extended-nexthop",
			.cbs = {
				.modify = instance_neighbor_capabilities_extended_nexthop_modify,
				.destroy = instance_neighbor_capabilities_extended_nexthop_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/software-version",
			.cbs = {
				.modify = instance_neighbor_capabilities_software_version_modify,
				.destroy = instance_neighbor_capabilities_software_version_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/software-version-latest-encoding",
			.cbs = {
				.modify = instance_neighbor_capabilities_software_version_latest_encoding_modify,
				.destroy = instance_neighbor_capabilities_software_version_latest_encoding_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/link-local",
			.cbs = {
				.modify = instance_neighbor_capabilities_link_local_modify,
				.destroy = instance_neighbor_capabilities_link_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/fqdn",
			.cbs = {
				.modify = instance_neighbor_capabilities_fqdn_modify,
				.destroy = instance_neighbor_capabilities_fqdn_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/dont-capability-negotiate",
			.cbs = {
				.modify = instance_neighbor_capabilities_dont_capability_negotiate_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/override-capability",
			.cbs = {
				.modify = instance_neighbor_capabilities_override_capability_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/capabilities/strict-capability-match",
			.cbs = {
				.modify = instance_neighbor_capabilities_strict_capability_match_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/rpki-strict",
			.cbs = {
				.modify = instance_neighbor_rpki_strict_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/sender-as-path-loop-detection",
			.cbs = {
				.modify = instance_neighbor_sender_as_path_loop_detection_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/path-attribute-discard",
			.cbs = {
				.create = instance_neighbor_path_attribute_discard_create,
				.destroy = instance_neighbor_path_attribute_discard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/path-attribute-treat-as-withdraw",
			.cbs = {
				.create = instance_neighbor_path_attribute_treat_as_withdraw_create,
				.destroy = instance_neighbor_path_attribute_treat_as_withdraw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/graceful-restart-mode",
			.cbs = {
				.modify = instance_neighbor_graceful_restart_mode_modify,
				.destroy = instance_neighbor_graceful_restart_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/send-nexthop-characteristics",
			.cbs = {
				.modify = instance_neighbor_send_nexthop_characteristics_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/disable-link-bw-encoding-ieee",
			.cbs = {
				.modify = instance_neighbor_disable_link_bw_encoding_ieee_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/extended-link-bandwidth",
			.cbs = {
				.modify = instance_neighbor_extended_link_bandwidth_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/extended-optional-parameters",
			.cbs = {
				.modify = instance_neighbor_extended_optional_parameters_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_unicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_unicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_unicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_unicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_multicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_multicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_multicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_multicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_multicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_labeled_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_vpn_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_vpn_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_vpn_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv4_vpn_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv4-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv4_vpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_unicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_unicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_unicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_multicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_multicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_multicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-multicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_multicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-labeled-unicast/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_labeled_unicast_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_activate_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_vpn_soo_create,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_vpn_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_vpn_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_weight_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/ipv6-vpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_ipv6_vpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/activate",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_activate_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_activate_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/tx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_addpath_tx_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_addpath_tx_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/tx-best-selected",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_addpath_tx_best_selected_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_addpath_tx_best_selected_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/disable-rx",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_addpath_disable_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/addpath/rx-paths-limit",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_addpath_rx_paths_limit_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_addpath_rx_paths_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/orf-prefix-list",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_orf_prefix_list_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_orf_prefix_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/route-reflector-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_route_reflector_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/next-hop-self/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_next_hop_self_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/next-hop-self/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_next_hop_self_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/remove-private-as",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_remove_private_as_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_remove_private_as_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/as-override",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_as_override_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/send-community/standard",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_send_community_standard_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_send_community_standard_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/send-community/extended",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_send_community_extended_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_send_community_extended_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/send-community/large",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_send_community_large_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_send_community_large_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/send-community/extended-rpki",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_send_community_extended_rpki_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/default-originate/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_default_originate_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/default-originate/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_default_originate_route_map_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_default_originate_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soft-reconfiguration-inbound",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soft_reconfiguration_inbound_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_count_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix/threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_threshold_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix/warning-only",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_warning_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix/restart-interval",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_restart_interval_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_restart_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix/force",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_force_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/maximum-prefix-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_out_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_maximum_prefix_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/route-server-client",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_route_server_client_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/nexthop-local-unchanged",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_nexthop_local_unchanged_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/allowas-in/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/allowas-in/count",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_count_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_count_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/allowas-in/origin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_origin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/allowas-in/route-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_route_map_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_allowas_in_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/accept-own",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_accept_own_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo",
			.cbs = {
				.create = instance_neighbor_afi_safis_l2vpn_evpn_soo_create,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as2",
			.cbs = {
				.create = instance_neighbor_afi_safis_l2vpn_evpn_soo_as2_create,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as2/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as2/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as4",
			.cbs = {
				.create = instance_neighbor_afi_safis_l2vpn_evpn_soo_as4_create,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/as4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/ipv4",
			.cbs = {
				.create = instance_neighbor_afi_safis_l2vpn_evpn_soo_ipv4_create,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/weight",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_weight_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_weight_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/attribute-unchanged/as-path",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_attribute_unchanged_as_path_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/attribute-unchanged/next-hop",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_attribute_unchanged_next_hop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/attribute-unchanged/med",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_attribute_unchanged_med_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening/enabled",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening/half-life",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_dampening_half_life_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_dampening_reuse_threshold_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_dampening_suppress_threshold_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_dampening_max_suppress_time_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/distribute-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_distribute_list_in_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_distribute_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/distribute-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_distribute_list_out_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_distribute_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/prefix-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_prefix_list_in_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_prefix_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/prefix-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_prefix_list_out_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_prefix_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/filter-list-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_filter_list_in_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_filter_list_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/filter-list-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_filter_list_out_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_filter_list_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/route-map-in",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_route_map_in_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_route_map_in_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/route-map-out",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_route_map_out_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_route_map_out_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/unsuppress-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_unsuppress_map_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_unsuppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/conditional-advertisement/advertise-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_advertise_map_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_advertise_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/conditional-advertisement/condition",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/neighbor/afi-safis/l2vpn-evpn/filters/conditional-advertisement/condition-map",
			.cbs = {
				.modify = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_map_modify,
				.destroy = instance_neighbor_afi_safis_l2vpn_evpn_filters_conditional_advertisement_condition_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/listen-limit",
			.cbs = {
				.modify = instance_listen_limit_modify,
				.destroy = instance_listen_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/administrative-shutdown/enabled",
			.cbs = {
				.modify = instance_administrative_shutdown_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/administrative-shutdown/message",
			.cbs = {
				.modify = instance_administrative_shutdown_message_modify,
				.destroy = instance_administrative_shutdown_message_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/allow-martian-nexthop",
			.cbs = {
				.modify = instance_allow_martian_nexthop_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/use-underlays-nexthop-weight",
			.cbs = {
				.modify = instance_use_underlays_nexthop_weight_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/fast-convergence",
			.cbs = {
				.modify = instance_fast_convergence_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_network_create,
				.destroy = instance_afi_safis_ipv4_unicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv4_unicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/network/backdoor",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_network_backdoor_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv4_unicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv4_unicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/redistribute",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_redistribute_create,
				.destroy = instance_afi_safis_ipv4_unicast_redistribute_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/redistribute/metric",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_redistribute_metric_modify,
				.destroy = instance_afi_safis_ipv4_unicast_redistribute_metric_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/redistribute/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_redistribute_route_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_unicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_unicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_table_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv4_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv4_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv4_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv4_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_unicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_unicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv4_unicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv4_unicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv4_unicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/export-vpn",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_export_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vpn",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_import_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vrf",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_import_vrf_create,
				.destroy = instance_afi_safis_ipv4_unicast_import_vrf_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/import-vrf-route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_import_vrf_route_map_modify,
				.destroy = instance_afi_safis_ipv4_unicast_import_vrf_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/route-map-import",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_route_map_import_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_route_map_import_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/route-map-export",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_route_map_export_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_route_map_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/value",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_label_export_value_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_label_export_value_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/auto",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_label_export_auto_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_label_export_auto_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/label-export/allocation-mode",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_label_export_allocation_mode_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_label_export_allocation_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rd_export_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as2",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rd_export_as2_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as2/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_as2_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as2/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_as2_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rd_export_ipv4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/ipv4/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_ipv4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/ipv4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_ipv4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rd_export_as4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as4/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_as4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/as4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_as4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/mac",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_mac_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rd-export/raw",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_rd_export_raw_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rd_export_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/nexthop-export",
			.cbs = {
				.modify = instance_afi_safis_ipv4_unicast_vpn_nexthop_export_modify,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_nexthop_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/as2",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_import_as2_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_import_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/as4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_import_as4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_import_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-import/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_import_ipv4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_import_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/as2",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_export_as2_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_export_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/as4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_export_as4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_export_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-unicast/vpn/rt-export/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv4_unicast_vpn_rt_export_ipv4_create,
				.destroy = instance_afi_safis_ipv4_unicast_vpn_rt_export_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv4_multicast_network_create,
				.destroy = instance_afi_safis_ipv4_multicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv4_multicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv4_multicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/network/backdoor",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_network_backdoor_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv4_multicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv4_multicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv4_multicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv4_multicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv4_multicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_multicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_multicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_table_map_modify,
				.destroy = instance_afi_safis_ipv4_multicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv4_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv4_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv4_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv4_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_multicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_multicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv4_multicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv4_multicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv4_multicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-multicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv4_multicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv4_multicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv4_labeled_unicast_network_create,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/network/backdoor",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_network_backdoor_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_table_map_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv4_labeled_unicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-labeled-unicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv4_labeled_unicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv4_labeled_unicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as2",
			.cbs = {
				.create = instance_afi_safis_ipv4_vpn_network_as2_create,
				.destroy = instance_afi_safis_ipv4_vpn_network_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as2/label",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_as2_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as2/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_as2_route_map_modify,
				.destroy = instance_afi_safis_ipv4_vpn_network_as2_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv4_vpn_network_ipv4_create,
				.destroy = instance_afi_safis_ipv4_vpn_network_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/ipv4/label",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_ipv4_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/ipv4/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_ipv4_route_map_modify,
				.destroy = instance_afi_safis_ipv4_vpn_network_ipv4_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as4",
			.cbs = {
				.create = instance_afi_safis_ipv4_vpn_network_as4_create,
				.destroy = instance_afi_safis_ipv4_vpn_network_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as4/label",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_as4_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/as4/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_as4_route_map_modify,
				.destroy = instance_afi_safis_ipv4_vpn_network_as4_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/raw",
			.cbs = {
				.create = instance_afi_safis_ipv4_vpn_network_raw_create,
				.destroy = instance_afi_safis_ipv4_vpn_network_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/raw/label",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_raw_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/network/raw/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_network_raw_route_map_modify,
				.destroy = instance_afi_safis_ipv4_vpn_network_raw_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_vpn_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_vpn_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_table_map_modify,
				.destroy = instance_afi_safis_ipv4_vpn_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv4_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv4_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv4_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv4_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv4_vpn_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv4_vpn_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_distance_local_modify,
				.destroy = instance_afi_safis_ipv4_vpn_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv4_vpn_distance_prefix_create,
				.destroy = instance_afi_safis_ipv4_vpn_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv4_vpn_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv4-vpn/retain-route-target-all",
			.cbs = {
				.modify = instance_afi_safis_ipv4_vpn_retain_route_target_all_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_network_create,
				.destroy = instance_afi_safis_ipv6_unicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv6_unicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv6_unicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv6_unicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/redistribute",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_redistribute_create,
				.destroy = instance_afi_safis_ipv6_unicast_redistribute_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/redistribute/metric",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_redistribute_metric_modify,
				.destroy = instance_afi_safis_ipv6_unicast_redistribute_metric_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/redistribute/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_redistribute_route_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_redistribute_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_unicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_table_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv6_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv6_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv6_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv6_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_unicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_unicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv6_unicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv6_unicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv6_unicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/export-vpn",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_export_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vpn",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_import_vpn_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vrf",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_import_vrf_create,
				.destroy = instance_afi_safis_ipv6_unicast_import_vrf_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/import-vrf-route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_import_vrf_route_map_modify,
				.destroy = instance_afi_safis_ipv6_unicast_import_vrf_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-import",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_route_map_import_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_route_map_import_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/route-map-export",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_route_map_export_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_route_map_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/value",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_label_export_value_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_label_export_value_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/auto",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_label_export_auto_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_label_export_auto_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/label-export/allocation-mode",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_label_export_allocation_mode_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_label_export_allocation_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rd_export_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as2/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_as2_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/ipv4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_ipv4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4/administrator",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/as4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_as4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/mac",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_mac_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rd-export/raw",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_rd_export_raw_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rd_export_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/nexthop-export",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_vpn_nexthop_export_modify,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_nexthop_export_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as2",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_import_as2_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_import_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/as4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_import_as4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_import_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-import/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_import_ipv4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_import_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as2",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_export_as2_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_export_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/as4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_export_as4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_export_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/vpn/rt-export/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv6_unicast_vpn_rt_export_ipv4_create,
				.destroy = instance_afi_safis_ipv6_unicast_vpn_rt_export_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-unicast/nexthop-prefer-global",
			.cbs = {
				.modify = instance_afi_safis_ipv6_unicast_nexthop_prefer_global_modify,
				.destroy = instance_afi_safis_ipv6_unicast_nexthop_prefer_global_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv6_multicast_network_create,
				.destroy = instance_afi_safis_ipv6_multicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv6_multicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv6_multicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv6_multicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv6_multicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv6_multicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv6_multicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv6_multicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_multicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_table_map_modify,
				.destroy = instance_afi_safis_ipv6_multicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv6_multicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv6_multicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv6_multicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv6_multicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_multicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_multicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv6_multicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv6_multicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv6_multicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-multicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv6_multicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv6_multicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/network",
			.cbs = {
				.create = instance_afi_safis_ipv6_labeled_unicast_network_create,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_network_route_map_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_network_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/network/label-index",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_network_label_index_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_network_label_index_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address",
			.cbs = {
				.create = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_create,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/as-set",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_as_set_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/summary-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_summary_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_route_map_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/origin",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_origin_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_origin_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/matching-med-only",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_matching_med_only_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/aggregate-address/suppress-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_suppress_map_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_aggregate_address_suppress_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_table_map_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_distance_local_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv6_labeled_unicast_distance_prefix_create,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-labeled-unicast/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv6_labeled_unicast_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv6_labeled_unicast_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2",
			.cbs = {
				.create = instance_afi_safis_ipv6_vpn_network_as2_create,
				.destroy = instance_afi_safis_ipv6_vpn_network_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2/label",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_as2_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as2/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_as2_route_map_modify,
				.destroy = instance_afi_safis_ipv6_vpn_network_as2_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4",
			.cbs = {
				.create = instance_afi_safis_ipv6_vpn_network_ipv4_create,
				.destroy = instance_afi_safis_ipv6_vpn_network_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4/label",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_ipv4_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/ipv4/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_ipv4_route_map_modify,
				.destroy = instance_afi_safis_ipv6_vpn_network_ipv4_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4",
			.cbs = {
				.create = instance_afi_safis_ipv6_vpn_network_as4_create,
				.destroy = instance_afi_safis_ipv6_vpn_network_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4/label",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_as4_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/as4/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_as4_route_map_modify,
				.destroy = instance_afi_safis_ipv6_vpn_network_as4_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw",
			.cbs = {
				.create = instance_afi_safis_ipv6_vpn_network_raw_create,
				.destroy = instance_afi_safis_ipv6_vpn_network_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw/label",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_raw_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/network/raw/route-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_network_raw_route_map_modify,
				.destroy = instance_afi_safis_ipv6_vpn_network_raw_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/maximum-paths/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_maximum_paths_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_vpn_maximum_paths_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/maximum-paths/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/maximum-paths/ibgp-equal-cluster-length",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_maximum_paths_ibgp_equal_cluster_length_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/table-map",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_table_map_modify,
				.destroy = instance_afi_safis_ipv6_vpn_table_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening/enabled",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_dampening_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening/half-life",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_dampening_half_life_modify,
				.destroy = instance_afi_safis_ipv6_vpn_dampening_half_life_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening/reuse-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_dampening_reuse_threshold_modify,
				.destroy = instance_afi_safis_ipv6_vpn_dampening_reuse_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening/suppress-threshold",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_dampening_suppress_threshold_modify,
				.destroy = instance_afi_safis_ipv6_vpn_dampening_suppress_threshold_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/dampening/max-suppress-time",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_dampening_max_suppress_time_modify,
				.destroy = instance_afi_safis_ipv6_vpn_dampening_max_suppress_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/ebgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_distance_ebgp_modify,
				.destroy = instance_afi_safis_ipv6_vpn_distance_ebgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/ibgp",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_distance_ibgp_modify,
				.destroy = instance_afi_safis_ipv6_vpn_distance_ibgp_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/local",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_distance_local_modify,
				.destroy = instance_afi_safis_ipv6_vpn_distance_local_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/prefix",
			.cbs = {
				.create = instance_afi_safis_ipv6_vpn_distance_prefix_create,
				.destroy = instance_afi_safis_ipv6_vpn_distance_prefix_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/prefix/distance",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_distance_prefix_distance_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/distance/prefix/access-list",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_distance_prefix_access_list_modify,
				.destroy = instance_afi_safis_ipv6_vpn_distance_prefix_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/ipv6-vpn/retain-route-target-all",
			.cbs = {
				.modify = instance_afi_safis_ipv6_vpn_retain_route_target_all_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-all-vni",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_all_vni_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-default-gw",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_default_gw_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-svi-ip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_svi_ip_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_create,
				.destroy = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as2/global-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as2/local-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as4/global-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/as4/local-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/ipv4/global-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_global_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/mac-vrf-soo/ipv4/local-admin",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_local_admin_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/enable-resolve-overlay-index",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_enable_resolve_overlay_index_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_multihoming_use_es_l3nhg_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_rx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_tx_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/enabled",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_dup_addr_detection_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/max-moves",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_dup_addr_detection_max_moves_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_dup_addr_detection_max_moves_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/time",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_dup_addr_detection_time_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_dup_addr_detection_time_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/freeze",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_dup_addr_detection_freeze_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_dup_addr_detection_freeze_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/flooding",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_flooding_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_flooding_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_rd_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_rd_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_as2_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_as2_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_rd_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_as4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_as4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/mac",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_mac_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/raw",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_rd_raw_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_rd_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/flooding",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_flooding_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_flooding_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/rts/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/rts/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/rts/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/wildcard-rts",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_import_wildcard_rts_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_import_wildcard_rts_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/import/auto/mode",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_route_target_import_auto_mode_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_import_auto_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export/rts/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export/rts/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export/rts/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target/export/auto/mode",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_route_target_export_auto_mode_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_vni_route_target_export_auto_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-default-gw",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_advertise_default_gw_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-svi-ip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_advertise_svi_ip_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-subnet",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_vni_advertise_subnet_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_rd_create,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_rd_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_as2_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_as2_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_rd_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_ipv4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_ipv4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_rd_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_as4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_as4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/mac",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_mac_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/raw",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_rd_raw_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_rd_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/rts/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_import_rts_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_import_rts_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/rts/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_import_rts_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_import_rts_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/rts/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_import_rts_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_import_rts_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/wildcard-rts",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_rts_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_rts_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/auto/mode",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_route_target_import_auto_mode_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_import_auto_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/import/auto/rfc8365-compatible",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_route_target_import_auto_rfc8365_compatible_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/rts/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_export_rts_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_export_rts_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/rts/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_export_rts_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_export_rts_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/rts/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_route_target_export_rts_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_export_rts_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/auto/mode",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_route_target_export_auto_mode_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_route_target_export_auto_mode_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target/export/auto/rfc8365-compatible",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_route_target_export_auto_rfc8365_compatible_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast",
			.cbs = {
				.apply_finish = instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_apply_finish,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/enabled",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/gateway-ip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_gateway_ip_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/route-map",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast",
			.cbs = {
				.apply_finish = instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_apply_finish,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/enabled",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/gateway-ip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_gateway_ip_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/route-map",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv4",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_default_originate_ipv4_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv6",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_default_originate_ipv6_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip",
			.cbs = {
				.apply_finish = instance_afi_safis_l2vpn_evpn_advertise_pip_apply_finish,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/enabled",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_pip_enabled_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/ip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_pip_ip_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_advertise_pip_ip_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/mac",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_advertise_pip_mac_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_advertise_pip_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_network_create,
				.destroy = instance_afi_safis_l2vpn_evpn_network_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_network_rd_create,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_network_rd_as2_create,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_as2_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_as2_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_network_rd_ipv4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_ipv4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_ipv4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4",
			.cbs = {
				.create = instance_afi_safis_l2vpn_evpn_network_rd_as4_create,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4/administrator",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_as4_administrator_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4/assigned-number",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_as4_assigned_number_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/mac",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_mac_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_mac_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/raw",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_rd_raw_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_network_rd_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/ethtag",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_ethtag_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/label",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_label_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/esi",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_esi_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/gwip",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_gwip_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/routermac",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_routermac_modify,
			}
		},
		{
			.xpath = "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/route-map",
			.cbs = {
				.modify = instance_afi_safis_l2vpn_evpn_network_route_map_modify,
				.destroy = instance_afi_safis_l2vpn_evpn_network_route_map_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

/*
 * proteus-types and proteus-bgp-evpn contribute no data nodes of their own
 * (typedefs / groupings only, inlined via import + uses into proteus-bgp)
 * and need no frr_yang_module_info. The still-dormant support modules below
 * do define data nodes but have no converted batch yet; register them with
 * ignore_cfg_cbs so libyang's auto-implement of their standalone trees
 * doesn't hit nb_validate_callbacks() with uncallbacked config nodes.
 * proteus-interface went live in M7 batch B4, proteus-bgp-filter in M7
 * batch B6 (real tables further down).
 */
const struct frr_yang_module_info proteus_filter_info = { .name = "proteus-filter",
							  .ignore_cfg_cbs = true,
							  .nodes = {
								  {
									  .xpath = NULL,
								  },
							  } };

/* M7 batch B6: proteus-bgp-filter is live (callbacks in
 * bgpd/proteus/bgp_nb_filter.c). Only community-alias is converted in B6;
 * the as-path / community / large-community / extcommunity lists stay
 * reject-stubbed until their own batches (M7 B7/B8).
 */
const struct frr_yang_module_info proteus_bgp_filter_info = {
	.name = "proteus-bgp-filter",
	.nodes = {
		{
			.xpath = "/proteus-bgp-filter:as-path-access-list",
			.cbs = {
				.create = as_path_access_list_create,
				.destroy = as_path_access_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:as-path-access-list/entry",
			.cbs = {
				.create = as_path_access_list_entry_create,
				.destroy = as_path_access_list_entry_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:as-path-access-list/entry/action",
			.cbs = {
				.modify = as_path_access_list_entry_action_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:as-path-access-list/entry/regex",
			.cbs = {
				.modify = as_path_access_list_entry_regex_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list",
			.cbs = {
				.create = community_list_create,
				.destroy = community_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/type",
			.cbs = {
				.modify = community_list_type_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry",
			.cbs = {
				.create = community_list_entry_create,
				.destroy = community_list_entry_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/action",
			.cbs = {
				.modify = community_list_entry_action_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/communities",
			.cbs = {
				.create = community_list_entry_communities_create,
				.destroy = community_list_entry_communities_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/communities/member",
			.cbs = {
				.create = community_list_entry_communities_member_create,
				.destroy = community_list_entry_communities_member_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/communities/well-known",
			.cbs = {
				.create = community_list_entry_communities_well_known_create,
				.destroy = community_list_entry_communities_well_known_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/communities/raw",
			.cbs = {
				.create = community_list_entry_communities_raw_create,
				.destroy = community_list_entry_communities_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-list/entry/regex",
			.cbs = {
				.modify = community_list_entry_regex_modify,
				.destroy = community_list_entry_regex_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list",
			.cbs = {
				.create = large_community_list_create,
				.destroy = large_community_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/type",
			.cbs = {
				.modify = large_community_list_type_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry",
			.cbs = {
				.create = large_community_list_entry_create,
				.destroy = large_community_list_entry_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry/action",
			.cbs = {
				.modify = large_community_list_entry_action_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry/large-communities",
			.cbs = {
				.create = large_community_list_entry_large_communities_create,
				.destroy = large_community_list_entry_large_communities_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry/large-communities/member",
			.cbs = {
				.create = large_community_list_entry_large_communities_member_create,
				.destroy = large_community_list_entry_large_communities_member_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry/large-communities/raw",
			.cbs = {
				.create = large_community_list_entry_large_communities_raw_create,
				.destroy = large_community_list_entry_large_communities_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry/regex",
			.cbs = {
				.modify = large_community_list_entry_regex_modify,
				.destroy = large_community_list_entry_regex_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list",
			.cbs = {
				.create = extcommunity_list_create,
				.destroy = extcommunity_list_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/type",
			.cbs = {
				.modify = extcommunity_list_type_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry",
			.cbs = {
				.create = extcommunity_list_entry_create,
				.destroy = extcommunity_list_entry_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/action",
			.cbs = {
				.modify = extcommunity_list_entry_action_modify,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_create,
				.destroy = extcommunity_list_entry_extcommunities_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as2",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_target_as2_create,
				.destroy = extcommunity_list_entry_extcommunities_route_target_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as4",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_target_as4_create,
				.destroy = extcommunity_list_entry_extcommunities_route_target_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/ipv4",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_target_ipv4_create,
				.destroy = extcommunity_list_entry_extcommunities_route_target_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as2",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_origin_as2_create,
				.destroy = extcommunity_list_entry_extcommunities_route_origin_as2_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as4",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_origin_as4_create,
				.destroy = extcommunity_list_entry_extcommunities_route_origin_as4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/ipv4",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_route_origin_ipv4_create,
				.destroy = extcommunity_list_entry_extcommunities_route_origin_ipv4_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/raw",
			.cbs = {
				.create = extcommunity_list_entry_extcommunities_raw_create,
				.destroy = extcommunity_list_entry_extcommunities_raw_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry/regex",
			.cbs = {
				.modify = extcommunity_list_entry_regex_modify,
				.destroy = extcommunity_list_entry_regex_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-alias",
			.cbs = {
				.create = community_alias_create,
				.destroy = community_alias_destroy,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:community-alias/alias-name",
			.cbs = {
				.modify = community_alias_alias_name_modify,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info proteus_bfd_info = { .name = "proteus-bfd",
						       .ignore_cfg_cbs = true,
						       .nodes = {
							       {
								       .xpath = NULL,
							       },
						       } };

/* M7 batch B4: proteus-interface is live (callbacks in
 * bgpd/proteus/bgp_nb_interface.c). bgpd owns only the two 'mpls bgp ...'
 * flags; description and the ipv6-nd subtree are zebra's surface and stay
 * reject-stubbed permanently.
 */
const struct frr_yang_module_info proteus_interface_info = {
	.name = "proteus-interface",
	.nodes = {
		{
			.xpath = "/proteus-interface:interface",
			.cbs = {
				.create = proteus_interface_create,
				.destroy = proteus_interface_destroy,
			}
		},
		{
			.xpath = "/proteus-interface:interface/description",
			.cbs = {
				.modify = proteus_interface_description_modify,
				.destroy = proteus_interface_description_destroy,
			}
		},
		{
			.xpath = "/proteus-interface:interface/mpls-bgp-forwarding",
			.cbs = {
				.modify = proteus_interface_mpls_bgp_forwarding_modify,
			}
		},
		{
			.xpath = "/proteus-interface:interface/mpls-bgp-l3vpn-multi-domain-switching",
			.cbs = {
				.modify = proteus_interface_mpls_bgp_l3vpn_multi_domain_switching_modify,
			}
		},
		{
			.xpath = "/proteus-interface:interface/ipv6-nd/ra-interval",
			.cbs = {
				.modify = proteus_interface_ipv6_nd_ra_interval_modify,
				.destroy = proteus_interface_ipv6_nd_ra_interval_destroy,
			}
		},
		{
			.xpath = "/proteus-interface:interface/ipv6-nd/ra-interval-msec",
			.cbs = {
				.modify = proteus_interface_ipv6_nd_ra_interval_msec_modify,
				.destroy = proteus_interface_ipv6_nd_ra_interval_msec_destroy,
			}
		},
		{
			.xpath = NULL,
		},
	}
};

const struct frr_yang_module_info proteus_route_map_info = { .name = "proteus-route-map",
							     .ignore_cfg_cbs = true,
							     .nodes = {
								     {
									     .xpath = NULL,
								     },
							     } };
