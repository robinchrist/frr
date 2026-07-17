// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Internal prototypes shared across the bgpd/proteus/bgp_cli_*.c CLI files
 * (bgpd-yang-conversion intermezzo split of bgp_cli.c). Not installed;
 * bgpd/mgmtd-internal use only.
 */
#ifndef _FRR_BGP_CLI_LOCAL_H_
#define _FRR_BGP_CLI_LOCAL_H_

#include "lib/northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

/* M5 B0: address-family block header/trailer (registered on the instance
 * afi-safis/<af> containers) and the node <-> container-name helper for
 * per-AF leaf commands (B1+) to build their xpath from vty->node. */
void afi_safi_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void afi_safi_cli_write_end(struct vty *vty, const struct lyd_node *dnode);
const char *bgp_afi_safi_container_name(int node);

void instance_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void instance_always_compare_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void instance_bestpath_aigp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void instance_bestpath_as_path_confed_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults);
void instance_bestpath_as_path_ignore_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults);
void instance_bestpath_as_path_multipath_relax_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults);
void instance_bestpath_bandwidth_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void instance_bestpath_compare_routerid_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults);
void instance_bestpath_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void instance_bestpath_peer_type_multipath_relax_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults);
void instance_bestpath_use_imported_attributes_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults);
void instance_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void instance_cli_write_end(struct vty *vty, const struct lyd_node *dnode);
void instance_client_to_client_reflection_cli_write(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults);
void instance_cluster_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void instance_coalesce_time_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void instance_confederation_identifier_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults);
void instance_confederation_peers_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void instance_default_dynamic_capability_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults);
void instance_default_ipv4_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void instance_default_ipv4_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults);
void instance_default_ipv4_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults);
void instance_default_ipv4_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_default_ipv4_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void instance_default_ipv6_flowspec_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void instance_default_ipv6_labeled_unicast_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults);
void instance_default_ipv6_multicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults);
void instance_default_ipv6_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_default_ipv6_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void instance_default_l2vpn_evpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void instance_default_link_local_capability_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_default_local_preference_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults);
void instance_default_show_hostname_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void instance_default_show_nexthop_hostname_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_default_software_version_capability_cli_write(struct vty *vty,
								   const struct lyd_node *dnode,
								   bool show_defaults);
void instance_default_software_version_capability_latest_encoding_cli_write(
	struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void instance_default_subgroup_pkt_queue_max_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults);
void instance_deterministic_med_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
void instance_disable_ebgp_connected_route_check_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults);
void instance_ebgp_requires_policy_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_enforce_first_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void instance_fast_external_failover_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults);
void instance_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void instance_graceful_restart_notification_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults);
void instance_graceful_restart_restart_time_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_graceful_restart_rib_stale_time_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults);
void instance_graceful_restart_select_defer_time_cli_write(struct vty *vty,
								  const struct lyd_node *dnode,
								  bool show_defaults);
void instance_graceful_restart_stalepath_time_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults);
void instance_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
void instance_hard_administrative_reset_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults);
void instance_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void instance_labeled_unicast_explicit_null_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_listen_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void instance_log_neighbor_changes_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_long_lived_graceful_restart_stale_time_cli_write(struct vty *vty,
								      const struct lyd_node *dnode,
								      bool show_defaults);
void instance_max_med_administrative_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults);
void instance_max_med_on_startup_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void instance_network_import_check_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_read_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void instance_reject_as_sets_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void instance_route_reflector_allow_outbound_policy_cli_write(struct vty *vty,
								     const struct lyd_node *dnode,
								     bool show_defaults);
void instance_router_id_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void instance_suppress_duplicates_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void instance_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_tcp_keepalive_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void instance_timers_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void instance_timers_conditional_advertisement_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults);
void instance_timers_default_originate_cli_write(struct vty *vty,
							const struct lyd_node *dnode,
							bool show_defaults);
void instance_timers_minimum_holdtime_cli_write(struct vty *vty,
						       const struct lyd_node *dnode,
						       bool show_defaults);
void instance_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void instance_write_quanta_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void neighbor_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void peer_group_cli_write(struct vty *vty, const struct lyd_node *dnode,
				 bool show_defaults);
void peer_group_listen_range_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void process_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void process_graceful_restart_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void process_graceful_restart_preserve_fw_state_cli_write(struct vty *vty,
								 const struct lyd_node *dnode,
								 bool show_defaults);
void process_graceful_restart_restart_time_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
							    bool show_defaults);
void process_graceful_restart_rib_stale_time_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults);
void process_graceful_restart_select_defer_time_cli_write(struct vty *vty,
								 const struct lyd_node *dnode,
								 bool show_defaults);
void process_graceful_restart_stalepath_time_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults);
void process_graceful_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void process_input_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void process_ipv6_auto_ra_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void process_no_rib_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
void process_output_queue_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
void process_route_map_delay_timer_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void process_send_extra_data_zebra_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void process_session_dscp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void process_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void process_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

/* Per-file install_node()/install_element() entry points, called from
 * bgp_cli_init() in bgp_cli_common.c. */
void bgp_cli_instance_init(void);
void bgp_cli_process_init(void);
void bgp_cli_neighbor_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CLI_LOCAL_H_ */
