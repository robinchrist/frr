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
void instance_ls_distribute_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
const char *bgp_afi_safi_container_name(int node);

/* M6 B1: 'vni N' ... 'exit-vni' list-entry frame (instance l2vpn-evpn). */
void instance_evpn_vni_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void instance_evpn_vni_cli_write_end(struct vty *vty, const struct lyd_node *dnode);

/* M6 B2: instance-level l2vpn-evpn advertise-flag emitters. */
void instance_evpn_advertise_all_vni_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void instance_evpn_advertise_default_gw_cli_write(struct vty *vty, const struct lyd_node *dnode,
						  bool show_defaults);
void instance_evpn_advertise_svi_ip_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void instance_evpn_enable_resolve_overlay_index_cli_write(struct vty *vty,
							  const struct lyd_node *dnode,
							  bool show_defaults);

/* M6 B3: instance-level l2vpn-evpn mac-vrf-soo + flooding emitters. */
void instance_evpn_mac_vrf_soo_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void instance_evpn_flooding_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

/* M6 B4: instance-level l2vpn-evpn dup-addr-detection emitter. */
void instance_evpn_dup_addr_detection_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);

/* M6 B5: instance-level l2vpn-evpn multihoming ead-es-frag-evi-limit +
 * ead-es-route-target-export emitters. */
void instance_evpn_multihoming_ead_es_frag_evi_limit_cli_write(struct vty *vty,
								const struct lyd_node *dnode,
								bool show_defaults);
void instance_evpn_ead_es_route_target_export_as2_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_evpn_ead_es_route_target_export_as4_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);
void instance_evpn_ead_es_route_target_export_ipv4_cli_write(struct vty *vty,
							      const struct lyd_node *dnode,
							      bool show_defaults);

/* M6 B9b: route-target / advertise-unicast / advertise-pip / multihoming
 * toggle / type-5 network emitters. */
void instance_evpn_rt_direction_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void instance_evpn_vni_rt_direction_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void instance_evpn_rt_auto_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void instance_evpn_vni_rt_auto_mode_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void instance_evpn_rt_auto_rfc8365_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void instance_evpn_advertise_unicast_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void instance_evpn_advertise_pip_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void instance_evpn_multihoming_use_es_l3nhg_cli_write(struct vty *vty,
						      const struct lyd_node *dnode,
						      bool show_defaults);
void instance_evpn_multihoming_ead_evi_rx_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void instance_evpn_multihoming_ead_evi_tx_cli_write(struct vty *vty,
						    const struct lyd_node *dnode,
						    bool show_defaults);
void instance_evpn_network_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

/* M6 B6: per-VNI 'rd'/'flooding'/'advertise-default-gw'/'advertise-svi-ip'/
 * 'advertise-subnet' emitters. */
void instance_evpn_vni_rd_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
void instance_evpn_vni_flooding_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void instance_evpn_vni_advertise_default_gw_cli_write(struct vty *vty, const struct lyd_node *dnode,
						       bool show_defaults);
void instance_evpn_vni_advertise_svi_ip_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void instance_evpn_vni_advertise_subnet_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

/* M6 B7: instance-level (per-VRF-instance role) 'rd'/'default-originate'
 * emitters ('advertise ipv4/ipv6 unicast' stays native, no emitter here --
 * see the reject-stub doc comment in bgp_cli_instance.c). */
void instance_evpn_rd_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void instance_evpn_default_originate_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void instance_evpn_default_originate_ipv6_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);

/* M5 B1: per-AF 'neighbor X activate' emitter, shared neighbor/peer-group. */
void neighbor_af_activate_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);

/* M5 B2: per-AF policy-attachment emitters, shared neighbor/peer-group. */
void neighbor_af_filter_dir_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void neighbor_af_unsuppress_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);

/* M5 B3: per-AF conditional-advertisement + site-of-origin emitters, shared
 * neighbor/peer-group. */
void neighbor_af_advertise_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void neighbor_af_soo_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);

/* Site-of-origin ASN:NN_OR_IP-ADDRESS:NN token parser (bgp_cli_neighbor.c):
 * shared by M5 B3's per-AF 'neighbor X soo' and M6 B3's instance-level
 * 'mac-vrf soo', both of which parse the identical grammar into the same
 * as2/as4/ipv4 choice shape. */
enum bgp_cli_soo_case { BGP_CLI_SOO_AS2, BGP_CLI_SOO_AS4, BGP_CLI_SOO_IPV4 };
bool bgp_cli_soo_parse(const char *token, enum bgp_cli_soo_case *soo_case,
		       char *global_admin_buf, size_t global_admin_buf_len,
		       char *local_admin_buf, size_t local_admin_buf_len);

/* M5 B4: per-AF plain PEER_FLAG_* boolean emitters, shared neighbor/
 * peer-group. */
void neighbor_af_route_reflector_client_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void neighbor_af_route_server_client_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void neighbor_af_encapsulation_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void neighbor_af_encapsulation_srv6_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void neighbor_af_encapsulation_mpls_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void neighbor_af_as_override_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
void neighbor_af_next_hop_self_enabled_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);
void neighbor_af_next_hop_self_force_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void neighbor_af_nexthop_local_unchanged_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void neighbor_af_soft_reconfiguration_inbound_cli_write(struct vty *vty,
							 const struct lyd_node *dnode,
							 bool show_defaults);
void neighbor_af_accept_own_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void neighbor_af_attribute_unchanged_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);

/* M5 batch B5: per-AF send-community + remove-private-as + capability orf
 * prefix-list emitters, shared neighbor/peer-group. */
void neighbor_af_send_community_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void neighbor_af_remove_private_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void neighbor_af_orf_prefix_list_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

/* M5 batch B6: per-AF default-originate + maximum-prefix (+opts) +
 * maximum-prefix-out + allowas-in + weight emitters, shared
 * neighbor/peer-group. */
void neighbor_af_default_originate_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void neighbor_af_maximum_prefix_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void neighbor_af_maximum_prefix_out_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void neighbor_af_allowas_in_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void neighbor_af_weight_cli_write(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);

/* M5 batch B7: per-AF addpath tx/tx-best-selected/disable-rx/rx-paths-limit
 * emitters, shared neighbor/peer-group. */
void neighbor_af_addpath_tx_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void neighbor_af_addpath_disable_rx_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void neighbor_af_addpath_rx_paths_limit_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);

/* M5 batch B8: per-neighbor dampening emitter, shared neighbor/peer-group. */
void neighbor_af_dampening_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);

void instance_administrative_shutdown_enabled_cli_write(struct vty *vty,
							       const struct lyd_node *dnode,
							       bool show_defaults);
void instance_advertisement_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void instance_allow_martian_nexthop_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_default_shutdown_cli_write(struct vty *vty, const struct lyd_node *dnode,
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
void instance_ebgp_connected_route_check_cli_write(struct vty *vty,
						   const struct lyd_node *dnode,
						   bool show_defaults);
void instance_ebgp_requires_policy_cli_write(struct vty *vty, const struct lyd_node *dnode,
						    bool show_defaults);
void instance_enforce_first_as_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void instance_fast_convergence_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void instance_fast_external_failover_cli_write(struct vty *vty, const struct lyd_node *dnode,
						      bool show_defaults);
void instance_graceful_restart_eor_cli_write(struct vty *vty,
					     const struct lyd_node *dnode,
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
void instance_use_underlays_nexthop_weight_cli_write(struct vty *vty,
							    const struct lyd_node *dnode,
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
void afi_safis_fs_local_install_iface_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void afi_safis_fs_redirect_import_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void afi_safis_srv6_sid_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void afi_safis_vpn_sid_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					bool show_defaults);
void instance_sid_vpn_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
void instance_srv6_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults);
void instance_srv6_cli_write_end(struct vty *vty, const struct lyd_node *dnode);
void instance_srv6_locator_cli_write(struct vty *vty, const struct lyd_node *dnode,
				     bool show_defaults);
void instance_srv6_encap_behavior_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void instance_srv6_only_cli_write(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void process_snmp_traps_rfc4273_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void process_snmp_traps_rfc4382_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void process_snmp_traps_bgp4_mibv2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					     bool show_defaults);
void process_session_dscp_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void process_suppress_fib_pending_cli_write(struct vty *vty, const struct lyd_node *dnode,
						   bool show_defaults);
void process_update_delay_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

/* M5 B9: instance-AF 'network' list emitters (ipv4 with backdoor, ipv6
 * without). */
void afi_safis_network_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);
void afi_safis_network_ipv6_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

/* M5 B10: instance-AF 'aggregate-address' list emitter (shared by ipv4/ipv6
 * -- af-aggregate-ipv4/-ipv6 model identical option leaves). */
void afi_safis_aggregate_address_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);

/* M5 B11: instance-AF 'redistribute' list emitter (shared by ipv4-unicast/
 * ipv6-unicast -- af-redistribute is one grouping used by both). */
void afi_safis_redistribute_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults);

/* M5 B12: instance-AF 'maximum-paths'/'table-map'/'bgp dampening' emitters
 * (shared by all eight instance AFs -- af-route-selection is one grouping
 * used by all of them). */
void afi_safis_maximum_paths_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
void afi_safis_table_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);
void afi_safis_dampening_cli_write(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults);

/* M5 B13: instance-AF 'distance bgp ...' triple + per-prefix 'distance
 * (1-255) PREFIX [ACCESSLIST]' emitters (shared by all eight instance AFs --
 * af-distance-ipv4/-ipv6 are one grouping shape used by all of them). The
 * container emitter renders the admin triple; the prefix-list emitter is
 * registered on the 'distance/prefix' list and renders one line per entry. */
void afi_safis_distance_cli_write(struct vty *vty, const struct lyd_node *dnode,
				  bool show_defaults);
void afi_safis_distance_prefix_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);

/* M5 B14: instance-AF 'nexthop prefer-global', ipv6-unicast only. */
void afi_safis_ipv6_unicast_nexthop_prefer_global_cli_write(struct vty *vty,
							     const struct lyd_node *dnode,
							     bool show_defaults);

/* M7 B1: instance-AF VPN leaking simple knobs (af-vpn-leaking's
 * export-vpn/import-vpn/import-vrf/import-vrf-route-map, ipv4/ipv6-unicast). */
void afi_safis_export_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
void afi_safis_import_vpn_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
void afi_safis_import_vrf_cli_write(struct vty *vty, const struct lyd_node *dnode,
				    bool show_defaults);
void afi_safis_import_vrf_route_map_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);

/* M7 B2: instance-AF VPN leaking, detailed vpn-policy block
 * (af-vpn-leaking's 'vpn' container, ipv4/ipv6-unicast). */
void afi_safis_vpn_route_map_import_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void afi_safis_vpn_route_map_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults);
void afi_safis_vpn_label_export_value_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults);
void afi_safis_vpn_label_export_auto_cli_write(struct vty *vty, const struct lyd_node *dnode,
					       bool show_defaults);
void afi_safis_vpn_label_export_allocation_mode_cli_write(struct vty *vty,
							   const struct lyd_node *dnode,
							   bool show_defaults);
void afi_safis_vpn_rd_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
				       bool show_defaults);
void afi_safis_vpn_nexthop_export_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void afi_safis_vpn_rt_import_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void afi_safis_vpn_rt_import_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void afi_safis_vpn_rt_import_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void afi_safis_vpn_rt_export_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void afi_safis_vpn_rt_export_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults);
void afi_safis_vpn_rt_export_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					    bool show_defaults);
void afi_safis_vpn_network_as2_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void afi_safis_vpn_network_as4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					 bool show_defaults);
void afi_safis_vpn_network_ipv4_cli_write(struct vty *vty, const struct lyd_node *dnode,
					  bool show_defaults);
void afi_safis_retain_route_target_all_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults);

/* Workstream C: interface-level 'mpls bgp ...' flag emitters, on
 * proteus-bgp's augment of frr-interface's interface list (defined in
 * bgp_cli_interface.c; the 'interface NAME' block frame is lib's). */
void lib_interface_bgp_mpls_bgp_forwarding_cli_write(struct vty *vty, const struct lyd_node *dnode,
						     bool show_defaults);
void lib_interface_bgp_mpls_bgp_l3vpn_multi_domain_switching_cli_write(struct vty *vty,
								       const struct lyd_node *dnode,
								       bool show_defaults);

/* Per-file install_node()/install_element() entry points, called from
 * bgp_cli_init() in bgp_cli_common.c. */
void bgp_cli_instance_init(void);
void bgp_cli_process_init(void);
void bgp_cli_interface_init(void);
void bgp_cli_filter_init(void);
void bgp_cli_dump_init(void);
void bgp_cli_neighbor_init(void);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_CLI_LOCAL_H_ */
