// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Internal prototypes shared across the bgpd/proteus/bgp_nb_*.c northbound
 * callback files (bgpd-yang-conversion intermezzo split of
 * bgp_nb_config.c). Not installed; bgpd/mgmtd-internal use only.
 */
#ifndef _FRR_BGP_NB_LOCAL_H_
#define _FRR_BGP_NB_LOCAL_H_

#include "lib/northbound.h"

#ifdef __cplusplus
extern "C" {
#endif

void bgp_nb_advertisement_delay_reset(struct bgp *bgp);
void bgp_nb_capability_flag_destroy(struct peer *peer, uint64_t flag, bool instance_default);
void bgp_nb_capability_send_dynamic_peer_group(struct peer *peer, afi_t afi, safi_t safi,
					       int capability_code, int action);
void bgp_nb_clear_star_soft(struct bgp *bgp, enum bgp_clear_type stype);
int bgp_nb_default_af_safi_conflict_validate(struct nb_cb_modify_args *args,
						    const char *sibling_relpath,
						    bool sibling_absent_default);
bool bgp_nb_get_local_as(const struct lyd_node *local_as_dnode, as_t *as, const char **as_str,
			 char *as_str_buf, size_t as_str_buf_len, bool *no_prepend,
			 bool *replace_as, bool *dual_as);
bool bgp_nb_get_remote_as(const struct lyd_node *session_dnode, as_t *as,
				  enum peer_asn_type *as_type, const char **as_str,
				  char *as_str_buf, size_t as_str_buf_len);
bool bgp_nb_get_role(const struct lyd_node *local_role_dnode, uint8_t *role, bool *strict_mode);
bool bgp_nb_gr_process_blocked_by_instance(void);
bool bgp_nb_graceful_shutdown_instance_blocked_by_process(void);
bool bgp_nb_graceful_shutdown_process_blocked_by_instance(void);
int bgp_nb_instance_apply(const struct lyd_node *instance_dnode);
int bgp_nb_instance_asn_apply(const struct lyd_node *dnode);
void bgp_nb_instance_confederation_identifier_apply(const struct lyd_node *dnode);
as_t bgp_nb_instance_get_asn(const struct lyd_node *instance_dnode);
void bgp_nb_instance_get_asn_pretty(const struct lyd_node *instance_dnode, as_t as,
					   char *buf, size_t buflen);
struct bgp *bgp_nb_instance_lookup(const struct lyd_node *dnode);
int bgp_nb_instance_replay(const struct lyd_node *instance_dnode);
void bgp_nb_instance_update_delay_apply(struct bgp *bgp, uint16_t delay,
					       uint16_t establish_wait);
int bgp_nb_local_as_validate(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len);
struct peer *bgp_nb_neighbor_lookup(const struct lyd_node *dnode);
int bgp_nb_neighbor_af_activate_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_activate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_activate_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_activate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
/* M5 batch B4: plain per-AF PEER_FLAG_* booleans (neighbor + peer-group). */
int bgp_nb_neighbor_af_flag_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
				   uint64_t flag);
int bgp_nb_peer_group_af_flag_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
				     uint64_t flag);
/* M5 batch B5: send-community tri-state destroy, remove-private-as enum,
 * capability orf prefix-list enum (neighbor + peer-group). */
int bgp_nb_neighbor_af_flag_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
				    uint64_t flag, bool compiled_default);
int bgp_nb_peer_group_af_flag_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
				      uint64_t flag, bool compiled_default);
int bgp_nb_neighbor_af_remove_private_as_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi);
int bgp_nb_neighbor_af_remove_private_as_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_peer_group_af_remove_private_as_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_peer_group_af_remove_private_as_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_neighbor_af_orf_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_neighbor_af_orf_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_peer_group_af_orf_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi);
int bgp_nb_peer_group_af_orf_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi);
/* M5 batch B2: per-AF policy attachments (neighbor + peer-group). */
int bgp_nb_neighbor_af_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					int direct);
int bgp_nb_neighbor_af_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					 int direct);
int bgp_nb_peer_group_af_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct);
int bgp_nb_peer_group_af_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct);
int bgp_nb_neighbor_af_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct);
int bgp_nb_neighbor_af_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct);
int bgp_nb_peer_group_af_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					    int direct);
int bgp_nb_peer_group_af_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi, int direct);
int bgp_nb_neighbor_af_filter_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct);
int bgp_nb_neighbor_af_filter_list_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct);
int bgp_nb_peer_group_af_filter_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					    int direct);
int bgp_nb_peer_group_af_filter_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi, int direct);
int bgp_nb_neighbor_af_distribute_list_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi, int direct);
int bgp_nb_neighbor_af_distribute_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi, int direct);
int bgp_nb_peer_group_af_distribute_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi, int direct);
int bgp_nb_peer_group_af_distribute_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi, int direct);
int bgp_nb_neighbor_af_unsuppress_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					     safi_t safi);
int bgp_nb_neighbor_af_unsuppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_peer_group_af_unsuppress_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_peer_group_af_unsuppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						safi_t safi);
/* M5 batch B3: per-AF conditional-advertisement + site-of-origin (neighbor
 * + peer-group). */
int bgp_nb_neighbor_af_advertise_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_advertise_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi);
int bgp_nb_neighbor_af_condition_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_condition_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_condition_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_condition_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi);
int bgp_nb_peer_group_af_advertise_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_peer_group_af_advertise_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_peer_group_af_condition_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_condition_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_condition_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_peer_group_af_condition_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_neighbor_af_soo_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_soo_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_soo_case_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_soo_case_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_soo_leaf_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_soo_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_soo_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_soo_case_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_soo_case_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_soo_leaf_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
/* M6 B3: 'mac-vrf soo' (bgp_nb_evpn.c) reuses the as2/as4/ipv4 choice
 * encoder shared with the per-AF soo above. */
void bgp_nb_soo_encode(const struct lyd_node *soo_dnode, struct ecommunity_val *eval);
/* M5 batch B6: per-AF default-originate + maximum-prefix (+opts) +
 * maximum-prefix-out + allowas-in + weight (neighbor + peer-group). */
int bgp_nb_neighbor_af_default_originate_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi);
int bgp_nb_neighbor_af_default_originate_route_map_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_default_originate_route_map_destroy(struct nb_cb_destroy_args *args,
							    afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_default_originate_enabled_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_default_originate_route_map_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_default_originate_route_map_destroy(struct nb_cb_destroy_args *args,
							      afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args,
							       afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args,
								afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_force_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args,
								 afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args,
								  afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_force_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_out_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_neighbor_af_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_out_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_peer_group_af_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi);
int bgp_nb_neighbor_af_allowas_in_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_neighbor_af_allowas_in_count_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_neighbor_af_allowas_in_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_neighbor_af_allowas_in_origin_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_neighbor_af_allowas_in_route_map_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_neighbor_af_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi);
int bgp_nb_peer_group_af_allowas_in_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_peer_group_af_allowas_in_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_peer_group_af_allowas_in_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_peer_group_af_allowas_in_origin_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_peer_group_af_allowas_in_route_map_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi);
int bgp_nb_peer_group_af_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi);
int bgp_nb_neighbor_af_weight_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_weight_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_weight_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_weight_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
/* M5 batch B7: per-AF addpath tx/tx-best-selected/disable-rx/rx-paths-limit
 * (neighbor + peer-group). */
int bgp_nb_neighbor_af_addpath_tx_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_addpath_tx_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_addpath_tx_best_selected_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi);
int bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_peer_group_af_addpath_tx_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_addpath_tx_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_peer_group_af_addpath_tx_best_selected_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi);
int bgp_nb_peer_group_af_addpath_tx_best_selected_destroy(struct nb_cb_destroy_args *args,
							  afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi);
int bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi);
int bgp_nb_peer_group_af_addpath_rx_paths_limit_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi);
int bgp_nb_peer_group_af_addpath_rx_paths_limit_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_neighbor_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi);
int bgp_nb_neighbor_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_neighbor_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_neighbor_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args,
							 afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args,
							    afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args,
							  afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_peer_group_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi,
						    safi_t safi);
int bgp_nb_peer_group_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						     safi_t safi);
int bgp_nb_peer_group_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args,
							  afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args,
							      afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args,
							    afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args,
							     afi_t afi, safi_t safi);
int bgp_nb_neighbor_bfd_apply(const struct lyd_node *dnode);
int bgp_nb_neighbor_local_as_apply(const struct lyd_node *dnode);
int bgp_nb_neighbor_local_as_destroy_apply(const struct lyd_node *dnode);
int bgp_nb_neighbor_remote_as_apply(const struct lyd_node *dnode);
int bgp_nb_neighbor_remote_as_destroy_apply(const struct lyd_node *dnode);
int bgp_nb_neighbor_remote_as_destroy_validate(const struct lyd_node *dnode,
						       char *errmsg, size_t errmsg_len);
int bgp_nb_neighbor_role_apply(const struct lyd_node *dnode);
int bgp_nb_path_attribute_validate(struct peer *peer, uint8_t attr_num, const char *what,
				   char *errmsg, size_t errmsg_len);
void bgp_nb_path_attribute_soft_clear(struct peer *peer);
struct peer_group *bgp_nb_peer_group_lookup(const struct lyd_node *dnode);
int bgp_nb_peer_group_bfd_apply(const struct lyd_node *dnode);
int bgp_nb_peer_group_local_as_apply(const struct lyd_node *dnode);
int bgp_nb_peer_group_local_as_destroy_apply(const struct lyd_node *dnode);
int bgp_nb_peer_group_remote_as_apply(const struct lyd_node *dnode);
int bgp_nb_peer_group_role_apply(const struct lyd_node *dnode);
int bgp_nb_peer_group_remote_as_delete_apply(const struct lyd_node *dnode);
void bgp_nb_process_update_delay_apply(uint16_t delay, uint16_t establish_wait);
void bgp_nb_reject_as_sets_reset_peers(struct bgp *bgp);
bool bgp_nb_update_delay_instance_blocked_by_process(void);
bool bgp_nb_update_delay_process_blocked_by_instance(void);
void bgp_nb_update_graceful_restart_capability(struct peer *peer);
/* M5 batch B9: instance-AF 'network' (ipv4/ipv6 x
 * unicast/multicast/labeled-unicast). */
int bgp_nb_af_network_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_network_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_network_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_network_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_network_label_index_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_network_label_index_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					  safi_t safi);
int bgp_nb_af_network_backdoor_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
/* M5 batch B10: instance-AF 'aggregate-address' (ipv4/ipv6 x
 * unicast/multicast/labeled-unicast). */
int bgp_nb_af_aggregate_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_as_set_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_summary_only_modify(struct nb_cb_modify_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_af_aggregate_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_origin_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_origin_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_aggregate_matching_med_only_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_af_aggregate_suppress_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_af_aggregate_suppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi);
/* M5 batch B11: instance-AF 'redistribute' (ipv4-unicast/ipv6-unicast
 * only -- af-redistribute is unicast-only). */
int bgp_nb_af_redistribute_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_redistribute_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_redistribute_metric_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_redistribute_metric_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					  safi_t safi);
int bgp_nb_af_redistribute_route_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_af_redistribute_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi);
/* M5 batch B12: instance-AF 'maximum-paths'/'table-map'/'bgp dampening'
 * (af-route-selection in proteus-bgp.yang), the eight instance AFs that
 * 'uses' the grouping (ipv4/ipv6 x unicast/multicast/labeled-unicast/vpn). */
int bgp_nb_af_maximum_paths_ebgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_maximum_paths_ebgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_maximum_paths_ibgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_maximum_paths_ibgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(struct nb_cb_modify_args *args,
							      afi_t afi, safi_t safi);
int bgp_nb_af_table_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_table_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					  safi_t safi);
int bgp_nb_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi);
int bgp_nb_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						safi_t safi);
int bgp_nb_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi);
int bgp_nb_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi);
int bgp_nb_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi);
/* M5 batch B13: instance-AF 'distance bgp ...' triple + per-prefix 'distance
 * (1-255) PREFIX [ACCESSLIST]' (af-distance-ipv4/-ipv6 in proteus-bgp.yang),
 * the same eight instance AFs that 'uses' the grouping. */
int bgp_nb_af_distance_ebgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_ebgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_ibgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_ibgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_local_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_local_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_prefix_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_prefix_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_distance_prefix_distance_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi);
int bgp_nb_af_distance_prefix_access_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi);
int bgp_nb_af_distance_prefix_access_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi);
/* M7 batch B1: instance-AF VPN leaking simple knobs (af-vpn-leaking's
 * export-vpn/import-vpn/import-vrf/import-vrf-route-map, ipv4/ipv6-unicast). */
int bgp_nb_af_export_vpn_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_import_vpn_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_import_vrf_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_import_vrf_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_import_vrf_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_import_vrf_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);

/* M7 batch B2: instance-AF VPN leaking, detailed vpn-policy block
 * (af-vpn-leaking's 'vpn' container, ipv4/ipv6-unicast). */
int bgp_nb_af_vpn_route_map_import_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_route_map_import_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_route_map_export_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_route_map_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_label_export_value_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_encap_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_neighbor_af_encap_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_encap_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_peer_group_af_encap_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_srv6_sid_export_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_srv6_sid_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_srv6_sid_export_dt46_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
void bgp_nb_af_srv6_sid_export_apply_finish(struct nb_cb_apply_finish_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_af_sid_export_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
void bgp_nb_af_vpn_label_export_apply_finish(struct nb_cb_apply_finish_args *args, afi_t afi,
					     safi_t safi);
int bgp_nb_af_vpn_label_export_value_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi);
int bgp_nb_af_vpn_label_export_auto_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_label_export_auto_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					    safi_t safi);
int bgp_nb_af_vpn_label_export_allocation_mode_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi);
int bgp_nb_af_vpn_label_export_allocation_mode_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_af_vpn_rd_export_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_as2_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						      safi_t safi);
int bgp_nb_af_vpn_rd_export_as2_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_af_vpn_rd_export_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_as4_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						      safi_t safi);
int bgp_nb_af_vpn_rd_export_as4_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi);
int bgp_nb_af_vpn_rd_export_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rd_export_ipv4_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi);
int bgp_nb_af_vpn_rd_export_ipv4_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi);
int bgp_nb_af_vpn_nexthop_export_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_nexthop_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_import_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi);
int bgp_nb_af_vpn_rt_export_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi);

/* M7 batch B3: MPLS-VPN static 'network' statements (af-network-vpn-ipv4/
 * -ipv6), ipv4-vpn/ipv6-vpn only; see bgp_nb_util.c. 'raw' has no legacy
 * parser for an arbitrary RD string and stays reject-stubbed permanently. */
int bgp_nb_af_vpn_network_as2_create(struct nb_cb_create_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as2_label_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as2_route_map_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as2_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as4_create(struct nb_cb_create_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as4_label_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as4_route_map_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_as4_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi);
int bgp_nb_af_vpn_network_ipv4_create(struct nb_cb_create_args *args, afi_t afi);
int bgp_nb_af_vpn_network_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi);
int bgp_nb_af_vpn_network_ipv4_label_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_ipv4_route_map_modify(struct nb_cb_modify_args *args, afi_t afi);
int bgp_nb_af_vpn_network_ipv4_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi);

/* 'bgp retain route-target all' (af-retain-route-target), ipv4/ipv6-vpn
 * only; default-on boolean, modify-only. See bgp_nb_util.c. */
int bgp_nb_af_retain_route_target_all_modify(struct nb_cb_modify_args *args, afi_t afi);

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_LOCAL_H_ */
