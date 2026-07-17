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

#ifdef __cplusplus
}
#endif

#endif /* _FRR_BGP_NB_LOCAL_H_ */
