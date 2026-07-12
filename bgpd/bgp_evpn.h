// SPDX-License-Identifier: GPL-2.0-or-later
/* E-VPN header for packet handling
 * Copyright (C) 2016 6WIND
 */

#ifndef _QUAGGA_BGP_EVPN_H
#define _QUAGGA_BGP_EVPN_H

#include "vxlan.h"
#include "bgpd.h"

#define EVPN_ROUTE_STRLEN 200 /* Must be >> MAC + IPv6 strings. */
/*
 *   RFC8365 "5.1.2.1.  Auto-Derivation of RT" defines:
 *
 *   0                   1                   2                   3
 *   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *  |     Global Administrator      |A| TYPE| D-ID  | Service ID    |
 *  +-----------------------------------------------+---------------+
 *  |       Service ID (Cont.)      |
 *  +-------------------------------+
 *
 * This FLAG corresponds to the "A" bit (leftmost bit of a 32-bit value)
 */
#define BGP_EVPN_RT_RFC8365_A_BIT 0x80000000

static inline bool is_evpn_underlay(const struct bgp *bgp)
{
	return bgp && bgp->evpn_vxlan_underlay_cfgd;
}

/* Global helper function to check whether EVPN as a protocol is generally
 * enabled. EVPN is generally enabled when at least one VRF is designated as a
 * VXLAN underlay (`vxlan-underlay` / legacy `advertise-all-vni`).
 */
static inline bool is_evpn_enabled(void)
{
	return bgp_evpn_underlays_count(&bgp_evpn_gbl()->underlays) > 0;
}

/* Indicates whether type-5 routes should be originated without overlay index,
 * and only the best path for each prefix is exported to EVPN
 *
 * True when VRF has a non-zero L3VNI (otherwise we don't have a label for our route!)
 * AND "advertise <afi> <safi>" is WITHOUT gateway-ip!
 */
static inline int bgp_evpn_should_originate_type5_routes_bestpath(const struct bgp *bgp_vrf, afi_t afi)
{
	uint16_t flags = bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN];

	/* TODO: Use bgp_evpn_vrf_has_l3vni -> Move bgp_evpn_vrf_has_l3vni to this header? */
	if (!bgp_vrf->l3vni)
		return 0;

	if (afi == AFI_IP && CHECK_FLAG(flags, BGP_L2VPN_EVPN_ADV_IPV4_UNICAST))
		return 1;
	if (afi == AFI_IP6 && CHECK_FLAG(flags, BGP_L2VPN_EVPN_ADV_IPV6_UNICAST))
		return 1;

	return 0;
}



 /* Indicates whether type-5 routes should be originated with overlay index (gateway IP)
 * and the routes use all paths are exported to EVPN using AddPath, and each
 * path's nexthop becomes the gateway IP of the corresponding type-5 paths.
 * True when VRF has a non-zero L3VNI (otherwise we don't have a label for our route!)
 * AND "advertise <afi> <safi>" is WITH "gateway-ip" option!
 */
static inline int bgp_evpn_should_originate_type5_routes_multipath(const struct bgp *bgp_vrf, afi_t afi)
{
	uint16_t flags = bgp_vrf->af_flags[AFI_L2VPN][SAFI_EVPN];

	/* TODO: Use bgp_evpn_vrf_has_l3vni -> Move bgp_evpn_vrf_has_l3vni to this header? */
	if (!bgp_vrf->l3vni)
		return 0;

	if (afi == AFI_IP && CHECK_FLAG(flags, BGP_L2VPN_EVPN_ADV_IPV4_UNICAST_GW_IP))
		return 1;
	if (afi == AFI_IP6 && CHECK_FLAG(flags, BGP_L2VPN_EVPN_ADV_IPV6_UNICAST_GW_IP))
		return 1;

	return 0;
}

/* Flag if the route's parent is a EVPN route. */
static inline struct bgp_path_info *
get_route_parent_evpn(struct bgp_path_info *ri)
{
	struct bgp_path_info *parent_ri;

	/* If not imported (or doesn't have a parent), bail. */
	if (ri->sub_type != BGP_ROUTE_IMPORTED || !ri->extra ||
	    !ri->extra->vrfleak || !ri->extra->vrfleak->parent)
		return NULL;

	/* Determine parent recursively */
	for (parent_ri = ri->extra->vrfleak->parent;
	     parent_ri->extra && parent_ri->extra->vrfleak &&
	     parent_ri->extra->vrfleak->parent;
	     parent_ri = parent_ri->extra->vrfleak->parent)
		;

	return parent_ri;
}

/* Flag if the route's parent is a EVPN route. */
static inline int is_route_parent_evpn(struct bgp_path_info *ri)
{
	struct bgp_path_info *parent_ri;
	struct bgp_table *table;
	struct bgp_dest *dest;

	parent_ri = get_route_parent_evpn(ri);
	if (!parent_ri)
		return 0;

	/* See if of family L2VPN/EVPN */
	dest = parent_ri->net;
	if (!dest)
		return 0;
	table = bgp_dest_table(dest);
	if (table &&
	    table->afi == AFI_L2VPN &&
	    table->safi == SAFI_EVPN)
		return 1;
	return 0;
}

#define IS_PATH_IMPORTED_FROM_EVPN_TABLE(pi)                                                      \
	(pi->sub_type == BGP_ROUTE_IMPORTED && is_route_parent_evpn(pi))

#define IS_L2VPN_AFI_IN_NON_DEFAULT_VRF(bgp, afi, safi)                                           \
	(afi == AFI_L2VPN && safi == SAFI_EVPN && !is_evpn_underlay(bgp))

/* Flag if the route path's family is EVPN. */
static inline bool is_pi_family_evpn(struct bgp_path_info *pi)
{
	return is_pi_family_matching(pi, AFI_L2VPN, SAFI_EVPN);
}

static inline bool evpn_resolve_overlay_index(void)
{
	struct bgp *underlay = bgp_get_evpn_default_underlay_vrf();

	return underlay ? underlay->resolve_overlay_index : false;
}

extern void bgp_evpn_vrf_upsert_prefix_as_type5_route(struct bgp *bgp_vrf, struct bgp_path_info *originator,
					   const struct prefix *p, struct attr *src_attr,
					   afi_t afi, safi_t safi, uint32_t addpath_id);
extern void bgp_evpn_vrf_upsert_prefix_as_type5_route_rt_override(
	struct bgp *bgp_vrf, struct bgp_path_info *originator, const struct prefix *p,
	struct attr *src_attr, afi_t afi, safi_t safi, uint32_t addpath_id,
	struct ecommunity *rt_override);
extern void bgp_evpn_vrf_delete_prefix_as_type5_route(struct bgp *bgp_vrf,
					  const struct bgp_path_info *originator,
					  const struct prefix *p, afi_t afi, safi_t safi,
					  uint32_t addpath_id);
extern void bgp_evpn_vrf_eject_afi_safi_prefixes_and_withdraw_their_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					   safi_t safi);
extern void bgp_evpn_vrf_inject_safi_afi_prefixes_and_originate_as_type5_routes(struct bgp *bgp_vrf, afi_t afi,
					    safi_t safi);
extern void bgp_evpn_vrf_delete(struct bgp *bgp_vrf);
extern void bgp_evpn_handle_router_id_update(struct bgp *bgp, int withdraw);
extern char *bgp_evpn_label2str(mpls_label_t *label, uint8_t num_labels,
				char *buf, int len);
extern void bgp_evpn_route2json(const struct prefix_evpn *p, json_object *json);
extern void bgp_evpn_encode_prefix(struct stream *s, const struct prefix *p,
				   const struct prefix_rd *prd,
				   mpls_label_t *label, uint8_t num_labels,
				   struct attr *attr, bool addpath_capable,
				   uint32_t addpath_tx_id);
extern int bgp_evpn_parse_and_process_evpn_nlri(struct peer *peer, struct attr *attr,
			       struct bgp_nlri *packet, bool withdraw);
extern int bgp_evpn_import_global_received_route(struct bgp *bgp, afi_t afi, safi_t safi,
				 const struct prefix *p,
				 struct bgp_path_info *ri);
extern int bgp_evpn_unimport_route(struct bgp *bgp, afi_t afi, safi_t safi,
				   const struct prefix *p,
				   struct bgp_path_info *ri);
extern void bgp_evpn_vrf_inject_prefix_and_originate_as_type5_route(struct bgp *bgp, struct bgp_dest *dest,
					struct bgp_path_info *pi, afi_t afi, safi_t safi);
extern void bgp_evpn_unexport_type5_route(struct bgp *bgp, const struct bgp_dest *dest,
					  const struct bgp_path_info *pi, afi_t afi, safi_t safi);
extern void
bgp_reimport_evpn_routes_upon_macvrf_soo_change(struct bgp *bgp,
						struct ecommunity *old_soo,
						struct ecommunity *new_soo);
extern void bgp_reimport_evpn_routes_upon_martian_change(
	struct bgp *bgp, enum bgp_martian_type martian_type, void *old_martian,
	void *new_martian);
extern void
bgp_filter_evpn_routes_upon_martian_change(struct bgp *bgp,
					   enum bgp_martian_type martian_type);
extern int bgp_evpn_local_macip_del(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
					int state);
extern int bgp_evpn_local_macip_add(struct bgp *bgp, vni_t vni,
				    struct ethaddr *mac, struct ipaddr *ip,
				    uint8_t flags, uint32_t seq, esi_t *esi);
extern int bgp_evpn_add_local_l3vni(struct bgp *underlay_vrf, vni_t vni, vrf_id_t vrf_id,
				    struct ethaddr *rmac, struct ethaddr *vrr_rmac,
				    struct ipaddr *originator_ip, bool prefix_routes_only,
				    ifindex_t svi_ifindex, bool is_anycast_mac,
				    const struct bgp_evpn_vni_dp_info *dp);
extern int bgp_evpn_del_local_l3vni(struct bgp *underlay_vrf, vni_t l3vni, vrf_id_t vrf_id);
extern void bgp_evpn_instance_down(struct bgp *bgp);
extern int bgp_evpn_del_local_l2vni(struct bgp *underlay_vrf, vni_t vni);
extern int bgp_evpn_add_local_l2vni(struct bgp *underlay_vrf, vni_t vni,
				    struct ipaddr *originator_ip, vrf_id_t tenant_vrf_id,
				    struct in_addr mcast_grp, ifindex_t svi_ifindex,
				    const struct bgp_evpn_vni_dp_info *dp);
extern void bgp_evpn_flood_control_change(struct bgp *bgp);
extern void bgp_evpn_cleanup_on_disable(struct bgp *bgp);
/* Re-send all VNI intents (their payload carries the resolved underlay) */
extern void bgp_evpn_vni_intent_resync(void);
extern void bgp_evpn_delete_auto_discovered_evis(struct bgp *bgp_evpn_mi);
extern void bgp_evpn_clean_and_free(struct bgp *bgp);
extern void bgp_evpn_init(struct bgp *bgp);
extern void bgp_evpn_global_init(void);
extern void bgp_evpn_global_fini(void);
extern int bgp_evpn_get_type5_prefixlen(const struct prefix *pfx);
extern bool bgp_evpn_is_prefix_nht_supported(const struct prefix *pfx);
extern void bgp_evpn_vrf_update_advertise_originated_type_5_routes(struct bgp *bgp_vrf);
extern void bgp_evpn_show_remote_ip_hash(struct bgp_evpn_evi *evi, struct vty *vty);
extern bool bgp_evpn_is_gateway_ip_resolved(struct bgp_nexthop_cache *bnc);
extern void bgp_evpn_handle_resolve_overlay_index_set(struct bgp_evpn_evi *evi);
extern void bgp_evpn_handle_resolve_overlay_index_unset(struct bgp_evpn_evi *evi);
extern mpls_label_t *bgp_evpn_path_info_labels_get_l3vni(mpls_label_t *labels,
							 uint8_t num_labels);
extern vni_t bgp_evpn_path_info_get_l3vni(const struct bgp_path_info *pi);
extern bool bgp_evpn_mpath_has_dvni(const struct bgp *bgp_vrf,
				    struct bgp_path_info *mpinfo);
extern bool is_route_injectable_into_evpn(struct bgp_path_info *pi);
extern bool is_route_injectable_into_evpn_non_supp(struct bgp_path_info *pi);
extern void bgp_aggr_supp_withdraw_from_evpn(struct bgp *bgp, afi_t afi,
					     safi_t safi);

extern enum zclient_send_status evpn_zebra_install(struct bgp *bgp,
						   struct bgp_evpn_evi *evi,
						   const struct prefix_evpn *p,
						   struct bgp_path_info *pi);
extern enum zclient_send_status
evpn_zebra_uninstall(struct bgp *bgp, struct bgp_evpn_evi *evi,
		     const struct prefix_evpn *p, struct bgp_path_info *pi,
		     bool is_sync);
bool bgp_evpn_skip_vrf_import_of_local_es(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
					  struct bgp_path_info *pi, int install);
int _bgp_evpn_vrf_uninstall_route_entry(struct bgp *bgp_vrf, const struct prefix_evpn *evp,
				      struct bgp_path_info *parent_pi);
extern void bgp_zebra_evpn_pop_items_from_announce_fifo(struct bgp_evpn_evi *evi);
extern int bgp_evpn_evi_install_uninstall_global_routes(struct bgp_evpn_evi *evi, bool install);
extern int bgp_evpn_evi_install_uninstall_global_routes_fifo(bool install);

extern void bgp_evpn_fill_rmac_nh_to_attr(struct bgp *bgp_vrf, struct attr *attr,
					  struct prefix_evpn *evp, struct ipaddr *vtep_ip);
#endif /* _QUAGGA_BGP_EVPN_H */
