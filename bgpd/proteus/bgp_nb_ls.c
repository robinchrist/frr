// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * BGP northbound callbacks: link-state address family (M9).
 * Copyright (C) 2026 Robin Christ, partimus GmbH
 */

#include <zebra.h>

#include "northbound.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_ls.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/proteus/bgp_nb_local.h"

/*
 * 'distribute bgp-fabric-link-state [instance-id WORD]'.
 *
 * Presence-container pattern: the container's own destroy callback turns
 * distribution off (the legacy 'no distribute' body), while apply_finish on
 * the container converges enable/instance-id from the FINAL tree - it fires
 * for both the initial create and an instance-id respec, and legacy's
 * withdraw-all-then-re-export on an instance-id change is reproduced here.
 * The instance-id leaf itself keeps no-op callbacks (registered so
 * nb_validate_callbacks() is satisfied).
 */
int instance_afi_safis_link_state_distribute_create(struct nb_cb_create_args *args)
{
	return NB_OK;
}

int instance_afi_safis_link_state_distribute_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp || !bgp->ls_info || !bgp->ls_info->enable_distribution)
		return NB_OK;

	bgp_redistribute_unset(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0);

	bgp->ls_info->enable_distribution = false;
	bgp->ls_info->instance_id = 0;
	bgp_ls_withdraw_all(bgp);

	return NB_OK;
}

void instance_afi_safis_link_state_distribute_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp = bgp_nb_instance_lookup(args->dnode);
	uint64_t instance_id = 0;

	if (!bgp)
		return;

	if (!bgp->ls_info) {
		zlog_warn("%s: BGP-LS not initialized, cannot enable fabric distribution",
			  __func__);
		return;
	}

	if (yang_dnode_exists(args->dnode, "instance-id"))
		instance_id = yang_dnode_get_uint64(args->dnode, "instance-id");

	if (bgp->ls_info->enable_distribution && bgp->ls_info->instance_id == instance_id)
		return;

	/* If already enabled with a different instance-id, withdraw all
	 * existing NLRIs before re-exporting with the new instance-id. */
	if (bgp->ls_info->enable_distribution && bgp->ls_info->instance_id != instance_id)
		bgp_ls_withdraw_all(bgp);

	bgp->ls_info->instance_id = instance_id;
	bgp->ls_info->enable_distribution = true;

	bgp_redist_add(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0);
	if (bgp_redistribute_set(bgp, AFI_IP6, ZEBRA_ROUTE_ALL, 0, false) != CMD_SUCCESS)
		zlog_warn("%s: failed to subscribe to IPv6 ZEBRA_ROUTE_ALL redistribution",
			  __func__);

	if (bgp_zclient && bgp_zclient->sock >= 0)
		bgp_zebra_srv6_manager_get_locator(NULL);

	if (bgp_ls_export_bgp_topology(bgp) != 0)
		zlog_warn("%s: failed to export BGP topology", __func__);
}

int instance_afi_safis_link_state_distribute_instance_id_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int instance_afi_safis_link_state_distribute_instance_id_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

/*
 * 'neighbor X local-link-id (1-4294967295)' / 'neighbor X remote-link-id
 * (1-4294967295)': BGP-LS link identifiers, session-level, valid on
 * neighbors and peer-groups (the legacy DEFPYs used
 * peer_and_group_lookup_vty(); a group resolves to group->conf and, as in
 * legacy, is not propagated to members).
 */
static struct peer *bgp_nb_ls_link_id_peer(const struct lyd_node *dnode)
{
	struct peer_group *group;

	if (yang_dnode_get_parent(dnode, "neighbor"))
		return bgp_nb_neighbor_lookup(dnode);

	group = bgp_nb_peer_group_lookup(dnode);
	return group ? group->conf : NULL;
}

static int bgp_nb_ls_link_id_apply(const struct lyd_node *dnode, bool local, bool set,
				   uint32_t link_id)
{
	struct peer *peer = bgp_nb_ls_link_id_peer(dnode);
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	uint64_t flag = local ? PEER_FLAG_LS_LOCAL_LINK_ID : PEER_FLAG_LS_REMOTE_LINK_ID;
	uint32_t *value;

	if (!peer || !bgp)
		return NB_OK;

	value = local ? &peer->ls_local_link_id : &peer->ls_remote_link_id;

	if (set) {
		if (CHECK_FLAG(peer->flags, flag) && *value == link_id)
			return NB_OK;
	} else {
		if (!CHECK_FLAG(peer->flags, flag))
			return NB_OK;
	}

	/* Withdraw the existing link NLRI before changing the key. */
	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_withdraw_bgp_link(bgp, peer);

	if (set) {
		*value = link_id;
		SET_FLAG(peer->flags, flag);
	} else {
		*value = 0;
		UNSET_FLAG(peer->flags, flag);
	}

	/* Re-originate with the new (or fallback) link ID. */
	if (bgp->ls_info && bgp->ls_info->enable_distribution)
		bgp_ls_originate_bgp_link(bgp, peer);

	return NB_OK;
}

int bgp_nb_neighbor_ls_local_link_id_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_ls_link_id_apply(args->dnode, true, true,
				       yang_dnode_get_uint32(args->dnode, NULL));
}

int bgp_nb_neighbor_ls_local_link_id_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_ls_link_id_apply(args->dnode, true, false, 0);
}

int bgp_nb_neighbor_ls_remote_link_id_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_ls_link_id_apply(args->dnode, false, true,
				       yang_dnode_get_uint32(args->dnode, NULL));
}

int bgp_nb_neighbor_ls_remote_link_id_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;
	return bgp_nb_ls_link_id_apply(args->dnode, false, false, 0);
}

/* Per-neighbor / per-peer-group link-state AF arms: thin AFI/SAFI wrappers
 * over the shared per-AF helpers, the flowspec pattern (M8.5 B-fs-af). */
int instance_neighbor_afi_safis_link_state_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_activate_modify(args, AFI_BGP_LS, SAFI_BGP_LS);
}

int instance_neighbor_afi_safis_link_state_filters_route_map_in_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_IN);
}

int instance_neighbor_afi_safis_link_state_filters_route_map_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_IN);
}

int instance_neighbor_afi_safis_link_state_filters_route_map_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_neighbor_af_route_map_modify(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_OUT);
}

int instance_neighbor_afi_safis_link_state_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_neighbor_af_route_map_destroy(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_OUT);
}

int instance_peer_group_afi_safis_link_state_activate_modify(struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_group_af_activate_modify(args, AFI_BGP_LS, SAFI_BGP_LS);
}

int instance_peer_group_afi_safis_link_state_filters_route_map_in_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_group_af_route_map_modify(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_IN);
}

int instance_peer_group_afi_safis_link_state_filters_route_map_in_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_group_af_route_map_destroy(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_IN);
}

int instance_peer_group_afi_safis_link_state_filters_route_map_out_modify(
	struct nb_cb_modify_args *args)
{
	return bgp_nb_peer_group_af_route_map_modify(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_OUT);
}

int instance_peer_group_afi_safis_link_state_filters_route_map_out_destroy(
	struct nb_cb_destroy_args *args)
{
	return bgp_nb_peer_group_af_route_map_destroy(args, AFI_BGP_LS, SAFI_BGP_LS, RMAP_OUT);
}
