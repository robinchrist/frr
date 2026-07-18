// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-interface northbound apply callbacks (M7 batch B4).
 *
 * First live batch for the proteus-interface module: bgp_nb.c flips the
 * module registration from its ignore_cfg_cbs stub to the real callback
 * table below (whole-module activation -- the complete table must land in
 * the same commit as the flip, or nb_validate_callbacks() exit(1)s at
 * startup; the M6 B9 regenerate-and-flip rule at module granularity).
 *
 * bgpd only owns the two interface-level 'mpls bgp ...' flags. The
 * 'description' leaf and the ipv6-nd subtree are zebra's surface, modeled
 * for round-trip/leafref completeness only, and stay reject-stubbed
 * permanently -- bgpd must never claim them.
 */
#include <zebra.h>
#include "lib/northbound.h"
#include "lib/vrf.h"
#include "lib/if.h"
#include "lib/yang_wrappers.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_nb.h"

/* Both 'mpls bgp ...' DEFPYs shared one body shape (bgp_vty.c, retired):
 * flip one BGP_INTERFACE_* flag on the interface's bgp_interface info and,
 * on a real transition only, trigger an NHT update so eBGP sessions over
 * the interface re-evaluate their next hops.
 *
 * Interface resolution is get-not-lookup with the same arguments as the
 * surviving bgp_interface node-entry DEFPY_NOSH: the config may arrive
 * before zebra's interface announcements, and bgp_if_new_hook sets up
 * ifp->info on creation either way. The 'interface NAME vrf VRF' netns
 * form is not modeled (see proteus-interface.yang).
 */
static void proteus_interface_mpls_flag_apply(struct interface *ifp, uint32_t flag, bool enable)
{
	struct bgp_interface *iifp = ifp->info;
	bool check;

	if (!iifp)
		return;

	check = CHECK_FLAG(iifp->flags, flag);
	if (check == enable)
		return;

	if (enable)
		SET_FLAG(iifp->flags, flag);
	else
		UNSET_FLAG(iifp->flags, flag);

	/* trigger a nht update on eBGP sessions */
	if (if_is_operative(ifp))
		bgp_nht_ifp_up(ifp);
}

static int proteus_interface_mpls_leaf_modify(struct nb_cb_modify_args *args, uint32_t flag)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	ifp = if_get_by_name(yang_dnode_get_string(args->dnode, "../name"), VRF_UNKNOWN,
			     VRF_DEFAULT_NAME);
	proteus_interface_mpls_flag_apply(ifp, flag, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int proteus_interface_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Pre-create the interface (and its bgp_interface info via
	 * bgp_if_new_hook) so the leaf applies below always find it. */
	if_get_by_name(yang_dnode_get_string(args->dnode, "name"), VRF_UNKNOWN, VRF_DEFAULT_NAME);

	return NB_OK;
}

int proteus_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Destroying the list entry destroys its leaves without individual
	 * callbacks, so clear both owned flags here (each transition-only,
	 * with the same NHT kick as the leaf path). The interface itself is
	 * not deleted -- legacy config removal never deleted interfaces
	 * either. */
	ifp = if_lookup_by_name(yang_dnode_get_string(args->dnode, "name"), VRF_DEFAULT);
	if (!ifp)
		return NB_OK;

	proteus_interface_mpls_flag_apply(ifp, BGP_INTERFACE_MPLS_BGP_FORWARDING, false);
	proteus_interface_mpls_flag_apply(ifp, BGP_INTERFACE_MPLS_L3VPN_SWITCHING, false);

	return NB_OK;
}

int proteus_interface_description_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/description");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int proteus_interface_description_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/description");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int proteus_interface_mpls_bgp_forwarding_modify(struct nb_cb_modify_args *args)
{
	return proteus_interface_mpls_leaf_modify(args, BGP_INTERFACE_MPLS_BGP_FORWARDING);
}

int proteus_interface_mpls_bgp_l3vpn_multi_domain_switching_modify(struct nb_cb_modify_args *args)
{
	return proteus_interface_mpls_leaf_modify(args, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
}

int proteus_interface_ipv6_nd_ra_interval_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/ipv6-nd/ra-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int proteus_interface_ipv6_nd_ra_interval_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/ipv6-nd/ra-interval");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int proteus_interface_ipv6_nd_ra_interval_msec_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/ipv6-nd/ra-interval-msec");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int proteus_interface_ipv6_nd_ra_interval_msec_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len,
			 "zebra-owned proteus-interface node, not implemented by bgpd: %s",
			 "/proteus-interface:interface/ipv6-nd/ra-interval-msec");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
