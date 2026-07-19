// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Interface-level northbound apply callbacks (workstream C).
 *
 * bgpd's two interface-level 'mpls bgp ...' flags augment frr-interface's
 * interface list (proteus-bgp.yang 'augment /frr-interface:lib/interface',
 * the frr-zebra pattern): the interface list itself is lib's surface
 * (frr_interface_info in lib/if.c, registered by bgp_main.c), bgpd only
 * implements the two leaves under its own 'bgp' container. The leaves were
 * previously modeled in the standalone proteus-interface module; that
 * module is now dormant (ignore_cfg_cbs stub in bgp_nb.c) pending removal.
 *
 * No create/destroy callbacks are needed here: the 'bgp' container is a
 * non-presence container and both leaves carry defaults, so every change
 * (including 'no ...' destroying the explicit leaf) surfaces as a modify.
 * Deleting the whole 'interface NAME' entry runs lib_interface_destroy,
 * which validates the interface as inactive and if_delete()s it -- the
 * bgp_interface info (and its flags) is freed via bgp_if_delete_hook, so
 * no per-leaf cleanup callback can or needs to fire on that path.
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
 * Interface resolution is get-not-lookup: the config may arrive before
 * zebra's interface announcements, and bgp_if_new_hook sets up ifp->info
 * on creation either way. The 'interface NAME vrf VRF' netns form is not
 * modeled on frr-interface's config tree bgpd sees.
 */
static void bgp_interface_mpls_flag_apply(struct interface *ifp, uint32_t flag, bool enable)
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

static int bgp_interface_mpls_leaf_modify(struct nb_cb_modify_args *args, uint32_t flag)
{
	struct interface *ifp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* leaf -> 'bgp' container -> interface list entry (key 'name') */
	ifp = if_get_by_name(yang_dnode_get_string(args->dnode, "../../name"), VRF_UNKNOWN,
			     VRF_DEFAULT_NAME);
	bgp_interface_mpls_flag_apply(ifp, flag, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int lib_interface_bgp_mpls_bgp_forwarding_modify(struct nb_cb_modify_args *args)
{
	return bgp_interface_mpls_leaf_modify(args, BGP_INTERFACE_MPLS_BGP_FORWARDING);
}

int lib_interface_bgp_mpls_bgp_l3vpn_multi_domain_switching_modify(struct nb_cb_modify_args *args)
{
	return bgp_interface_mpls_leaf_modify(args, BGP_INTERFACE_MPLS_L3VPN_SWITCHING);
}
