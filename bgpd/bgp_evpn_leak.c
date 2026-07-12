// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN local auto route leak - see bgp_evpn_leak.h for the concept.
 *
 * Copyright (C) 2026 Robin Christ
 */

#include <zebra.h>

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_leak.h"

bool bgp_lal_export_effective(struct bgp *bgp_vrf)
{
	struct bgp *bgp_default;

	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
		return false;

	if (bgp_vrf->evpn_lal_export_cfgd != BGP_LAL_INHERIT)
		return bgp_vrf->evpn_lal_export_cfgd == BGP_LAL_ENABLE;

	bgp_default = bgp_get_default();
	return bgp_default && bgp_default->evpn_lal_export_cfgd == BGP_LAL_ENABLE;
}

bool bgp_lal_import_effective(struct bgp *bgp_vrf)
{
	struct bgp *bgp_default;

	if (bgp_vrf->inst_type != BGP_INSTANCE_TYPE_VRF)
		return false;

	if (bgp_vrf->evpn_lal_import_cfgd != BGP_LAL_INHERIT)
		return bgp_vrf->evpn_lal_import_cfgd == BGP_LAL_ENABLE;

	bgp_default = bgp_get_default();
	return bgp_default && bgp_default->evpn_lal_import_cfgd == BGP_LAL_ENABLE;
}

/* The CLI already rejects combining local-auto-route-leak with the classic
 * leak machinery on the same tenant instance, but only for *explicit*
 * per-VRF knobs: the default instance's process-wide default may be enabled
 * while classic-leak VRFs exist. Such VRFs must simply never participate.
 */
static bool bgp_lal_classic_leak_cfgd(struct bgp *bgp)
{
	afi_t afi;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		if (CHECK_FLAG(bgp->af_flags[afi][SAFI_UNICAST],
			       BGP_CONFIG_VRF_TO_VRF_IMPORT | BGP_CONFIG_VRF_TO_VRF_EXPORT |
				       BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT |
				       BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT))
			return true;
	}

	return false;
}

static bool bgp_lal_dest_eligible(struct bgp *src, struct bgp *dst)
{
	if (dst == src)
		return false;
	if (dst->inst_type != BGP_INSTANCE_TYPE_VRF)
		return false;
	if (!bgp_lal_import_effective(dst))
		return false;
	if (bgp_lal_classic_leak_cfgd(dst))
		return false;

	return true;
}

static void bgp_lal_dests_add(struct vrf_mapped_bgp_instance_slu_head *out, struct bgp *dst)
{
	struct vrf_mapped_bgp_instance *item;

	item = vrf_mapped_bgp_instance_new(dst);
	if (vrf_mapped_bgp_instance_slu_add(out, item) != NULL)
		vrf_mapped_bgp_instance_free(item); /* already present */
}

void bgp_lal_compute_dests(struct bgp *src, struct vrf_mapped_bgp_instance_slu_head *out)
{
	struct bgp_evpn_effective_fq_rt *rt;
	struct vrf_mapped_bgp_instance *mapped;

	if (src->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;
	if (!bgp_lal_export_effective(src))
		return;
	if (bgp_lal_classic_leak_cfgd(src))
		return;

	frr_each (bgp_evpn_effective_fq_rt_slu, &src->effective_fq_export_rts, rt) {
		struct vrf_fq_irt_node *fq_irt;
		struct vrf_wildcard_irt_node *wc_irt;

		fq_irt = lookup_vrf_fq_irt_node_by_ecom_val(rt->ecom_val);
		if (fq_irt) {
			frr_each (vrf_mapped_bgp_instance_slu, &fq_irt->vrfs, mapped) {
				if (bgp_lal_dest_eligible(src, mapped->bgp))
					bgp_lal_dests_add(out, mapped->bgp);
			}
		}

		/* A wildcard import RT (*:local-admin) matches any exporter
		 * carrying that local-admin - same semantics as the EVPN
		 * import matcher.
		 */
		wc_irt = lookup_vrf_wildcard_irt_node_by_ecom_val(rt->ecom_val);
		if (wc_irt) {
			frr_each (vrf_mapped_bgp_instance_slu, &wc_irt->vrfs, mapped) {
				if (bgp_lal_dest_eligible(src, mapped->bgp))
					bgp_lal_dests_add(out, mapped->bgp);
			}
		}
	}
}

void bgp_lal_reconcile_source(struct bgp *src)
{
	struct vrf_mapped_bgp_instance_slu_head new_dests;
	struct vrf_mapped_bgp_instance *item, *next;

	vrf_mapped_bgp_instance_slu_init(&new_dests);
	bgp_lal_compute_dests(src, &new_dests);

	/* Removed destinations: flush what we leaked into them */
	frr_each_safe (vrf_mapped_bgp_instance_slu, &src->lal_dests, item) {
		struct vrf_mapped_bgp_instance key = { .bgp = item->bgp };

		if (vrf_mapped_bgp_instance_slu_find(&new_dests, &key))
			continue;

		bgp_lal_flush_dest_from_source(item->bgp, src);
		vrf_mapped_bgp_instance_slu_del(&src->lal_dests, item);
		vrf_mapped_bgp_instance_free(item);
	}

	/* Added destinations: leak the full source RIB into them */
	while ((next = vrf_mapped_bgp_instance_slu_pop(&new_dests))) {
		if (vrf_mapped_bgp_instance_slu_add(&src->lal_dests, next) != NULL) {
			vrf_mapped_bgp_instance_free(next); /* unchanged pair */
			continue;
		}

		bgp_lal_leak_rib_to_dest(src, next->bgp);
	}

	vrf_mapped_bgp_instance_slu_fini(&new_dests);
}

void bgp_lal_reconcile_all(void)
{
	struct listnode *node;
	struct bgp *bgp;

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, bgp))
		bgp_lal_reconcile_source(bgp);
}

/* Full-table walkers - implemented with the leak engine in a follow-up
 * commit; adjacency bookkeeping is functional without them.
 */
void bgp_lal_leak_rib_to_dest(struct bgp *src, struct bgp *dst)
{
}

void bgp_lal_flush_dest_from_source(struct bgp *dst, struct bgp *src)
{
}
