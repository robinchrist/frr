// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN local auto route leak - see bgp_evpn_leak.h for the concept.
 *
 * Copyright (C) 2026 Robin Christ
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_attr.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_nht.h"
#include "bgpd/bgp_debug.h"
#include "bgpd/bgp_evpn.h"
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
	if (dst->vrf_id == VRF_UNKNOWN)
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
	if (src->vrf_id == VRF_UNKNOWN)
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

bool bgp_lal_path_is_lal(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent;
	struct bgp_table *table;

	if (pi->sub_type != BGP_ROUTE_IMPORTED || !pi->extra || !pi->extra->vrfleak ||
	    !pi->extra->vrfleak->parent)
		return false;

	parent = pi->extra->vrfleak->parent;
	if (!parent->net)
		return false;

	table = bgp_dest_table(parent->net);
	return table && table->safi == SAFI_UNICAST;
}

/* The instance the parent path lives in - the previous hop of the leak
 * chain (NOT necessarily the nexthop VRF, which is vrfleak->bgp_orig, the
 * ultimate origin).
 */
static struct bgp *bgp_lal_path_immediate_source(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent = pi->extra->vrfleak->parent;

	return bgp_dest_table(parent->net)->bgp;
}

static bool bgp_lal_source_path_eligible(struct bgp_path_info *pi)
{
	if (bgp_path_suppressed(pi))
		return false;

	/* Any imported path - EVPN-, VPN- or LAL-imported - is blocked from
	 * onward propagation by default; the re-export-imported config is
	 * the single opt-in (follow-up commits).
	 */
	if (pi->sub_type == BGP_ROUTE_IMPORTED && pi->extra && pi->extra->vrfleak &&
	    pi->extra->vrfleak->parent)
		return false;

	return true;
}

/* Sibling of leak_update_nexthop_valid() (bgp_mplsvpn.c), minus the
 * VPN-only parts (SRv6/labels). The ultimate-parent walk keeps the
 * NHT exemptions correct across multi-hop chains.
 */
static bool bgp_lal_nexthop_valid(struct bgp *dst, struct attr *new_attr, afi_t afi,
				  struct bgp_path_info *src_pi, struct bgp_path_info *bpi,
				  struct bgp *bgp_orig, const struct prefix *p)
{
	struct bgp_path_info *bpi_ultimate;
	struct bgp_table *table;
	struct interface *ifp;

	bpi_ultimate = bgp_get_imported_bpi_ultimate(src_pi);
	table = bgp_dest_table(bpi_ultimate->net);

	/* The nexthop is invalid if the origin VRF does not exist */
	if (bgp_orig->vrf_id == VRF_UNKNOWN)
		return false;

	/* The nexthop is invalid if the origin VRF interface is down */
	ifp = if_get_vrf_loopback(bgp_orig->vrf_id);
	if (ifp && !if_is_up(ifp))
		return false;

	/* No nexthop tracking for redistributed routes or for EVPN-imported
	 * routes that get re-leaked
	 */
	if (bpi_ultimate->sub_type == BGP_ROUTE_REDISTRIBUTE || is_pi_family_evpn(bpi_ultimate) ||
	    CHECK_FLAG(bpi_ultimate->flags, BGP_PATH_ACCEPT_OWN))
		return true;

	if (bpi_ultimate->type == ZEBRA_ROUTE_BGP && bpi_ultimate->sub_type == BGP_ROUTE_STATIC &&
	    table && (table->safi == SAFI_UNICAST || table->safi == SAFI_LABELED_UNICAST)) {
		/* the route is defined with the "network <prefix>" command */
		if (CHECK_FLAG(bgp_orig->flags, BGP_FLAG_IMPORT_CHECK))
			return bgp_find_or_add_nexthop(dst, bgp_orig, afi, SAFI_UNICAST,
						       bpi_ultimate, NULL, 0, p, bpi_ultimate);
		return true;
	}

	if (bpi_ultimate->type == ZEBRA_ROUTE_BGP && bpi_ultimate->sub_type == BGP_ROUTE_AGGREGATE)
		return true;

	return bgp_find_or_add_nexthop(dst, bgp_orig, afi, SAFI_UNICAST, bpi, NULL, 0, p,
				       bpi_ultimate);
}

/* Sibling of leak_update() (bgp_mplsvpn.c), trimmed of the VPN-only
 * behavior (labels, SRv6, RT-change VPN withdraw, ACCEPT_OWN). Consumes
 * new_attr (stores or uninterns it); does NOT unlock bn.
 */
static struct bgp_path_info *bgp_lal_leak_update(struct bgp *dst, struct bgp_dest *bn,
						 struct attr *new_attr /* interned */, afi_t afi,
						 struct bgp_path_info *src_pi, struct bgp *bgp_orig,
						 const struct prefix *nexthop_orig)
{
	int debug = BGP_DEBUG(vpn, VPN_LEAK_FROM_VRF);
	const struct prefix *p = bgp_dest_get_prefix(bn);
	struct bgp_path_info *bpi;
	struct bgp_path_info *new;

	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->vrfleak && bpi->extra->vrfleak->parent == src_pi)
			break;
	}

	if (bpi) {
		if (CHECK_FLAG(src_pi->flags, BGP_PATH_REMOVED) &&
		    CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED)) {
			bgp_attr_unintern(&new_attr);
			return NULL;
		}

		if (!CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED) &&
		    attrhash_cmp(bpi->attr, new_attr) &&
		    bgp_lal_nexthop_valid(dst, new_attr, afi, src_pi, bpi, bgp_orig, p) ==
			    !!CHECK_FLAG(bpi->flags, BGP_PATH_VALID)) {
			bgp_attr_unintern(&new_attr);
			if (debug)
				zlog_debug("%s: ->%s: %pBD: Found local leak, no change",
					   __func__, dst->name_pretty, bn);
			return NULL;
		}

		bgp_path_info_set_flag(bn, bpi, BGP_PATH_ATTR_CHANGED);

		if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
			bgp_path_info_restore(bn, bpi);
		else
			bgp_aggregate_decrement(dst, p, bpi, afi, SAFI_UNICAST);
		bgp_attr_unintern(&bpi->attr);
		bpi->attr = new_attr;
		bpi->uptime = monotime(NULL);

		if (bgp_lal_nexthop_valid(dst, new_attr, afi, src_pi, bpi, bgp_orig, p))
			bgp_path_info_set_flag(bn, bpi, BGP_PATH_VALID);
		else
			bgp_path_info_unset_flag(bn, bpi, BGP_PATH_VALID);

		bgp_aggregate_increment(dst, p, bpi, afi, SAFI_UNICAST);
		bgp_process(dst, bn, bpi, afi, SAFI_UNICAST);

		if (debug)
			zlog_debug("%s: ->%s: %pBD: Found local leak, changed attr", __func__,
				   dst->name_pretty, bn);

		return bpi;
	}

	if (CHECK_FLAG(src_pi->flags, BGP_PATH_REMOVED)) {
		bgp_attr_unintern(&new_attr);
		return NULL;
	}

	if (bgp_orig->vrf_id == VRF_UNKNOWN) {
		bgp_attr_unintern(&new_attr);
		if (debug)
			zlog_debug("%s: ->%s: %pFX: origin VRF does not exist, not leaking",
				   __func__, dst->name_pretty, p);
		return NULL;
	}

	new = info_make(ZEBRA_ROUTE_BGP, BGP_ROUTE_IMPORTED, 0, dst->peer_self, new_attr, bn);

	bgp_path_info_extra_get(new);
	if (!new->extra->vrfleak)
		new->extra->vrfleak = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
					      sizeof(struct bgp_path_info_extra_vrfleak));

	if (src_pi->peer)
		new->extra->vrfleak->peer_orig = peer_lock(src_pi->peer);

	new->extra->vrfleak->parent = bgp_path_info_lock(src_pi);
	bgp_dest_lock_node((struct bgp_dest *)src_pi->net);

	new->extra->vrfleak->bgp_orig = bgp_lock(bgp_orig);

	if (nexthop_orig)
		new->extra->vrfleak->nexthop_orig = *nexthop_orig;

	if (bgp_lal_nexthop_valid(dst, new_attr, afi, src_pi, new, bgp_orig, p))
		bgp_path_info_set_flag(bn, new, BGP_PATH_VALID);
	else
		bgp_path_info_unset_flag(bn, new, BGP_PATH_VALID);

	bgp_path_info_add(bn, new);
	bgp_aggregate_increment(dst, p, new, afi, SAFI_UNICAST);
	bgp_process(dst, bn, new, afi, SAFI_UNICAST);

	if (debug)
		zlog_debug("%s: ->%s: %pBD: Added new local leak", __func__, dst->name_pretty, bn);

	return new;
}

static void bgp_lal_leak_path_to_dest(struct bgp *src, struct bgp_path_info *pi, struct bgp *dst)
{
	const struct prefix *p = bgp_dest_get_prefix(pi->net);
	afi_t afi = family2afi(p->family);
	struct attr static_attr;
	struct attr *new_attr;
	struct bgp_dest *bn;
	struct bgp *bgp_orig;
	struct prefix nexthop_orig = { 0 };

	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	/* bgp_orig is the nexthop VRF: the leaked copy keeps the source
	 * path's nexthop verbatim, which resolves in the ULTIMATE origin
	 * instance (relevant once re-export allows multi-hop chains).
	 */
	if (pi->extra && pi->extra->vrfleak && pi->extra->vrfleak->bgp_orig)
		bgp_orig = pi->extra->vrfleak->bgp_orig;
	else
		bgp_orig = src;

	/* never hand a route back to the instance whose table resolves its
	 * nexthop (the full traversal-chain guard lands in a follow-up)
	 */
	if (dst == bgp_orig)
		return;

	if (afi == AFI_IP) {
		nexthop_orig.family = AF_INET;
		nexthop_orig.u.prefix4 = pi->attr->nexthop;
		nexthop_orig.prefixlen = IPV4_MAX_BITLEN;
	} else {
		nexthop_orig.family = AF_INET6;
		nexthop_orig.u.prefix6 = pi->attr->mp_nexthop_global;
		nexthop_orig.prefixlen = IPV6_MAX_BITLEN;
	}

	/* shallow copy; no rewrite - local leaking attaches no RTs, the
	 * matching is purely between configured RT sets
	 */
	static_attr = *pi->attr;
	new_attr = bgp_attr_intern(&static_attr);

	bn = bgp_node_get(dst->rib[afi][SAFI_UNICAST], p);
	bgp_lal_leak_update(dst, bn, new_attr, afi, pi, bgp_orig, &nexthop_orig);
	bgp_dest_unlock_node(bn);
}

static void bgp_lal_remove_leaked_path(struct bgp *dst, struct bgp_dest *bn,
				       struct bgp_path_info *bpi, afi_t afi)
{
	bgp_aggregate_decrement(dst, bgp_dest_get_prefix(bn), bpi, afi, SAFI_UNICAST);
	bgp_path_info_mark_for_delete(bn, bpi);
	bgp_process(dst, bn, bpi, afi, SAFI_UNICAST);
}

void bgp_lal_from_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	struct vrf_mapped_bgp_instance *dest;

	if (!from_bgp || from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF ||
	    !vrf_mapped_bgp_instance_slu_count(&from_bgp->lal_dests))
		return;

	if (!bgp_lal_source_path_eligible(pi))
		return;

	frr_each (vrf_mapped_bgp_instance_slu, &from_bgp->lal_dests, dest)
		bgp_lal_leak_path_to_dest(from_bgp, pi, dest->bgp);
}

void bgp_lal_from_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	const struct prefix *p;
	afi_t afi;
	struct listnode *node;
	struct bgp *dst;

	if (!from_bgp || from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	p = bgp_dest_get_prefix(pi->net);
	afi = family2afi(p->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	/* Children are located by parent pointer across ALL instances, not
	 * via lal_dests - the adjacency may have changed since the leak
	 * (adjacency-change cleanup is the flush walkers' job, but a path
	 * withdraw must never miss a child).
	 */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, dst)) {
		struct bgp_dest *bn;
		struct bgp_path_info *bpi;

		if (dst == from_bgp || dst->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		bn = bgp_node_lookup(dst->rib[afi][SAFI_UNICAST], p);
		if (!bn)
			continue;

		for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
			if (bpi->extra && bpi->extra->vrfleak && bpi->extra->vrfleak->parent == pi)
				break;
		}

		if (bpi)
			bgp_lal_remove_leaked_path(dst, bn, bpi, afi);

		bgp_dest_unlock_node(bn);
	}
}

void bgp_lal_leak_rib_to_dest(struct bgp *src, struct bgp *dst)
{
	afi_t afi;
	struct bgp_dest *bn;
	struct bgp_path_info *pi;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (bn = bgp_table_top(src->rib[afi][SAFI_UNICAST]); bn;
		     bn = bgp_route_next(bn)) {
			for (pi = bgp_dest_get_bgp_path_info(bn); pi; pi = pi->next) {
				if (!bgp_lal_source_path_eligible(pi))
					continue;
				if (CHECK_FLAG(pi->flags, BGP_PATH_REMOVED))
					continue;
				bgp_lal_leak_path_to_dest(src, pi, dst);
			}
		}
	}
}

void bgp_lal_flush_dest_from_source(struct bgp *dst, struct bgp *src)
{
	afi_t afi;
	struct bgp_dest *bn;
	struct bgp_path_info *bpi, *bpi_next;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (bn = bgp_table_top(dst->rib[afi][SAFI_UNICAST]); bn;
		     bn = bgp_route_next(bn)) {
			bpi_next = bgp_dest_get_bgp_path_info(bn);
			while (bpi_next) {
				bpi = bpi_next;
				bpi_next = bpi->next;

				if (!bgp_lal_path_is_lal(bpi))
					continue;
				if (bgp_lal_path_immediate_source(bpi) != src)
					continue;

				bgp_lal_remove_leaked_path(dst, bn, bpi, afi);
			}
		}
	}
}

/* Instance teardown: synchronously flush every local-leak relationship the
 * instance participates in - children into it and its leaks out of the
 * other instances. Must run in bgp_delete() while the tables still exist.
 */
void bgp_lal_instance_down(struct bgp *bgp)
{
	struct vrf_mapped_bgp_instance *item;
	struct vrf_mapped_bgp_instance key = { .bgp = bgp };
	struct listnode *node;
	struct bgp *other;

	while ((item = vrf_mapped_bgp_instance_slu_pop(&bgp->lal_dests))) {
		bgp_lal_flush_dest_from_source(item->bgp, bgp);
		vrf_mapped_bgp_instance_free(item);
	}

	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, other)) {
		if (other == bgp)
			continue;

		item = vrf_mapped_bgp_instance_slu_find(&other->lal_dests, &key);
		if (!item)
			continue;

		bgp_lal_flush_dest_from_source(bgp, other);
		vrf_mapped_bgp_instance_slu_del(&other->lal_dests, item);
		vrf_mapped_bgp_instance_free(item);
	}
}
