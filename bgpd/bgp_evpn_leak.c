// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN local auto route leak - see bgp_evpn_leak.h for the concept.
 *
 * Copyright (C) 2026 Robin Christ
 */

#include <zebra.h>

#include "if.h"
#include "prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
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

static void bgp_lal_reexport_local_resync(struct bgp *bgp);

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

	/* Re-export destinations are per-route (rewritten RT sets) and thus
	 * not covered by the pair diff above - resync them whenever the RT
	 * landscape may have changed.
	 */
	bgp_lal_reexport_local_resync(src);
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

static bool bgp_lal_path_is_imported(struct bgp_path_info *pi)
{
	return pi->sub_type == BGP_ROUTE_IMPORTED && pi->extra && pi->extra->vrfleak &&
	       pi->extra->vrfleak->parent;
}

static bool bgp_lal_path_is_evpn_imported(struct bgp_path_info *pi)
{
	struct bgp_path_info *parent;
	struct bgp_table *table;

	if (!bgp_lal_path_is_imported(pi))
		return false;

	parent = pi->extra->vrfleak->parent;
	if (!parent->net)
		return false;

	table = bgp_dest_table(parent->net);
	return table && table->afi == AFI_L2VPN && table->safi == SAFI_EVPN;
}

/* imported path of a kind the re-export feature covers (EVPN- or
 * LAL-imported; never VPN-imported)
 */
bool bgp_lal_path_is_reexportable_import(struct bgp_path_info *pi)
{
	return bgp_lal_path_is_lal(pi) || bgp_lal_path_is_evpn_imported(pi);
}

/* re-export requires at least one configured RT to become active */
static bool bgp_lal_reexport_local_active(struct bgp *bgp)
{
	return bgp->evpn_reexport && CHECK_FLAG(bgp->evpn_reexport->scope, BGP_REEXPORT_SCOPE_LOCAL) &&
	       bgp->evpn_reexport->rt_ecom;
}

static bool bgp_lal_source_path_eligible(struct bgp *src, struct bgp_path_info *pi)
{
	if (bgp_path_suppressed(pi))
		return false;

	/* Imported paths are blocked from onward propagation by default;
	 * the re-export-imported block is the single opt-in, and only for
	 * EVPN- and LAL-imported paths (never VPN-imported ones).
	 */
	if (bgp_lal_path_is_imported(pi))
		return bgp_lal_reexport_local_active(src) &&
		       (bgp_lal_path_is_lal(pi) || bgp_lal_path_is_evpn_imported(pi));

	return true;
}

/* Loop guard: would leaking src_pi from src_bgp into dst_bgp revisit an
 * instance the path already traversed? The materialized traversal chain
 * makes cycles (including those closed by future re-export RT rewrites)
 * self-terminating; the depth cap is a pure resource backstop far above
 * any sane VRF chain.
 */
bool bgp_lal_would_loop(struct bgp_path_info *src_pi, struct bgp *src_bgp, struct bgp *dst_bgp)
{
	struct bgp_path_info_extra_vrfleak *vrfleak =
		src_pi->extra ? src_pi->extra->vrfleak : NULL;
	uint8_t i;

	if (dst_bgp == src_bgp)
		return true;

	if (!vrfleak || !vrfleak->lal_traversed)
		return false; /* first hop */

	if (vrfleak->lal_num_traversed + 1 >= BGP_LAL_MAX_HOPS) {
		zlog_warn("%s: local auto leak chain for %pBD would exceed %u hops, not leaking into %s",
			  __func__, src_pi->net, BGP_LAL_MAX_HOPS, dst_bgp->name_pretty);
		return true;
	}

	for (i = 0; i < vrfleak->lal_num_traversed; i++) {
		if (vrfleak->lal_traversed[i] == dst_bgp)
			return true;
	}

	return false;
}

/* chain(new) = chain(parent) + [src_bgp]; every entry bgp_lock()ed,
 * released in bgp_path_info_extra_free()
 */
static void bgp_lal_traversed_populate(struct bgp_path_info *new, struct bgp_path_info *src_pi,
				       struct bgp *src_bgp)
{
	struct bgp_path_info_extra_vrfleak *parent_vrfleak =
		src_pi->extra ? src_pi->extra->vrfleak : NULL;
	uint8_t parent_len = 0;
	uint8_t i;

	if (parent_vrfleak && parent_vrfleak->lal_traversed)
		parent_len = parent_vrfleak->lal_num_traversed;

	new->extra->vrfleak->lal_traversed = XCALLOC(MTYPE_BGP_ROUTE_EXTRA_VRFLEAK,
						     sizeof(struct bgp *) * (parent_len + 1));

	for (i = 0; i < parent_len; i++)
		new->extra->vrfleak->lal_traversed[i] =
			bgp_lock(parent_vrfleak->lal_traversed[i]);

	new->extra->vrfleak->lal_traversed[parent_len] = bgp_lock(src_bgp);
	new->extra->vrfleak->lal_num_traversed = parent_len + 1;
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
						 struct bgp_path_info *src_pi, struct bgp *src_bgp,
						 struct bgp *bgp_orig,
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

	bgp_lal_traversed_populate(new, src_pi, src_bgp);

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

/* Rewritten RT set for re-exporting an imported path (matching artifact
 * only - local leaking never attaches RTs to the leaked copy). Returns a
 * fresh ecommunity owned by the caller, or NULL when nothing applies.
 */
static struct ecommunity *bgp_lal_reexport_rt_set(struct bgp *bgp, struct bgp_path_info *pi)
{
	struct bgp_evpn_reexport_config *cfg = bgp->evpn_reexport;
	struct ecommunity *result = NULL;

	if (cfg->mode == BGP_REEXPORT_OVERRIDE)
		return ecommunity_dup(cfg->rt_ecom);

	/* additive: original carried RTs + configured */
	if (bgp_lal_path_is_evpn_imported(pi)) {
		/* The VRF copy had its RTs stripped on install - the original
		 * carried RTs live on the parent (EVPN) path's attr.
		 */
		struct bgp_path_info *parent = pi->extra->vrfleak->parent;
		struct ecommunity *parent_ecom = bgp_attr_get_ecommunity(parent->attr);
		uint32_t i;
		uint8_t *pnt;

		for (i = 0; parent_ecom && i < parent_ecom->size; i++) {
			struct ecommunity_val eval;

			pnt = parent_ecom->val + (i * parent_ecom->unit_size);
			if (pnt[1] != ECOMMUNITY_ROUTE_TARGET ||
			    (pnt[0] != ECOMMUNITY_ENCODE_AS && pnt[0] != ECOMMUNITY_ENCODE_IP &&
			     pnt[0] != ECOMMUNITY_ENCODE_AS4))
				continue;

			memcpy(&eval, pnt, ECOMMUNITY_SIZE);
			if (!result)
				result = ecommunity_new();
			ecommunity_add_val(result, &eval, true, false);
		}
	} else {
		/* LAL-imported: unicast paths carry no RTs - the "original"
		 * set is what the leak was matched on, the ultimate origin
		 * VRF's effective export RTs.
		 */
		struct bgp *bgp_orig = pi->extra->vrfleak->bgp_orig;
		struct bgp_evpn_effective_fq_rt *rt;

		if (bgp_orig) {
			frr_each (bgp_evpn_effective_fq_rt_slu, &bgp_orig->effective_fq_export_rts,
				  rt) {
				if (!result)
					result = ecommunity_new();
				ecommunity_add_val(result, &rt->ecom_val, true, false);
			}
		}
	}

	/* merge in the configured RTs (ecommunity_merge mutates arg 1, which
	 * is ours; cfg->rt_ecom is only read)
	 */
	if (!result)
		result = ecommunity_dup(cfg->rt_ecom);
	else
		result = ecommunity_merge(result, cfg->rt_ecom);

	return result;
}

/* Per-route destination set for a re-exported path: match the rewritten
 * RT set against the process-global import-RT tables. Additive mode makes
 * the set path-dependent, so the cached lal_dests cannot be used here.
 */
static void bgp_lal_reexport_compute_dests(struct bgp *src, struct ecommunity *rt_set,
					   struct vrf_mapped_bgp_instance_slu_head *out)
{
	uint32_t i;
	struct vrf_mapped_bgp_instance *mapped;

	for (i = 0; i < rt_set->size; i++) {
		struct ecommunity_val eval;
		struct vrf_fq_irt_node *fq_irt;
		struct vrf_wildcard_irt_node *wc_irt;

		memcpy(&eval, rt_set->val + (i * rt_set->unit_size), ECOMMUNITY_SIZE);

		fq_irt = lookup_vrf_fq_irt_node_by_ecom_val(eval);
		if (fq_irt) {
			frr_each (vrf_mapped_bgp_instance_slu, &fq_irt->vrfs, mapped) {
				if (bgp_lal_dest_eligible(src, mapped->bgp))
					bgp_lal_dests_add(out, mapped->bgp);
			}
		}

		wc_irt = lookup_vrf_wildcard_irt_node_by_ecom_val(eval);
		if (wc_irt) {
			frr_each (vrf_mapped_bgp_instance_slu, &wc_irt->vrfs, mapped) {
				if (bgp_lal_dest_eligible(src, mapped->bgp))
					bgp_lal_dests_add(out, mapped->bgp);
			}
		}
	}
}

static void bgp_lal_remove_leaked_path(struct bgp *dst, struct bgp_dest *bn,
				       struct bgp_path_info *bpi, afi_t afi);

static void bgp_lal_leak_path_to_dest(struct bgp *src, struct bgp_path_info *pi, struct bgp *dst)
{
	const struct prefix *p = bgp_dest_get_prefix(pi->net);
	afi_t afi = family2afi(p->family);
	struct attr static_attr;
	struct attr *new_attr;
	struct bgp_dest *bn;
	struct bgp_path_info *child;
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

	if (bgp_lal_would_loop(pi, src, dst))
		return;

	/* extra safety net on top of the chain guard */
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
	child = bgp_lal_leak_update(dst, bn, new_attr, afi, pi, src, bgp_orig, &nexthop_orig);
	bgp_dest_unlock_node(bn);

	/* Chain propagation: if the destination re-exports its imported
	 * routes into the local leak, the fresh child continues onward.
	 * Bounded by the traversal-chain guard (depth <= number of VRFs).
	 */
	if (child)
		bgp_lal_from_vrf_update(dst, child);
}

/* Remove the child of `pi` in dst's unicast table, if any (recursively
 * withdrawing grandchildren first).
 */
static void bgp_lal_withdraw_child_in_dest(struct bgp *src, struct bgp_path_info *pi,
					   struct bgp *dst, afi_t afi)
{
	const struct prefix *p = bgp_dest_get_prefix(pi->net);
	struct bgp_dest *bn;
	struct bgp_path_info *bpi;

	bn = bgp_node_lookup(dst->rib[afi][SAFI_UNICAST], p);
	if (!bn)
		return;

	for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
		if (bpi->extra && bpi->extra->vrfleak && bpi->extra->vrfleak->parent == pi)
			break;
	}

	if (bpi)
		bgp_lal_remove_leaked_path(dst, bn, bpi, afi);

	bgp_dest_unlock_node(bn);
}

static void bgp_lal_remove_leaked_path(struct bgp *dst, struct bgp_dest *bn,
				       struct bgp_path_info *bpi, afi_t afi)
{
	/* re-export chains: take down grandchildren first */
	bgp_lal_from_vrf_withdraw(dst, bpi);

	bgp_aggregate_decrement(dst, bgp_dest_get_prefix(bn), bpi, afi, SAFI_UNICAST);
	bgp_path_info_mark_for_delete(bn, bpi);
	bgp_process(dst, bn, bpi, afi, SAFI_UNICAST);
}

void bgp_lal_from_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	struct vrf_mapped_bgp_instance *dest;

	if (!from_bgp || from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	if (!vrf_mapped_bgp_instance_slu_count(&from_bgp->lal_dests) &&
	    !bgp_lal_reexport_local_active(from_bgp))
		return;

	if (!bgp_lal_source_path_eligible(from_bgp, pi))
		return;

	if (bgp_lal_path_is_imported(pi)) {
		/* Re-export: per-route destination set from the rewritten RT
		 * set (path-dependent in additive mode). Destinations no
		 * longer matching are pruned right here so that a parent
		 * attr change (e.g. changed RTs on the remote EVPN route)
		 * cleans up its stale children.
		 */
		struct vrf_mapped_bgp_instance_slu_head dests;
		struct vrf_mapped_bgp_instance key;
		struct ecommunity *rt_set;
		struct vrf_mapped_bgp_instance *item;
		struct listnode *node;
		struct bgp *dst;
		const struct prefix *p = bgp_dest_get_prefix(pi->net);
		afi_t afi = family2afi(p->family);

		if (afi != AFI_IP && afi != AFI_IP6)
			return;

		rt_set = bgp_lal_reexport_rt_set(from_bgp, pi);
		if (!rt_set)
			return;

		vrf_mapped_bgp_instance_slu_init(&dests);
		bgp_lal_reexport_compute_dests(from_bgp, rt_set, &dests);
		ecommunity_free(&rt_set);

		for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, dst)) {
			if (dst == from_bgp || dst->inst_type != BGP_INSTANCE_TYPE_VRF)
				continue;

			key.bgp = dst;
			if (vrf_mapped_bgp_instance_slu_find(&dests, &key))
				bgp_lal_leak_path_to_dest(from_bgp, pi, dst);
			else
				bgp_lal_withdraw_child_in_dest(from_bgp, pi, dst, afi);
		}

		while ((item = vrf_mapped_bgp_instance_slu_pop(&dests)))
			vrf_mapped_bgp_instance_free(item);
		vrf_mapped_bgp_instance_slu_fini(&dests);
		return;
	}

	frr_each (vrf_mapped_bgp_instance_slu, &from_bgp->lal_dests, dest)
		bgp_lal_leak_path_to_dest(from_bgp, pi, dest->bgp);
}

void bgp_lal_from_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi)
{
	afi_t afi;
	struct listnode *node;
	struct bgp *dst;

	if (!from_bgp || from_bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	afi = family2afi(bgp_dest_get_prefix(pi->net)->family);
	if (afi != AFI_IP && afi != AFI_IP6)
		return;

	/* Children are located by parent pointer across ALL instances, not
	 * via lal_dests - the adjacency may have changed since the leak
	 * (adjacency-change cleanup is the flush walkers' job, but a path
	 * withdraw must never miss a child).
	 */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, dst)) {
		if (dst == from_bgp || dst->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		bgp_lal_withdraw_child_in_dest(from_bgp, pi, dst, afi);
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
				/* imported (re-export) paths use per-route
				 * destination sets and are resynced by
				 * bgp_lal_reexport_local_resync(), not by
				 * pair-level walks
				 */
				if (bgp_lal_path_is_imported(pi))
					continue;
				if (!bgp_lal_source_path_eligible(src, pi))
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

/* ---------------------- re-export scope external ---------------------- */

static bool bgp_lal_reexport_external_active(struct bgp *bgp)
{
	return bgp->evpn_reexport &&
	       CHECK_FLAG(bgp->evpn_reexport->scope, BGP_REEXPORT_SCOPE_EXTERNAL) &&
	       bgp->evpn_reexport->rt_ecom;
}

/* Should this (bestpath) path be re-originated into EVPN as a type-5 with
 * the rewritten RT set? Driven from the bestpath injection hook in
 * bgp_route.c - the generic origination path stays blocked for imported
 * routes (is_route_injectable_into_evpn), this is the single opt-in.
 */
bool bgp_lal_reexport_external_applies(struct bgp *bgp, struct bgp_path_info *pi)
{
	if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return false;
	if (!bgp_lal_reexport_external_active(bgp))
		return false;
	if (bgp_path_suppressed(pi))
		return false;

	return bgp_lal_path_is_lal(pi) || bgp_lal_path_is_evpn_imported(pi);
}

struct ecommunity *bgp_lal_reexport_external_rt_set(struct bgp *bgp, struct bgp_path_info *pi)
{
	return bgp_lal_reexport_rt_set(bgp, pi);
}

/* Bring the externally re-originated type-5s in line with the current
 * config/RIB: for every prefix whose bestpath is an imported path, upsert
 * or delete its type-5. Needed on re-export config changes and when the
 * origination preconditions (underlay/L3VNI) come up - the bestpath hook
 * only fires on selection changes.
 */
void bgp_lal_reexport_external_resync(struct bgp *bgp)
{
	afi_t afi;
	struct bgp_dest *bn;
	struct bgp_path_info *pi;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (bn = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); bn;
		     bn = bgp_route_next(bn)) {
			for (pi = bgp_dest_get_bgp_path_info(bn); pi; pi = pi->next) {
				if (!CHECK_FLAG(pi->flags, BGP_PATH_SELECTED))
					continue;
				if (!bgp_lal_path_is_imported(pi))
					break; /* normal origination owns this prefix */

				if (bgp_lal_reexport_external_applies(bgp, pi)) {
					struct ecommunity *rt_override =
						bgp_lal_reexport_rt_set(bgp, pi);

					bgp_evpn_vrf_upsert_prefix_as_type5_route_rt_override(
						bgp, pi, bgp_dest_get_prefix(bn), pi->attr, afi,
						SAFI_UNICAST, 0, rt_override);
					if (rt_override)
						ecommunity_free(&rt_override);
				} else {
					bgp_evpn_vrf_delete_prefix_as_type5_route(
						bgp, pi, bgp_dest_get_prefix(bn), afi,
						SAFI_UNICAST, 0);
				}
				break; /* one bestpath per prefix */
			}
		}
	}
}

/* Flush all re-export-derived children of `src` (LAL paths elsewhere whose
 * parent is an imported path in src), then re-evaluate every imported path
 * against the current re-export config. Called on any event that may have
 * changed per-route re-export destination sets; parent-matched restore in
 * the leak core keeps unchanged children churn-free.
 */
static void bgp_lal_reexport_local_resync(struct bgp *bgp)
{
	afi_t afi;
	struct bgp_dest *bn;
	struct bgp_path_info *bpi, *bpi_next;
	struct listnode *node;
	struct bgp *dst;

	if (bgp->inst_type != BGP_INSTANCE_TYPE_VRF)
		return;

	/* flush stale children */
	for (ALL_LIST_ELEMENTS_RO(bm->bgp, node, dst)) {
		if (dst == bgp || dst->inst_type != BGP_INSTANCE_TYPE_VRF)
			continue;

		for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
			for (bn = bgp_table_top(dst->rib[afi][SAFI_UNICAST]); bn;
			     bn = bgp_route_next(bn)) {
				bpi_next = bgp_dest_get_bgp_path_info(bn);
				while (bpi_next) {
					bpi = bpi_next;
					bpi_next = bpi->next;

					if (!bgp_lal_path_is_lal(bpi))
						continue;
					if (bgp_lal_path_immediate_source(bpi) != bgp)
						continue;
					if (!bgp_lal_path_is_imported(bpi->extra->vrfleak->parent))
						continue;

					bgp_lal_remove_leaked_path(dst, bn, bpi, afi);
				}
			}
		}
	}

	if (!bgp_lal_reexport_local_active(bgp))
		return;

	/* re-evaluate all imported paths (the marked-for-delete children
	 * above are found by parent match and restored when still wanted)
	 */
	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		for (bn = bgp_table_top(bgp->rib[afi][SAFI_UNICAST]); bn;
		     bn = bgp_route_next(bn)) {
			for (bpi = bgp_dest_get_bgp_path_info(bn); bpi; bpi = bpi->next) {
				if (!bgp_lal_path_is_imported(bpi))
					continue;
				if (CHECK_FLAG(bpi->flags, BGP_PATH_REMOVED))
					continue;
				bgp_lal_from_vrf_update(bgp, bpi);
			}
		}
	}
}

/* ------------------- re-export-imported configuration ------------------- */

DEFINE_MTYPE_STATIC(BGPD, BGP_EVPN_REEXPORT_CFG, "BGP EVPN re-export-imported config");

/* Rebuild cfg->rt_ecom from the configured RT list. Called on every config
 * change; the engine reconciliation lands in a follow-up commit.
 */
static void bgp_lal_reexport_rebuild_ecom(struct bgp_evpn_reexport_config *cfg)
{
	struct bgp_evpn_cfgd_rt *cfgd_rt;
	struct ecommunity_val eval;

	if (cfg->rt_ecom)
		ecommunity_free(&cfg->rt_ecom);

	frr_each (bgp_evpn_cfgd_rt_slu, &cfg->rts, cfgd_rt) {
		if (!bgp_evpn_cfgd_rt_to_ecom_val(cfgd_rt, &eval))
			continue; /* cannot happen - wildcards are rejected at config time */

		if (!cfg->rt_ecom)
			cfg->rt_ecom = ecommunity_new();
		ecommunity_add_val(cfg->rt_ecom, &eval, true, false);
	}
}

struct bgp_evpn_reexport_config *bgp_lal_reexport_get(struct bgp *bgp)
{
	struct bgp_evpn_reexport_config *cfg;

	if (bgp->evpn_reexport)
		return bgp->evpn_reexport;

	cfg = XCALLOC(MTYPE_BGP_EVPN_REEXPORT_CFG, sizeof(*cfg));
	bgp_evpn_cfgd_rt_slu_init(&cfg->rts);
	cfg->mode = BGP_REEXPORT_ADDITIVE;
	cfg->scope = BGP_REEXPORT_SCOPE_DEFAULT;

	bgp->evpn_reexport = cfg;
	return cfg;
}

void bgp_lal_reexport_delete(struct bgp *bgp)
{
	struct bgp_evpn_reexport_config *cfg = bgp->evpn_reexport;
	struct bgp_evpn_cfgd_rt *cfgd_rt;

	if (!cfg)
		return;

	bgp->evpn_reexport = NULL;
	bgp_lal_reexport_config_changed(bgp);

	while ((cfgd_rt = bgp_evpn_cfgd_rt_slu_pop(&cfg->rts)))
		bgp_evpn_cfgd_rt_free(cfgd_rt);
	bgp_evpn_cfgd_rt_slu_fini(&cfg->rts);

	if (cfg->rt_ecom)
		ecommunity_free(&cfg->rt_ecom);

	XFREE(MTYPE_BGP_EVPN_REEXPORT_CFG, cfg);
}

/* Consumes cfgd_rt. Returns -1 on duplicate. */
int bgp_lal_reexport_add_rt(struct bgp *bgp, struct bgp_evpn_cfgd_rt *cfgd_rt)
{
	struct bgp_evpn_reexport_config *cfg = bgp_lal_reexport_get(bgp);

	if (bgp_evpn_cfgd_rt_slu_add(&cfg->rts, cfgd_rt) != NULL) {
		bgp_evpn_cfgd_rt_free(cfgd_rt);
		return -1;
	}

	bgp_lal_reexport_config_changed(bgp);
	return 0;
}

/* Consumes cfgd_rt (used as lookup key). Returns -1 when not configured. */
int bgp_lal_reexport_del_rt(struct bgp *bgp, struct bgp_evpn_cfgd_rt *cfgd_rt)
{
	struct bgp_evpn_reexport_config *cfg = bgp->evpn_reexport;
	struct bgp_evpn_cfgd_rt *found;

	if (cfg)
		found = bgp_evpn_cfgd_rt_slu_find(&cfg->rts, cfgd_rt);
	else
		found = NULL;

	bgp_evpn_cfgd_rt_free(cfgd_rt);

	if (!found)
		return -1;

	bgp_evpn_cfgd_rt_slu_del(&cfg->rts, found);
	bgp_evpn_cfgd_rt_free(found);

	bgp_lal_reexport_config_changed(bgp);
	return 0;
}

void bgp_lal_reexport_set_mode(struct bgp *bgp, enum bgp_reexport_mode mode)
{
	struct bgp_evpn_reexport_config *cfg = bgp_lal_reexport_get(bgp);

	if (cfg->mode == mode)
		return;

	cfg->mode = mode;
	bgp_lal_reexport_config_changed(bgp);
}

void bgp_lal_reexport_set_scope(struct bgp *bgp, uint8_t scope)
{
	struct bgp_evpn_reexport_config *cfg = bgp_lal_reexport_get(bgp);

	if (cfg->scope == scope)
		return;

	cfg->scope = scope;
	bgp_lal_reexport_config_changed(bgp);
}

/* Re-evaluate everything that depends on the re-export block: rebuild the
 * prebuilt ecom, then withdraw/re-leak the affected imported routes.
 */
void bgp_lal_reexport_config_changed(struct bgp *bgp)
{
	if (bgp->evpn_reexport)
		bgp_lal_reexport_rebuild_ecom(bgp->evpn_reexport);

	if (bgp->inst_type == BGP_INSTANCE_TYPE_VRF) {
		bgp_lal_reexport_local_resync(bgp);
		bgp_lal_reexport_external_resync(bgp);
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
