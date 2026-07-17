// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for instance-level /proteus-bgp:instance/afi-safis l2vpn-evpn address family.
 *
 * Split out of bgpd/bgp_nb_config.c (bgpd-yang-conversion intermezzo):
 * pure code motion, function bodies unchanged.
 */
#include <zebra.h>

#include "lib/northbound.h"
#include "lib/vrf.h"
#include "lib/asn.h"
#include "lib/log.h"
#include "lib/yang_wrappers.h"
#include "lib/frrevent.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_evpn.h"
#include "bgpd/bgp_evpn_mh.h"
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
#include "bgpd/bgp_rd.h"
#include "bgpd/proteus/bgp_nb_local.h"


/* 'advertise-all-vni' (M6 batch B2). THE risky EVPN flag: toggles whether
 * bgpd consumes zebra's VXLAN VNI state (bgp_zebra_advertise_all_vni via
 * evpn_set/unset_advertise_all_vni). Two hazards reproduced from the legacy
 * bgp_evpn_advertise_all_vni_cmd:
 *   1. Single-EVPN-owning-instance guard, at NB_EV_VALIDATE: enabling is
 *      rejected when a different bgp instance already owns EVPN
 *      (bgp_get_evpn() != this bgp), mirroring the legacy
 *      CMD_WARNING_CONFIG_FAILED "Please unconfigure EVPN in ...".
 *   2. Fire the zebra advertise toggle exactly once per commit: the APPLY
 *      body no-ops when the flag already holds the requested value, so a
 *      re-apply of the same value never re-issues bgp_zebra_advertise_all_vni
 *      (nor the set_evpn / cleanup side effects). */
int instance_afi_safis_l2vpn_evpn_advertise_all_vni_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgp *bgp_evpn;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!yang_dnode_get_bool(args->dnode, NULL))
			break;
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_evpn = bgp_get_evpn();
		if (bgp_evpn && bgp_evpn != bgp) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Please unconfigure EVPN in %s", bgp_evpn->name_pretty);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (bgp->advertise_all_vni == enable)
			break;
		if (enable)
			evpn_set_advertise_all_vni(bgp);
		else
			evpn_unset_advertise_all_vni(bgp);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_autort_rfc8365_compatible_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/autort-rfc8365-compatible");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* 'advertise-default-gw' (M6 batch B2, instance-level, vpn=NULL). The legacy
 * bgp_evpn_advertise_default_gw_cmd only honors the positive form under an
 * EVPN-enabled instance (its EVPN_ENABLED guard returned CMD_WARNING, i.e.
 * ignored the line without aborting the load); the negative form is
 * unconditional. Both setters are self-guarded/idempotent. The role guard is
 * kept at APPLY (not VALIDATE) because advertise-all-vni, which sets
 * EVPN_ENABLED, is applied before this leaf within the same commit (schema
 * order); a VALIDATE-time check would see the pre-apply state and wrongly
 * reject a config that enables both at once. */
int instance_afi_safis_l2vpn_evpn_advertise_default_gw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (!EVPN_ENABLED(bgp))
			return NB_OK;
		evpn_set_advertise_default_gw(bgp, NULL);
	} else {
		evpn_unset_advertise_default_gw(bgp, NULL);
	}

	return NB_OK;
}

/* 'advertise-svi-ip' (M6 batch B2, instance-level, vpn=NULL). Same
 * EVPN_ENABLED positive-only role guard as advertise-default-gw (legacy
 * bgp_evpn_advertise_svi_ip_cmd returned CMD_WARNING when not enabled);
 * evpn_set_advertise_svi_macip() is self-guarded/idempotent for both the
 * set (1) and unset (0) forms. */
int instance_afi_safis_l2vpn_evpn_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (!EVPN_ENABLED(bgp))
			return NB_OK;
		evpn_set_advertise_svi_macip(bgp, NULL, 1);
	} else {
		evpn_set_advertise_svi_macip(bgp, NULL, 0);
	}

	return NB_OK;
}

/* 'mac-vrf soo ASN:NN_OR_IP-ADDRESS:NN' (M6 batch B3, instance-level,
 * macvrf_soo_global_cmd / no_macvrf_soo_global_cmd). proteus-bgp already
 * models 'soo' as the same as2/as4/ipv4 'route-origin' choice under a
 * presence container that M5 B3 established for the per-(peer,afi,safi)
 * site-of-origin -- bgp_nb_soo_encode() (bgp_nb_util.c, un-static'd) is
 * reused verbatim to turn the already-typed leaves back into a struct
 * ecommunity_val. The difference from M5 B3's shape is scope: this is a
 * single value on the EVPN-owning bgp instance (bgp->evpn_info->soo), not
 * one per (peer,afi,safi), and its lifecycle (martian-route
 * unimport/reimport) is entirely inside bgp_evpn_handle_global_macvrf_soo_change()
 * (bgp_evpn.c, already extern in bgp_evpn_private.h), which itself no-ops
 * and frees the new value when it matches the old one -- so no
 * unset-then-set flag trick is needed here.
 *
 * Legacy's DEFPY carries a single-EVPN-owning-instance guard with two
 * distinct severities: a different, already-existing EVPN owner is a hard
 * CMD_WARNING_CONFIG_FAILED; nobody owning EVPN yet is a soft CMD_WARNING.
 * Mirroring advertise-all-vni's own guard (M6 batch B2): the hard case is
 * checked at NB_EV_VALIDATE (bgp_nb_mac_vrf_soo_owner_guard(), below) --
 * safe there because it only rejects when a *different* instance already
 * owns EVPN, a fact stable across this commit's pending changes, and at
 * VALIDATE time bgp_get_evpn() still reads the pre-commit value even when
 * this same commit is also enabling advertise-all-vni on this instance
 * (schema order places advertise-all-vni first). The soft case (no EVPN
 * owner yet) is a silent no-op at APPLY, matching advertise-default-gw/
 * svi-ip's own EVPN_ENABLED guard placement.
 */
static int bgp_nb_mac_vrf_soo_owner_guard(const struct lyd_node *dnode, char *errmsg,
					  size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	struct bgp *bgp_evpn;

	if (!bgp)
		return NB_OK;

	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn && bgp_evpn != bgp) {
		snprintf(errmsg, errmsg_len,
			 "Please configure MAC-VRF SoO in the EVPN underlay: %s",
			 bgp_evpn->name_pretty);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/* Reread the whole 'mac-vrf-soo' container and (re)apply it on the
 * EVPN-owning instance; shared by the choice case's own create and its two
 * leaves' modify, same "reread the container, not the trigger leaf"
 * discipline as M5 B3's bgp_nb_af_soo_set(). A case switch (e.g. as2 ->
 * ipv4) destroys the old case before this fires for the new one
 * (northbound processes every DESTROY in a commit before any
 * CREATE/MODIFY), so no stale case is ever read here.
 */
static void bgp_nb_mac_vrf_soo_set(const struct lyd_node *dnode)
{
	const struct lyd_node *soo_dnode = yang_dnode_get_parent(dnode, "mac-vrf-soo");
	struct bgp *bgp_evpn;
	struct ecommunity_val eval;
	struct ecommunity *ecomm_soo;

	if (!yang_dnode_exists(soo_dnode, "as2") && !yang_dnode_exists(soo_dnode, "as4") &&
	    !yang_dnode_exists(soo_dnode, "ipv4"))
		/* Choice case destroyed from under us by a case switch in this
		 * same commit; the new case's own create/modify (also in this
		 * commit) will re-drive this with the new value.
		 */
		return;

	bgp_evpn = bgp_get_evpn();
	if (!bgp_evpn || !bgp_evpn->evpn_info)
		/* Legacy's soft CMD_WARNING: nobody owns EVPN yet. */
		return;

	bgp_nb_soo_encode(soo_dnode, &eval);

	ecomm_soo = ecommunity_new();
	ecommunity_add_val(ecomm_soo, &eval, false, false);
	ecommunity_str(ecomm_soo);

	bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn, ecomm_soo);
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* No-op: the mandatory choice case's own create and its two
		 * leaves' modify (same commit) already do the real work once
		 * all three exist in the target tree.
		 */
		break;
	}

	return NB_OK;
}

/* The presence container's own destroy is the one place that
 * unconditionally clears bgp->evpn_info->soo, matching legacy's
 * no_macvrf_soo_global -- which itself never checks 'bgp != bgp_evpn'
 * (unlike the positive form), always clearing the true EVPN-owning
 * instance's soo regardless of which instance's context issued the 'no'.
 * Reached only by a genuine 'no mac-vrf soo', not a case switch (switching
 * case leaves the enclosing presence container alone).
 */
int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp_evpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_evpn = bgp_get_evpn();
	if (bgp_evpn && bgp_evpn->evpn_info)
		bgp_evpn_handle_global_macvrf_soo_change(bgp_evpn, NULL /* new_soo */);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see the doc comment above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_global_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as2_local_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see the doc comment above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_global_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_as4_local_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see the doc comment above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_global_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_mac_vrf_soo_ipv4_local_admin_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_mac_vrf_soo_owner_guard(args->dnode, args->errmsg,
						      args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_mac_vrf_soo_set(args->dnode);
		break;
	}

	return NB_OK;
}

/* 'enable-resolve-overlay-index' (M6 batch B2). The legacy
 * bgp_evpn_enable_resolve_overlay_index_cmd guards BOTH set and unset on
 * bgp == bgp_get_evpn() (returning CMD_WARNING otherwise, i.e. ignoring the
 * line). bgp_evpn_set_unset_resolve_overlay_index() is self-guarded/idempotent
 * (no-op when already in the requested state), so a re-apply of the same value
 * re-walks nothing. Role guard at APPLY for the same schema-order reason as
 * advertise-default-gw. */
int instance_afi_safis_l2vpn_evpn_enable_resolve_overlay_index_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (bgp != bgp_get_evpn())
		return NB_OK;

	bgp_evpn_set_unset_resolve_overlay_index(bgp, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/* 'ead-es-frag evi-limit (1-1000)' (M6 batch B5, bgp_evpn_ead_es_frag_evi_limit_cmd).
 * bgp_mh_info (== bm->mh_info) is a single process-wide struct, not
 * per-bgp-instance state -- like every other multihoming leaf in this
 * container -- so unlike the rest of bgp_nb_evpn.c's callbacks there is no
 * bgp instance to look up here. No YANG default (evi_per_es_frag's compiled
 * default BGP_EVPN_MAX_EVI_PER_ES_FRAG is a plain numeric constant, same
 * no-default-leaf shape as B4's dup-addr-detection max-moves/time), so
 * DESTROY restores that constant directly, mirroring legacy's own
 * 'no ead-es-frag evi-limit' branch.
 */
int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_mh_info->evi_per_es_frag = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_mh_info->evi_per_es_frag = BGP_EVPN_MAX_EVI_PER_ES_FRAG;

	return NB_OK;
}

/* 'ead-es-route-target export RT' (M6 batch B5, bgp_evpn_ead_es_rt_cmd /
 * no_bgp_evpn_ead_es_rt_cmd). proteus-bgp-evpn.yang's ead-es-route-target-export
 * container 'uses pt:route-target-set' (as2/as4/ipv4 keyed lists, same
 * shape B9 will give the VRF/VNI route-target subtrees) -- unlike those,
 * this container was already correctly modeled here (a plain manual RT
 * set; EAD-ES export has no 'auto'/wildcard grammar to remodel), so it
 * converts in this batch rather than deferring to B9.
 *
 * Every list entry's keys (global-admin + local-admin) ARE the RT's whole
 * value, so a create/destroy needs no separate leaf-modify callback --
 * encode the entry into a struct ecommunity_val with
 * encode_route_target_{as,as4,ip}() (bgp_ecommunity.h; the same helpers
 * bgp_nb_soo_encode() already pulls in for the M5/M6 soo choice), wrap it
 * in a throwaway struct ecommunity, and hand it to
 * bgp_evpn_mh_config_ead_export_rt() (bgp_evpn_mh.c) -- the exact setter
 * legacy's two DEFUNs already used, reused rather than reimplemented.
 * That setter matches by value (bgp_evpn_rt_matches_existing(), un-static'd
 * from bgp_evpn_vty.c for this), not by YANG list identity, and its own
 * del=true branch asserts on no match; bgp_nb_ead_es_rt_apply() guards
 * both directions explicitly so a create racing an already-present value or
 * a destroy of an already-absent one (replay/abort edge cases) is a silent
 * no-op instead.
 */
static struct bgp *bgp_nb_ead_es_rt_owner(const struct lyd_node *dnode)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);

	if (!bgp || !EVPN_ENABLED(bgp))
		/* Legacy's hard CMD_WARNING ("only supported under EVPN
		 * VRF"); this softens to a silent no-op, matching
		 * advertise-svi-ip's own EVPN_ENABLED guard placement (M6
		 * batch B2).
		 */
		return NULL;

	return bgp;
}

static void bgp_nb_ead_es_rt_apply(const struct lyd_node *dnode, struct ecommunity_val *eval,
				   bool del)
{
	struct bgp *bgp = bgp_nb_ead_es_rt_owner(dnode);
	struct ecommunity *ecom;
	bool exists;

	if (!bgp)
		return;

	ecom = ecommunity_new();
	ecommunity_add_val(ecom, eval, false, false);
	ecommunity_str(ecom);

	exists = bgp_evpn_rt_matches_existing(bgp_mh_info->ead_es_export_rtl, ecom);

	if (del && !exists) {
		ecommunity_free(&ecom);
		return;
	}
	if (!del && exists) {
		ecommunity_free(&ecom);
		return;
	}

	bgp_evpn_mh_config_ead_export_rt(bgp, ecom, del);
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_create(
	struct nb_cb_create_args *args)
{
	struct ecommunity_val eval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	encode_route_target_as(yang_dnode_get_uint16(args->dnode, "global-admin"),
			       yang_dnode_get_uint32(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ecommunity_val eval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	encode_route_target_as(yang_dnode_get_uint16(args->dnode, "global-admin"),
			       yang_dnode_get_uint32(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_create(
	struct nb_cb_create_args *args)
{
	struct ecommunity_val eval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	encode_route_target_as4(yang_dnode_get_uint32(args->dnode, "global-admin"),
				yang_dnode_get_uint16(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ecommunity_val eval;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	encode_route_target_as4(yang_dnode_get_uint32(args->dnode, "global-admin"),
				yang_dnode_get_uint16(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_create(
	struct nb_cb_create_args *args)
{
	struct ecommunity_val eval;
	struct in_addr ip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	yang_dnode_get_ipv4(&ip, args->dnode, "global-admin");
	encode_route_target_ip(&ip, yang_dnode_get_uint16(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	struct ecommunity_val eval;
	struct in_addr ip;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	memset(&eval, 0, sizeof(eval));
	yang_dnode_get_ipv4(&ip, args->dnode, "global-admin");
	encode_route_target_ip(&ip, yang_dnode_get_uint16(args->dnode, "local-admin"), &eval, true);
	bgp_nb_ead_es_rt_apply(args->dnode, &eval, true);

	return NB_OK;
}

/* 'use-es-l3nhg' / 'disable-ead-evi-rx' / 'disable-ead-evi-tx' left
 * unimplemented (M6 batch B5): all three are default-on/off *compiled*
 * constants (BGP_EVPN_MH_USE_ES_L3NHG_DEF, BGP_EVPN_MH_EAD_EVI_RX_DEF,
 * BGP_EVPN_MH_EAD_EVI_TX_DEF, all 'true' in bgp_evpn_mh.h), the same shape
 * as B4's dup-addr-detection/enabled -- but proteus-bgp-evpn.yang's three
 * leaves carry no 'default' statement, unlike every other default-on/off
 * boolean across proteus-bgp.yang / proteus-bgp-evpn.yang. Without that
 * statement DESTROY cannot resolve back to the compiled default the doc's
 * Tier A scheme (and the legacy emitter's own "write whichever form
 * differs from the compiled default" logic) assumes exists on the wire.
 * This is a YANG modeling gap (YANG files are out of scope for conversion
 * batches), not a missing callback body -- reported upstream per the batch
 * brief rather than silently worked around. bgp_mh_info->host_routes_use_l3nhg
 * / enable_ead_evi_rx / enable_ead_evi_tx stay reachable only through the
 * still-native bare 'use-es-l3nhg' / 'disable-ead-evi-rx' / 'disable-ead-evi-tx'
 * toggles (bgp_evpn_vty.c); bgp_config_write_evpn_info()'s corresponding
 * lines stay native and ungated, same as dup-addr-detection/enabled's.
 */
int instance_afi_safis_l2vpn_evpn_multihoming_use_es_l3nhg_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_use_es_l3nhg_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/use-es-l3nhg");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_rx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_rx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-rx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_tx_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_disable_ead_evi_tx_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/disable-ead-evi-tx");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* 'enabled' left unimplemented (M6 batch B4): proteus-bgp-evpn.yang's
 * dup-addr-detection/enabled leaf has no 'default "true"' statement, unlike
 * every other default-on boolean in the proteus-bgp modules, so the Tier A
 * "destroy resolves to the true default" mechanics its own description
 * assumes don't exist on the wire. This is a YANG modeling gap (YANG files
 * are out of scope for this batch), not a missing callback body -- reported
 * upstream rather than silently worked around. bgp->evpn_info->dup_addr_detect
 * stays reachable only through the still-native bare 'dup-addr-detection' /
 * 'no dup-addr-detection' toggle (bgp_evpn_vty.c).
 */
int instance_afi_safis_l2vpn_evpn_dup_addr_detection_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_enabled_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* max-moves/time/freeze (M6 batch B4, dup_addr_detection_cmd /
 * dup_addr_detection_auto_recovery_cmd): none of the three carry a YANG
 * default (same no-default numeric-leaf shape as B8's per-neighbor
 * dampening half-life/reuse-threshold/etc.), so every leaf's MODIFY/DESTROY
 * reroutes to a single "reread the whole dup-addr-detection container,
 * reapply to bgp->evpn_info, notify zebra" helper -- a reread after any one
 * leaf's change still recomputes a fully consistent set, and unset leaves
 * fall back to the same EVPN_DAD_DEFAULT_* legacy itself used. Configuring
 * any of the three also (re)asserts dup_addr_detect, mirroring both legacy
 * DEFPYs' own unconditional 'bgp_vrf->evpn_info->dup_addr_detect = true'
 * side effect -- the field is otherwise only ever turned off by the
 * still-native bare 'no dup-addr-detection' (dup_addr_detect's own leaf is
 * not convertible this batch, see above).
 */
static void bgp_nb_dup_addr_detection_apply(struct bgp *bgp, const struct lyd_node *dnode)
{
	if (!bgp || !bgp->evpn_info)
		return;

	bgp->evpn_info->dup_addr_detect = true;

	bgp->evpn_info->dad_max_moves = yang_dnode_exists(dnode, "max-moves")
						 ? yang_dnode_get_uint16(dnode, "max-moves")
						 : EVPN_DAD_DEFAULT_MAX_MOVES;
	bgp->evpn_info->dad_time = yang_dnode_exists(dnode, "time")
					    ? yang_dnode_get_uint16(dnode, "time")
					    : EVPN_DAD_DEFAULT_TIME;

	if (yang_dnode_exists(dnode, "freeze")) {
		const char *freeze = yang_dnode_get_string(dnode, "freeze");

		bgp->evpn_info->dad_freeze = true;
		bgp->evpn_info->dad_freeze_time =
			strmatch(freeze, "permanent") ? 0 : strtoul(freeze, NULL, 10);
	} else {
		bgp->evpn_info->dad_freeze = false;
		bgp->evpn_info->dad_freeze_time = 0;
	}

	bgp_zebra_dup_addr_detection(bgp);
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_max_moves_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_max_moves_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_time_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_time_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_freeze_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_freeze_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
}

/* 'flooding <disable|head-end-replication>' (M6 batch B3, instance-level,
 * bgp_evpn_flood_control_cmd). No YANG default (Tier B, "unset means FRR's
 * own default head-end-replication"): legacy's DEFPY collapses 'no
 * flooding' and 'flooding head-end-replication' onto the exact same
 * VXLAN_FLOOD_HEAD_END_REPL value, so MODIFY and DESTROY share the same
 * "restore head-end-replication" APPLY body for that case; MODIFY only
 * additionally handles 'disable'. bgp->vxlan_flood_ctrl == flood_ctrl is
 * checked first to reproduce the legacy no-op-on-unchanged-value guard
 * before calling bgp_evpn_flood_control_change() (bgp_evpn.c), which walks
 * every local L2VNI's flood control inheritance.
 */
int instance_afi_safis_l2vpn_evpn_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	enum vxlan_flood_control flood_ctrl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (strmatch(yang_dnode_get_string(args->dnode, NULL), "disable"))
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	if (bgp->vxlan_flood_ctrl == flood_ctrl)
		return NB_OK;

	bgp->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_flooding_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (bgp->vxlan_flood_ctrl == VXLAN_FLOOD_HEAD_END_REPL)
		return NB_OK;

	bgp->vxlan_flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;
	bgp_evpn_flood_control_change(bgp);

	return NB_OK;
}

/* Look up the bgpevpn object for a dnode nested anywhere under a
 * '.../l2vpn-evpn/vni[vni-id=N]' list entry -- every M6 batch B6 per-VNI
 * sub-leaf callback below needs this in addition to the enclosing bgp
 * instance. Returns NULL if the bgp instance is gone or the vni entry
 * doesn't (yet) exist as a live bgpevpn, which callers treat as a silent
 * no-op -- the same "recreated/destroyed elsewhere in this commit"
 * tolerance as instance_afi_safis_l2vpn_evpn_vni_destroy() below.
 */
static struct bgpevpn *bgp_nb_evpn_vni_lookup(const struct lyd_node *dnode)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const struct lyd_node *vni_dnode;

	if (!bgp)
		return NULL;

	vni_dnode = yang_dnode_get_parent(dnode, "vni");
	if (!vni_dnode)
		return NULL;

	return bgp_evpn_lookup_vni(bgp, yang_dnode_get_uint32(vni_dnode, "vni-id"));
}

/* 'vni N' ... 'exit-vni' sub-block create (M6 batch B1). Real keyed-list
 * create: mirrors the legacy bgp_evpn_vni DEFUN_NOSH, calling the same
 * (now shared) evpn_create_update_vni() core. Idempotent by VNI id -- the
 * legacy DEFUN_NOSH stays native during the coexistence window, so both
 * paths may create the same VNI in one file load; whichever runs second
 * just re-marks the already-created bgpevpn as configured. */
int instance_afi_safis_l2vpn_evpn_vni_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	vni_t vni;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vni = yang_dnode_get_uint32(args->dnode, "vni-id");

	if (!evpn_create_update_vni(bgp, vni))
		return NB_ERR_RESOURCE;

	return NB_OK;
}

/* 'no vni N' destroy (M6 batch B1). Tolerates an already-gone VNI as a
 * silent no-op (the common case once mgmtd's northbound destroy and bgpd's
 * legacy no_bgp_evpn_vni DEFUN both run for the same line during the
 * coexistence window), mirroring the M3/M4 lifecycle-destroy pattern. */
int instance_afi_safis_l2vpn_evpn_vni_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	vni_t vni;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vni = yang_dnode_get_uint32(args->dnode, "vni-id");

	vpn = bgp_evpn_lookup_vni(bgp, vni);
	if (!vpn || !is_vni_configured(vpn))
		return NB_OK;

	evpn_delete_vni(bgp, vpn);

	return NB_OK;
}

/* Per-VNI 'rd ASN:NN_OR_IP-ADDRESS:NN' (M6 batch B6, bgp_evpn_vni_rd_cmd /
 * no_bgp_evpn_vni_rd_cmd / no_bgp_evpn_vni_rd_without_val_cmd). Modeled as
 * the same mandatory as2/as4/ipv4 'route-distinguisher' choice
 * (proteus-types.yang) M6 B3 already established for mac-vrf-soo's
 * as2/as4/ipv4 'route-origin' choice, under a per-VNI presence container --
 * so this follows that exact "reread the whole container on any case
 * create/leaf modify" idiom (bgp_nb_evpn_vni_rd_set(), below) rather than
 * mac-vrf-soo's ecommunity encode helpers: an RD is a distinct RFC 4364
 * wire format (bgpd/bgp_rd.h), not an extended community, so
 * bgp_nb_rd_encode() below builds a struct prefix_rd directly instead of
 * reusing encode_route_target_{as,as4,ip}(). Its three cases are exactly
 * str2prefix_rd()'s three encodings (RD_TYPE_AS/_AS4/_IP) picked by case
 * name rather than re-derived from the administrator's magnitude -- the
 * CLI side (bgp_cli_instance.c) already chose the case matching
 * str2prefix_rd()'s own AS<=65535-vs->65535 split when it parsed the
 * legacy token, so this side never needs to re-guess.
 *
 * The legacy positive-form DEFUNs (bgp_evpn_vni_rd_cmd) guard on
 * EVPN_ENABLED(bgp) (bgp->advertise_all_vni), returning a soft CMD_WARNING
 * -- not CMD_WARNING_CONFIG_FAILED -- when unset, i.e. silently dropping
 * the line rather than aborting the load; reproduced as an APPLY-time
 * no-op in bgp_nb_evpn_vni_rd_set(), same schema-order reasoning as
 * instance_afi_safis_l2vpn_evpn_advertise_default_gw_modify() above
 * (advertise-all-vni may apply earlier in the same commit). The negative
 * forms carried the same guard plus a "does the given RD match the
 * currently configured one" check; the mgmtd CLI (bgp_cli_instance.c)
 * drops that value-match validation in favor of an unconditional destroy
 * of the presence container, matching M6 B3's mac-vrf-soo 'no' form -- a
 * config-fidelity no-op either way, since destroy always resolves back to
 * the auto-derived RD regardless of what value the (never actually
 * consulted) 'no rd <val>' argument names.
 */
static bool bgp_nb_rd_encode(const struct lyd_node *rd_dnode, struct prefix_rd *prd,
			     char *pretty_buf, size_t pretty_buf_len)
{
	memset(prd, 0, sizeof(*prd));
	prd->family = AF_UNSPEC;
	prd->prefixlen = 64;
	prd->val[0] = 0;

	if (yang_dnode_exists(rd_dnode, "as2")) {
		uint16_t administrator = yang_dnode_get_uint16(rd_dnode, "as2/administrator");
		uint32_t assigned = yang_dnode_get_uint32(rd_dnode, "as2/assigned-number");

		prd->val[1] = RD_TYPE_AS;
		prd->val[2] = (administrator >> 8) & 0xff;
		prd->val[3] = administrator & 0xff;
		prd->val[4] = (assigned >> 24) & 0xff;
		prd->val[5] = (assigned >> 16) & 0xff;
		prd->val[6] = (assigned >> 8) & 0xff;
		prd->val[7] = assigned & 0xff;
		snprintf(pretty_buf, pretty_buf_len, "%u:%u", administrator, assigned);
	} else if (yang_dnode_exists(rd_dnode, "as4")) {
		uint32_t administrator = yang_dnode_get_uint32(rd_dnode, "as4/administrator");
		uint16_t assigned = yang_dnode_get_uint16(rd_dnode, "as4/assigned-number");

		prd->val[1] = RD_TYPE_AS4;
		prd->val[2] = (administrator >> 24) & 0xff;
		prd->val[3] = (administrator >> 16) & 0xff;
		prd->val[4] = (administrator >> 8) & 0xff;
		prd->val[5] = administrator & 0xff;
		prd->val[6] = (assigned >> 8) & 0xff;
		prd->val[7] = assigned & 0xff;
		snprintf(pretty_buf, pretty_buf_len, "%u:%u", administrator, assigned);
	} else if (yang_dnode_exists(rd_dnode, "ipv4")) {
		struct in_addr ip;
		uint16_t assigned = yang_dnode_get_uint16(rd_dnode, "ipv4/assigned-number");
		char ip_str[INET_ADDRSTRLEN];

		yang_dnode_get_ipv4(&ip, rd_dnode, "ipv4/administrator");

		prd->val[1] = RD_TYPE_IP;
		memcpy(&prd->val[2], &ip, 4);
		prd->val[6] = (assigned >> 8) & 0xff;
		prd->val[7] = assigned & 0xff;

		inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
		snprintf(pretty_buf, pretty_buf_len, "%s:%u", ip_str, assigned);
	} else {
		/* Choice case destroyed from under us by a case switch in this
		 * same commit; the new case's own create/modify (also in
		 * this commit) will re-drive this with the new value, same
		 * "correctly process the change of a case inside a choice"
		 * ordering as mac-vrf-soo above.
		 */
		return false;
	}

	return true;
}

static void bgp_nb_evpn_vni_rd_set(const struct lyd_node *dnode)
{
	const struct lyd_node *rd_dnode = yang_dnode_get_parent(dnode, "rd");
	struct bgp *bgp;
	struct bgpevpn *vpn;
	struct prefix_rd prd;
	char rd_pretty[RD_ADDRSTRLEN];

	bgp = bgp_nb_instance_lookup(dnode);
	if (!bgp || !EVPN_ENABLED(bgp))
		return;

	vpn = bgp_nb_evpn_vni_lookup(dnode);
	if (!vpn)
		return;

	if (!bgp_nb_rd_encode(rd_dnode, &prd, rd_pretty, sizeof(rd_pretty)))
		return;

	if (bgp_evpn_rd_matches_existing(vpn, &prd))
		return;

	evpn_configure_rd(bgp, vpn, &prd, rd_pretty);
}

int instance_afi_safis_l2vpn_evpn_vni_rd_create(struct nb_cb_create_args *args)
{
	/* No-op: the mandatory choice case's own create and its two leaves'
	 * modify (same commit) already do the real work once all three exist
	 * in the target tree, same as mac-vrf-soo's presence container. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp || !EVPN_ENABLED(bgp))
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn || !is_rd_configured(vpn))
		return NB_OK;

	evpn_unconfigure_rd(bgp, vpn);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vni_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vni_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vni_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_mac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_mac_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_raw_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* Per-VNI 'flooding <disable|head-end-replication>' (M6 batch B6,
 * bgp_evpn_flood_control_vni_cmd). Same enum/no-YANG-default shape as the
 * AF-level 'flooding' leaf (M6 B3,
 * instance_afi_safis_l2vpn_evpn_flooding_modify()/_destroy() above): MODIFY
 * only ever carries 'disable' or 'head-end-replication'; DESTROY restores
 * VXLAN_FLOOD_INHERIT_GLOBAL, the per-VNI-only tri-state meaning "inherit
 * the address-family/tenant-VRF setting" that has no AF-level equivalent.
 * bgp->vxlan_flood_ctrl == flood_ctrl / vpn->vxlan_flood_ctrl == flood_ctrl
 * is checked first to reproduce legacy's no-op-on-unchanged-value guard
 * before calling bgp_evpn_flood_control_change().
 */
int instance_afi_safis_l2vpn_evpn_vni_flooding_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;
	enum vxlan_flood_control flood_ctrl;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn)
		return NB_OK;

	if (strmatch(yang_dnode_get_string(args->dnode, NULL), "disable"))
		flood_ctrl = VXLAN_FLOOD_DISABLED;
	else
		flood_ctrl = VXLAN_FLOOD_HEAD_END_REPL;

	if (vpn->vxlan_flood_ctrl == flood_ctrl)
		return NB_OK;

	vpn->vxlan_flood_ctrl = flood_ctrl;
	bgp_evpn_flood_control_change(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_flooding_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn)
		return NB_OK;

	if (vpn->vxlan_flood_ctrl == VXLAN_FLOOD_INHERIT_GLOBAL)
		return NB_OK;

	vpn->vxlan_flood_ctrl = VXLAN_FLOOD_INHERIT_GLOBAL;
	bgp_evpn_flood_control_change(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_both_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/route-target-both/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* Per-VNI 'advertise-default-gw' (M6 batch B6, vpn != NULL variant of the
 * M6 B2 instance-level leaf above; bgp_evpn_advertise_default_gw_vni_cmd /
 * no_bgp_evpn_advertise_default_gw_vni_cmd). Unlike the instance-level
 * form, legacy's per-VNI DEFPYs carried no EVPN_ENABLED guard at all, so
 * none is reproduced here; evpn_set_advertise_default_gw()/
 * evpn_unset_advertise_default_gw() are self-guarded/idempotent either
 * way. */
int instance_afi_safis_l2vpn_evpn_vni_advertise_default_gw_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_advertise_default_gw(bgp, vpn);
	else
		evpn_unset_advertise_default_gw(bgp, vpn);

	return NB_OK;
}

/* Per-VNI 'advertise-svi-ip' (M6 batch B6, vpn != NULL variant of the M6 B2
 * instance-level leaf above; bgp_evpn_advertise_svi_ip_vni_cmd). No
 * EVPN_ENABLED guard in legacy here either;
 * evpn_set_advertise_svi_macip() is self-guarded/idempotent for both the
 * set and unset forms. */
int instance_afi_safis_l2vpn_evpn_vni_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn)
		return NB_OK;

	evpn_set_advertise_svi_macip(bgp, vpn, yang_dnode_get_bool(args->dnode, NULL) ? 1 : 0);

	return NB_OK;
}

/* Per-VNI 'advertise-subnet' (M6 batch B6, bgp_evpn_advertise_vni_subnet_cmd /
 * no_bgp_evpn_advertise_vni_subnet_cmd, both legacy DEFUN_HIDDEN). The
 * positive form's legacy bgp_lookup_by_vrf_id(vpn->tenant_vrf_id) guard
 * (silently drops the line -- CMD_WARNING, not CONFIG_FAILED -- when the
 * VNI has no tenant VRF attached) is reproduced here; the negative form
 * carried no such guard in legacy, so none is added to the destroy path
 * (evpn_unset_advertise_subnet() is self-guarded/idempotent regardless). */
int instance_afi_safis_l2vpn_evpn_vni_advertise_subnet_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct bgpevpn *vpn;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn = bgp_nb_evpn_vni_lookup(args->dnode);
	if (!vpn)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		if (!bgp_lookup_by_vrf_id(vpn->tenant_vrf_id))
			return NB_OK;
		evpn_set_advertise_subnet(bgp, vpn);
	} else {
		evpn_unset_advertise_subnet(bgp, vpn);
	}

	return NB_OK;
}

/* Per-VRF-instance 'rd ASN:NN_OR_IP-ADDRESS:NN' (M6 batch B7,
 * bgp_evpn_vrf_rd_cmd / no_bgp_evpn_vrf_rd_cmd /
 * no_bgp_evpn_vrf_rd_without_val_cmd). Same mandatory as2/as4/ipv4
 * 'route-distinguisher' choice, one level up from the per-VNI 'rd'
 * container M6 B6 already converted (bgp_nb_evpn_vni_rd_set() above) --
 * this reuses that same bgp_nb_rd_encode() helper and the identical
 * "reread the whole container on any case create/leaf modify" idiom,
 * against the VRF instance directly rather than a struct bgpevpn. Unlike
 * the per-VNI positive form, the legacy VRF-level DEFUNs carried no
 * EVPN_ENABLED(bgp) guard (bgp_evpn_vty.c), so bgp_nb_evpn_vrf_rd_set()
 * below has none either. The negative forms carried a "does the given RD
 * match the currently configured one" check that the mgmtd CLI
 * (bgp_cli_instance.c) drops in favor of an unconditional destroy of the
 * presence container, matching M6 B6's per-VNI 'no rd' precedent.
 */
static void bgp_nb_evpn_vrf_rd_set(const struct lyd_node *dnode)
{
	const struct lyd_node *rd_dnode = yang_dnode_get_parent(dnode, "rd");
	struct bgp *bgp;
	struct prefix_rd prd;
	char rd_pretty[RD_ADDRSTRLEN];

	bgp = bgp_nb_instance_lookup(dnode);
	if (!bgp)
		return;

	if (!bgp_nb_rd_encode(rd_dnode, &prd, rd_pretty, sizeof(rd_pretty)))
		return;

	if (bgp_evpn_vrf_rd_matches_existing(bgp, &prd))
		return;

	evpn_configure_vrf_rd(bgp, &prd, rd_pretty);
}

int instance_afi_safis_l2vpn_evpn_rd_create(struct nb_cb_create_args *args)
{
	/* No-op: the mandatory choice case's own create and its two leaves'
	 * modify (same commit) already do the real work once all three exist
	 * in the target tree, same as the per-VNI 'rd' container above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp || !is_vrf_rd_configured(bgp))
		return NB_OK;

	evpn_unconfigure_vrf_rd(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vrf_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vrf_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: fires only on a case switch, see bgp_nb_evpn_vrf_rd_set()'s
	 * doc comment. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rd_set(args->dnode);

	return NB_OK;
}

/* mac/raw: same as the per-VNI 'rd' choice above, these two cases stay
 * reject-stubs -- 'mac' is blocked by a 'must false()' in proteus-types.yang
 * (FRR's str2prefix_rd() cannot parse type-6 RDs) and 'raw' has no legacy
 * producer (str2prefix_rd() never emits it), so bgp_nb_rd_encode() has no
 * case for either and neither is reachable from any real CLI input. */
int instance_afi_safis_l2vpn_evpn_rd_mac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_mac_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_raw_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/wildcard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/wildcard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_auto_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-import/auto");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_auto_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-export/auto");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_both_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/route-target-both/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* 'advertise <ipv4|ipv6> unicast [gateway-ip] [route-map WORD]'
 * (bgp_evpn_advertise_type5_cmd / no_bgp_evpn_advertise_type5_cmd):
 * SCOUTED for M6 batch B7 but reject-stubbed -- an initial implementation
 * (enabled/gateway-ip converted, route-map's leafref value routed through
 * unchanged) broke bgp_evpn_rt5's r2, whose frr.conf defines its
 * route-maps *after* the 'router bgp ... vrf ...' blocks that reference
 * them: proteus-bgp-evpn.yang's 'route-map' leaf is a real
 * `leafref path "/rmap:route-map/rmap:name"` (default require-instance),
 * so mgmtd's candidate-config validation rejects that forward reference
 * ("Invalid leafref value 'rmap4' - no target instance ..."), and the
 * rejection aborted the rest of that router's config-load transaction,
 * dropping the *next* VRF's unrelated rd/route-target/advertise lines too.
 * DO-NOT-MODIFY-YANG applies to this batch, so 'route-map' can't be
 * retyped to a plain string (the fix that landed on the bfd 'profile' leaf
 * for the same class of problem, proteus-bgp.yang); per the mis-shaped-row
 * precedent (B4/B5), the whole advertise-<afi>-unicast family stays a
 * reject-stub rather than ship a real regression -- 'enabled'/'gateway-ip'
 * can't be split out into their own mgmtd command either, since legacy's
 * single grammar line combining them with 'route-map' would collide with
 * a new command at the same install node (same reasoning as advertise-pip
 * below). bgp_config_write_evpn_info's two blocks (bgpd/bgp_evpn_vty.c)
 * stay fully native/ungated as a result. */
int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_gateway_ip_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/gateway-ip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv4-unicast/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_enabled_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_gateway_ip_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/gateway-ip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-ipv6-unicast/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* 'default-originate <ipv4|ipv6>' (M6 batch B7,
 * bgp_evpn_default_originate_cmd / no_bgp_evpn_default_originate_cmd).
 * evpn_process_default_originate_cmd() (bgp_evpn_vty.c) is the un-static'd
 * legacy helper -- already self-guarded/idempotent (evpn_default_originate_set()
 * bail-out), so it needed no extraction, just a plain (afi, add) call. */
int instance_afi_safis_l2vpn_evpn_default_originate_ipv4_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	evpn_process_default_originate_cmd(bgp, AFI_IP, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_default_originate_ipv6_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	evpn_process_default_originate_cmd(bgp, AFI_IP6, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/* 'advertise-pip [ip A.B.C.D [mac X:X:X:X:X:X]]' /
 * 'no advertise-pip [ip A.B.C.D [mac X:X:X:X:X:X]]'
 * (bgp_evpn_advertise_pip_ip_mac_cmd): scouted for M6 batch B7, left as a
 * reject-stub family for two independent reasons, either one sufficient on
 * its own:
 *
 *  1. proteus-bgp-evpn.yang's 'enabled' leaf has no 'default "true"'
 *     statement (the same B4/B5-style gap as dup-addr-detection/enabled
 *     and the multihoming disable-ead-evi-rx/-tx/use-es-l3nhg leaves) --
 *     FRR's compiled default is advertise-pip on, with no wire
 *     representation of that default to convert onto.
 *
 *  2. Even with (1) fixed, 'ip'/'mac' are not independently convertible:
 *     legacy's single DEFPY grammar ("[no] advertise-pip [ip A.B.C.D [mac
 *     ...]]") always enables/disables PIP and sets its static ip/mac in
 *     one atomic command -- there is no legacy form that sets ip/mac
 *     without also touching 'enabled'. Since 'enabled' stays native (1),
 *     the legacy DEFUN must stay installed unmodified, and a new mgmtd
 *     command for 'advertise-pip ip ...' would collide with it (two
 *     commands, one grammar, same install node) -- so ip/mac stay
 *     reject-stubs alongside 'enabled' rather than splitting ownership.
 *
 * bgp_config_write_evpn_info's advertise-pip block (bgpd/bgp_evpn_vty.c)
 * stays fully native/ungated as a result -- see the comment there.
 */
int instance_afi_safis_l2vpn_evpn_advertise_pip_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_enabled_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_ip_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/ip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_ip_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/ip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_mac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_mac_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/advertise-pip/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* EVPN type-5 static 'network <A.B.C.D/M|X:X::X:X/M> rd RD ethtag WORD
 * label WORD esi WORD gwip <A.B.C.D|X:X::X:X> routermac WORD [route-map
 * RMAP_NAME]' (evpnrt5_network_cmd / no_evpnrt5_network_cmd,
 * bgpd/bgp_evpn_vty.c): scouted for M6 batch B8, left as a reject-stub
 * family for the whole 'network' list -- same class of problem as B7's
 * advertise-<afi>-unicast family, not a new one:
 *
 *  proteus-bgp-evpn.yang's trailing optional 'route-map' leaf is a real
 *  `leafref path "/rmap:route-map/rmap:name"`, but legacy's single DEFPY
 *  grammar has always tolerated the referenced route-map being defined
 *  *after* this line (lazy route_map_lookup_by_name() binding). Routing
 *  that value through nb_cli_enqueue_change() hits mgmtd's candidate-config
 *  leafref validation exactly as B7's advertise-unicast conversion did,
 *  aborting the whole config-load transaction on any forward reference --
 *  a real regression, not merely a cosmetic one. DO-NOT-MODIFY-YANG applies
 *  to this batch, so 'route-map' can't be retyped to a plain string (the
 *  fix already applied to the bfd 'profile' leaf for the same class of
 *  problem).
 *
 *  The mandatory siblings ('rd'/'ethtag'/'label'/'esi'/'gwip'/'routermac')
 *  can't be split into their own mgmtd command either: legacy's grammar is
 *  one atomic DEFUN with 'route-map' as its only optional trailing token,
 *  compiled only into bgpd today (bgp_evpn_vty.c is not in mgmtd's source
 *  list). Since mgmtd is the sole live CLI entry point in the integrated
 *  build, dropping 'route-map' from a new mgmtd-only command would make it
 *  impossible to configure a type-5 network's route-map at all -- the same
 *  silent-feature-loss outcome the mis-shaped-row precedent (B4/B5/B7)
 *  rejects. So the entire 'network' list (key/rd/ethtag/label/esi/gwip/
 *  routermac/route-map, ~28 nodes) stays a reject-stub, flagged for a
 *  future YANG fix (add 'require-instance false;' to 'route-map') before
 *  reattempting. bgp_config_write_network_evpn (bgpd/bgp_route.c) stays
 *  fully native/ungated as a result.
 */
int instance_afi_safis_l2vpn_evpn_network_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as2/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/ipv4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/as4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_mac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_mac_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/mac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_raw_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/rd/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_ethtag_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/ethtag");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_label_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/label");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_esi_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/esi");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_gwip_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/gwip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_routermac_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/routermac");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_route_map_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_route_map_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/network/route-map");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
