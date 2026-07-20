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
 * container 'uses pt:route-target-set' (as2/as4/ipv4 keyed lists, the
 * same shape as the VRF/VNI route-target/<import|export>/rts sets) --
 * unlike those, this container was already correctly modeled here (a
 * plain manual RT set; EAD-ES export has no 'auto'/wildcard grammar to
 * remodel), so it converts in this batch rather than deferring to B9.
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

/* 'use-es-l3nhg' / 'ead-evi-rx' / 'ead-evi-tx' (M6 batch B9b; B5 had
 * reject-stubbed all three because their YANG leaves carried no 'default'
 * statement, and M6 batch B9a added the defaults matching the compiled
 * BGP_EVPN_MH_USE_ES_L3NHG_DEF / _EAD_EVI_RX_DEF / _EAD_EVI_TX_DEF
 * constants). Plain Tier A leaves now: modify-only, a delete resolves to
 * the YANG default. Like every other multihoming leaf here, bgp_mh_info
 * is process-wide state, so there is no bgp instance to look up.
 * use-es-l3nhg is a bare field write with no side-effect call, exactly
 * like the legacy bgp_evpn_use_es_l3nhg_cmd; the two ead-evi-* leaves
 * reproduce their legacy DEFPYs' fire-only-on-change guard around
 * bgp_evpn_switch_ead_evi_rx()/_tx() (which walk/update ES state). The
 * positive ead-evi-* leaves map directly onto the enable_ead_evi_*
 * fields.
 */
int instance_afi_safis_l2vpn_evpn_multihoming_use_es_l3nhg_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_mh_info->host_routes_use_l3nhg = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_evi_rx_modify(
	struct nb_cb_modify_args *args)
{
	bool enable_rx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable_rx = yang_dnode_get_bool(args->dnode, NULL);
	if (enable_rx != bgp_mh_info->enable_ead_evi_rx) {
		bgp_mh_info->enable_ead_evi_rx = enable_rx;
		bgp_evpn_switch_ead_evi_rx();
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_evi_tx_modify(
	struct nb_cb_modify_args *args)
{
	bool enable_tx;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	enable_tx = yang_dnode_get_bool(args->dnode, NULL);
	if (enable_tx != bgp_mh_info->enable_ead_evi_tx) {
		bgp_mh_info->enable_ead_evi_tx = enable_tx;
		bgp_evpn_switch_ead_evi_tx();
	}

	return NB_OK;
}

/* 'dup-addr-detection' / 'no dup-addr-detection' bare toggle -- the
 * 'enabled' leaf (M6 batch B9b; B4 had reject-stubbed it because the
 * leaf carried no 'default "true"' statement, added by M6 batch B9a).
 * Tier-A-inverted: modify-only, only the negative form is ever written
 * back, a delete resolves to the true default. Routes through the same
 * reread-the-whole-container helper as max-moves/time/freeze below,
 * which since this conversion reads the enabled leaf instead of
 * unconditionally asserting it -- so the legacy DEFPYs' "configuring
 * max-moves/time or freeze also turns detection back on" side effect now
 * lives in the CLI layer (the value-bearing mgmtd DEFPYs delete
 * './enabled' back to its true default, bgp_cli_instance.c), keeping the
 * datastore and bgp->evpn_info->dup_addr_detect in lockstep. The legacy
 * bare 'no dup-addr-detection' additionally reset max-moves/time/freeze
 * to their defaults; the mgmtd 'no' form deletes those leaves alongside,
 * so the reread reproduces that too.
 */
/* max-moves/time/freeze (M6 batch B4, dup_addr_detection_cmd /
 * dup_addr_detection_auto_recovery_cmd): none of the three carry a YANG
 * default (same no-default numeric-leaf shape as B8's per-neighbor
 * dampening half-life/reuse-threshold/etc.), so every leaf's MODIFY/DESTROY
 * reroutes to a single "reread the whole dup-addr-detection container,
 * reapply to bgp->evpn_info, notify zebra" helper -- a reread after any one
 * leaf's change still recomputes a fully consistent set, and unset leaves
 * fall back to the same EVPN_DAD_DEFAULT_* legacy itself used. Since M6
 * B9b the dup_addr_detect flag is read from the (now defaulted) 'enabled'
 * leaf instead of being asserted unconditionally -- see the doc comment
 * on the enabled_modify callback above; the legacy "configuring
 * max-moves/time or freeze also turns detection back on" side effect
 * moved to the CLI layer (the value-bearing mgmtd DEFPYs delete
 * './enabled' back to its true default, bgp_cli_instance.c), keeping the
 * datastore and bgp->evpn_info->dup_addr_detect in lockstep. A
 * destroy-side reread sees the pre-commit sibling values (destroy dnodes
 * point into the old tree); any sibling changed in the same commit
 * re-drives this helper with its own final value afterwards, so the last
 * apply always runs against the fully-new state.
 */
static void bgp_nb_dup_addr_detection_apply(struct bgp *bgp, const struct lyd_node *dnode)
{
	if (!bgp || !bgp->evpn_info)
		return;

	bgp->evpn_info->dup_addr_detect = yang_dnode_get_bool(dnode, "enabled");

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

int instance_afi_safis_l2vpn_evpn_dup_addr_detection_enabled_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_dup_addr_detection_apply(bgp_nb_instance_lookup(args->dnode),
					yang_dnode_get_parent(args->dnode, "dup-addr-detection"));

	return NB_OK;
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

/* Per-VNI and VRF-level 'route-target <both|import|export> RTLIST...' /
 * 'auto-route-target <both|import|export> <add-always|add-never|
 * add-if-no-manual[|rfc8365-compatible]>' (M6 batch B9b, on B9a's
 * direction-primary route-target tree: manual rts, the import-only
 * wildcard-rts leaf-list and the automatic route-target's mode -- plus,
 * VRF-level only, the rfc8365-compatible encoding switch -- all live
 * under route-target/<import|export>; 'both' is a CLI input alias the
 * mgmtd DEFPYs expand into both direction subtrees, never seen here).
 *
 * Every manual-RT list entry's keys ARE the RT's whole value, so
 * create/destroy is the complete operation (same shape as B5's
 * ead-es-route-target-export). Each callback builds the typed
 * struct bgp_evpn_cfgd_rt directly from the already-typed YANG leaves
 * and drives the per-direction legacy setters:
 * bgp_evpn_configure/unconfigure_{import,export}_rt_for_vrf
 * (bgp_evpn.c) for the VRF level,
 * evpn_configure/unconfigure_{import,export}_rt_for_l2vni
 * (bgp_evpn_vty.c, un-static'd) per VNI. Those setters expect the
 * caller to have checked for duplicate adds / missing deletes (they
 * uninstall+reinstall or withdraw+re-advertise routes unconditionally,
 * and the configure side takes ownership of a heap cfgd_rt), so the
 * bgp_nb_evpn_{vrf,vni}_rt_apply() helpers below reproduce the retired
 * vrf_rt_add/del / l2vni_rt_add/del dispatchers' presence checks: a
 * create of an already-present RT and a destroy of an already-absent
 * one are silent no-ops, keeping the B2 fire-only-on-real-transition
 * rule (no route churn on replays).
 *
 * The auto/mode leaves map the YANG enum (identical keywords) through
 * bgp_evpn_autort_mode_from_str() onto the mode setters, which are
 * self-guarded/idempotent; mode destroy resolves to the
 * never-configured BGP_EVPN_AUTORT_NOT_CFGD state via the unconfigure
 * setters. The VRF-level rfc8365-compatible leaves (default false,
 * modify-only) route through the equally self-guarded
 * evpn_set/unset_autort_rfc8365().
 *
 * Role guards: the legacy per-VNI DEFPYs carried an EVPN_ENABLED soft
 * CMD_WARNING guard, reproduced as an APPLY-time no-op (same
 * schema-order reasoning as the B6 per-VNI rd callbacks: advertise-all-vni
 * may be applied earlier in the same commit, so a VALIDATE-time check
 * would read stale state); the VNI lookup itself already tolerates a
 * missing bgpevpn. The VRF-level DEFPYs had no role guard, so the VRF
 * callbacks have none either.
 */
static void bgp_nb_evpn_cfgd_rt_from_dnode(struct bgp_evpn_cfgd_rt *rt,
					   const struct lyd_node *dnode,
					   enum bgp_evpn_cfgd_rt_type type)
{
	memset(rt, 0, sizeof(*rt));
	rt->type = type;

	switch (type) {
	case BGP_EVPN_CFGD_RT_TYPE_WILDCARD:
		rt->payload.wildcard_rt.local_admin = yang_dnode_get_uint32(dnode, NULL);
		break;
	case BGP_EVPN_CFGD_RT_TYPE_AS2:
		rt->payload.as2_rt.as = yang_dnode_get_uint16(dnode, "global-admin");
		rt->payload.as2_rt.local_admin = yang_dnode_get_uint32(dnode, "local-admin");
		break;
	case BGP_EVPN_CFGD_RT_TYPE_IP4:
		yang_dnode_get_ipv4(&rt->payload.ip4_rt.ip, dnode, "global-admin");
		rt->payload.ip4_rt.local_admin = yang_dnode_get_uint16(dnode, "local-admin");
		break;
	case BGP_EVPN_CFGD_RT_TYPE_AS4:
		rt->payload.as4_rt.as = yang_dnode_get_uint32(dnode, "global-admin");
		rt->payload.as4_rt.local_admin = yang_dnode_get_uint16(dnode, "local-admin");
		break;
	}
}

static void bgp_nb_evpn_vrf_rt_apply(const struct lyd_node *dnode, enum bgp_evpn_cfgd_rt_type type,
				     bool import, bool del)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	struct bgp_evpn_rt_config *rt_config;
	struct bgp_evpn_cfgd_rt rt;
	bool exists;

	if (!bgp)
		return;

	rt_config = bgp->vrf_route_target_config;
	bgp_nb_evpn_cfgd_rt_from_dnode(&rt, dnode, type);
	exists = !!bgp_evpn_cfgd_rt_slu_find(import ? &rt_config->cfgd_import
						    : &rt_config->cfgd_export,
					     &rt);

	if (del) {
		if (!exists)
			return;
		if (import)
			bgp_evpn_unconfigure_import_rt_for_vrf(bgp, &rt);
		else
			bgp_evpn_unconfigure_export_rt_for_vrf(bgp, &rt);
	} else {
		if (exists)
			return;
		if (import)
			bgp_evpn_configure_import_rt_for_vrf(bgp, bgp_evpn_cfgd_rt_dup(&rt));
		else
			bgp_evpn_configure_export_rt_for_vrf(bgp, bgp_evpn_cfgd_rt_dup(&rt));
	}
}

/* The bgp/vpn pair every per-VNI RT callback operates on, or vpn == NULL
 * for "silently skip" (instance gone, VNI not materialized, or the
 * legacy EVPN_ENABLED soft guard). */
static struct bgpevpn *bgp_nb_evpn_vni_rt_owner(const struct lyd_node *dnode, struct bgp **bgp_out)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);

	*bgp_out = bgp;
	if (!bgp || !EVPN_ENABLED(bgp))
		return NULL;

	return bgp_nb_evpn_vni_lookup(dnode);
}

static void bgp_nb_evpn_vni_rt_apply(const struct lyd_node *dnode, enum bgp_evpn_cfgd_rt_type type,
				     bool import, bool del)
{
	struct bgp *bgp;
	struct bgpevpn *vpn = bgp_nb_evpn_vni_rt_owner(dnode, &bgp);
	struct bgp_evpn_rt_config *rt_config;
	struct bgp_evpn_cfgd_rt rt;
	bool exists;

	if (!vpn)
		return;

	rt_config = vpn->rt_config;
	bgp_nb_evpn_cfgd_rt_from_dnode(&rt, dnode, type);
	exists = !!bgp_evpn_cfgd_rt_slu_find(import ? &rt_config->cfgd_import
						    : &rt_config->cfgd_export,
					     &rt);

	if (del) {
		if (!exists)
			return;
		if (import)
			evpn_unconfigure_import_rt_for_l2vni(bgp, vpn, &rt);
		else
			evpn_unconfigure_export_rt_for_l2vni(bgp, vpn, &rt);
	} else {
		if (exists)
			return;
		if (import)
			evpn_configure_import_rt_for_l2vni(bgp, vpn, bgp_evpn_cfgd_rt_dup(&rt));
		else
			evpn_configure_export_rt_for_l2vni(bgp, vpn, bgp_evpn_cfgd_rt_dup(&rt));
	}
}

static void bgp_nb_evpn_vni_auto_rt_apply(const struct lyd_node *dnode, bool import,
					  const char *mode)
{
	struct bgp *bgp;
	struct bgpevpn *vpn = bgp_nb_evpn_vni_rt_owner(dnode, &bgp);

	if (!vpn)
		return;

	if (!mode) {
		if (import)
			evpn_unconfigure_import_auto_rt_for_l2vni(bgp, vpn);
		else
			evpn_unconfigure_export_auto_rt_for_l2vni(bgp, vpn);
	} else if (import) {
		evpn_configure_import_auto_rt_for_l2vni(bgp, vpn,
							bgp_evpn_autort_mode_from_str(mode));
	} else {
		evpn_configure_export_auto_rt_for_l2vni(bgp, vpn,
							bgp_evpn_autort_mode_from_str(mode));
	}
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as2_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as2_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as4_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_as4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_ipv4_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_rts_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_wildcard_rts_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_WILDCARD, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_wildcard_rts_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_WILDCARD, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_auto_mode_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_auto_rt_apply(args->dnode, true,
					      yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_import_auto_mode_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_auto_rt_apply(args->dnode, true, NULL);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as2_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as2_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as4_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_as4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_ipv4_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_rts_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_auto_mode_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_auto_rt_apply(args->dnode, false,
					      yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_route_target_export_auto_mode_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vni_auto_rt_apply(args->dnode, false, NULL);

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

/* VRF-level route-target callbacks: same shape as the per-VNI set above
 * (see the shared doc comment there), driving the bgp_evpn.c VRF setters
 * through bgp_nb_evpn_vrf_rt_apply(); no role guard (the legacy VRF
 * DEFPYs had none). The two rfc8365-compatible leaves are VRF-only. */
int instance_afi_safis_l2vpn_evpn_route_target_import_rts_as2_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_rts_as2_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_rts_as4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_rts_as4_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_rts_ipv4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_rts_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_rts_create(
	struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_WILDCARD, true, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_wildcard_rts_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_WILDCARD, true, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_auto_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_evpn_configure_import_auto_rt_for_vrf(bgp, bgp_evpn_autort_mode_from_str(
							       yang_dnode_get_string(args->dnode,
										     NULL)));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_auto_mode_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_evpn_unconfigure_import_auto_rt_for_vrf(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_import_auto_rfc8365_compatible_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_autort_rfc8365(bgp, true /* import */, false /* export */);
	else
		evpn_unset_autort_rfc8365(bgp, true /* import */, false /* export */);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_as2_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_as2_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS2, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_as4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_as4_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_AS4, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_ipv4_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, false, false);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_rts_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_evpn_vrf_rt_apply(args->dnode, BGP_EVPN_CFGD_RT_TYPE_IP4, false, true);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_auto_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_evpn_configure_export_auto_rt_for_vrf(bgp, bgp_evpn_autort_mode_from_str(
							       yang_dnode_get_string(args->dnode,
										     NULL)));

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_auto_mode_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_evpn_unconfigure_export_auto_rt_for_vrf(bgp);

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_route_target_export_auto_rfc8365_compatible_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		evpn_set_autort_rfc8365(bgp, false /* import */, true /* export */);
	else
		evpn_unset_autort_rfc8365(bgp, false /* import */, true /* export */);

	return NB_OK;
}

/* 'advertise <ipv4|ipv6> unicast [gateway-ip] [route-map WORD]' (M6
 * batch B9b; B7 had reject-stubbed the family over its then-leafref
 * 'route-map' leaf rejecting forward references -- M6 batch B9a retyped
 * it to a plain string). The three leaves form one atomic legacy command
 * (enabled and gateway-ip are alternatives, FRR stores/writes exactly
 * one), so the whole container converts as one unit through a single
 * apply_finish callback per AF: it fires once per commit, after every
 * other callback, with the container from the NEW tree -- rereading the
 * complete (enabled, gateway-ip, route-map) tuple and handing it to
 * evpn_process_advertise_type5_cmd() (bgp_evpn_vty.c, the extracted
 * legacy transition machinery, itself a no-op when the requested state
 * is already configured). Per-leaf reread-and-reissue callbacks were
 * deliberately NOT used here: destroys run before modifies and their
 * dnodes point into the old tree, so a 'no advertise ...' (route-map
 * destroy + enabled modify) would transiently reissue an
 * advertise-with-old-flags -- a real withdraw/re-advertise churn cycle
 * -- before the disable lands. The leaf callbacks below therefore
 * accept every event and do nothing; apply_finish does all the work.
 */
static void bgp_nb_evpn_advertise_unicast_finish(const struct lyd_node *dnode, afi_t afi)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const char *rmap_name = NULL;
	bool enabled, gateway_ip;

	if (!bgp)
		return;

	enabled = yang_dnode_get_bool(dnode, "enabled");
	gateway_ip = yang_dnode_get_bool(dnode, "gateway-ip");
	if (yang_dnode_exists(dnode, "route-map"))
		rmap_name = yang_dnode_get_string(dnode, "route-map");

	evpn_process_advertise_type5_cmd(bgp, afi,
					 gateway_ip ? OVERLAY_INDEX_GATEWAY_IP
						    : OVERLAY_INDEX_TYPE_NONE,
					 rmap_name, enabled || gateway_ip);
}

void instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_nb_evpn_advertise_unicast_finish(args->dnode, AFI_IP);
}

void instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_apply_finish(
	struct nb_cb_apply_finish_args *args)
{
	bgp_nb_evpn_advertise_unicast_finish(args->dnode, AFI_IP6);
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_enabled_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_gateway_ip_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv4_unicast_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_enabled_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_gateway_ip_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_modify(
	struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_ipv6_unicast_route_map_destroy(
	struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
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

/* '[no] advertise-pip [ip A.B.C.D [mac X:X:X:X:X:X]]' (M6 batch B9b;
 * B7 had reject-stubbed the family, and M6 batch B9a added the missing
 * 'default "true"' on enabled plus the must constraints binding a
 * static ip to enabled and a static mac to the ip -- the one atomic
 * legacy command). Same one-apply_finish-per-commit shape as the
 * advertise-<afi>-unicast containers above, for the same
 * destroys-before-modifies churn reason: the whole (enabled, ip, mac)
 * tuple is reread from the NEW tree once and handed to
 * evpn_process_advertise_pip_cmd() (bgp_evpn_vty.c), which itself
 * no-ops unless the stored state actually changes.
 *
 * Role guard: legacy hard-rejected the command outside a per-VRF
 * instance ("supported under L3VNI BGP EVPN VRF",
 * CMD_WARNING_CONFIG_FAILED when EVPN_ENABLED(bgp)). Reproduced as an
 * APPLY-time silent skip rather than a VALIDATE rejection -- the
 * EVPN-owning default instance is only known post-apply within a commit
 * that also toggles advertise-all-vni (the B2/B6 schema-order
 * reasoning), and a config carrying advertise-pip leaves on the EVPN
 * underlay instance was equally non-functional under legacy (the line
 * was dropped at load).
 */
void instance_afi_safis_l2vpn_evpn_advertise_pip_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp = bgp_nb_instance_lookup(args->dnode);
	struct in_addr ip;
	struct ethaddr mac;
	bool has_ip, has_mac;

	if (!bgp || EVPN_ENABLED(bgp))
		return;

	has_ip = yang_dnode_exists(args->dnode, "ip");
	if (has_ip)
		yang_dnode_get_ipv4(&ip, args->dnode, "ip");
	has_mac = yang_dnode_exists(args->dnode, "mac");
	if (has_mac)
		yang_dnode_get_mac(&mac, args->dnode, "mac");

	evpn_process_advertise_pip_cmd(bgp, yang_dnode_get_bool(args->dnode, "enabled"),
				       has_ip ? &ip : NULL, has_mac ? &mac : NULL);
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_enabled_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_ip_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_ip_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_mac_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_advertise_pip_mac_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/* EVPN type-5 static 'network <A.B.C.D/M|X:X::X:X/M> rd RD ethtag WORD
 * label WORD esi WORD gwip <A.B.C.D|X:X::X:X> routermac WORD [route-map
 * NAME]' (M6 batch B9b; B8 had reject-stubbed the whole list over its
 * then-leafref 'route-map' leaf, retyped to a plain string by M6 batch
 * B9a). M5 network-list idiom (bgp_nb_af_network_* in bgp_nb_util.c):
 * the list entry's create/destroy calls the same bgp_static_set() core
 * the retired evpnrt5_network DEFUNs reached through
 * bgp_static_set_vty(), and every option-leaf modify rereads the whole
 * entry and reissues the set (bgp_static_set() updates an existing
 * (rd, prefix) entry in place). EVPN specifics on top of M5's shape:
 *
 * - bgp_static_set() keys EVPN statics by (rd, prefix) while the YANG
 *   list is keyed by prefix alone (one statement per prefix, B9a's
 *   deliberate shape). An rd change that switches the choice case
 *   (e.g. as2 -> ipv4) is fully handled: the old case's destroy --
 *   which fires exactly on a case switch, before any create, its dnode
 *   still reading the old tree -- negates the entry under its old rd,
 *   and the new case's own create re-adds it. An rd VALUE change
 *   within the same case is an in-place leaf modify; its
 *   reread-and-reissue adds the entry under the new rd and leaves the
 *   old (rd, prefix) static configured in bgpd until an explicit 'no
 *   network ... rd <old>' -- exactly what legacy did when a second
 *   'network P rd RD2 ...' line arrived without removing the first
 *   (the prefix-keyed datastore merely narrows how that state can be
 *   reached). The rd presence container itself can never be destroyed
 *   on a surviving entry (the B9a 'must' requires an rd), so its
 *   destroy is a no-op.
 * - The 'route-map' token: the retired positive DEFUN parsed it but
 *   passed NULL to bgp_static_set_vty() and the emitter never wrote it
 *   back; here it is stored and applied for real (see the retirement
 *   comment in bgp_evpn_vty.c).
 * - ethtag/label are numeric YANG leaves; bgp_static_set() takes their
 *   canonical string forms directly, as it does prefix/esi/gwip/
 *   routermac.
 */
static const char *bgp_nb_evpn_network_rd_str(const struct lyd_node *entry_dnode, char *buf,
					      size_t buf_len)
{
	const struct lyd_node *rd_dnode = yang_dnode_get(entry_dnode, "rd");

	if (!rd_dnode)
		return NULL;

	if (yang_dnode_exists(rd_dnode, "as2"))
		snprintf(buf, buf_len, "%s:%s",
			 yang_dnode_get_string(rd_dnode, "as2/administrator"),
			 yang_dnode_get_string(rd_dnode, "as2/assigned-number"));
	else if (yang_dnode_exists(rd_dnode, "as4"))
		snprintf(buf, buf_len, "%s:%s",
			 yang_dnode_get_string(rd_dnode, "as4/administrator"),
			 yang_dnode_get_string(rd_dnode, "as4/assigned-number"));
	else if (yang_dnode_exists(rd_dnode, "ipv4"))
		snprintf(buf, buf_len, "%s:%s",
			 yang_dnode_get_string(rd_dnode, "ipv4/administrator"),
			 yang_dnode_get_string(rd_dnode, "ipv4/assigned-number"));
	else
		/* Case switch mid-commit: the new case's own create (same
		 * commit) re-drives the set with the new rd. */
		return NULL;

	return buf;
}

static int bgp_nb_evpn_network_set(const struct lyd_node *entry_dnode, bool negate, char *errmsg,
				   size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_instance_lookup(entry_dnode);
	char rd_buf[64];
	const char *prefix_str, *rd_str, *rmap;
	int ret;

	if (!bgp)
		return NB_OK;

	rd_str = bgp_nb_evpn_network_rd_str(entry_dnode, rd_buf, sizeof(rd_buf));
	if (!rd_str)
		return NB_OK;

	prefix_str = yang_dnode_get_string(entry_dnode, "prefix");
	rmap = negate ? NULL
		      : (yang_dnode_exists(entry_dnode, "route-map")
				 ? yang_dnode_get_string(entry_dnode, "route-map")
				 : NULL);

	ret = bgp_static_set(bgp, negate, prefix_str, rd_str,
			     yang_dnode_get_string(entry_dnode, "label"), AFI_L2VPN, SAFI_EVPN,
			     rmap, 0 /* backdoor */, 0 /* label_index */, BGP_EVPN_IP_PREFIX_ROUTE,
			     yang_dnode_get_string(entry_dnode, "esi"),
			     yang_dnode_get_string(entry_dnode, "gwip"),
			     yang_dnode_get_string(entry_dnode, "ethtag"),
			     negate ? NULL : yang_dnode_get_string(entry_dnode, "routermac"),
			     errmsg, errmsg_len);
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: bgp_static_set() failed for %s: %s",
			 __func__, prefix_str, errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* Reissue the full entry after one option leaf changed (modify dnodes
 * live in the new tree, so the reread sees the final state). */
static int bgp_nb_evpn_network_reissue(const struct lyd_node *leaf_dnode, char *errmsg,
				       size_t errmsg_len)
{
	return bgp_nb_evpn_network_set(yang_dnode_get_parent(leaf_dnode, "network"), false, errmsg,
				       errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(args->dnode, false, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(args->dnode, true, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_create(struct nb_cb_create_args *args)
{
	/* No-op: the mandatory choice case's own create does the real work
	 * once its two leaves exist in the target tree. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_destroy(struct nb_cb_destroy_args *args)
{
	/* Unreachable on a surviving entry (the entry's 'must' requires an
	 * rd) and subsumed by the entry's own destroy otherwise. */
	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), false,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	/* Fires only on an rd case switch: negate the entry under its old
	 * rd (this dnode still reads the old tree) before the new case's
	 * create re-adds it. */
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), true,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as2_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), false,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), true,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_ipv4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), false,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_set(yang_dnode_get_parent(args->dnode, "network"), true,
				       args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_rd_as4_assigned_number_modify(
	struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

/* mac/raw rd cases: no legacy producer (str2prefix_rd() never emits
 * either, and 'mac' is blocked by a 'must false()' in
 * proteus-types.yang), same permanent reject-stubs as the vni/instance
 * 'rd' choices. */
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
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_label_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_esi_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_gwip_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_routermac_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_route_map_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_evpn_network_reissue(args->dnode, args->errmsg, args->errmsg_len);
}

int instance_afi_safis_l2vpn_evpn_network_route_map_destroy(struct nb_cb_destroy_args *args)
{
	/* The destroy dnode reads the old tree; reissue the entry with the
	 * route-map explicitly dropped (M5's network route-map destroy
	 * idiom: reread the other leaves, never the destroyed one). */
	const struct lyd_node *entry_dnode;
	struct bgp *bgp;
	char rd_buf[64];
	const char *rd_str;
	char errmsg[256];
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");
	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	rd_str = bgp_nb_evpn_network_rd_str(entry_dnode, rd_buf, sizeof(rd_buf));
	if (!rd_str)
		return NB_OK;

	ret = bgp_static_set(bgp, false, yang_dnode_get_string(entry_dnode, "prefix"), rd_str,
			     yang_dnode_get_string(entry_dnode, "label"), AFI_L2VPN, SAFI_EVPN,
			     NULL /* rmap */, 0, 0, BGP_EVPN_IP_PREFIX_ROUTE,
			     yang_dnode_get_string(entry_dnode, "esi"),
			     yang_dnode_get_string(entry_dnode, "gwip"),
			     yang_dnode_get_string(entry_dnode, "ethtag"),
			     yang_dnode_get_string(entry_dnode, "routermac"), errmsg,
			     sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: bgp_static_set() failed: %s",
			 __func__, errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}
