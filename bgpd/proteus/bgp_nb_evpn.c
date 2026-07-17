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
#include "bgpd/bgp_evpn_private.h"
#include "bgpd/bgp_evpn_vty.h"
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

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_frag_evi_limit_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-frag-evi-limit");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as2_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_as4_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_create(
	struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_multihoming_ead_es_route_target_export_ipv4_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/multihoming/ead-es-route-target-export/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

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

int instance_afi_safis_l2vpn_evpn_vni_rd_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as2_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as2/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_ipv4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/ipv4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_rd_as4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/rd/as4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

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

int instance_afi_safis_l2vpn_evpn_vni_flooding_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/flooding");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_flooding_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/flooding");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

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

int instance_afi_safis_l2vpn_evpn_vni_advertise_default_gw_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-default-gw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_advertise_svi_ip_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-svi-ip");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_vni_advertise_subnet_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/vni/advertise-subnet");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as2_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as2/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_ipv4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/ipv4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_administrator_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4/administrator");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_rd_as4_assigned_number_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/rd/as4/assigned-number");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

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

int instance_afi_safis_l2vpn_evpn_default_originate_ipv4_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_afi_safis_l2vpn_evpn_default_originate_ipv6_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/afi-safis/l2vpn-evpn/default-originate/ipv6");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

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
