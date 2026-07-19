// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for instance-global scalars under /proteus-bgp:instance (bestpath, timers, confederation, etc).
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
#include "bgpd/bgp_mplsvpn.h"
#include "bgpd/bgp_srv6.h"
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
#include "bgpd/proteus/bgp_nb_local.h"


int instance_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_instance_apply(args->dnode);
	}

	return NB_OK;
}

int instance_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (bgp)
			bgp_delete(bgp);
		break;
	}

	return NB_OK;
}

int instance_instance_type_modify(struct nb_cb_modify_args *args)
{
	/* consumed directly by instance_create()/instance_destroy() */
	return NB_OK;
}

int instance_autonomous_system_plain_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_instance_asn_apply(args->dnode);

	return NB_OK;
}

int instance_autonomous_system_plain_destroy(struct nb_cb_destroy_args *args)
{
	/* the instance 'must' forbids removing the ASN without removing the
	 * whole instance, so this only fires alongside instance_destroy() */
	return NB_OK;
}

int instance_autonomous_system_asdot_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_instance_asn_apply(args->dnode);

	return NB_OK;
}

int instance_autonomous_system_asdot_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int instance_autonomous_system_asdot_high_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_instance_asn_apply(args->dnode);

	return NB_OK;
}

int instance_autonomous_system_asdot_low_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_instance_asn_apply(args->dnode);

	return NB_OK;
}

int instance_as_notation_modify(struct nb_cb_modify_args *args)
{
	/* consumed directly by instance_create() */
	return NB_OK;
}

int instance_as_notation_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int instance_router_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr router_id;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		yang_dnode_get_ipv4(&router_id, args->dnode, NULL);
		bgp_router_id_static_set(bgp, router_id);
		break;
	}

	return NB_OK;
}

int instance_router_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_router_id_static_set(bgp, (struct in_addr){ .s_addr = INADDR_ANY });
		break;
	}

	return NB_OK;
}

int instance_cluster_id_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct in_addr cluster;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		/* inet_aton(), not inet_pton(): the union type also accepts
		 * a plain decimal 32-bit value, and inet_aton() is what the
		 * legacy DEFUN used to accept both forms.
		 */
		inet_aton(yang_dnode_get_string(args->dnode, NULL), &cluster);
		bgp_cluster_id_set(bgp, &cluster);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_OUT);
		break;
	}

	return NB_OK;
}

int instance_cluster_id_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_cluster_id_unset(bgp);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_OUT);
		break;
	}

	return NB_OK;
}

int instance_fast_external_failover_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		/* inverted: leaf true (fast failover on) -> UNSET the "no
		 * fast failover" flag, leaf false -> SET it.
		 */
		if (yang_dnode_get_bool(args->dnode, NULL))
			UNSET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
		else
			SET_FLAG(bgp->flags, BGP_FLAG_NO_FAST_EXT_FAILOVER);
		break;
	}

	return NB_OK;
}

/* Per-VRF override of the process-wide '/proteus-bgp:process/ipv6-auto-ra'
 * leaf: mirrors the legacy BGP_NODE branch of bgp_ipv6_auto_ra_cmd (this
 * instance's flag only, no bm-> touch). Destroy restores the leaf's
 * "inherit process behavior" semantics by resyncing this instance's flag
 * to the process-wide bm-> setting, exactly what the legacy DEFPY left in
 * place before any per-VRF override was ever typed.
 */
int instance_ipv6_auto_ra_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA,
			  !yang_dnode_get_bool(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int instance_ipv6_auto_ra_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		COND_FLAG(bgp->flags, BGP_FLAG_IPV6_NO_AUTO_RA,
			  CHECK_FLAG(bm->flags, BM_FLAG_IPV6_NO_AUTO_RA));
		break;
	}

	return NB_OK;
}

/* Both leaves drive the same bgp_suppress_fib_pending_set(bgp, set,
 * adv_delay) call (bgpd.c), matching bgp_suppress_fib_pending_cmd exactly,
 * including its VIEW-instance no-op and zclient-not-ready deferral -- both
 * live entirely inside the setter. Same re-read-sibling-and-reapply shape as
 * the process-scope pair above.
 */
int instance_suppress_fib_pending_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enabled;
	uint16_t adv_delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	enabled = yang_dnode_get_bool(args->dnode, NULL);
	adv_delay = yang_dnode_get_uint16(args->dnode, "../advertisement-delay");

	bgp_suppress_fib_pending_set(bgp, enabled, adv_delay);

	return NB_OK;
}

int instance_suppress_fib_pending_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enabled;
	uint16_t adv_delay;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	adv_delay = yang_dnode_get_uint16(args->dnode, NULL);
	enabled = yang_dnode_get_bool(args->dnode, "../enabled");

	bgp_suppress_fib_pending_set(bgp, enabled, adv_delay);

	return NB_OK;
}

int instance_log_neighbor_changes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		break;
	}

	return NB_OK;
}

int instance_log_neighbor_changes_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_log_neighbor_changes_default())
			SET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_LOG_NEIGHBOR_CHANGES);
		break;
	}

	return NB_OK;
}

int instance_always_compare_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ALWAYS_COMPARE_MED);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_ebgp_requires_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		break;
	}

	return NB_OK;
}

int instance_ebgp_requires_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_ebgp_requires_policy_default())
			SET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_EBGP_REQUIRES_POLICY);
		break;
	}

	return NB_OK;
}

/* Interim bridge (delete at M8 when peer creation becomes a northbound
 * transaction operation, see the commit message for the full rationale):
 * during config-file load, native 'neighbor ... remote-as' peer creation
 * (bgpd.c peer_new(), ~1792-1807) still runs immediately as bgpd reads the
 * file, while these instance-default capability/enforce-first-as leaves are
 * mgmtd-owned and only reach bgpd once mgmtd pushes its batched commit over
 * the backend connection. A peer created earlier in the file therefore
 * never gets seeded. Replay peer_new()'s seeding onto peers that already
 * exist, gated on bgp_nb_reseed_gate() (below) so interactive config keeps
 * legacy's future-peers-only semantics untouched (legacy interactive
 * 'bgp default ...' never iterated existing peers either). Override-aware
 * apply mirrors peer_group2peer_config_copy() (bgpd.c ~3412-3435): a peer
 * with an explicit (non-inherited) value for the flag is left alone.
 */

/* bgp_nb_reseed_gate() - is this APPLY part of the config-load window?
 *
 * bgp_config_inprocess() (bgp_vty.c) only tracks bgpd's own vty_read_file()
 * of bgpd.conf, bracketed by the literal 'XFRR_start_configuration'/
 * 'XFRR_end_configuration' markers that vtysh emits for an integrated
 * frr.conf. Split-config per-daemon files (the normal case, e.g. every
 * topotest) never contain those markers, so bgp_config_inprocess()
 * never becomes true for them, even though mgmtd still separately reads
 * and northbound-commits bgpd.conf and still pushes the result to bgpd as
 * one batched backend transaction once bgpd registers as a backend client
 * -- the exact race this bridge exists to paper over. bgp_config_inprocess()
 * is kept as the primary gate (it is correct for integrated frr.conf), and
 * this is a fallback for the split-config case: the first backend APPLY
 * bgpd ever processes is -- by construction, since mgmtd commits an entire
 * config file as a single transaction -- indistinguishable from "the
 * config-file load just caught up", so treat it as one. The gate stays
 * open for the remainder of that same synchronous APPLY batch (the closing
 * event is only queued, not yet run) and closes for good on the next event
 * loop turn, before any later transaction -- reload or interactive -- can
 * reach a callback.
 */
static bool bgp_nb_reseed_window_open = true;
static struct event *bgp_nb_reseed_window_close_ev;

static void bgp_nb_reseed_window_close(struct event *t)
{
	bgp_nb_reseed_window_open = false;
}

static bool bgp_nb_reseed_gate(void)
{
	/* Arm the one-shot window close on the very first call regardless of
	 * which branch answers below: otherwise an integrated frr.conf load
	 * (answered by bgp_config_inprocess()) would never queue the close, and
	 * the first post-boot interactive change -- inprocess now false, window
	 * never exercised -- would find the fallback window still open and
	 * wrongly re-seed live peers, breaking legacy future-peers-only
	 * semantics. The close fires one event-loop turn later; during an
	 * integrated load bgp_config_inprocess() keeps covering the rest of the
	 * load, so closing the fallback window early is harmless.
	 */
	if (bgp_nb_reseed_window_open && !bgp_nb_reseed_window_close_ev)
		event_add_event(bm->master, bgp_nb_reseed_window_close, NULL, 0,
				&bgp_nb_reseed_window_close_ev);

	if (bgp_config_inprocess())
		return true;

	return bgp_nb_reseed_window_open;
}

static void bgp_reseed_default_capability(struct bgp *bgp, uint64_t bgp_flag, uint64_t peer_flag)
{
	struct listnode *node;
	struct peer *peer;

	if (!CHECK_FLAG(bgp->flags, bgp_flag))
		return;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (!CHECK_FLAG(peer->flags_override, peer_flag))
			SET_FLAG(peer->flags, peer_flag);
	}
}

static void bgp_reseed_default_enforce_first_as(struct bgp *bgp)
{
	struct listnode *node;
	struct peer *peer;

	if (!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
		return;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		if (CHECK_FLAG(peer->flags_override, PEER_FLAG_ENFORCE_FIRST_AS))
			continue;
		/* Mirror peer_new()'s manual set (bgpd.c ~1792-1795): the flag
		 * defaults to enabled, so it must be marked inverted for
		 * correct 'show running-config' display.
		 */
		SET_FLAG(peer->flags_invert, PEER_FLAG_ENFORCE_FIRST_AS);
		SET_FLAG(peer->flags, PEER_FLAG_ENFORCE_FIRST_AS);
	}
}

int instance_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		if (bgp_nb_reseed_gate())
			bgp_reseed_default_enforce_first_as(bgp);
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			FOREACH_AFI_SAFI (afi, safi)
				peer_on_policy_change(peer, afi, safi, 0);
		}
		break;
	}

	return NB_OK;
}

int instance_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node;
	struct peer *peer;
	afi_t afi;
	safi_t safi;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = bgp_enforce_first_as_default();
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS);
		for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
			FOREACH_AFI_SAFI (afi, safi)
				peer_on_policy_change(peer, afi, safi, 0);
		}
		break;
	}

	return NB_OK;
}

int instance_labeled_unicast_explicit_null_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *value;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		value = yang_dnode_get_string(args->dnode, NULL);
		UNSET_FLAG(bgp->flags,
			   BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
		if (strmatch(value, "ipv4"))
			SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV4_EXPLICIT_NULL);
		else if (strmatch(value, "ipv6"))
			SET_FLAG(bgp->flags, BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
		else
			SET_FLAG(bgp->flags,
				 BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
		break;
	}

	return NB_OK;
}

int instance_labeled_unicast_explicit_null_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		UNSET_FLAG(bgp->flags,
			   BGP_FLAG_LU_IPV4_EXPLICIT_NULL | BGP_FLAG_LU_IPV6_EXPLICIT_NULL);
		break;
	}

	return NB_OK;
}

int instance_reject_as_sets_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->reject_as_sets = yang_dnode_get_bool(args->dnode, NULL);
		bgp_nb_reject_as_sets_reset_peers(bgp);
		break;
	}

	return NB_OK;
}

int instance_suppress_duplicates_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		break;
	}

	return NB_OK;
}

int instance_suppress_duplicates_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_suppress_duplicates_default())
			SET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SUPPRESS_DUPLICATES);
		break;
	}

	return NB_OK;
}

int instance_hard_administrative_reset_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
		break;
	}

	return NB_OK;
}

int instance_hard_administrative_reset_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_hard_administrative_reset_default())
			SET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_HARD_ADMIN_RESET);
		break;
	}

	return NB_OK;
}

int instance_default_ipv4_unicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_default_af_safi_conflict_validate(args, "../ipv4-labeled-unicast",
								false);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP][SAFI_UNICAST] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv4_multicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP][SAFI_MULTICAST] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv4_labeled_unicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_default_af_safi_conflict_validate(args, "../ipv4-unicast", true);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP][SAFI_LABELED_UNICAST] = yang_dnode_get_bool(args->dnode,
										    NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv4_vpn_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP][SAFI_MPLS_VPN] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv4_flowspec_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP][SAFI_FLOWSPEC] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv6_unicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_default_af_safi_conflict_validate(args, "../ipv6-labeled-unicast",
								false);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP6][SAFI_UNICAST] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv6_multicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP6][SAFI_MULTICAST] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv6_labeled_unicast_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_default_af_safi_conflict_validate(args, "../ipv6-unicast", true);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP6][SAFI_LABELED_UNICAST] = yang_dnode_get_bool(args->dnode,
										     NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv6_vpn_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP6][SAFI_MPLS_VPN] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_ipv6_flowspec_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_IP6][SAFI_FLOWSPEC] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

int instance_default_l2vpn_evpn_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->default_af[AFI_L2VPN][SAFI_EVPN] = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/* 'segment-routing srv6' block (M8.5 B-srv6-block). The presence
 * container's DESTROY runs the composite legacy unset
 * (no_bgp_segment_routing_srv6): locator teardown (SID withdraw/release,
 * async-safe via bgp_srv6_locator_unset), encap reset + refresh, and -
 * deliberate divergence from the legacy wart - srv6-only back to its
 * true default instead of forced false (legacy left a stray 'no
 * srv6-only' emission after removing the block). */
int instance_srv6_create(struct nb_cb_create_args *args)
{
	/* Presence marker only; children carry the state. */
	return NB_OK;
}

int instance_srv6_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (strlen(bgp->srv6_locator_name) > 0)
		bgp_srv6_locator_unset(bgp);

	if (bgp->srv6_encap_behavior != SRV6_HEADEND_BEHAVIOR_H_ENCAPS) {
		bgp->srv6_encap_behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;
		bgp_segment_routing_srv6_hencaps_refresh(bgp);
	}

	if (!bgp->srv6_only)
		bgp_srv6_only_change(bgp, true);

	return NB_OK;
}

int instance_srv6_locator_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *name;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Legacy rejects changing a configured locator without
		 * deleting it first; compare against the runtime name (the
		 * lookup is absent during a fresh config load, where any
		 * name is fine). */
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (bgp && strlen(bgp->srv6_locator_name) > 0 &&
		    !strmatch(yang_dnode_get_string(args->dnode, NULL), bgp->srv6_locator_name)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "srv6 locator is already configured");
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
		name = yang_dnode_get_string(args->dnode, NULL);
		if (strmatch(bgp->srv6_locator_name, name))
			break;
		bgp_srv6_sids_unset(bgp);
		snprintf(bgp->srv6_locator_name, sizeof(bgp->srv6_locator_name), "%s", name);
		/* Asynchronous: the locator (and subsequent SIDs) arrive via
		 * the zebra SRv6 manager reply. */
		bgp_zebra_srv6_manager_get_locator(name);
		break;
	}

	return NB_OK;
}

int instance_srv6_locator_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (strlen(bgp->srv6_locator_name) > 0)
		bgp_srv6_locator_unset(bgp);

	return NB_OK;
}

int instance_srv6_only_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val != bgp->srv6_only)
		bgp_srv6_only_change(bgp, val);

	return NB_OK;
}

int instance_srv6_encap_behavior_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	enum srv6_headend_behavior behavior;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Legacy wart preserved: always operates on the default instance,
	 * whichever instance's block carried the line. */
	bgp = bgp_get_default();
	if (!bgp)
		return NB_OK;

	if (strmatch(yang_dnode_get_string(args->dnode, NULL), "H_Encaps_Red"))
		behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS_RED;
	else
		behavior = SRV6_HEADEND_BEHAVIOR_H_ENCAPS;

	if (behavior == bgp->srv6_encap_behavior)
		return NB_OK;

	bgp->srv6_encap_behavior = behavior;
	bgp_segment_routing_srv6_hencaps_refresh(bgp);

	return NB_OK;
}

/* 'sid vpn per-vrf export' (M8.5 B-srv6-pervrf). Convergence model:
 * the presence container's apply_finish reads the FINAL choice state and
 * reconciles the runtime once per commit (mode changes and value changes
 * are one prechange/withdraw + one postchange/re-leak cycle); the case
 * leaves have no callbacks of their own. Full 'no sid vpn per-vrf
 * export' is the container DESTROY (a destroyed container's own
 * apply_finish is skipped). Exclusions vs the per-AF and unicast sid
 * forms plus legacy's mode-change rejection are checked at VALIDATE
 * against the runtime; the sibling forms convert later in the M8.5
 * train, at which point these can move into the model. */
static void bgp_nb_sid_vpn_export_unset(struct bgp *bgp)
{
	if (!is_srv6_vpn_vrf_enabled(bgp))
		return;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);

	bgp->tovpn_sid_index = 0;
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	UNSET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);
	XFREE(MTYPE_BGP_SRV6_SID, bgp->tovpn_sid_explicit);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
}

/* Case-leaf callbacks: no-ops (the container apply_finish converges from
 * the final tree), but nb_validate_callbacks requires them to exist for
 * every config-bearing node. */
int instance_sid_vpn_export_leaf_modify(struct nb_cb_modify_args *args)
{
	return NB_OK;
}

int instance_sid_vpn_export_leaf_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int instance_sid_vpn_export_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (is_srv6_vpn_afi_enabled(bgp, AFI_IP) || is_srv6_vpn_afi_enabled(bgp, AFI_IP6)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "per-vrf sid and per-af sid are mutually exclusive");
			return NB_ERR_VALIDATION;
		}
		if (is_srv6_unicast_enabled(bgp, AFI_IP) || is_srv6_unicast_enabled(bgp, AFI_IP6)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "sid export is configured on unicast");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_sid_vpn_export_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_nb_sid_vpn_export_unset(bgp);

	return NB_OK;
}

void instance_sid_vpn_export_apply_finish(struct nb_cb_apply_finish_args *args)
{
	struct bgp *bgp = bgp_nb_instance_lookup(args->dnode);
	bool want_auto, have_auto, have_explicit;
	uint32_t want_idx = 0;
	const char *want_explicit = NULL;
	struct in6_addr sid;

	if (!bgp)
		return;

	want_auto = yang_dnode_exists(args->dnode, "auto") &&
		    yang_dnode_get_bool(args->dnode, "auto");
	if (yang_dnode_exists(args->dnode, "index"))
		want_idx = yang_dnode_get_uint32(args->dnode, "index");
	if (yang_dnode_exists(args->dnode, "explicit"))
		want_explicit = yang_dnode_get_string(args->dnode, "explicit");

	have_auto = CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	have_explicit = CHECK_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);

	/* no change */
	if (want_auto == have_auto && want_idx == bgp->tovpn_sid_index &&
	    !want_explicit == !have_explicit &&
	    (!want_explicit ||
	     (bgp->tovpn_sid_explicit && inet_pton(AF_INET6, want_explicit, &sid) == 1 &&
	      IPV6_ADDR_SAME(&sid, bgp->tovpn_sid_explicit))))
		return;

	/* one withdraw/re-leak cycle: clear the old mode, set the new */
	bgp_nb_sid_vpn_export_unset(bgp);

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);

	if (want_auto) {
		SET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_AUTO);
	} else if (want_idx != 0) {
		bgp->tovpn_sid_index = want_idx;
	} else if (want_explicit) {
		bgp->tovpn_sid_explicit = XCALLOC(MTYPE_BGP_SRV6_SID, sizeof(struct in6_addr));
		inet_pton(AF_INET6, want_explicit, bgp->tovpn_sid_explicit);
		SET_FLAG(bgp->vrf_flags, BGP_VRF_TOVPN_SID_EXPLICIT);
	}

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP, bgp_get_default(), bgp);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, AFI_IP6, bgp_get_default(), bgp);
}

/* 'bgp default shutdown' (M8 batch B2). Deliberately NOT in the reseed
 * bridge: legacy emits this line AFTER the neighbor lines precisely so a
 * restart's file replay does not shut peers that already exist (FRR
 * #2286); the converted leaf keeps those future-peers-only semantics by
 * only setting bgp->autoshutdown (seeded into each subsequent
 * peer_create), never touching existing peers. A hand-written file that
 * placed the line before its neighbors now behaves as if it were written
 * after them - the machine-emitted order, and the leaf's documented
 * intent. */
int instance_default_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->autoshutdown = yang_dnode_get_bool(args->dnode, NULL);
		break;
	}

	return NB_OK;
}

/* 'bgp default local-preference (0-4294967295)' (Tier A: static
 * default-on scalar, no inheritance -- see the YANG leaf's "default"
 * statement). Destroy is not registered: the northbound layer resolves a
 * destroy on a default-bearing leaf to a modify-with-default, which
 * dispatches back through this same .modify callback with the value
 * already reset to 100, matching the legacy no-form's unset behavior
 * (bgpd.c's now-retired bgp_default_local_preference_unset(), superseded
 * by this callback). The legacy DEFUN's bgp_clear_star_soft_in() side
 * effect (soft-reprocess inbound updates so the new default applies to
 * already-received routes) is replicated via the vty-free
 * bgp_nb_clear_star_soft() helper.
 */
int instance_default_local_preference_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_default_local_preference_set(bgp, yang_dnode_get_uint32(args->dnode, NULL));
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_IN);
		break;
	}

	return NB_OK;
}

int instance_default_show_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
		break;
	}

	return NB_OK;
}

int instance_default_show_hostname_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_show_hostname_default())
			SET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_HOSTNAME);
		break;
	}

	return NB_OK;
}

int instance_default_show_nexthop_hostname_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		break;
	}

	return NB_OK;
}

int instance_default_show_nexthop_hostname_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_show_nexthop_hostname_default())
			SET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SHOW_NEXTHOP_HOSTNAME);
		break;
	}

	return NB_OK;
}

int instance_default_software_version_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		if (bgp_nb_reseed_gate())
			bgp_reseed_default_capability(bgp, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD,
						      PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
		break;
	}

	return NB_OK;
}

int instance_default_software_version_capability_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_software_version_capability_default())
			SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD);
		break;
	}

	return NB_OK;
}

int instance_default_software_version_capability_latest_encoding_modify(
	struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
		if (bgp_nb_reseed_gate())
			bgp_reseed_default_capability(bgp, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW,
						      PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
		break;
	}

	return NB_OK;
}

int instance_default_software_version_capability_latest_encoding_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_software_version_capability_latest_encoding_default())
			SET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW);
		break;
	}

	return NB_OK;
}

int instance_default_link_local_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		if (bgp_nb_reseed_gate())
			bgp_reseed_default_capability(bgp, BGP_FLAG_LINK_LOCAL_CAPABILITY,
						      PEER_FLAG_CAPABILITY_LINK_LOCAL);
		break;
	}

	return NB_OK;
}

int instance_default_link_local_capability_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_link_local_capability_default())
			SET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_LINK_LOCAL_CAPABILITY);
		break;
	}

	return NB_OK;
}

int instance_default_dynamic_capability_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
		if (bgp_nb_reseed_gate())
			bgp_reseed_default_capability(bgp, BGP_FLAG_DYNAMIC_CAPABILITY,
						      PEER_FLAG_DYNAMIC_CAPABILITY);
		break;
	}

	return NB_OK;
}

int instance_default_dynamic_capability_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_default_dynamic_capability_default())
			SET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY);
		break;
	}

	return NB_OK;
}

/* 'bgp default subgroup-pkt-queue-max (20-100)' (Tier A: static
 * default-on scalar, no inheritance). Destroy is not registered for the
 * same reason as local-preference above: the northbound layer resolves a
 * destroy on this default-bearing leaf to a modify-with-default (40),
 * dispatched back through .modify, matching the legacy no-form's unset
 * behavior (bgpd.c's now-retired bgp_default_subgroup_pkt_queue_max_unset(),
 * superseded by this callback). No other side effect in the legacy setter
 * (unlike local-preference, no soft-reprocess is triggered).
 */
int instance_default_subgroup_pkt_queue_max_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp_default_subgroup_pkt_queue_max_set(bgp,
						       yang_dnode_get_uint8(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int instance_client_to_client_reflection_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		/* inverted: leaf true (reflection on) -> UNSET the "no
		 * client-to-client" flag, leaf false -> SET it.
		 */
		if (yang_dnode_get_bool(args->dnode, NULL))
			UNSET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
		else
			SET_FLAG(bgp->flags, BGP_FLAG_NO_CLIENT_TO_CLIENT);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_OUT);
		break;
	}

	return NB_OK;
}

int instance_disable_ebgp_connected_route_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DISABLE_NH_CONNECTED_CHK);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_IN);
		break;
	}

	return NB_OK;
}

int instance_confederation_identifier_plain_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_instance_confederation_identifier_apply(args->dnode);

	return NB_OK;
}

int instance_confederation_identifier_plain_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_confederation_id_unset(bgp);

	return NB_OK;
}

int instance_confederation_identifier_asdot_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_instance_confederation_identifier_apply(args->dnode);

	return NB_OK;
}

int instance_confederation_identifier_asdot_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_confederation_id_unset(bgp);

	return NB_OK;
}

int instance_confederation_identifier_asdot_high_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_instance_confederation_identifier_apply(args->dnode);

	return NB_OK;
}

int instance_confederation_identifier_asdot_low_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_instance_confederation_identifier_apply(args->dnode);

	return NB_OK;
}

int instance_confederation_peers_plain_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	as_t as;
	char as_str[16];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	as = yang_dnode_get_uint32(args->dnode, NULL);
	snprintf(as_str, sizeof(as_str), "%u", as);

	bgp_confederation_peers_add(bgp, as, as_str);

	return NB_OK;
}

int instance_confederation_peers_plain_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	as_t as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	as = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_confederation_peers_remove(bgp, as);

	return NB_OK;
}

int instance_confederation_peers_asdot_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	as_t high, low, as;
	char as_str[16];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	high = yang_dnode_get_uint16(args->dnode, "high");
	low = yang_dnode_get_uint16(args->dnode, "low");
	as = (high << 16) | low;
	snprintf(as_str, sizeof(as_str), "%u.%u", high, low);

	bgp_confederation_peers_add(bgp, as, as_str);

	return NB_OK;
}

int instance_confederation_peers_asdot_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	as_t high, low, as;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	high = yang_dnode_get_uint16(args->dnode, "high");
	low = yang_dnode_get_uint16(args->dnode, "low");
	as = (high << 16) | low;
	bgp_confederation_peers_remove(bgp, as);

	return NB_OK;
}

/* Legacy no_bgp_deterministic_med's addpath-dmed rejection ('bgp
 * deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is
 * in use'): scans every peer/afi/safi for bgp_addpath_dmed_required(). Runs
 * at NB_EV_VALIDATE rather than APPLY so a bad config is rejected before
 * anything is applied, same as the legacy CLI.
 *
 * VALIDATE has no guaranteed bgp struct (the instance may be created in the
 * same transaction as this leaf, and northbound validates the whole
 * candidate before applying any of it) -- bgp_nb_instance_lookup() can
 * legitimately return NULL here. That is not a reason to skip the check
 * unsafely: if the instance does not exist yet, it has no peers, so there
 * is nothing that could have addpath-tx-bestpath-per-AS configured, and the
 * check trivially passes. If the instance does already exist -- the normal
 * case of disabling this on a running config -- the check is authoritative
 * at VALIDATE time because it reads live struct bgp/peer state, which is
 * runtime state independent of the northbound candidate tree.
 */
static int instance_deterministic_med_validate_disable(const struct lyd_node *dnode, char *errmsg,
						       size_t errmsg_len)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	struct peer *peer;
	struct listnode *node;
	afi_t afi;
	safi_t safi;

	if (!bgp)
		return NB_OK;

	for (ALL_LIST_ELEMENTS_RO(bgp->peer, node, peer)) {
		FOREACH_AFI_SAFI (afi, safi)
			if (bgp_addpath_dmed_required(peer->addpath_type[afi][safi])) {
				snprintf(errmsg, errmsg_len,
					 "bgp deterministic-med cannot be disabled while addpath-tx-bestpath-per-AS is in use");
				return NB_ERR_VALIDATION;
			}
	}

	return NB_OK;
}

int instance_deterministic_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!yang_dnode_get_bool(args->dnode, NULL))
			return instance_deterministic_med_validate_disable(args->dnode,
									   args->errmsg,
									   args->errmsg_len);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_deterministic_med_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (!bgp_deterministic_med_default())
			return instance_deterministic_med_validate_disable(args->dnode,
									   args->errmsg,
									   args->errmsg_len);
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = bgp_deterministic_med_default();
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_DETERMINISTIC_MED);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_update_delay_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_instance_blocked_by_process()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "per-vrf update-delay config not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		delay = yang_dnode_get_uint16(args->dnode, NULL);
		establish_wait = yang_dnode_exists(args->dnode, "../establish-wait")
					 ? yang_dnode_get_uint16(args->dnode, "../establish-wait")
					 : 0;
		if (establish_wait && delay < establish_wait) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-delay less than the establish-wait");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	delay = yang_dnode_get_uint16(args->dnode, NULL);
	establish_wait = yang_dnode_exists(args->dnode, "../establish-wait")
				 ? yang_dnode_get_uint16(args->dnode, "../establish-wait")
				 : 0;
	bgp_nb_instance_update_delay_apply(bgp, delay, establish_wait);

	return NB_OK;
}

/* Unlike the process-wide no-form, bgp_update_delay_deconfig_vty() DOES
 * guard: "If configured globally, cannot remove from one bgp instance".
 */
int instance_update_delay_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_instance_blocked_by_process()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "bgp update-delay configured globally, delete per-vrf not permitted");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_nb_instance_update_delay_apply(bgp, BGP_UPDATE_DELAY_DEFAULT, 0);

	return NB_OK;
}

int instance_update_delay_establish_wait_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t delay, establish_wait;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_instance_blocked_by_process()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "per-vrf update-delay config not permitted with global update-delay");
			return NB_ERR_VALIDATION;
		}
		establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
		bgp = bgp_nb_instance_lookup(args->dnode);
		delay = yang_dnode_exists(args->dnode, "../delay")
				? yang_dnode_get_uint16(args->dnode, "../delay")
				: (bgp ? bgp->v_update_delay : 0);
		if (delay < establish_wait) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-delay less than the establish-wait");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	establish_wait = yang_dnode_get_uint16(args->dnode, NULL);
	delay = yang_dnode_exists(args->dnode, "../delay")
			? yang_dnode_get_uint16(args->dnode, "../delay")
			: bgp->v_update_delay;
	bgp_nb_instance_update_delay_apply(bgp, delay, establish_wait);

	return NB_OK;
}

int instance_update_delay_establish_wait_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_update_delay_instance_blocked_by_process()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "bgp update-delay configured globally, delete per-vrf not permitted");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_nb_instance_update_delay_apply(bgp, BGP_UPDATE_DELAY_DEFAULT, 0);

	return NB_OK;
}

/* advertisement-delay, per-instance form: no mutual-exclusion guard, same
 * asymmetry note as the process-wide leaf above.
 */
int instance_advertisement_delay_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->v_advertisement_delay = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

int instance_advertisement_delay_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_nb_advertisement_delay_reset(bgp);

	return NB_OK;
}

/* on-startup/period's modify only needs to set v_maxmed_onstartup: the CLI
 * (bgp_maxmed_onstartup_cli_cmd, bgp_cli.c) always enqueues a MODIFY or a
 * DESTROY on 'med' alongside every 'period' change, so maxmed_onstartup_value
 * is kept correct independently and doesn't need a sibling read here (unlike
 * B2's keepalive/holdtime pair, whose single legacy setter needs both values
 * on every call).
 */
int instance_max_med_on_startup_period_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->v_maxmed_onstartup = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);

	return NB_OK;
}

/* Full 'no bgp max-med on-startup' behavior: cancel the timer if still
 * pending and reset both fields, mirroring no_bgp_maxmed_onstartup_cmd.
 */
int instance_max_med_on_startup_period_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (event_is_scheduled(bgp->t_maxmed_onstartup)) {
		event_cancel(&bgp->t_maxmed_onstartup);
		bgp->maxmed_onstartup_over = 1;
	}

	bgp->v_maxmed_onstartup = BGP_MAXMED_ONSTARTUP_UNCONFIGURED;
	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);

	return NB_OK;
}

int instance_max_med_on_startup_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->maxmed_onstartup_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);

	return NB_OK;
}

int instance_max_med_on_startup_med_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->maxmed_onstartup_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);

	return NB_OK;
}

/* No .destroy is registered for this leaf (YANG default "false"): a 'no
 * bgp max-med administrative' DESTROY resolves to a MODIFY with the default
 * value, same mechanism as the Tier A booleans (lib/northbound.c
 * nb_config_diff: a default-bearing leaf never truly disappears from the
 * tree once auto-defaulted, so the diff is a value replace, not a delete).
 */
int instance_max_med_administrative_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->v_maxmed_admin = yang_dnode_get_bool(args->dnode, NULL);
	bgp_maxmed_update(bgp);

	return NB_OK;
}

int instance_max_med_administrative_med_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->maxmed_admin_value = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_maxmed_update(bgp);

	return NB_OK;
}

int instance_max_med_administrative_med_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->maxmed_admin_value = BGP_MAXMED_VALUE_DEFAULT;
	bgp_maxmed_update(bgp);

	return NB_OK;
}

int instance_write_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->wpkt_quanta, yang_dnode_get_uint8(args->dnode, NULL),
			      memory_order_relaxed);

	return NB_OK;
}

int instance_write_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->wpkt_quanta, BGP_WRITE_PACKET_MAX, memory_order_relaxed);

	return NB_OK;
}

int instance_read_quanta_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->rpkt_quanta, yang_dnode_get_uint8(args->dnode, NULL),
			      memory_order_relaxed);

	return NB_OK;
}

int instance_read_quanta_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	atomic_store_explicit(&bgp->rpkt_quanta, BGP_READ_PACKET_MAX, memory_order_relaxed);

	return NB_OK;
}

int instance_coalesce_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->heuristic_coalesce = false;
	bgp->coalesce_time = yang_dnode_get_uint32(args->dnode, NULL);

	return NB_OK;
}

int instance_coalesce_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->heuristic_coalesce = true;
	bgp->coalesce_time = BGP_DEFAULT_SUBGROUP_COALESCE_TIME;

	return NB_OK;
}

int instance_long_lived_graceful_restart_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->llgr_stale_time = yang_dnode_get_uint32(args->dnode, NULL);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_SET);
		break;
	}

	return NB_OK;
}

int instance_long_lived_graceful_restart_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		bgp->llgr_stale_time = BGP_DEFAULT_LLGR_STALE_TIME;
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_UNSET);
		break;
	}

	return NB_OK;
}

/* The YANG 'must' requires idle/interval/probes together or not at all, and
 * the CLI (bgp_tcp_keepalive_cli_cmd, bgp_cli.c) always modifies all three
 * in one transaction, but northbound only invokes a leaf's callback when its
 * own value actually changed - so each modify reads its unchanged siblings
 * via a relative "../<leaf>" xpath (falling back to the instance's current
 * field when a sibling was never configured), same shape as B2's
 * instance_timers_keepalive_modify()/_holdtime_modify(), and all three
 * converge on the same bgp_tcp_keepalive_set() call the legacy DEFPY used.
 */
int instance_tcp_keepalive_idle_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t idle, interval;
	uint8_t probes;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	idle = yang_dnode_get_uint16(args->dnode, NULL);
	interval = yang_dnode_exists(args->dnode, "../interval")
			   ? yang_dnode_get_uint16(args->dnode, "../interval")
			   : bgp->tcp_keepalive_intvl;
	probes = yang_dnode_exists(args->dnode, "../probes")
			 ? yang_dnode_get_uint8(args->dnode, "../probes")
			 : bgp->tcp_keepalive_probes;

	bgp_tcp_keepalive_set(bgp, idle, interval, probes);

	return NB_OK;
}

/* Destroy on any one of the three leaves resets all three, matching the
 * YANG 'must' (all-or-nothing) and no_bgp_tcp_keepalive_cmd's
 * bgp_tcp_keepalive_unset(). Idempotent, so it's harmless if the CLI's
 * paired DESTROYs on the other two leaves fire the same reset again.
 */
int instance_tcp_keepalive_idle_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_tcp_keepalive_unset(bgp);

	return NB_OK;
}

int instance_tcp_keepalive_interval_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t idle, interval;
	uint8_t probes;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	interval = yang_dnode_get_uint16(args->dnode, NULL);
	idle = yang_dnode_exists(args->dnode, "../idle")
		       ? yang_dnode_get_uint16(args->dnode, "../idle")
		       : bgp->tcp_keepalive_idle;
	probes = yang_dnode_exists(args->dnode, "../probes")
			 ? yang_dnode_get_uint8(args->dnode, "../probes")
			 : bgp->tcp_keepalive_probes;

	bgp_tcp_keepalive_set(bgp, idle, interval, probes);

	return NB_OK;
}

int instance_tcp_keepalive_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_tcp_keepalive_unset(bgp);

	return NB_OK;
}

int instance_tcp_keepalive_probes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t idle, interval;
	uint8_t probes;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	probes = yang_dnode_get_uint8(args->dnode, NULL);
	idle = yang_dnode_exists(args->dnode, "../idle")
		       ? yang_dnode_get_uint16(args->dnode, "../idle")
		       : bgp->tcp_keepalive_idle;
	interval = yang_dnode_exists(args->dnode, "../interval")
			   ? yang_dnode_get_uint16(args->dnode, "../interval")
			   : bgp->tcp_keepalive_intvl;

	bgp_tcp_keepalive_set(bgp, idle, interval, probes);

	return NB_OK;
}

int instance_tcp_keepalive_probes_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_tcp_keepalive_unset(bgp);

	return NB_OK;
}

int instance_bestpath_as_path_ignore_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_IGNORE);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_as_path_confed_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_CONFED);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_as_path_multipath_relax_enabled_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_ASPATH_MULTIPATH_RELAX);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_as_path_multipath_relax_as_set_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_MULTIPATH_RELAX_AS_SET);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_compare_routerid_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_ROUTER_ID);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

/* Legacy DEFPY guarded the flag flip on CHECK_FLAG() first and only called
 * bgp_recalculate_all_bestpaths() when the value actually changed; that
 * guard is redundant here because the northbound layer only invokes
 * .modify when the candidate value differs from the running one.
 */
int instance_bestpath_use_imported_attributes_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_BESTPATH_USE_IMPORTED_ATTRS);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_aigp_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_aigp_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (bgp_bestpath_aigp_default())
			SET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_COMPARE_AIGP);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_med_confed_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_MED_CONFED);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_med_missing_as_worst_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_MED_MISSING_AS_WORST);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

int instance_bestpath_peer_type_multipath_relax_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_PEERTYPE_MULTIPATH_RELAX);
		bgp_recalculate_all_bestpaths(bgp);
		break;
	}

	return NB_OK;
}

/* bgp->lb_handling is a separate enum field, not a BGP_FLAG_* bit; unset
 * (destroy) maps to BGP_LINK_BW_ECMP, the legacy no-form's target. Both
 * modify and destroy redo route install exactly like the legacy DEFPYs'
 * FOREACH_AFI_SAFI/bgp_zebra_announce_table() loop.
 */
int instance_bestpath_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	const char *bw_cfg;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;

		bw_cfg = yang_dnode_get_string(args->dnode, NULL);
		if (strmatch(bw_cfg, "ignore"))
			bgp->lb_handling = BGP_LINK_BW_IGNORE_BW;
		else if (strmatch(bw_cfg, "skip-missing"))
			bgp->lb_handling = BGP_LINK_BW_SKIP_MISSING;
		else if (strmatch(bw_cfg, "default-weight-for-missing"))
			bgp->lb_handling = BGP_LINK_BW_DEFWT_4_MISSING;

		FOREACH_AFI_SAFI (afi, safi) {
			if (!bgp_fibupd_safi(safi))
				continue;
			bgp_zebra_announce_table(bgp, afi, safi);
		}
		break;
	}

	return NB_OK;
}

int instance_bestpath_bandwidth_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	afi_t afi;
	safi_t safi;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;

		bgp->lb_handling = BGP_LINK_BW_ECMP;

		FOREACH_AFI_SAFI (afi, safi) {
			if (!bgp_fibupd_safi(safi))
				continue;
			bgp_zebra_announce_table(bgp, afi, safi);
		}
		break;
	}

	return NB_OK;
}

int instance_route_reflector_allow_outbound_policy_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_OUT);
		break;
	}

	return NB_OK;
}

int instance_route_reflector_allow_outbound_policy_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = bgp_route_reflector_allow_outbound_policy_default();
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_RR_ALLOW_OUTBOUND_POLICY);
		update_group_announce_rrclients(bgp);
		bgp_nb_clear_star_soft(bgp, BGP_CLEAR_SOFT_OUT);
		break;
	}

	return NB_OK;
}

int instance_network_import_check_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = yang_dnode_get_bool(args->dnode, NULL);
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
		break;
	}

	return NB_OK;
}

int instance_network_import_check_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	bool enable;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;
		enable = bgp_network_import_check_default();
		if (enable == !!CHECK_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK))
			break;
		if (enable)
			SET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_IMPORT_CHECK);
		bgp_static_redo_import_check(bgp);
		break;
	}

	return NB_OK;
}

/* 'timers bgp <keepalive> <holdtime>' sets both leaves in one CLI line
 * (bgp_cli.c's bgp_timers_cli_cmd enqueues both changes in a single
 * transaction), so either leaf's APPLY may run first; each reads its
 * sibling out of the same candidate dnode tree via a relative xpath,
 * falling back to the instance's current value if the sibling was never
 * configured (e.g. a hypothetical single-leaf northbound edit outside the
 * CLI). Both converge on the same bgp_timers_set() call the legacy DEFUN
 * used, preserving its keepalive-vs-holdtime/3 clamp exactly.
 */
int instance_timers_keepalive_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t keepalive, holdtime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	keepalive = yang_dnode_get_uint16(args->dnode, NULL);
	holdtime = yang_dnode_exists(args->dnode, "../holdtime")
			   ? yang_dnode_get_uint16(args->dnode, "../holdtime")
			   : bgp->default_holdtime;

	bgp_timers_set(NULL, bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);

	return NB_OK;
}

int instance_timers_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_timers_set(NULL, bgp, DFLT_BGP_KEEPALIVE, DFLT_BGP_HOLDTIME, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);

	return NB_OK;
}

int instance_timers_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t keepalive, holdtime;

	switch (args->event) {
	case NB_EV_VALIDATE:
		holdtime = yang_dnode_get_uint16(args->dnode, NULL);
		if (holdtime < 3 && holdtime != 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "hold time value must be either 0 or greater than 3");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	keepalive = yang_dnode_exists(args->dnode, "../keepalive")
			    ? yang_dnode_get_uint16(args->dnode, "../keepalive")
			    : bgp->default_keepalive;

	bgp_timers_set(NULL, bgp, keepalive, holdtime, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);

	return NB_OK;
}

int instance_timers_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_timers_set(NULL, bgp, DFLT_BGP_KEEPALIVE, DFLT_BGP_HOLDTIME, DFLT_BGP_CONNECT_RETRY,
		       BGP_DEFAULT_DELAYOPEN);

	return NB_OK;
}

int instance_timers_minimum_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->default_min_holdtime = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

int instance_timers_minimum_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->default_min_holdtime = 0;

	return NB_OK;
}

int instance_timers_conditional_advertisement_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->condition_check_period = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

int instance_timers_conditional_advertisement_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
		UNSET_FLAG(peer->sflags, PEER_STATUS_COND_ADV_PENDING);

	bgp->condition_check_period = DEFAULT_CONDITIONAL_ROUTES_POLL_TIME;

	return NB_OK;
}

int instance_timers_default_originate_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->rmap_def_originate_eval_timer = yang_dnode_get_uint16(args->dnode, NULL);
	event_cancel(&bgp->t_rmap_def_originate_eval);

	return NB_OK;
}

int instance_timers_default_originate_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->rmap_def_originate_eval_timer = 0;
	event_cancel(&bgp->t_rmap_def_originate_eval);

	return NB_OK;
}

int instance_listen_limit_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_listen_limit_set(bgp, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_listen_limit_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_listen_limit_unset(bgp);

	return NB_OK;
}

/* M7 batch B5: misc instance flags. All three mirror pure-assignment
 * legacy bodies (bgp_allow_martian / bgp_fast_convergence /
 * bgp_use_underlying_nexthop_weight, bgp_vty.c, retired) with no side
 * effects, so plain idempotent assignment, no transition guard.
 */
int instance_allow_martian_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->allow_martian = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}

int instance_use_underlays_nexthop_weight_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_USE_RECURSIVE_WEIGHT);

	return NB_OK;
}

int instance_fast_convergence_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->fast_convergence = yang_dnode_get_bool(args->dnode, NULL);

	return NB_OK;
}
