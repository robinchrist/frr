// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for the instance+process graceful-restart and graceful-shutdown family.
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
#include "bgpd/proteus/bgp_nb_local.h"


int process_graceful_restart_mode_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool disable;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_gr_process_blocked_by_instance()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "global graceful-restart config not permitted: per-vrf graceful-restart configuration exists");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	disable = strmatch(yang_dnode_get_string(args->dnode, NULL), "disable");

	if (disable) {
		SET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
		UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
	} else {
		SET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);
		UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
	}

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_inst_gr_config_vty(NULL, bgp, true, disable);

	return NB_OK;
}

/* No VALIDATE guard here: as established above, the per-vrf-conflict guard
 * is only ever reachable on a real transition into the "configured" state,
 * which DESTROY (a transition back towards helper) never is.
 */
int process_graceful_restart_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool disable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	disable = strmatch(yang_dnode_get_string(args->dnode, NULL), "disable");

	if (disable)
		UNSET_FLAG(bm->flags, BM_FLAG_GR_DISABLED);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GR_RESTARTER);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_inst_gr_config_vty(NULL, bgp, false, disable);

	return NB_OK;
}

/* Tier A default-off boolean, same shape as B12's graceful-shutdown: no
 * mutual-exclusion guard exists in legacy for preserve-fw-state at either
 * scope, and SET_FLAG/UNSET_FLAG are naturally idempotent, so no transition
 * guard is needed either.
 */
int process_graceful_restart_preserve_fw_state_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool new_val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	new_val = yang_dnode_get_bool(args->dnode, NULL);

	if (new_val)
		SET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GR_PRESERVE_FWD);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (new_val)
			SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	}

	return NB_OK;
}

int process_graceful_restart_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;
	uint16_t restart;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	restart = yang_dnode_get_uint16(args->dnode, NULL);
	bm->restart_time = restart;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->restart_time = restart;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
			    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
				bgp_nb_update_graceful_restart_capability(peer);
			else
				bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
						    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
		}
	}

	return NB_OK;
}

int process_graceful_restart_restart_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode, *pnode, *pnnode;
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->restart_time = BGP_DEFAULT_RESTART_TIME;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->restart_time = BGP_DEFAULT_RESTART_TIME;
		for (ALL_LIST_ELEMENTS(bgp->peer, pnode, pnnode, peer)) {
			if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
			    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
				bgp_nb_update_graceful_restart_capability(peer);
			else
				bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
						    CAPABILITY_CODE_RESTART,
						    CAPABILITY_ACTION_UNSET);
		}
	}

	return NB_OK;
}

int process_graceful_restart_stalepath_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t stalepath;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	stalepath = yang_dnode_get_uint16(args->dnode, NULL);
	bm->stalepath_time = stalepath;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->stalepath_time = stalepath;

	return NB_OK;
}

int process_graceful_restart_stalepath_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;

	return NB_OK;
}

int process_graceful_restart_select_defer_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t defer_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bm->select_defer_time = defer_time;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->select_defer_time = defer_time;
		if (defer_time == 0)
			SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}

	return NB_OK;
}

int process_graceful_restart_select_defer_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
		UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	}

	return NB_OK;
}

/* Fresh code, see the batch-level comment above: mirrors the value (and the
 * bgp_zebra_stale_timer_update() notification the working instance-side
 * setter performs) into every existing VRF instance, matching the mirror
 * shape of restart-time/stalepath-time/select-defer-time above.
 */
int process_graceful_restart_rib_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	uint16_t stale_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	bm->rib_stale_time = stale_time;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->rib_stale_time = stale_time;
		bgp_zebra_stale_timer_update(bgp);
	}

	return NB_OK;
}

int process_graceful_restart_rib_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bm->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
		bgp_zebra_stale_timer_update(bgp);
	}

	return NB_OK;
}

int process_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;
	bool new_val;

	switch (args->event) {
	case NB_EV_VALIDATE:
		new_val = yang_dnode_get_bool(args->dnode, NULL);
		if (new_val && bgp_nb_graceful_shutdown_process_blocked_by_instance()) {
			snprintf(args->errmsg, args->errmsg_len,
				 "graceful-shutdown configuration found in a vrf: global graceful-shutdown not permitted");
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		return NB_OK;
	case NB_EV_APPLY:
		break;
	}

	new_val = yang_dnode_get_bool(args->dnode, NULL);

	/* Legacy re-entry behavior: bgp_global_graceful_shutdown_config_vty()
	 * and _deconfig_vty() are both no-ops when the flag is already at
	 * the requested state, so a replay reapplying the same value
	 * (bgp_nb_instance_replay()) never re-fires
	 * bgp_initiate_graceful_shut_unshut() on every peer of every
	 * instance.
	 */
	if (new_val == CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
		return NB_OK;

	if (new_val)
		SET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);
	else
		UNSET_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp))
		bgp_initiate_graceful_shut_unshut(NULL, bgp);

	return NB_OK;
}

/* Mirrors bgp_graceful_shutdown_cmd's/no_bgp_graceful_shutdown_cmd's
 * per-instance branch: same YANG-default-boolean shape as the process
 * callback above (no .destroy, both directions handled through this one
 * MODIFY), but here the process-blocked guard applies unconditionally in
 * both directions -- see bgp_nb_graceful_shutdown_instance_blocked_by_process()
 * above.
 */
int instance_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	bool new_val;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (bgp_nb_graceful_shutdown_instance_blocked_by_process()) {
			new_val = yang_dnode_get_bool(args->dnode, NULL);
			snprintf(args->errmsg, args->errmsg_len,
				 new_val ? "per-vrf graceful-shutdown config not permitted with global graceful-shutdown"
					 : "bgp graceful-shutdown configured globally, delete per-vrf not permitted");
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

	new_val = yang_dnode_get_bool(args->dnode, NULL);

	/* Legacy re-entry behavior: both the positive and negative DEFUN
	 * bodies only touch the flag (and fire the side effect) when it
	 * isn't already at the requested state, so a replay of an
	 * already-shut instance (bgp_nb_instance_replay()) stays harmless.
	 */
	if (new_val == CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
		return NB_OK;

	if (new_val)
		SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN);

	bgp_initiate_graceful_shut_unshut(NULL, bgp);

	return NB_OK;
}

/* No VALIDATE guard against bm->flags here -- see the block comment above
 * process_graceful_restart_mode_modify(): the per-instance halves of
 * bgp_graceful_restart_cmd/bgp_graceful_restart_disable_cmd never check
 * bm->flags before calling bgp_inst_gr_config_vty(), so neither does this.
 */
int instance_graceful_restart_mode_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	bool disable;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	disable = strmatch(yang_dnode_get_string(args->dnode, NULL), "disable");

	ret = bgp_inst_gr_config_vty(NULL, bgp, true, disable);

	/* bgp_graceful_restart_disable_cmd's per-instance branch additionally
	 * force-unsets the RESTART and LLGR capabilities on every peer on a
	 * successful transition into disable mode -- unique to this one
	 * transition, no other mode change (process-wide, or the
	 * 'restarter' value at either scope) does this in legacy.
	 */
	if (disable && ret == BGP_GR_SUCCESS) {
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_UNSET);
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_LLGR, CAPABILITY_ACTION_UNSET);
		}
	}

	return NB_OK;
}

int instance_graceful_restart_mode_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	bool disable;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	/* Old value, same as process_graceful_restart_mode_destroy() above. */
	disable = strmatch(yang_dnode_get_string(args->dnode, NULL), "disable");

	bgp_inst_gr_config_vty(NULL, bgp, false, disable);

	return NB_OK;
}

int instance_graceful_restart_notification_modify(struct nb_cb_modify_args *args)
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
		if (yang_dnode_get_bool(args->dnode, NULL))
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		/* Matches the legacy DEFPY: capability renegotiation is
		 * unconditionally CAPABILITY_ACTION_SET regardless of the
		 * new flag's polarity.
		 */
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
		break;
	}

	return NB_OK;
}

int instance_graceful_restart_notification_destroy(struct nb_cb_destroy_args *args)
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
		if (bgp_graceful_restart_notification_default())
			SET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		else
			UNSET_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_NOTIFICATION);
		for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer))
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
		break;
	}

	return NB_OK;
}

int instance_graceful_restart_preserve_fw_state_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		SET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_GR_PRESERVE_FWD);

	return NB_OK;
}

int instance_graceful_restart_restart_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;
	uint16_t restart;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	restart = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->restart_time = restart;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
			bgp_nb_update_graceful_restart_capability(peer);
		else
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_SET);
	}

	return NB_OK;
}

int instance_graceful_restart_restart_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct listnode *node, *nnode;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->restart_time = BGP_DEFAULT_RESTART_TIME;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		if (!CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_RCV) ||
		    !CHECK_FLAG(peer->cap, PEER_CAP_DYNAMIC_ADV))
			bgp_nb_update_graceful_restart_capability(peer);
		else
			bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST,
					    CAPABILITY_CODE_RESTART, CAPABILITY_ACTION_UNSET);
	}

	return NB_OK;
}

int instance_graceful_restart_stalepath_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->stalepath_time = yang_dnode_get_uint16(args->dnode, NULL);

	return NB_OK;
}

int instance_graceful_restart_stalepath_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->stalepath_time = BGP_DEFAULT_STALEPATH_TIME;

	return NB_OK;
}

int instance_graceful_restart_select_defer_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	uint16_t defer_time;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	defer_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp->select_defer_time = defer_time;
	if (defer_time == 0)
		SET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);
	else
		UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);

	return NB_OK;
}

int instance_graceful_restart_select_defer_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->select_defer_time = BGP_DEFAULT_SELECT_DEFERRAL_TIME;
	UNSET_FLAG(bgp->flags, BGP_FLAG_SELECT_DEFER_DISABLE);

	return NB_OK;
}

/* Legacy instance-side setter works fine today (only the process-side twin
 * is dead code, see the batch-level comment above) -- ported faithfully.
 */
int instance_graceful_restart_rib_stale_time_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->rib_stale_time = yang_dnode_get_uint16(args->dnode, NULL);
	bgp_zebra_stale_timer_update(bgp);

	return NB_OK;
}

int instance_graceful_restart_rib_stale_time_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp->rib_stale_time = BGP_DEFAULT_RIB_STALE_TIME;
	bgp_zebra_stale_timer_update(bgp);

	return NB_OK;
}

/* 'neighbor X shutdown [message MSG...]' / 'neighbor X shutdown rtt
 * (1-65535) [count (1-255)]' (bgp_vty.c, retired -- see
 * bgp_cli_neighbor.c's neighbor_shutdown*_cli_cmd family, M4 batch B4):
 * 'enabled' maps to PEER_FLAG_SHUTDOWN, gating both the CLI-emission and
 * the CEASE-notification effect of 'message' but NOT its storage --
 * peer_tx_shutdown_message_set()/_unset() run unconditionally from
 * message's own modify/destroy callbacks below, matching the inventory's
 * "message/rtt args are stored on the peer regardless" framing. This is
 * a deliberate decoupling from one legacy quirk: peer_flag_modify_vty()
 * (bgp_vty.c) always cleared tx_shutdown_message as a side effect of
 * *any* PEER_FLAG_SHUTDOWN unset, even a bare 'no neighbor X shutdown'
 * with no 'message' keyword at all, because legacy had no way to
 * independently manage a pending message without the flag. The new
 * grammar's 'no' forms (bgp_cli_neighbor.c) reproduce that same
 * composite effect at the CLI layer instead, by enqueueing DESTROY on
 * both 'enabled' and 'message' together -- so this callback itself stays
 * a pure mirror of its own leaf, and a bypass via direct northbound edit
 * (skipping the CLI's paired destroy) is the one case where the two
 * diverge, which is the intended, documented, decoupled behavior.
 *
 * 'rtt/threshold' is a second, wholly independent flag
 * (PEER_FLAG_RTT_SHUTDOWN) in legacy -- the YANG model has no separate
 * boolean for it, so this callback treats the leaf's own presence as
 * that flag's mirror (matching legacy's 'shutdown rtt N' also implicitly
 * setting PEER_FLAG_RTT_SHUTDOWN). 'rtt/count' is independent again, same
 * shape as 'message': stored via its own modify/destroy regardless of
 * 'rtt/threshold', defaulting to 1 (peer_new()'s rtt_keepalive_conf
 * initializer) when destroyed or never set, matching legacy's
 * unconditional inclusion of 'count %u' in the config-write line.
 */
int instance_peer_group_shutdown_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_SHUTDOWN);
	else
		peer_flag_unset(group->conf, PEER_FLAG_SHUTDOWN);

	return NB_OK;
}

int instance_peer_group_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_tx_shutdown_message_set(group->conf, yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_tx_shutdown_message_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_shutdown_rtt_threshold_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	group->conf->rtt_expected = yang_dnode_get_uint16(args->dnode, NULL);
	peer_flag_set(group->conf, PEER_FLAG_RTT_SHUTDOWN);

	return NB_OK;
}

int instance_peer_group_shutdown_rtt_threshold_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	group->conf->rtt_expected = 0;
	peer_flag_unset(group->conf, PEER_FLAG_RTT_SHUTDOWN);

	return NB_OK;
}

int instance_peer_group_shutdown_rtt_count_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	group->conf->rtt_keepalive_conf = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

int instance_peer_group_shutdown_rtt_count_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	group->conf->rtt_keepalive_conf = 1;

	return NB_OK;
}

/* 'neighbor X graceful-shutdown' (RFC 8326 per-peer, bgp_vty.c, retired --
 * see bgp_cli_neighbor.c's neighbor_graceful_shutdown_cli_cmd, M4 batch
 * B4). Legacy always follows the PEER_FLAG_GRACEFUL_SHUTDOWN flag
 * transition with an immediate soft reset (clear the session's inbound
 * routes and re-announce outbound so the GSHUT community change takes
 * effect right away) -- reproduced via bgp_peer_soft_reset() (bgp_vty.c,
 * exposed via bgp_vty.h for this caller), which fans out to every current
 * group member when 'peer' is a peer-group's group->conf (detected via
 * PEER_STATUS_GROUP, exactly like legacy's own
 * '!CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)' branch) -- so the same
 * modify body serves both scopes below.
 */
int instance_peer_group_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_GRACEFUL_SHUTDOWN);
	else
		peer_flag_unset(group->conf, PEER_FLAG_GRACEFUL_SHUTDOWN);

	bgp_peer_soft_reset(group->conf, CHECK_FLAG(group->conf->sflags, PEER_STATUS_GROUP));

	return NB_OK;
}

int instance_peer_group_graceful_restart_mode_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/graceful-restart-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_graceful_restart_mode_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/graceful-restart-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* See the peer-group-scope callback's comment above for the
 * enabled/message/rtt gating design shared by both scopes.
 */
int instance_neighbor_shutdown_enabled_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_SHUTDOWN);
	else
		peer_flag_unset(peer, PEER_FLAG_SHUTDOWN);

	return NB_OK;
}

int instance_neighbor_shutdown_message_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_set(peer, yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_shutdown_message_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tx_shutdown_message_unset(peer);

	return NB_OK;
}

int instance_neighbor_shutdown_rtt_threshold_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_expected = yang_dnode_get_uint16(args->dnode, NULL);
	peer_flag_set(peer, PEER_FLAG_RTT_SHUTDOWN);

	return NB_OK;
}

int instance_neighbor_shutdown_rtt_threshold_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_expected = 0;
	peer_flag_unset(peer, PEER_FLAG_RTT_SHUTDOWN);

	return NB_OK;
}

int instance_neighbor_shutdown_rtt_count_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_keepalive_conf = yang_dnode_get_uint8(args->dnode, NULL);

	return NB_OK;
}

int instance_neighbor_shutdown_rtt_count_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->rtt_keepalive_conf = 1;

	return NB_OK;
}

/* See the peer-group-scope callback's comment above for why
 * bgp_peer_soft_reset() (bgp_vty.h) is the correct post-flag-transition
 * side effect here.
 */
int instance_neighbor_graceful_shutdown_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);
	else
		peer_flag_unset(peer, PEER_FLAG_GRACEFUL_SHUTDOWN);

	bgp_peer_soft_reset(peer, CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP));

	return NB_OK;
}

int instance_neighbor_graceful_restart_mode_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/graceful-restart-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_graceful_restart_mode_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/graceful-restart-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_shutdown_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/shutdown");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
