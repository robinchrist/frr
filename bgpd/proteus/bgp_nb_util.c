// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Shared helpers for the proteus-bgp northbound callbacks (instance/neighbor/peer-group lookup and replay, ASN apply, GR capability helper).
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


/* Both leaves below drive bgp_global_update_delay_config_vty()'s core
 * (bm->v_update_delay/v_establish_wait, mirrored into every VRF instance)
 * from bgpd/bgp_vty.c. establish_wait == 0 is used as the "not given"
 * sentinel, exactly like the legacy DEFPY's "$wait" token (establish-wait's
 * YANG range starts at 1, so 0 is never a real explicit value).
 */
void bgp_nb_process_update_delay_apply(uint16_t delay, uint16_t establish_wait)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	bm->v_update_delay = delay;
	bm->v_establish_wait = establish_wait ? establish_wait : delay;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		bgp->v_update_delay = bm->v_update_delay;
		bgp->v_establish_wait = bm->v_establish_wait;
	}
}

/* Mirrors bgp_global_update_delay_config_vty()'s "see if update-delay is
 * set per-vrf" guard: only checked while the global value is still at its
 * default (a no-op re-set of an already-global config is always allowed).
 * Read against the live bm->/bgp-> runtime state, not the candidate tree,
 * per the milestone's cross-scope VALIDATE convention.
 */
bool bgp_nb_update_delay_process_blocked_by_instance(void)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (bm->v_update_delay != BGP_UPDATE_DELAY_DEFAULT)
		return false;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp->v_update_delay != BGP_UPDATE_DELAY_DEFAULT)
			return true;
	}

	return false;
}

/* Shared by the process-wide and per-instance "no advertisement-delay"
 * destroy callbacks: replicates no_bgp_global_advertisement_delay_cmd's /
 * no_bgp_advertisement_delay_cmd's per-bgp body byte-for-byte, including
 * the mid-flight timer cancellation (bgpd/bgp_vty.c).
 */
void bgp_nb_advertisement_delay_reset(struct bgp *bgp)
{
	bgp->v_advertisement_delay = BGP_ADVERTISEMENT_DELAY_DEFAULT;
	if (bgp->advertisement_delay_started && !bgp->advertisement_delay_over) {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
		if (!bgp_update_delay_active(bgp) && !bgp->main_zebra_update_hold) {
			bgp->main_peers_update_hold = 0;
			bgp_start_routeadv(bgp);
		}
	} else {
		event_cancel(&bgp->t_advertisement_delay);
		bgp->advertisement_delay_started = 0;
		bgp->advertisement_delay_over = 0;
	}
}

/* Milestone 2 batch B13: 'bgp graceful-restart'/'bgp graceful-restart-disable'
 * mode (process + instance pair), and 'bgp graceful-restart preserve-fw-state'
 * (process + instance pair). Legacy is two dual-purpose DEFUN pairs
 * (bgp_graceful_restart_cmd/no_bgp_graceful_restart_cmd,
 * bgp_graceful_restart_disable_cmd/no_bgp_graceful_restart_disable_cmd,
 * bgpd/bgp_vty.c) branching on vty->node, both feeding
 * bgp_inst_gr_config_vty() (still bgpd/bgp_vty.c, exposed via bgp_vty.h) --
 * that function drives one of four commands (GLOBAL_GR_CMD/NO_GLOBAL_GR_CMD/
 * GLOBAL_DISABLE_CMD/NO_GLOBAL_DISABLE_CMD) through struct bgp's own
 * GLOBAL_GR_FSM (bgp_global_gr_init(), bgpd.c) to update
 * bgp->global_gr_present_state (GLOBAL_HELPER/GLOBAL_GR/GLOBAL_DISABLE). The
 * FSM already treats a redundant re-application of the current state as
 * BGP_GR_NO_OPERATION (bgp_gr_update_all(), bgp_fsm.c), so no extra
 * transition guard is needed here for idempotency across
 * bgp_nb_instance_replay() -- unlike B12's graceful-shutdown, which had to
 * add one by hand.
 *
 * The YANG mode leaf has no default (absence == helper mode); MODIFY
 * carries "restarter"/"disable", DESTROY returns to helper. DESTROY can't
 * tell which of the two legacy 'no' forms a user "meant" from the new value
 * alone (there isn't one), so it reads the *old* value straight off
 * args->dnode -- valid at NB_EV_APPLY for a leaf being destroyed, same as
 * instance_confederation_peers_plain_destroy() above -- and feeds the
 * matching command. This reproduces the FSM's own asymmetric behavior
 * exactly: e.g. legacy "no bgp graceful-restart" is a no-op while in
 * GLOBAL_DISABLE, because NO_GLOBAL_GR_CMD only has a defined transition out
 * of GLOBAL_GR.
 */

/* Mirrors bgp_global_gr_config_vty()'s "see if GR is set per-vrf and warn
 * user to delete" guard: only checked while bm is unconfigured
 * (BM_FLAG_GR_CONFIGURED, a compound of BM_FLAG_GR_RESTARTER|
 * BM_FLAG_GR_DISABLED, clear). Once bm is configured this always returns
 * false, matching legacy exactly -- the guard in bgp_global_gr_config_vty()
 * is unreachable once bm holds either flag, both because the check itself
 * is skipped and because the leading "already at target" no-op return in
 * legacy also intercepts every no-op re-application before the guard would
 * run. There is no equivalent guard on the per-instance DEFUN branches
 * (bgp_graceful_restart_cmd's/bgp_graceful_restart_disable_cmd's per-instance
 * halves never check bm->flags at all) -- do not add one to the instance
 * callbacks below.
 */
bool bgp_nb_gr_process_blocked_by_instance(void)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (CHECK_FLAG(bm->flags, BM_FLAG_GR_CONFIGURED))
		return false;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (bgp_global_gr_mode_get(bgp) != GLOBAL_HELPER)
			return true;
	}

	return false;
}

/* Milestone 2 batch B14: 'bgp graceful-restart restart-time/stalepath-time/
 * select-defer-time/rib-stale-time' (process + instance pairs). Legacy is
 * three dual-purpose DEFUN pairs (restart-time, stalepath-time,
 * select-defer-time) branching on vty->node, same shape as B12/B13, plus a
 * fourth (rib-stale-time) whose process-side (CONFIG_NODE) half is dead code
 * -- bgp_graceful_restart_rib_stale_time_cmd always does
 * VTY_DECLVAR_CONTEXT(bgp, bgp) with no vty->node branch, so the CONFIG_NODE
 * install_element never successfully executes its body and no legacy code
 * path ever writes bm->rib_stale_time, even though bgp_config_write() reads
 * it. process_graceful_restart_rib_stale_time_modify/_destroy() below are
 * therefore fresh, correct code (mirroring into every instance + the zebra
 * stale-timer notification the instance-side setter performs), not a port
 * of the non-functional legacy body -- pre-existing bgpd bug, worth a
 * separate upstream report, independent of this conversion.
 *
 * None of the four have a YANG default (no-default leaves get modify+destroy
 * per the batch's transition-guard rule), and none of the four legacy DEFUNs
 * carry a mutual-exclusion guard beyond bgp_config_write()'s own emission
 * gating (see the cli_show comments in bgp_cli.c) -- unlike 'mode' (B13),
 * there is no runtime rejection to replicate here, only value + side-effect
 * mirroring.
 */

/* Moved here (was static in bgp_vty.c, inside the now-retired
 * bgp_graceful_restart_restart_time_cmd/no_... DEFUN pair): resets the BGP
 * session so the updated restart-time capability gets re-exchanged. Both the
 * process-wide and per-instance restart-time callbacks below need it.
 */
void bgp_nb_update_graceful_restart_capability(struct peer *peer)
{
	enum peer_mode peer_gr_mode;
	enum global_mode global_gr_mode;

	global_gr_mode = bgp_global_gr_mode_get(peer->bgp);

	peer_gr_mode = bgp_peer_gr_mode_get(peer);

	/* Skip if peer is not in graceful restart mode */
	if (!((peer_gr_mode == PEER_GR) ||
	      (peer_gr_mode == PEER_GLOBAL_INHERIT && global_gr_mode == GLOBAL_GR)))
		return;

	if (BGP_DEBUG(graceful_restart, GRACEFUL_RESTART))
		zlog_debug("Resetting session for %s: Peer GR mode %s, Global GR mode %s",
			   peer->host, print_peer_gr_mode(peer_gr_mode),
			   print_global_gr_mode(global_gr_mode));

	/* Reset the session so that the updated capability can be
	 * exchanged again
	 */
	if (BGP_IS_VALID_STATE_FOR_NOTIF(peer->connection->status)) {
		peer_set_last_reset(peer, PEER_DOWN_CAPABILITY_CHANGE);
		bgp_notify_send(peer->connection, BGP_NOTIFY_CEASE, BGP_NOTIFY_CEASE_CONFIG_CHANGE);
	}
}

/* Milestone 2 batch B12: 'bgp graceful-shutdown' (process + instance
 * pair). Legacy is a single dual-purpose DEFUN (bgp_graceful_shutdown_cmd /
 * no_bgp_graceful_shutdown_cmd, bgpd/bgp_vty.c) branching on vty->node --
 * split here into independent process/instance northbound callbacks that
 * share the mutual-exclusion helpers below.
 *
 * Both leaves carry a YANG 'default "false"' (Tier A, positive-only legacy
 * emission), which makes NB_CB_DESTROY schema-invalid for them
 * (nb_cb_operation_is_valid() in lib/northbound.c refuses DESTROY on any
 * leaf with a YANG default) -- unlike update-delay (B11), there is no
 * .destroy callback at all (matching the already-generated stub table
 * entries, bgp_nb.c). Deleting the explicit override back to the default
 * is instead delivered as a MODIFY carrying the default value (libyang's
 * LYD_DIFF_DEFAULTS diff mode, lib/northbound.c:nb_config_diff()), same
 * shape as B10's suppress-fib-pending 'enabled'. Both modify callbacks
 * below therefore handle the false transition themselves -- there is no
 * separate no-form entry point to rely on.
 */

/* Mirrors bgp_global_graceful_shutdown_config_vty()'s guard: only checked
 * for the true (shutdown-on) transition, and only while the global flag
 * isn't already set -- a redundant re-set is always allowed, matching
 * update-delay's process-side "only check while still at default" pattern
 * (B11). The false transition (bgp_global_graceful_shutdown_deconfig_vty())
 * has no guard at all in legacy code.
 */
bool bgp_nb_graceful_shutdown_process_blocked_by_instance(void)
{
	struct listnode *node, *nnode;
	struct bgp *bgp;

	if (CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN))
		return false;

	for (ALL_LIST_ELEMENTS(bm->bgp, node, nnode, bgp)) {
		if (CHECK_FLAG(bgp->flags, BGP_FLAG_GRACEFUL_SHUTDOWN))
			return true;
	}

	return false;
}

/* Mirrors bgp_graceful_shutdown_cmd's/no_bgp_graceful_shutdown_cmd's
 * per-instance branch: the instance form is blocked outright whenever the
 * process-wide flag is set, in both directions (true and false), same
 * shape as update-delay's instance-side guard (B11).
 */
bool bgp_nb_graceful_shutdown_instance_blocked_by_process(void)
{
	return CHECK_FLAG(bm->flags, BM_FLAG_GRACEFUL_SHUTDOWN);
}

/*
 * Milestone 1 slice: 'router bgp ASN [<view|vrf> NAME] [as-notation ...]',
 * 'bgp router-id', '[no] bgp log-neighbor-changes'. The instance-type,
 * autonomous-system and as-notation leaves below are consumed directly out
 * of the instance subtree by instance_create()/instance_destroy() (the
 * whole 'router bgp ...' line lands as a single YANG edit). A changed ASN
 * on a running instance means destroy-and-recreate, not modify: a config
 * file's 'no router bgp X' + 'router bgp Y' arrives as one batched mgmtd
 * commit whose datastore diff collapses to an autonomous-system leaf
 * modify (the list key is the vrf, not the ASN), and the legacy file-load
 * semantics for that sequence are a fresh instance.
 */

/* The bgp struct is always looked up by vrf/view name, never kept as an
 * nb_running_set_entry() pointer: in a mixed legacy/converted daemon the
 * legacy CLI can delete and recreate the instance underneath the northbound
 * layer (e.g. an ASN change during config replay), and a stored pointer
 * would dangle. Lookup-by-name makes every callback converge on whatever
 * instance currently exists.
 */
struct bgp *bgp_nb_instance_lookup(const struct lyd_node *dnode)
{
	const struct lyd_node *instance_dnode = yang_dnode_get_parent(dnode, "instance");
	const char *vrf = yang_dnode_get_string(instance_dnode, "vrf");

	if (strmatch(vrf, VRF_DEFAULT_NAME))
		return bgp_get_default();

	return bgp_lookup_by_name(vrf);
}

/* Vty-free equivalent of the CLI's bgp_clear_star_soft_in()/_out() (both
 * static in bgp_vty.c, and only usable with a live vty since they route
 * error reporting through it): soft-clear every established peer's
 * activated AFI/SAFIs in the given direction. There is no vty in a
 * northbound APPLY context, so this skips the CLI helpers' error-reporting
 * side channel entirely rather than passing a NULL vty into vty_out().
 */
void bgp_nb_clear_star_soft(struct bgp *bgp, enum bgp_clear_type stype)
{
	struct peer *peer;
	struct listnode *node, *nnode;
	afi_t afi;
	safi_t safi;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		FOREACH_AFI_SAFI (afi, safi) {
			if (!peer->afc[afi][safi])
				continue;
			peer_clear_soft(peer, afi, safi, stype);
		}
	}
}

as_t bgp_nb_instance_get_asn(const struct lyd_node *instance_dnode)
{
	if (yang_dnode_exists(instance_dnode, "autonomous-system/plain"))
		return yang_dnode_get_uint32(instance_dnode, "autonomous-system/plain");

	return ((as_t)yang_dnode_get_uint16(instance_dnode, "autonomous-system/asdot/high") << 16) |
	       yang_dnode_get_uint16(instance_dnode, "autonomous-system/asdot/low");
}

void bgp_nb_instance_get_asn_pretty(const struct lyd_node *instance_dnode, as_t as,
					   char *buf, size_t buflen)
{
	enum asnotation_mode mode = yang_dnode_exists(instance_dnode, "autonomous-system/plain")
					    ? ASNOTATION_PLAIN
					    : ASNOTATION_DOTPLUS;

	asn_asn2string(&as, buf, buflen, mode);
}

int bgp_nb_instance_apply(const struct lyd_node *instance_dnode)
{
	struct bgp *bgp;
	const char *vrf;
	const char *name;
	enum bgp_instance_type inst_type;
	as_t as;
	char as_pretty[ASN_STRING_MAX_SIZE];
	enum asnotation_mode asnotation = ASNOTATION_UNDEFINED;
	int ret;

	vrf = yang_dnode_get_string(instance_dnode, "vrf");
	as = bgp_nb_instance_get_asn(instance_dnode);
	bgp_nb_instance_get_asn_pretty(instance_dnode, as, as_pretty, sizeof(as_pretty));

	if (strmatch(vrf, VRF_DEFAULT_NAME)) {
		name = NULL;
		inst_type = BGP_INSTANCE_TYPE_DEFAULT;
	} else if (strmatch(yang_dnode_get_string(instance_dnode, "instance-type"), "view")) {
		name = vrf;
		inst_type = BGP_INSTANCE_TYPE_VIEW;
	} else {
		name = vrf;
		inst_type = BGP_INSTANCE_TYPE_VRF;
	}

	if (yang_dnode_exists(instance_dnode, "as-notation")) {
		const char *notation = yang_dnode_get_string(instance_dnode, "as-notation");

		if (strmatch(notation, "dot+"))
			asnotation = ASNOTATION_DOTPLUS;
		else if (strmatch(notation, "dot"))
			asnotation = ASNOTATION_DOT;
		else
			asnotation = ASNOTATION_PLAIN;
	}

	ret = bgp_get_vty(&bgp, &as, name, inst_type, as_pretty, asnotation);
	if (ret < 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: bgp_get_vty() failed for vrf %s: %d",
			 __func__, vrf, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* Re-apply every configured node under a freshly recreated instance by
 * invoking its APPLY callback against the current datastore subtree. A
 * destroy-and-recreate triggered by an ASN change replaces the struct bgp
 * with one carrying compiled-in defaults, but the commit's datastore diff
 * only covers the autonomous-system leaves - the other instance leaves
 * kept their values, so no callback fires for them and their runtime
 * state would silently revert to the defaults. All instance callbacks
 * look the struct up by vrf name and are idempotent, so replaying the
 * whole subtree is safe even for leaves whose callback also runs
 * regularly later in the same commit.
 */
int bgp_nb_instance_replay(const struct lyd_node *instance_dnode)
{
	struct lyd_node *elem;
	int ret = NB_OK;

	LYD_TREE_DFS_BEGIN (instance_dnode, elem) {
		if (elem != instance_dnode && elem->schema && elem->schema->priv) {
			const struct nb_node *nb_node = elem->schema->priv;
			char errmsg[256] = "";
			int cbret = NB_OK;

			if ((elem->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST)) &&
			    nb_node->cbs.modify) {
				struct nb_cb_modify_args args = {
					.event = NB_EV_APPLY,
					.dnode = elem,
					.errmsg = errmsg,
					.errmsg_len = sizeof(errmsg),
				};

				cbret = nb_node->cbs.modify(&args);
			} else if (nb_node->cbs.create) {
				struct nb_cb_create_args args = {
					.event = NB_EV_APPLY,
					.dnode = elem,
					.errmsg = errmsg,
					.errmsg_len = sizeof(errmsg),
				};

				cbret = nb_node->cbs.create(&args);
			}

			if (cbret != NB_OK) {
				flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
					 "%s: replay of %s failed: %d (%s)", __func__,
					 elem->schema->name, cbret, errmsg);
				ret = cbret;
			}
		}
		LYD_TREE_DFS_END(instance_dnode, elem);
	}

	return ret;
}

/* Shared APPLY body of the autonomous-system leaf callbacks: recreate the
 * instance when the (whole-subtree) ASN no longer matches the running bgp
 * struct. Idempotent, since several of these leaves can change in one
 * commit (e.g. a plain <-> asdot switch) - the first one recreates, the
 * rest see a matching ASN.
 */
int bgp_nb_instance_asn_apply(const struct lyd_node *dnode)
{
	const struct lyd_node *instance_dnode = yang_dnode_get_parent(dnode, "instance");
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	int ret;

	if (!bgp)
		/* recreated by the legacy CLI or created by
		 * instance_create() later in this same commit */
		return NB_OK;

	if (bgp_nb_instance_get_asn(instance_dnode) == bgp->as)
		return NB_OK;

	bgp_delete(bgp);

	ret = bgp_nb_instance_apply(instance_dnode);
	if (ret != NB_OK)
		return ret;

	return bgp_nb_instance_replay(instance_dnode);
}

/* Peer-group and neighbor list entries are looked up by key exactly like
 * bgp_nb_instance_lookup() above, never cached: remote-as/peer-group-bind
 * mutate the peer/peer-group struct in place (peer_remote_as()/
 * peer_group_bind(), bgpd.c), but a legacy CLI 'no neighbor ...'/'no
 * neighbor WORD peer-group' can still delete the struct underneath a
 * later leaf callback in the same commit.
 */
struct peer_group *bgp_nb_peer_group_lookup(const struct lyd_node *dnode)
{
	const struct lyd_node *pg_dnode = yang_dnode_get_parent(dnode, "peer-group");
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);

	if (!bgp || !pg_dnode)
		return NULL;

	return peer_group_lookup(bgp, yang_dnode_get_string(pg_dnode, "name"));
}

struct peer *bgp_nb_neighbor_lookup(const struct lyd_node *dnode)
{
	const struct lyd_node *nbr_dnode = yang_dnode_get_parent(dnode, "neighbor");
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const char *address;
	union sockunion su;

	if (!bgp || !nbr_dnode)
		return NULL;

	address = yang_dnode_get_string(nbr_dnode, "address");

	if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
	    yang_dnode_get_bool(nbr_dnode, "interface-peer"))
		return peer_lookup_by_conf_if(bgp, address);

	if (str2sockunion(address, &su) < 0)
		return NULL;

	return peer_lookup(bgp, &su);
}

/* Shared remote-as reader for both peer-group and neighbor (both use the
 * same 'remote-as' container from the shared neighbor-session-parameters
 * grouping). Mirrors bgp_nb_instance_get_asn()'s plain/asdot handling and
 * adds the relationship-keyword case. session_dnode is the peer-group or
 * neighbor list entry itself (remote-as is a direct child). Returns false
 * if remote-as is entirely absent (a neighbor inheriting from its
 * peer-group, or a peer-group with none configured yet).
 */
bool bgp_nb_get_remote_as(const struct lyd_node *session_dnode, as_t *as,
				  enum peer_asn_type *as_type, const char **as_str,
				  char *as_str_buf, size_t as_str_buf_len)
{
	if (yang_dnode_exists(session_dnode, "remote-as/plain")) {
		*as = yang_dnode_get_uint32(session_dnode, "remote-as/plain");
		*as_type = AS_SPECIFIED;
		snprintf(as_str_buf, as_str_buf_len, "%u", *as);
		*as_str = as_str_buf;
		return true;
	}

	if (yang_dnode_exists(session_dnode, "remote-as/asdot/high")) {
		as_t high = yang_dnode_get_uint16(session_dnode, "remote-as/asdot/high");
		as_t low = yang_dnode_get_uint16(session_dnode, "remote-as/asdot/low");

		*as = (high << 16) | low;
		*as_type = AS_SPECIFIED;
		snprintf(as_str_buf, as_str_buf_len, "%u.%u", high, low);
		*as_str = as_str_buf;
		return true;
	}

	if (yang_dnode_exists(session_dnode, "remote-as/type")) {
		const char *type = yang_dnode_get_string(session_dnode, "remote-as/type");

		*as = 0;
		*as_str = NULL;
		if (strmatch(type, "internal"))
			*as_type = AS_INTERNAL;
		else if (strmatch(type, "external"))
			*as_type = AS_EXTERNAL;
		else
			*as_type = AS_AUTO;
		return true;
	}

	*as = 0;
	*as_type = AS_UNSPECIFIED;
	*as_str = NULL;
	return false;
}

/* Shared APPLY body for the peer-group remote-as leaves: recompute the
 * whole remote-as container (not just the leaf that fired) and call the
 * legacy setter, mirroring bgp_nb_instance_asn_apply()'s "reread the
 * container, not the trigger leaf" pattern. peer_group_remote_as() is a
 * no-op if the value already matches (bgpd.c:3486-3487), so this converges
 * safely even though several remote-as leaves can be present in one
 * commit and each calls this.
 */
int bgp_nb_peer_group_remote_as_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const struct lyd_node *pg_dnode;
	const char *name;
	as_t as;
	enum peer_asn_type as_type;
	const char *as_str;
	char as_buf[ASN_STRING_MAX_SIZE];
	int ret;

	if (!bgp)
		return NB_OK;

	pg_dnode = yang_dnode_get_parent(dnode, "peer-group");
	name = yang_dnode_get_string(pg_dnode, "name");

	if (!bgp_nb_get_remote_as(pg_dnode, &as, &as_type, &as_str, as_buf, sizeof(as_buf)))
		return NB_OK;

	ret = peer_group_remote_as(bgp, name, &as, as_type, as_str);
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_group_remote_as() failed for %s: %d", __func__, name, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_peer_group_remote_as_delete_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const struct lyd_node *pg_dnode;
	struct peer_group *group;

	if (!bgp)
		return NB_OK;

	pg_dnode = yang_dnode_get_parent(dnode, "peer-group");
	group = peer_group_lookup(bgp, yang_dnode_get_string(pg_dnode, "name"));
	if (!group)
		return NB_OK;

	peer_group_remote_as_delete(group);

	return NB_OK;
}

/* Shared APPLY body for the neighbor remote-as leaves. Same "reread the
 * whole container" discipline as above; peer_remote_as() creates the peer
 * on first use (addressed form) or mutates it in place, and is a no-op
 * when the value already matches (bgpd.c:2417-2418), so repeated firing
 * within one commit converges safely. Never called for a neighbor whose
 * remote-as comes solely from an inherited peer-group -- there is no
 * remote-as leaf present in that case, so bgp_nb_get_remote_as() returns
 * false and this is a no-op.
 */
int bgp_nb_neighbor_remote_as_apply(const struct lyd_node *dnode)
{
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	const struct lyd_node *nbr_dnode;
	const char *address;
	union sockunion su;
	union sockunion *su_ptr = NULL;
	const char *conf_if = NULL;
	as_t as;
	enum peer_asn_type as_type;
	const char *as_str;
	char as_buf[ASN_STRING_MAX_SIZE];
	int ret;

	if (!bgp)
		return NB_OK;

	nbr_dnode = yang_dnode_get_parent(dnode, "neighbor");
	address = yang_dnode_get_string(nbr_dnode, "address");

	if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
	    yang_dnode_get_bool(nbr_dnode, "interface-peer")) {
		conf_if = address;
	} else {
		if (str2sockunion(address, &su) < 0)
			return NB_OK;
		su_ptr = &su;
	}

	if (!bgp_nb_get_remote_as(nbr_dnode, &as, &as_type, &as_str, as_buf, sizeof(as_buf)))
		return NB_OK;

	ret = peer_remote_as(bgp, su_ptr, conf_if, &as, as_type, as_str);
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_remote_as() failed for %s: %d", __func__, address, ret);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* Only the interface-peer (WORD/conf_if) form has a legacy equivalent for
 * clearing remote-as without deleting the neighbor
 * (no_neighbor_interface_peer_group_remote_as, bgp_vty.c, now converted
 * here): peer_as_change(peer, 0, AS_UNSPECIFIED, NULL) resets to
 * unspecified in place. An addressed neighbor's remote-as destroy leaf
 * callback rejects at VALIDATE instead (see
 * instance_neighbor_remote_as_plain_destroy() and siblings) since legacy
 * has no partial-unset there -- this helper is therefore only ever
 * reached for conf_if peers.
 */
int bgp_nb_neighbor_remote_as_destroy_apply(const struct lyd_node *dnode)
{
	struct peer *peer = bgp_nb_neighbor_lookup(dnode);

	if (!peer)
		return NB_OK;

	peer_as_change(peer, 0, AS_UNSPECIFIED, NULL);

	return NB_OK;
}

/* Shared VALIDATE guard for the neighbor remote-as leaves' destroy
 * callbacks: addressed neighbors have no legacy "clear remote-as, keep
 * the neighbor" operation (the grammar accepts a 'remote-as ...' suffix
 * on 'no neighbor <addr>' but the DEFUN body ignored it and always
 * deleted the whole peer -- see bgp_vty.c's now-removed no_neighbor()).
 * Only conf_if (interface) neighbors have a real equivalent
 * (no_neighbor_interface_peer_group_remote_as). This callback never fires
 * as part of a whole-neighbor-entry destroy cascade: nb_config_diff_deleted()
 * (lib/northbound.c) only recurses into child destroy callbacks when
 * F_NB_CB_DESTROY_RECURSE is set, which the neighbor list node does not
 * set, so rejecting here cannot block 'no neighbor <addr>'.
 */
int bgp_nb_neighbor_remote_as_destroy_validate(const struct lyd_node *dnode,
						       char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *nbr_dnode = yang_dnode_get_parent(dnode, "neighbor");

	if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
	    yang_dnode_get_bool(nbr_dnode, "interface-peer"))
		return NB_OK;

	snprintf(errmsg, errmsg_len,
		 "removing remote-as from an addressed neighbor requires deleting the neighbor; bgpd has no partial unset");
	return NB_ERR_VALIDATION;
}

/* Shared APPLY body for reject-as-sets modify/destroy: reset every peer's
 * session so the AS_SET/AS_CONFED_SET filtering behavior change takes
 * effect, matching both legacy DEFUNs' identical peer-reset loop.
 */
void bgp_nb_reject_as_sets_reset_peers(struct bgp *bgp)
{
	struct peer *peer;
	struct listnode *node, *nnode;

	for (ALL_LIST_ELEMENTS(bgp->peer, node, nnode, peer)) {
		peer_set_last_reset(peer, PEER_DOWN_AS_SETS_REJECT);
		peer_notify_config_change(peer->connection);
	}
}

/*
 * 'bgp default <afi-safi>' SAFI-conflict check (legacy bgp_vty.c:3918,
 * BGP_ERR_PEER_SAFI_CONFLICT): the unicast and labeled-unicast leaves for a
 * given AFI can't both be default-activated at once. The legacy DEFPY only
 * rejects when the *new* value is true (clearing either leaf is always
 * fine), so this only runs from a leaf's modify path, never destroy.
 *
 * ipv4-unicast now carries a static YANG default of "true" (Tier A: static
 * default-on boolean, no inheritance, chain root); ipv6-unicast and the
 * ipv4/ipv6-labeled-unicast siblings carry a YANG default of "false". Every
 * leaf in this conflict pair is therefore always materialized in the data
 * tree, so a plain read is safe on both sides; sibling_absent_default is
 * kept only as a defensive fallback and should never actually trigger.
 */
int bgp_nb_default_af_safi_conflict_validate(struct nb_cb_modify_args *args,
						    const char *sibling_relpath,
						    bool sibling_absent_default)
{
	bool sibling_active;

	if (!yang_dnode_get_bool(args->dnode, NULL))
		return NB_OK;

	if (yang_dnode_exists(args->dnode, sibling_relpath))
		sibling_active = yang_dnode_get_bool(args->dnode, "%s", sibling_relpath);
	else
		sibling_active = sibling_absent_default;

	if (!sibling_active)
		return NB_OK;

	snprintf(args->errmsg, args->errmsg_len,
		 "Cannot activate peer for both 'unicast' and 'labeled-unicast' by default");
	return NB_ERR_VALIDATION;
}

/* Shared APPLY body of the confederation/identifier leaf callbacks: reads
 * whichever of plain/asdot is present under the "identifier" container and
 * calls bgp_confederation_id_set(). Idempotent (bgp_confederation_id_set()
 * itself no-ops when the AS/pretty-string pair is unchanged), so it's safe
 * to call from every one of plain/asdot-create/high/low's modify paths -
 * same "recompute from current subtree" shape as
 * bgp_nb_instance_asn_apply(). The reconstructed pretty string is always
 * the canonical decimal or "<high>.<low>" spelling, matching
 * instance_cli_write()'s autonomous-system rendering in bgp_cli.c (the
 * legacy pretty string is never a distinct user-typed spelling once
 * asn_str2asn() has parsed it).
 *
 * Destroys of 'plain'/'asdot' unconditionally unset the confederation ID;
 * this is safe even for a notation switch (plain -> asdot or vice versa)
 * because northbound always processes all destroys in a commit before any
 * create/modify (lib/northbound.c nb_config_cb_compare(), "to correctly
 * process the change of a case inside a choice") - the destroy's unset is
 * immediately superseded by the new case's modify/create.
 */
void bgp_nb_instance_confederation_identifier_apply(const struct lyd_node *dnode)
{
	const struct lyd_node *identifier_dnode = yang_dnode_get_parent(dnode, "identifier");
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	as_t as;
	char as_str[16];

	if (!bgp)
		return;

	if (yang_dnode_exists(identifier_dnode, "plain")) {
		as = yang_dnode_get_uint32(identifier_dnode, "plain");
		snprintf(as_str, sizeof(as_str), "%u", as);
	} else if (yang_dnode_exists(identifier_dnode, "asdot")) {
		as_t high = yang_dnode_get_uint16(identifier_dnode, "asdot/high");
		as_t low = yang_dnode_get_uint16(identifier_dnode, "asdot/low");

		as = (high << 16) | low;
		snprintf(as_str, sizeof(as_str), "%u.%u", high, low);
	} else {
		return;
	}

	bgp_confederation_id_set(bgp, as, as_str);
}

/* Mirrors bgp_update_delay_config_vty()'s/_deconfig_vty()'s guard: refuses
 * outright whenever the process-wide value is non-default, in both
 * directions (modify and destroy), unlike the process side's guard above
 * which only fires while the global value is still at its own default.
 * Read against the live bm-> runtime state per the milestone's cross-scope
 * VALIDATE convention.
 */
bool bgp_nb_update_delay_instance_blocked_by_process(void)
{
	return bm->v_update_delay != BGP_UPDATE_DELAY_DEFAULT;
}

/* Mirrors bgp_update_delay_config_vty()'s/_deconfig_vty()'s core
 * (bgp->v_update_delay/v_establish_wait), same establish_wait == 0
 * "not given" sentinel as the process-wide helper above.
 */
void bgp_nb_instance_update_delay_apply(struct bgp *bgp, uint16_t delay,
					       uint16_t establish_wait)
{
	bgp->v_update_delay = delay;
	bgp->v_establish_wait = establish_wait ? establish_wait : delay;
}

/* Send dynamic capability on the peer(s) that own the TCP BGP session
 * (M4 batch B8, moved vty-free from bgp_vty.c's static
 * bgp_vty_capability_send_dynamic_peer_group(), now retired -- the
 * capabilities/extended-nexthop callback is the only remaining caller).
 * The peer-group template (PEER_STATUS_GROUP) stays Idle; members in
 * peer->group->peer are Established, so a peer-group edit must fan the
 * dynamic capability message out to each live member instead of the
 * (unconnected) template.
 */
void bgp_nb_capability_send_dynamic_peer_group(struct peer *peer, afi_t afi, safi_t safi,
					       int capability_code, int action)
{
	struct listnode *node;
	struct peer *member;
	struct peer_group *pg;

	if (!peer)
		return;

	if (CHECK_FLAG(peer->sflags, PEER_STATUS_GROUP)) {
		pg = peer->group;
		if (!pg)
			return;
		for (ALL_LIST_ELEMENTS_RO(pg->peer, node, member))
			bgp_capability_send(member->connection, afi, safi, capability_code, action);
	} else {
		bgp_capability_send(peer->connection, afi, safi, capability_code, action);
	}
}

/* Restores one of the capabilities container's six Tier B leaves (dynamic,
 * extended-nexthop, software-version[-latest-encoding], link-local, fqdn)
 * to "no explicit config on this list entry" (M4 batch B8). DESTROY of one
 * of these leaves has no direct legacy CLI equivalent: legacy's bare 'no
 * neighbor X capability ...' is itself an explicit-false MODIFY (the Tier B
 * deprecated-alias shape, tiers.md), not a "forget I ever configured this"
 * operation. A peer-group member reverts to inheriting its group's value
 * via peer_flag_inherit() (bgpd.c), the same vty-free helper already used
 * by the _unset() helpers for update-source/tcp-mss/local-as/etc. A
 * standalone peer or a peer-group entry itself (peer_group_active() is
 * false for both -- there's no group to inherit from) reverts to whatever
 * a freshly created peer would carry for this flag, replicating peer_new()'s
 * own seeding for the flag family: instance_default is bgp->flags-derived
 * for dynamic/software-version[-latest-encoding]/link-local (each has a
 * matching already-converted instance-level 'bgp default ...' leaf,
 * bgp_nb_instance.c), unconditionally true for fqdn (peer_new() sets it
 * with no bgp-> dependency at all), and unconditionally false for
 * extended-nexthop (no instance-level default toggle exists for ENHE --
 * only the separate unnumbered/conf_if force-on, handled entirely at
 * neighbor creation, M4 batch B1).
 */
void bgp_nb_capability_flag_destroy(struct peer *peer, uint64_t flag, bool instance_default)
{
	if (peer_group_active(peer)) {
		peer_flag_inherit(peer, flag);
		return;
	}

	if (instance_default)
		peer_flag_set(peer, flag);
	else
		peer_flag_unset(peer, flag);
}
