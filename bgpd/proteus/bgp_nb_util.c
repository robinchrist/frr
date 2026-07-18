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
#include "lib/bfd.h"
#include "lib/prefix.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_bfd.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/bgp_io.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_updgrp.h"
#include "bgpd/bgp_conditional_adv.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_zebra.h"
#include "bgpd/bgp_fsm.h"
#include "bgpd/bgp_damp.h"
#include "bgpd/bgp_mpath.h"
#include "bgpd/bgp_open.h"
#include "bgpd/bgp_packet.h"
#include "bgpd/bgp_addpath.h"
#include "bgpd/bgp_mplsvpn.h"
#include "lib/routemap.h"
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

/*
 * M5 batch B1: shared per-AF 'activate' apply, parameterized by afi/safi.
 *
 * The thin per-container delegators (instance_neighbor_afi_safis_<af>_
 * activate_modify/destroy and their peer-group twins, one pair per
 * afi-safis container in bgp_nb_{neighbor,peer_group}_afi_*.c) pass their
 * compile-time afi/safi here so a single implementation covers all nine
 * proteus families and both the neighbor and peer-group scope. This is the
 * template every M5 per-AF leaf batch (B2+) reuses: a shared helper keyed on
 * afi/safi, called from a one-line generated stub.
 *
 * 'conf' is the real peer for neighbor scope and group->conf for peer-group
 * scope; peer_activate()/peer_deactivate() (bgpd.c) already fan a group
 * template out to its members via the PEER_STATUS_GROUP branch, exactly as
 * the retired neighbor_activate/no_neighbor_activate DEFUNs relied on
 * peer_and_group_lookup_vty() handing them either shape. Looked up by key on
 * every call, never cached, for the same reason as bgp_nb_neighbor_lookup()
 * (a legacy 'no neighbor ...' can delete the struct underneath a later leaf
 * callback in the same commit).
 */
static int bgp_nb_af_activate_set(struct peer *conf, bool activate, afi_t afi, safi_t safi)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (activate)
		ret = peer_activate(conf, afi, safi);
	else
		ret = peer_deactivate(conf, afi, safi);

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_%sactivate() failed: %d",
			 __func__, activate ? "" : "de", ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

/* Destroy (the activate leaf is removed) means "follow the per-AF default
 * activation" again: a peer-group member inherits its group's activation, a
 * standalone peer follows bgp->default_af[afi][safi] ('bgp default
 * <afi>-<safi>'). Reached in practice only when the whole neighbor/group is
 * deleted (conf then resolves NULL and this no-ops) -- frr-reload removes an
 * explicit 'neighbor X activate' with 'no neighbor X activate', which is a
 * modify-to-false, not a leaf destroy. */
static int bgp_nb_af_activate_default(struct peer *conf, afi_t afi, safi_t safi)
{
	bool baseline;

	if (!conf)
		return NB_OK;

	if (peer_group_active(conf))
		baseline = conf->group->conf->afc[afi][safi];
	else
		baseline = conf->bgp->default_af[afi][safi];

	return bgp_nb_af_activate_set(conf, baseline, afi, safi);
}

int bgp_nb_neighbor_af_activate_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_activate_set(bgp_nb_neighbor_lookup(args->dnode),
					      yang_dnode_get_bool(args->dnode, NULL), afi, safi);
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_activate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_activate_default(bgp_nb_neighbor_lookup(args->dnode), afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_activate_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_activate_set(group ? group->conf : NULL,
					      yang_dnode_get_bool(args->dnode, NULL), afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_activate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_activate_default(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

/*
 * M5 batch B4: plain per-AF PEER_FLAG_* booleans -- route-reflector-client,
 * route-server-client, as-override, next-hop-self's two leaves (enabled/
 * force), nexthop-local-unchanged, attribute-unchanged's three sub-leaves
 * (as-path/next-hop/med), soft-reconfiguration-inbound, accept-own. All
 * eleven xpaths are `type boolean; default "false";` at both neighbor and
 * peer-group scope, matching the plain-flag category, not activate's tri-
 * state: reverting a defaulted leaf to its default never invokes a destroy
 * callback (frr's northbound code generator did not scaffold one for any of
 * these eleven xpaths -- confirmed by grep, no "not yet implemented" destroy
 * stub exists for them), so only MODIFY is wired up, mirroring the existing
 * plain-boolean instance-scope leaves (e.g. instance_neighbor_passive_modify
 * in bgp_nb_neighbor.c). peer_af_flag_set()/peer_af_flag_unset() (bgpd.c)
 * already carry every side effect the retired DEFUNs relied on -- the
 * PEER_FLAG_SOFT_RECONFIG route-refresh/clear-in table entry
 * (peer_change_reset_in), the EVPN NEXTHOP_UNCHANGED coupling on next-hop-
 * self, the route-server-client -> NEXTHOP_UNCHANGED coupling, and the
 * peer-group -> member fanout via peer_group2peer_config_copy_af() -- so
 * this helper does nothing beyond calling them with the looked-up peer.
 */
static int bgp_nb_peer_af_flag_apply(struct peer *conf, bool set, afi_t afi, safi_t safi,
				     uint64_t flag)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (set)
		ret = peer_af_flag_set(conf, afi, safi, flag);
	else
		ret = peer_af_flag_unset(conf, afi, safi, flag);

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_af_flag_%sset() failed: %d",
			 __func__, set ? "" : "un", ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_flag_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
				   uint64_t flag)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_peer_af_flag_apply(bgp_nb_neighbor_lookup(args->dnode),
						 yang_dnode_get_bool(args->dnode, NULL), afi, safi,
						 flag);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_flag_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
				     uint64_t flag)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_peer_af_flag_apply(group ? group->conf : NULL,
						 yang_dnode_get_bool(args->dnode, NULL), afi, safi,
						 flag);
	}

	return NB_OK;
}

/*
 * M5 batch B2: shared per-AF policy-attachment apply, parameterized by
 * afi/safi (and, for the four directional families, the FILTER_IN/
 * FILTER_OUT or RMAP_IN/RMAP_OUT direction) -- the B1 delegator template
 * applied to route-map/prefix-list/filter-list/distribute-list in|out and
 * unsuppress-map (single, no direction). These are plain string leaves
 * (policy NAMES, not the policies themselves) stored in
 * peer->filter[afi][safi] (bgp_config_write_filter(), bgp_vty.c); no M3
 * route-map dependency. Every generated per-container stub
 * (instance_{neighbor,peer_group}_afi_safis_<af>_filters_<leaf>_
 * {modify,destroy}) is a one-line call into the neighbor/peer-group
 * wrapper below with its compile-time afi/safi/direction, exactly like
 * B1's activate. Like bgp_nb_af_activate_set()/_default(), a NULL peer/
 * group (deleted underneath by an earlier leaf in the same commit) is a
 * silent no-op, never an error.
 */

int bgp_nb_neighbor_af_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					int direct)
{
	struct peer *peer;
	struct route_map *map;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			/* peer deleted underneath in this same commit */
			return NB_OK;

		map = route_map_lookup_by_name(yang_dnode_get_string(args->dnode, NULL));
		ret = peer_route_map_set(peer, afi, safi, direct,
					 yang_dnode_get_string(args->dnode, NULL), map);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_route_map_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					 int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_route_map_unset(peer, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_route_map_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct)
{
	struct peer_group *group;
	struct route_map *map;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		map = route_map_lookup_by_name(yang_dnode_get_string(args->dnode, NULL));
		ret = peer_route_map_set(group->conf, afi, safi, direct,
					 yang_dnode_get_string(args->dnode, NULL), map);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_route_map_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_route_map_unset(group->conf, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_route_map_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_prefix_list_set(peer, afi, safi, direct,
					   yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_prefix_list_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_prefix_list_unset(peer, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_prefix_list_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					    int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_prefix_list_set(group->conf, afi, safi, direct,
					   yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_prefix_list_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi, int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_prefix_list_unset(group->conf, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_prefix_list_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_filter_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					  int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_aslist_set(peer, afi, safi, direct,
				      yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_aslist_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_filter_list_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
					   int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_aslist_unset(peer, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_aslist_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_filter_list_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					    int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_aslist_set(group->conf, afi, safi, direct,
				      yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_aslist_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_filter_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi, int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_aslist_unset(group->conf, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_aslist_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_distribute_list_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi, int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_distribute_set(peer, afi, safi, direct,
					  yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_distribute_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_distribute_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi, int direct)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_distribute_unset(peer, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_distribute_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_distribute_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi, int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_distribute_set(group->conf, afi, safi, direct,
					  yang_dnode_get_string(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_distribute_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_distribute_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi, int direct)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_distribute_unset(group->conf, afi, safi, direct);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_distribute_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_unsuppress_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer *peer;
	struct route_map *map;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		map = route_map_lookup_by_name(yang_dnode_get_string(args->dnode, NULL));
		ret = peer_unsuppress_map_set(peer, afi, safi,
					      yang_dnode_get_string(args->dnode, NULL), map);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_unsuppress_map_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_unsuppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					      safi_t safi)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;

		ret = peer_unsuppress_map_unset(peer, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_unsuppress_map_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_unsuppress_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi)
{
	struct peer_group *group;
	struct route_map *map;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		map = route_map_lookup_by_name(yang_dnode_get_string(args->dnode, NULL));
		ret = peer_unsuppress_map_set(group->conf, afi, safi,
					      yang_dnode_get_string(args->dnode, NULL), map);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_unsuppress_map_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_unsuppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						safi_t safi)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;

		ret = peer_unsuppress_map_unset(group->conf, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_unsuppress_map_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

/* Shared "reread the whole bfd container and reconfigure" apply for both
 * neighbor and peer-group (both share the 'bfd' container from the
 * neighbor-session-parameters grouping, M4 batch B10). The datastore is
 * authoritative, so every one of the six bfd_config-data leaves (enabled,
 * detect-multiplier, min-rx, min-tx, check-control-plane-failure, profile)
 * routes its modify/destroy here and recomputes the full session config,
 * the same "reread the container, not the trigger leaf" discipline as
 * bgp_nb_{neighbor,peer_group}_local_as_apply() -- which makes the callback
 * order within a commit and the presence-vs-default state of any sibling
 * leaf irrelevant. Mirrors legacy neighbor_bfd/neighbor_bfd_param/
 * neighbor_bfd_check_controlplane_failure/neighbor_bfd_profile plus their
 * 'no' forms (bgpd/bgp_bfd.c, retired): each of those first calls
 * bgp_{peer,group}_configure_bfd() then sets the relevant bfd_config
 * field(s) and calls bgp_peer_config_apply(). 'conf' is the real peer for
 * neighbor scope and group->conf for peer-group scope (the latter carries
 * PEER_STATUS_GROUP, so bgp_group_configure_bfd()/bgp_peer_config_apply()
 * fan out to members internally, exactly as peer_and_group_lookup_vty()
 * resolved a group name to group->conf in the retired DEFUNs).
 *
 * A datastore 'enabled' of false maps to bgp_peer_remove_bfd_config(),
 * which is legacy 'no neighbor X bfd's bgp_group_remove_bfd()/
 * bgp_peer_remove_bfd() dispatch -- it frees (or, for a group member,
 * resets and re-inherits) the session, replicating the teardown side
 * effect. The strict flag (PEER_FLAG_BFD_STRICT) and its hold-time live
 * outside bfd_config's data path and are handled by the dedicated
 * strict/strict-hold-time callbacks, not here.
 */
static int bgp_nb_bfd_apply(struct peer *conf, const struct lyd_node *bfd_dnode, bool is_group)
{
	if (!yang_dnode_get_bool(bfd_dnode, "enabled")) {
		bgp_peer_remove_bfd_config(conf);
		return NB_OK;
	}

	if (is_group)
		bgp_group_configure_bfd(conf);
	else
		bgp_peer_configure_bfd(conf, true);

	conf->bfd_config->detection_multiplier = yang_dnode_get_uint8(bfd_dnode,
								      "detect-multiplier");
	conf->bfd_config->min_rx = yang_dnode_get_uint32(bfd_dnode, "min-rx");
	conf->bfd_config->min_tx = yang_dnode_get_uint32(bfd_dnode, "min-tx");
	conf->bfd_config->cbit = yang_dnode_get_bool(bfd_dnode, "check-control-plane-failure");

	if (yang_dnode_exists(bfd_dnode, "profile"))
		strlcpy(conf->bfd_config->profile, yang_dnode_get_string(bfd_dnode, "profile"),
			sizeof(conf->bfd_config->profile));
	else
		conf->bfd_config->profile[0] = 0;

	bgp_peer_config_apply(conf, conf->group);

	return NB_OK;
}

int bgp_nb_neighbor_bfd_apply(const struct lyd_node *dnode)
{
	struct peer *peer = bgp_nb_neighbor_lookup(dnode);

	if (!peer)
		return NB_OK;

	return bgp_nb_bfd_apply(peer, yang_dnode_get_parent(dnode, "bfd"), false);
}

int bgp_nb_peer_group_bfd_apply(const struct lyd_node *dnode)
{
	struct peer_group *group = bgp_nb_peer_group_lookup(dnode);

	if (!group)
		return NB_OK;

	return bgp_nb_bfd_apply(group->conf, yang_dnode_get_parent(dnode, "bfd"), true);
}

/* Shared local-as reader for both peer-group and neighbor (both use the
 * same 'local-as' container from the shared neighbor-session-parameters
 * grouping, M4 batch B9). Mirrors bgp_nb_get_remote_as()'s plain/asdot
 * handling, minus the relationship-keyword case (local-as has no
 * internal/external/auto form). local_as_dnode is the 'local-as' container
 * itself -- any of its descendants can resolve it via
 * yang_dnode_get_parent(dnode, "local-as"). no_prepend/replace_as/dual_as
 * are optional out-params (pass NULL to skip): all three carry a YANG
 * default of "false" and so are always materialized once the container
 * exists, same reasoning as bgp_nb_default_af_safi_conflict_validate()'s
 * comment on always-materialized default leaves. Returns false if no ASN
 * is configured at all (the container is present with none of its choice
 * cases populated -- unreachable via the CLI, whose ASNUM token is
 * mandatory in every local-as grammar, but checked for northbound-client
 * parity, matching bgp_nb_get_remote_as()'s own defensive false return).
 */
bool bgp_nb_get_local_as(const struct lyd_node *local_as_dnode, as_t *as, const char **as_str,
			 char *as_str_buf, size_t as_str_buf_len, bool *no_prepend,
			 bool *replace_as, bool *dual_as)
{
	if (no_prepend)
		*no_prepend = yang_dnode_get_bool(local_as_dnode, "no-prepend");
	if (replace_as)
		*replace_as = yang_dnode_get_bool(local_as_dnode, "replace-as");
	if (dual_as)
		*dual_as = yang_dnode_get_bool(local_as_dnode, "dual-as");

	if (yang_dnode_exists(local_as_dnode, "plain")) {
		*as = yang_dnode_get_uint32(local_as_dnode, "plain");
		snprintf(as_str_buf, as_str_buf_len, "%u", *as);
		*as_str = as_str_buf;
		return true;
	}

	if (yang_dnode_exists(local_as_dnode, "asdot/high")) {
		as_t high = yang_dnode_get_uint16(local_as_dnode, "asdot/high");
		as_t low = yang_dnode_get_uint16(local_as_dnode, "asdot/low");

		*as = (high << 16) | low;
		snprintf(as_str_buf, as_str_buf_len, "%u.%u", high, low);
		*as_str = as_str_buf;
		return true;
	}

	*as = 0;
	*as_str = NULL;
	return false;
}

/* Legacy neighbor_local_as/neighbor_local_as_no_prepend/
 * neighbor_local_as_no_prepend_replace_as (bgp_vty.c, retired) all funnel
 * into peer_local_as_set(), whose only config-time rejection is
 * BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS when the requested local-as equals
 * the instance's own AS (bgpd.c:7576-7577, "if (bgp->as == as) return
 * BGP_ERR_CANNOT_HAVE_LOCAL_AS_SAME_AS"). Note there is no legacy check
 * against remote-as: peer_local_as_set() never compares 'as' to
 * peer->as/change_local_as's own remote-as sibling -- a local-as equal to
 * the peer's remote-as is accepted and simply makes the session look
 * iBGP (see the local_as == peer->as tests in peer_sort(), bgpd.c:1199/
 * 1228/1278). Mirrored here at NB_EV_VALIDATE, reading runtime bgp->as
 * (the established pattern, e.g. ttl-security-hops' ebgp-multihop
 * cross-check in bgp_nb_neighbor.c), so a bad local-as is rejected before
 * anything applies rather than surfacing as a silently-ignored setter
 * failure at APPLY. dnode is any descendant of the 'local-as' container
 * (the leaf that fired VALIDATE).
 */
int bgp_nb_local_as_validate(const struct lyd_node *dnode, char *errmsg, size_t errmsg_len)
{
	const struct lyd_node *local_as_dnode = yang_dnode_get_parent(dnode, "local-as");
	struct bgp *bgp = bgp_nb_instance_lookup(dnode);
	as_t as;
	const char *as_str;
	char as_buf[ASN_STRING_MAX_SIZE];

	if (!bgp)
		return NB_OK;

	if (!bgp_nb_get_local_as(local_as_dnode, &as, &as_str, as_buf, sizeof(as_buf), NULL, NULL,
				 NULL))
		return NB_OK;

	if (bgp->as == as) {
		snprintf(errmsg, errmsg_len, "Cannot have local-as same as BGP AS number");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/* Shared APPLY for the neighbor local-as leaves (plain/asdot ASN and the
 * no-prepend/replace-as/dual-as modifiers): recompute the whole local-as
 * container and call peer_local_as_set(), the same "reread the container,
 * not the trigger leaf" discipline as bgp_nb_neighbor_remote_as_apply() --
 * peer_local_as_set() is itself a no-op when nothing actually changed
 * (bgpd.c:7589-7592), so it's safe to call from every one of plain/
 * asdot-create/asdot-high/asdot-low/no-prepend/replace-as/dual-as's
 * modify path. A peer with no ASN configured is a no-op (see
 * bgp_nb_get_local_as()'s doc comment).
 */
int bgp_nb_neighbor_local_as_apply(const struct lyd_node *dnode)
{
	struct peer *peer = bgp_nb_neighbor_lookup(dnode);
	const struct lyd_node *local_as_dnode;
	as_t as;
	const char *as_str;
	char as_buf[ASN_STRING_MAX_SIZE];
	bool no_prepend, replace_as, dual_as;
	int ret;

	if (!peer)
		return NB_OK;

	local_as_dnode = yang_dnode_get_parent(dnode, "local-as");
	if (!bgp_nb_get_local_as(local_as_dnode, &as, &as_str, as_buf, sizeof(as_buf), &no_prepend,
				 &replace_as, &dual_as))
		return NB_OK;

	ret = peer_local_as_set(peer, as, no_prepend, replace_as, dual_as, as_str);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_local_as_set() failed",
			 __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* Destroy of local-as/plain or local-as/asdot unconditionally unsets
 * local-as. Safe even for a notation switch (plain -> asdot or vice
 * versa) because northbound always processes all destroys in a commit
 * before any create/modify (lib/northbound.c nb_config_cb_compare(), "to
 * correctly process the change of a case inside a choice") -- the
 * destroy's unset is immediately superseded by the new case's create/
 * modify, the same reasoning already documented for the confederation-
 * identifier leaves above.
 */
int bgp_nb_neighbor_local_as_destroy_apply(const struct lyd_node *dnode)
{
	struct peer *peer = bgp_nb_neighbor_lookup(dnode);

	if (!peer)
		return NB_OK;

	peer_local_as_unset(peer);

	return NB_OK;
}

/* Peer-group-scope counterparts of the two helpers above: same shared
 * "reread the container"/"unconditional unset" logic, calling the legacy
 * setters on group->conf (which already carries PEER_STATUS_GROUP and so
 * takes the fan-out-to-members branch inside peer_local_as_set()/_unset()
 * itself), mirroring peer_and_group_lookup_vty() resolving a peer-group
 * name to group->conf in the retired DEFUNs -- same pattern already used
 * for ebgp-multihop/ttl-security-hops (bgp_nb_peer_group.c).
 */
int bgp_nb_peer_group_local_as_apply(const struct lyd_node *dnode)
{
	struct peer_group *group = bgp_nb_peer_group_lookup(dnode);
	const struct lyd_node *local_as_dnode;
	as_t as;
	const char *as_str;
	char as_buf[ASN_STRING_MAX_SIZE];
	bool no_prepend, replace_as, dual_as;
	int ret;

	if (!group)
		return NB_OK;

	local_as_dnode = yang_dnode_get_parent(dnode, "local-as");
	if (!bgp_nb_get_local_as(local_as_dnode, &as, &as_str, as_buf, sizeof(as_buf), &no_prepend,
				 &replace_as, &dual_as))
		return NB_OK;

	ret = peer_local_as_set(group->conf, as, no_prepend, replace_as, dual_as, as_str);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_local_as_set() failed",
			 __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_peer_group_local_as_destroy_apply(const struct lyd_node *dnode)
{
	struct peer_group *group = bgp_nb_peer_group_lookup(dnode);

	if (!group)
		return NB_OK;

	peer_local_as_unset(group->conf);

	return NB_OK;
}

/* Shared 'local-role' container reader for both peer-group and neighbor
 * (M4 batch B12). Mirrors bgp_nb_get_local_as()'s shape: local_role_dnode is
 * the 'local-role' container itself, resolved by any of its descendants via
 * yang_dnode_get_parent(dnode, "local-role"). strict_mode is an optional
 * out-param (pass NULL to skip); it carries a YANG default of "false" and so
 * is always materialized once the container exists, same reasoning as
 * local-as's no-prepend/replace-as/dual-as. Returns false (role left at
 * ROLE_UNDEFINED) if 'role' itself is absent -- unreachable via the CLI,
 * whose role token is mandatory in every 'local-role' grammar, but checked
 * for northbound-client parity and so a same-transaction destroy of 'role'
 * (see the neighbor-scope destroy callback's comment) makes a
 * still-pending strict-mode modify a safe no-op instead of resurrecting the
 * role via stale data, matching bgp_nb_get_local_as()'s own defensive
 * false return.
 */
bool bgp_nb_get_role(const struct lyd_node *local_role_dnode, uint8_t *role, bool *strict_mode)
{
	const char *role_str;

	if (strict_mode)
		*strict_mode = yang_dnode_get_bool(local_role_dnode, "strict-mode");

	if (!yang_dnode_exists(local_role_dnode, "role")) {
		*role = ROLE_UNDEFINED;
		return false;
	}

	role_str = yang_dnode_get_string(local_role_dnode, "role");
	if (strmatch(role_str, "provider"))
		*role = ROLE_PROVIDER;
	else if (strmatch(role_str, "rs-server"))
		*role = ROLE_RS_SERVER;
	else if (strmatch(role_str, "rs-client"))
		*role = ROLE_RS_CLIENT;
	else if (strmatch(role_str, "customer"))
		*role = ROLE_CUSTOMER;
	else
		*role = ROLE_PEER;

	return true;
}

/* Shared APPLY for the neighbor 'local-role' leaves (role and strict-mode,
 * M4 batch B12): recompute the whole container and call peer_role_set(),
 * the same "reread the container, not the trigger leaf" discipline as
 * bgp_nb_neighbor_local_as_apply() above -- both neighbor_role_cli_cmd's
 * bare and strict-mode variants (bgp_cli_neighbor.c) enqueue a MODIFY on
 * 'role' together with an explicit MODIFY "true"/"false" on 'strict-mode'
 * (strict-mode has a YANG default and so is modify-only, no .destroy, the
 * same convention as every other default-bearing boolean in this file --
 * see aigp/oad's CLI), so either leaf's own modify callback reaching this
 * shared apply always finds both values already resolved on the dnode
 * regardless of which one fired. A peer with no role configured at all is a
 * no-op (see bgp_nb_get_role()'s doc comment) -- reached when a same-
 * transaction 'role' destroy (the 'no' form) has already removed it by the
 * time strict-mode's own modify-to-false runs, since destroys are applied
 * before modifies within a commit (lib/northbound.c).
 *
 * bgp_capability_send() reproduces the unconditional
 * CAPABILITY_ACTION_SET call every legacy 'neighbor X local-role ...' DEFPY
 * makes after peer_role_set_vty() (bgp_vty.c, retired), regardless of the
 * setter's return value (dynamic capability renegotiation without a full
 * session reset, inventory section 1.17) -- peer_role_set() failure is
 * still reported via NB_ERR_RESOURCE, matching the flog_err()-on-failure
 * idiom used throughout this file (e.g. peer_ttl_security_hops_unset()).
 */
int bgp_nb_neighbor_role_apply(const struct lyd_node *dnode)
{
	struct peer *peer = bgp_nb_neighbor_lookup(dnode);
	const struct lyd_node *local_role_dnode;
	uint8_t role;
	bool strict_mode;
	int ret;

	if (!peer)
		return NB_OK;

	local_role_dnode = yang_dnode_get_parent(dnode, "local-role");
	if (!bgp_nb_get_role(local_role_dnode, &role, &strict_mode))
		return NB_OK;

	ret = peer_role_set(peer, role, strict_mode);
	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_SET);
	if (ret != CMD_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_role_set() failed", __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

/* Peer-group-scope counterpart of the helper above: same shared "reread the
 * container" logic, calling peer_role_set() on group->conf, which already
 * carries PEER_STATUS_GROUP and so takes the fan-out-to-members branch
 * inside peer_role_set() itself (bgpd.c) -- mirroring
 * peer_and_group_lookup_vty() resolving a peer-group name to group->conf in
 * the retired DEFPYs, same pattern already used for local-as
 * (bgp_nb_peer_group_local_as_apply() above).
 *
 * bgp_capability_send() is called on group->conf->connection directly, NOT
 * fanned out to live members via bgp_nb_capability_send_dynamic_peer_group()
 * (the dedicated helper the capabilities/dynamic leaf uses, B8) -- legacy's
 * neighbor_role_cmd/neighbor_role_strict_cmd/no_neighbor_role_cmd (bgp_vty.c,
 * retired) never used that helper either, calling bgp_capability_send()
 * unconditionally on whatever peer_and_group_lookup_vty() returned. Since
 * bgp_capability_send() no-ops on a non-established connection
 * (bgp_packet.c) and the peer-group template connection is never
 * established, this call is a legacy no-op for peer-group scope -- faithfully
 * reproduced as-is rather than "fixed" into a member fan-out, which would be
 * a behavior change beyond this batch's replicate-legacy-exactly scope.
 */
int bgp_nb_peer_group_role_apply(const struct lyd_node *dnode)
{
	struct peer_group *group = bgp_nb_peer_group_lookup(dnode);
	const struct lyd_node *local_role_dnode;
	uint8_t role;
	bool strict_mode;
	int ret;

	if (!group)
		return NB_OK;

	local_role_dnode = yang_dnode_get_parent(dnode, "local-role");
	if (!bgp_nb_get_role(local_role_dnode, &role, &strict_mode))
		return NB_OK;

	ret = peer_role_set(group->conf, role, strict_mode);
	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_SET);
	if (ret != CMD_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_role_set() failed", __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
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

/* Shared VALIDATE guard for the 'path-attribute-discard'/
 * 'path-attribute-treat-as-withdraw' leaf-list entries (M4 batch B14):
 * mirrors the two rejection checks inside bgp_path_attribute_discard_vty()/
 * bgp_path_attribute_withdraw_vty() (bgp_attr.c, retired) -- the seven
 * unconditionally-mandatory attributes, and the three eBGP-only attributes
 * when the peer/peer-group isn't eBGP-sorted. Legacy prints a warning and
 * silently skips just that one number while still accepting and applying
 * the rest of the line (CMD_SUCCESS regardless); like B4's oad, this
 * rejects instead of silently no-opping, so a candidate that would
 * silently drop an entry under legacy is caught at commit time. 'what'
 * names the leaf-list ("discard"/"treat-as-withdraw") for the error text.
 * Called with peer == group->conf for the peer-group scope, exactly like
 * peer_and_group_lookup_vty() hands the same 'struct peer *' shape to the
 * legacy _vty() functions for either scope.
 */
int bgp_nb_path_attribute_validate(struct peer *peer, uint8_t attr_num, const char *what,
				   char *errmsg, size_t errmsg_len)
{
	if (attr_num == BGP_ATTR_ORIGIN || attr_num == BGP_ATTR_AS_PATH ||
	    attr_num == BGP_ATTR_NEXT_HOP || attr_num == BGP_ATTR_MULTI_EXIT_DISC ||
	    attr_num == BGP_ATTR_MP_REACH_NLRI || attr_num == BGP_ATTR_MP_UNREACH_NLRI ||
	    attr_num == BGP_ATTR_EXT_COMMUNITIES) {
		snprintf(errmsg, errmsg_len, "Can't %s path-attribute %u", what, attr_num);
		return NB_ERR_VALIDATION;
	}

	if (peer->sort != BGP_PEER_EBGP &&
	    (attr_num == BGP_ATTR_LOCAL_PREF || attr_num == BGP_ATTR_ORIGINATOR_ID ||
	     attr_num == BGP_ATTR_CLUSTER_LIST)) {
		snprintf(errmsg, errmsg_len, "Can %s path-attribute %u only for eBGP", what,
			 attr_num);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

/* Shared APPLY side effect for every path-attribute-discard/-treat-as-
 * withdraw create/destroy callback (M4 batch B14): legacy's
 * 'discard_soft_clear'/'withdraw_soft_clear' labels (bgp_attr.c, retired)
 * trigger an inbound route-refresh across every afi/safi after any change,
 * so the routing table picks up attributes that are now dropped/kept
 * differently. Firing this once per leaf-list entry (rather than once per
 * legacy CLI line, which could set several entries at once) is redundant
 * when a single commit touches more than one entry, but each call is
 * idempotent.
 */
void bgp_nb_path_attribute_soft_clear(struct peer *peer)
{
	afi_t afi;
	safi_t safi;

	FOREACH_AFI_SAFI (afi, safi)
		peer_clear_soft(peer, afi, safi, BGP_CLEAR_SOFT_IN);
}

/*
 * M5 batch B3: shared per-AF conditional-advertisement apply (neighbor +
 * peer-group). Legacy's single 'neighbor X advertise-map NAME <exist-map|
 * non-exist-map> NAME' DEFPY (bgp_vty.c, retired) always supplies all three
 * values together, so -- the same "reread the container, not the trigger
 * leaf" discipline as bgp_nb_get_local_as() -- every one of the container's
 * three leaves' MODIFY callbacks reroutes here, recomputing the whole
 * 'conditional-advertisement' container and calling peer_advertise_map_set()
 * (bgp_conditional_adv.c), which is itself peer-group-aware (fans a template
 * out to its members), exactly as the retired DEFUN relied on
 * peer_and_group_lookup_vty() handing it either shape. advertise-map/
 * condition-map are looked up permissively (route_map_lookup_by_name(),
 * no existence error), matching B2's route-map/prefix-list attachment
 * leaves -- a forward reference to a not-yet-defined route-map is legal.
 */
static int bgp_nb_af_advertise_map_set(struct peer *conf, afi_t afi, safi_t safi,
				       const struct lyd_node *cond_adv_dnode)
{
	struct route_map *advertise_map, *condition_map;
	const char *advertise_str, *condition_str;
	bool condition;
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (!yang_dnode_exists(cond_adv_dnode, "advertise-map") ||
	    !yang_dnode_exists(cond_adv_dnode, "condition-map") ||
	    !yang_dnode_exists(cond_adv_dnode, "condition"))
		/* Unreachable via the CLI (all three are mandatory in the one
		 * DEFPY grammar) but checked for northbound-client parity,
		 * matching bgp_nb_get_local_as()'s own defensive early return.
		 */
		return NB_OK;

	advertise_str = yang_dnode_get_string(cond_adv_dnode, "advertise-map");
	condition_str = yang_dnode_get_string(cond_adv_dnode, "condition-map");
	condition = strmatch(yang_dnode_get_string(cond_adv_dnode, "condition"), "exist");

	advertise_map = route_map_lookup_by_name(advertise_str);
	condition_map = route_map_lookup_by_name(condition_str);

	ret = peer_advertise_map_set(conf, afi, safi, advertise_str, advertise_map, condition_str,
				     condition_map, condition);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_advertise_map_set() failed: %d",
			 __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

/* Unconditional clear, matching legacy no_neighbor_advertise_map's 'no ...
 * advertise-map NAME <exist-map|non-exist-map> NAME' grammar, whose trailing
 * tokens are accepted but never inspected: peer_advertise_map_unset() only
 * uses its name/map arguments on the 'set' path, so passing NULLs here is
 * exactly what the retired DEFUN's negative form did. Idempotent when
 * advertise-map is already absent (the function's own early return), so
 * firing it from more than one of the container's three leaves' DESTROY in
 * the same commit -- e.g. 'no neighbor X advertise-map ...' destroying the
 * whole container at once -- is safe.
 */
static int bgp_nb_af_advertise_map_unset(struct peer *conf, afi_t afi, safi_t safi)
{
	int ret;

	if (!conf)
		return NB_OK;

	ret = peer_advertise_map_unset(conf, afi, safi, NULL, NULL, NULL, NULL,
				       CONDITION_NON_EXIST);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_advertise_map_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_advertise_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_set(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_advertise_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_unset(bgp_nb_neighbor_lookup(args->dnode), afi,
						     safi);
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_condition_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_set(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_condition_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_unset(bgp_nb_neighbor_lookup(args->dnode), afi,
						     safi);
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_condition_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_set(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_condition_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_advertise_map_unset(bgp_nb_neighbor_lookup(args->dnode), afi,
						     safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_advertise_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_set(group ? group->conf : NULL, afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_advertise_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_unset(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_condition_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_set(group ? group->conf : NULL, afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_condition_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_unset(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_condition_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_set(group ? group->conf : NULL, afi, safi,
						   yang_dnode_get_parent(args->dnode,
									 "conditional-advertisement"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_condition_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_advertise_map_unset(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

/*
 * M5 batch B3: shared per-AF site-of-origin (soo) apply (neighbor +
 * peer-group). proteus-bgp models soo as a YANG 'choice' -- as2/as4/ipv4,
 * the same three RFC 4360 subtype 0x03 encodings bgp_ecommunity.c's
 * ecommunity_gettoken() distinguishes for the legacy 'neighbor X soo
 * ASN:NN_OR_IP-ADDRESS:NN' token -- under a presence container, rather than
 * the single opaque string the legacy CLI grammar accepts. bgp_ecommunity.c
 * is bgpd-only (not linked into mgmtd), so the mgmtd-side CLI
 * (bgp_cli_neighbor.c) parses that token into a case plus two typed leaves
 * itself (bgp_cli_soo_parse()); this side re-derives the same struct
 * ecommunity legacy built via ecommunity_str2com() directly from the
 * already-typed leaves (bgp_nb_soo_encode(), below), no string re-parsing
 * here. bgp_nb_soo_encode() itself is un-static'd and shared with M6 B3's
 * instance-level 'mac-vrf soo' (bgp_nb_evpn.c), which reuses the identical
 * as2/as4/ipv4 choice shape for the site-of-origin extended community.
 *
 * The three case containers' create and their two leaves' modify all
 * reroute to the same "reread the soo container" idiom as
 * advertise-map above (bgp_nb_af_soo_set()); a case container's own DESTROY
 * is a no-op -- it fires only on a case switch (e.g. as2 -> ipv4), and
 * northbound processes every DESTROY in a commit before any CREATE/MODIFY
 * (the same "correctly process the change of a case inside a choice"
 * ordering already relied on for local-as's plain/asdot switch), so the new
 * case's own create/modify in the same commit supersedes it. The presence
 * container's ('soo') own DESTROY is the one place that unconditionally
 * clears peer->soo[afi][safi] and unsets PEER_FLAG_SOO, matching legacy's
 * no_neighbor_soo -- reached only by a genuine 'no neighbor X soo', not a
 * case switch (switching case leaves the enclosing presence container
 * alone).
 */
void bgp_nb_soo_encode(const struct lyd_node *soo_dnode, struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));

	if (yang_dnode_exists(soo_dnode, "as2")) {
		encode_route_target_as(yang_dnode_get_uint16(soo_dnode, "as2/global-admin"),
				       yang_dnode_get_uint32(soo_dnode, "as2/local-admin"), eval,
				       true);
	} else if (yang_dnode_exists(soo_dnode, "as4")) {
		encode_route_target_as4(yang_dnode_get_uint32(soo_dnode, "as4/global-admin"),
					yang_dnode_get_uint16(soo_dnode, "as4/local-admin"), eval,
					true);
	} else if (yang_dnode_exists(soo_dnode, "ipv4")) {
		struct in_addr ip;

		yang_dnode_get_ipv4(&ip, soo_dnode, "ipv4/global-admin");
		encode_route_target_ip(&ip, yang_dnode_get_uint16(soo_dnode, "ipv4/local-admin"),
				       eval, true);
	} else
		return;

	/* encode_route_target_{as,as4,ip}() (bgp_ecommunity.h) stamp
	 * ECOMMUNITY_ROUTE_TARGET (RFC 4360 subtype 0x02); retag for
	 * site-of-origin (subtype 0x03) -- the only difference between the
	 * two grammars' wire encoding, so reuse rather than duplicate the
	 * byte-layout logic.
	 */
	eval->val[1] = ECOMMUNITY_SITE_ORIGIN;
}

static int bgp_nb_af_soo_set(struct peer *conf, afi_t afi, safi_t safi,
			     const struct lyd_node *dnode)
{
	const struct lyd_node *soo_dnode = yang_dnode_get_parent(dnode, "soo");
	struct ecommunity_val eval;
	struct ecommunity *ecomm_soo;
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (!yang_dnode_exists(soo_dnode, "as2") && !yang_dnode_exists(soo_dnode, "as4") &&
	    !yang_dnode_exists(soo_dnode, "ipv4"))
		/* Choice case destroyed from under us by a case switch in this
		 * same commit; the new case's own create/modify (also in this
		 * commit) will re-drive this with the new value.
		 */
		return NB_OK;

	bgp_nb_soo_encode(soo_dnode, &eval);

	ecomm_soo = ecommunity_new();
	ecommunity_add_val(ecomm_soo, &eval, false, false);
	ecommunity_str(ecomm_soo);

	/* Same "only touch the stored value, and re-fire the flag, when it
	 * actually changed" trick as legacy's neighbor_soo DEFPY (bgp_vty.c,
	 * retired): peer_af_flag_set() is called unconditionally below either
	 * way, but the unset+set pair around it forces a fresh flag
	 * transition -- and hence peer_change_action() -- whenever the
	 * encoded value actually changed, not only when the flag itself was
	 * previously clear.
	 */
	if (!ecommunity_match(conf->soo[afi][safi], ecomm_soo)) {
		ecommunity_free(&conf->soo[afi][safi]);
		conf->soo[afi][safi] = ecomm_soo;
		peer_af_flag_unset(conf, afi, safi, PEER_FLAG_SOO);
	} else {
		ecommunity_free(&ecomm_soo);
	}

	ret = peer_af_flag_set(conf, afi, safi, PEER_FLAG_SOO);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_af_flag_set() failed: %d",
			 __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int bgp_nb_af_soo_unset(struct peer *conf, afi_t afi, safi_t safi)
{
	int ret;

	if (!conf)
		return NB_OK;

	ecommunity_free(&conf->soo[afi][safi]);

	ret = peer_af_flag_unset(conf, afi, safi, PEER_FLAG_SOO);
	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_af_flag_unset() failed: %d",
			 __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_soo_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	/* No-op: the mandatory choice case's own create and its two leaves'
	 * modify (same commit, see bgp_nb_af_soo_set()'s doc comment above)
	 * already do the real work once all three exist in the target tree.
	 */
	return NB_OK;
}

int bgp_nb_neighbor_af_soo_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_soo_unset(bgp_nb_neighbor_lookup(args->dnode), afi, safi);
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_soo_case_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_soo_set(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					 args->dnode);
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_soo_case_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	/* No-op: fires only on a case switch, see the doc comment above. */
	return NB_OK;
}

int bgp_nb_neighbor_af_soo_leaf_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_soo_set(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					 args->dnode);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_soo_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	return NB_OK;
}

int bgp_nb_peer_group_af_soo_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_soo_unset(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_soo_case_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_soo_set(group ? group->conf : NULL, afi, safi, args->dnode);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_soo_case_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	return NB_OK;
}

int bgp_nb_peer_group_af_soo_leaf_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_soo_set(group ? group->conf : NULL, afi, safi, args->dnode);
	}

	return NB_OK;
}

/*
 * M5 batch B5: shared per-AF send-community (standard/extended/large
 * tri-state trio) destroy, remove-private-as (four-way enumeration) and
 * capability orf prefix-list (send/receive/both enumeration) apply, all
 * afi/safi-parameterized (neighbor + peer-group), reusing B1's delegator
 * template.
 *
 * send-community's standard/extended/large leaves (proteus-bgp.yang's
 * neighbor-af/send-community container, 834-850) carry NO YANG default --
 * FRR sends every community flavor by default (peer_new(), bgpd.c, SETs both
 * af_flags and af_flags_invert for all three at peer creation) -- so MODIFY
 * true/false already reuses B4's bgp_nb_{neighbor,peer_group}_af_flag_modify()
 * unchanged: 'neighbor X send-community[ <type>]' -> MODIFY true ->
 * peer_af_flag_set(), 'no ...' -> MODIFY false -> peer_af_flag_unset(), the
 * same peer_af_flag_set_vty()/peer_af_flag_unset_vty() calls the retired
 * neighbor_send_community/neighbor_send_community_type DEFUNs made
 * (bgp_vty.c). Only DESTROY needs a new helper below (the leaves' no-default
 * status means both a modify and destroy stub were generated, unlike B4's
 * default-false flags), reached only via a genuine leaf removal -- the
 * primary CLI grammar always issues an explicit MODIFY true/false, the same
 * asymmetry as B1's activate. A peer-group member reverts to inheriting its
 * group's value via peer_af_flag_inherit(); a standalone peer or a
 * peer-group's own conf entry (peer_group_active() is false for both, since
 * group->conf always carries PEER_STATUS_GROUP) reverts to the compiled-in
 * default, mirroring bgp_nb_capability_flag_destroy()'s established shape
 * for the equivalent non-per-AF case (M4 batch B8).
 */
static void bgp_nb_af_flag_destroy(struct peer *conf, afi_t afi, safi_t safi, uint64_t flag,
				   bool compiled_default)
{
	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return;

	if (peer_group_active(conf)) {
		peer_af_flag_inherit(conf, afi, safi, flag);
		return;
	}

	if (compiled_default)
		peer_af_flag_set(conf, afi, safi, flag);
	else
		peer_af_flag_unset(conf, afi, safi, flag);
}

int bgp_nb_neighbor_af_flag_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
				    uint64_t flag, bool compiled_default)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_flag_destroy(bgp_nb_neighbor_lookup(args->dnode), afi, safi, flag,
				       compiled_default);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_flag_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi,
				      uint64_t flag, bool compiled_default)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_flag_destroy(group ? group->conf : NULL, afi, safi, flag,
				       compiled_default);
	}

	return NB_OK;
}

/*
 * remove-private-as (proteus-bgp.yang's neighbor-af/remove-private-as leaf,
 * 802-813, `type enumeration { basic; all; replace-as; all-replace-as; }`,
 * no default) collapses the four legacy DEFUN/no-DEFUN pairs
 * (neighbor_remove_private_as[_all][_replace_as], bgp_vty.c, retired) --
 * each of which independently toggled exactly one of
 * PEER_FLAG_REMOVE_PRIVATE_AS{,_ALL,_REPLACE,_ALL_REPLACE} and left the
 * other three untouched -- into a single mutually-exclusive value. MODIFY
 * sets the flag matching the new enum value and unsets the other three
 * unconditionally, so the runtime af_flags state can never carry more than
 * one of the four bits at once, even if a pre-conversion config had left a
 * stale combination behind; bgp_config_write_peer_af()'s emission
 * (bgp_vty.c) already only ever displayed the highest-priority bit anyway
 * (all-replace-as > replace-as > all > basic), so no displayed behavior
 * changes. DESTROY unsets (or, for a peer-group member, inherits) all four
 * via bgp_nb_af_flag_destroy() above, with a compiled-in default of false
 * (no private-AS scrubbing) for every constituent flag.
 */
static const struct {
	const char *value;
	uint64_t flag;
} bgp_nb_remove_private_as_map[] = {
	{ "basic", PEER_FLAG_REMOVE_PRIVATE_AS },
	{ "all", PEER_FLAG_REMOVE_PRIVATE_AS_ALL },
	{ "replace-as", PEER_FLAG_REMOVE_PRIVATE_AS_REPLACE },
	{ "all-replace-as", PEER_FLAG_REMOVE_PRIVATE_AS_ALL_REPLACE },
};

static int bgp_nb_af_remove_private_as_set(struct peer *conf, afi_t afi, safi_t safi,
					   const char *value)
{
	unsigned int i;
	int ret = 0;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	for (i = 0; i < array_size(bgp_nb_remove_private_as_map); i++) {
		if (strmatch(value, bgp_nb_remove_private_as_map[i].value))
			ret |= peer_af_flag_set(conf, afi, safi,
						bgp_nb_remove_private_as_map[i].flag);
		else
			ret |= peer_af_flag_unset(conf, afi, safi,
						  bgp_nb_remove_private_as_map[i].flag);
	}

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_af_flag_set()/peer_af_flag_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int bgp_nb_af_remove_private_as_default(struct peer *conf, afi_t afi, safi_t safi)
{
	unsigned int i;

	for (i = 0; i < array_size(bgp_nb_remove_private_as_map); i++)
		bgp_nb_af_flag_destroy(conf, afi, safi, bgp_nb_remove_private_as_map[i].flag,
				       false);

	return NB_OK;
}

int bgp_nb_neighbor_af_remove_private_as_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_remove_private_as_set(bgp_nb_neighbor_lookup(args->dnode), afi,
						       safi,
						       yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_remove_private_as_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_remove_private_as_default(bgp_nb_neighbor_lookup(args->dnode),
							   afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_remove_private_as_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_remove_private_as_set(group ? group->conf : NULL, afi, safi,
						       yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_remove_private_as_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_remove_private_as_default(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

/*
 * capability orf prefix-list (proteus-bgp.yang's neighbor-af/orf-prefix-list
 * leaf, 761-768, `type enumeration { send; receive; both; }`, no default)
 * collapses the legacy neighbor_capability_orf_prefix/no_... DEFUN pair's
 * <send|receive|both> argument into a single enum value, driving
 * PEER_FLAG_ORF_PREFIX_SM/_RM the same way legacy's strmatch() dispatch did
 * (bgp_vty.c, retired): "send" -> SM only, "receive" -> RM only, "both" ->
 * both. MODIFY sets exactly the flags the new value implies and unsets the
 * other, so (like remove-private-as above) the runtime state never drifts
 * from what the enum currently says. Both legacy DEFUNs additionally called
 * bgp_capability_send() unconditionally on whatever peer_and_group_lookup_vty()
 * returned, to renegotiate the ORF capability dynamically; reproduced here on
 * 'conf' directly with no peer-group member fan-out, the same
 * replicate-legacy-exactly reasoning as bgp_nb_peer_group_role_apply()'s
 * identical local-role call (M4 batch B12) -- the peer-group template
 * connection is never established, so bgp_capability_send() is a no-op for
 * peer-group scope either way (bgp_packet.c). DESTROY unsets/inherits both
 * flags via bgp_nb_af_flag_destroy() (compiled-in default false, no ORF
 * negotiated) and sends the capability UNSET action, matching legacy's 'no'
 * form.
 */
static int bgp_nb_af_orf_prefix_list_set(struct peer *conf, afi_t afi, safi_t safi,
					 const char *value)
{
	bool sm = strmatch(value, "send") || strmatch(value, "both");
	bool rm = strmatch(value, "receive") || strmatch(value, "both");
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	ret = (sm ? peer_af_flag_set(conf, afi, safi, PEER_FLAG_ORF_PREFIX_SM)
		  : peer_af_flag_unset(conf, afi, safi, PEER_FLAG_ORF_PREFIX_SM)) |
	      (rm ? peer_af_flag_set(conf, afi, safi, PEER_FLAG_ORF_PREFIX_RM)
		  : peer_af_flag_unset(conf, afi, safi, PEER_FLAG_ORF_PREFIX_RM));

	bgp_capability_send(conf->connection, afi, safi, CAPABILITY_CODE_ORF,
			    CAPABILITY_ACTION_SET);

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_af_flag_set()/peer_af_flag_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int bgp_nb_af_orf_prefix_list_default(struct peer *conf, afi_t afi, safi_t safi)
{
	if (!conf)
		return NB_OK;

	bgp_nb_af_flag_destroy(conf, afi, safi, PEER_FLAG_ORF_PREFIX_SM, false);
	bgp_nb_af_flag_destroy(conf, afi, safi, PEER_FLAG_ORF_PREFIX_RM, false);

	bgp_capability_send(conf->connection, afi, safi, CAPABILITY_CODE_ORF,
			    CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int bgp_nb_neighbor_af_orf_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_orf_prefix_list_set(bgp_nb_neighbor_lookup(args->dnode), afi,
						     safi,
						     yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_orf_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_orf_prefix_list_default(bgp_nb_neighbor_lookup(args->dnode), afi,
							 safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_orf_prefix_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_orf_prefix_list_set(group ? group->conf : NULL, afi, safi,
						     yang_dnode_get_string(args->dnode, NULL));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_orf_prefix_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						 safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_orf_prefix_list_default(group ? group->conf : NULL, afi, safi);
	}

	return NB_OK;
}

/*
 * M5 batch B6: per-AF default-originate + maximum-prefix (+opts) +
 * maximum-prefix-out + allowas-in + weight, all afi/safi-parameterized
 * (neighbor + peer-group), reusing B1's delegator template.
 *
 * default-originate and allowas-in are, like B3's conditional-advertisement,
 * multi-leaf containers whose legacy DEFPY/DEFUN always supplies every
 * member together, so every one of a container's leaves' MODIFY/DESTROY
 * callbacks reroutes to a shared "reread the whole container, call the
 * legacy setter" helper -- the same idiom bgp_nb_af_advertise_map_set()
 * established, safe here for the same reason: by NB_EV_APPLY every pending
 * change in the transaction is already committed to the dnode tree, so
 * rereading sibling leaves via the parent container always sees the final
 * post-commit state regardless of which specific leaf's callback fired
 * first. maximum-prefix is the same shape with five leaves instead of
 * three/four. maximum-prefix-out and weight are plain independent leaves
 * needing no such rereading.
 */

/*
 * default-originate (neighbor-af's 'default-originate' container,
 * proteus-bgp.yang 855-867: 'enabled' boolean, default false; 'route-map'
 * string, no default) replaces legacy's neighbor_default_originate/_rmap/
 * no_neighbor_default_originate DEFUN trio (bgp_vty.c, retained for the
 * still-native BGP_NODE hidden aliases only). peer_default_originate_set()/
 * _unset() (bgpd.c) are themselves peer-group-aware (member fan-out,
 * inherit-on-unset), exactly like the retired DEFUNs relied on
 * peer_and_group_lookup_vty() handing them either shape. Legacy's bare
 * 'default-originate' (no route-map) explicitly clears any previously
 * configured route-map (peer_default_originate_set()'s '!rmap' branch), so
 * 'enabled=true with route-map absent' correctly maps to
 * peer_default_originate_set(conf, afi, safi, NULL, NULL) here too.
 */
static int bgp_nb_af_default_originate_apply(struct peer *conf, afi_t afi, safi_t safi,
					      const struct lyd_node *cont_dnode)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (yang_dnode_get_bool(cont_dnode, "enabled")) {
		const char *rmap = NULL;
		struct route_map *route_map = NULL;

		if (yang_dnode_exists(cont_dnode, "route-map")) {
			rmap = yang_dnode_get_string(cont_dnode, "route-map");
			route_map = route_map_lookup_by_name(rmap);
		}

		ret = peer_default_originate_set(conf, afi, safi, rmap, route_map);
	} else {
		ret = peer_default_originate_unset(conf, afi, safi);
	}

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_default_originate_set()/_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_default_originate_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_default_originate_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
							 safi, yang_dnode_get_parent(args->dnode,
										     "default-originate"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_default_originate_route_map_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_default_originate_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
							 safi, yang_dnode_get_parent(args->dnode,
										     "default-originate"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_default_originate_route_map_destroy(struct nb_cb_destroy_args *args,
							    afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_default_originate_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
							 safi, yang_dnode_get_parent(args->dnode,
										     "default-originate"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_default_originate_enabled_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_default_originate_apply(group ? group->conf : NULL, afi, safi,
							 yang_dnode_get_parent(args->dnode,
									       "default-originate"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_default_originate_route_map_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_default_originate_apply(group ? group->conf : NULL, afi, safi,
							 yang_dnode_get_parent(args->dnode,
									       "default-originate"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_default_originate_route_map_destroy(struct nb_cb_destroy_args *args,
							      afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_default_originate_apply(group ? group->conf : NULL, afi, safi,
							 yang_dnode_get_parent(args->dnode,
									       "default-originate"));
	}

	return NB_OK;
}

/*
 * maximum-prefix (neighbor-af's 'maximum-prefix' container, proteus-bgp.yang
 * 876-918: 'count' uint32 no default, 'threshold' uint8 no default,
 * 'warning-only' boolean default false, 'restart-interval' uint16 no
 * default, 'force' boolean default false) replaces legacy's six
 * neighbor_maximum_prefix[_threshold][_warning][_restart] DEFUN
 * combinations plus no_neighbor_maximum_prefix (bgp_vty.c, retained for the
 * still-native BGP_NODE hidden aliases and the unreachability
 * BGP_IPV4U_NODE/BGP_IPV6U_NODE installs, which proteus-bgp does not
 * model). 'count' absent means "not configured" -- the same sentinel the
 * container-destroy path (whole container removed, so 'count' is always
 * among the departing children whenever it was ever set, since the CLI
 * grammar makes it mandatory for every positive form) resolves to,
 * reusing peer_maximum_prefix_unset() as the single teardown path exactly
 * like B3's advertise-map container.
 */
static int bgp_nb_af_maximum_prefix_apply(struct peer *conf, afi_t afi, safi_t safi,
					   const struct lyd_node *cont_dnode)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (!yang_dnode_exists(cont_dnode, "count")) {
		ret = peer_maximum_prefix_unset(conf, afi, safi);
	} else {
		uint32_t count = yang_dnode_get_uint32(cont_dnode, "count");
		uint8_t threshold = yang_dnode_exists(cont_dnode, "threshold")
					    ? yang_dnode_get_uint8(cont_dnode, "threshold")
					    : MAXIMUM_PREFIX_THRESHOLD_DEFAULT;
		bool warning = yang_dnode_get_bool(cont_dnode, "warning-only");
		uint16_t restart = yang_dnode_exists(cont_dnode, "restart-interval")
					   ? yang_dnode_get_uint16(cont_dnode, "restart-interval")
					   : 0;
		bool force = yang_dnode_get_bool(cont_dnode, "force");

		ret = peer_maximum_prefix_set(conf, afi, safi, count, threshold, warning, restart,
					      force);
	}

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_maximum_prefix_set()/_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args,
							       afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args,
								afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_force_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_maximum_prefix_apply(bgp_nb_neighbor_lookup(args->dnode), afi,
						      safi, yang_dnode_get_parent(args->dnode,
										  "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_threshold_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_warning_only_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_restart_interval_modify(struct nb_cb_modify_args *args,
								 afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_restart_interval_destroy(struct nb_cb_destroy_args *args,
								  afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_force_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_maximum_prefix_apply(group ? group->conf : NULL, afi, safi,
						      yang_dnode_get_parent(args->dnode,
									    "maximum-prefix"));
	}

	return NB_OK;
}

/*
 * maximum-prefix-out (neighbor-af's plain 'maximum-prefix-out' uint32 leaf,
 * proteus-bgp.yang 920-926, no default) replaces legacy's
 * neighbor_maximum_prefix_out/no_... DEFUN pair (bgp_vty.c, retained for
 * the still-native bare BGP_NODE install and the unreachability
 * BGP_IPV4U_NODE/BGP_IPV6U_NODE installs). A plain independent leaf, no
 * container rereading needed.
 */
int bgp_nb_neighbor_af_maximum_prefix_out_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;
		ret = peer_maximum_prefix_out_set(peer, afi, safi,
						  yang_dnode_get_uint32(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_maximum_prefix_out_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;
		ret = peer_maximum_prefix_out_unset(peer, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_maximum_prefix_out_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_out_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;
		ret = peer_maximum_prefix_out_set(group->conf, afi, safi,
						  yang_dnode_get_uint32(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_maximum_prefix_out_set() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_maximum_prefix_out_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;
		ret = peer_maximum_prefix_out_unset(group->conf, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_maximum_prefix_out_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

/*
 * allowas-in (neighbor-af's 'allowas-in' container, proteus-bgp.yang
 * 943-976: 'enabled' boolean default false, 'count' uint8 1-10 no default,
 * 'origin' boolean default false with a 'must' enforcing mutual exclusion
 * with 'count', 'route-map' string no default) replaces legacy's
 * neighbor_allowas_in/no_neighbor_allowas_in DEFPY pair (bgp_vty.c,
 * retained for the still-native BGP_NODE hidden aliases). Same
 * whole-container-reread idiom as default-originate above:
 * peer_allowas_in_set()'s allow_num argument collapses 'origin' (0),
 * explicit 'count' or -- when neither is present, exactly like legacy's
 * bare 'allowas-in' -- BGP_ALLOWAS_IN_DEFAULT (3).
 */
static int bgp_nb_af_allowas_in_apply(struct peer *conf, afi_t afi, safi_t safi,
				      const struct lyd_node *cont_dnode)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	if (!yang_dnode_get_bool(cont_dnode, "enabled")) {
		ret = peer_allowas_in_unset(conf, afi, safi);
	} else {
		bool origin = yang_dnode_get_bool(cont_dnode, "origin");
		int allow_num;
		const char *rmap = NULL;

		if (origin)
			allow_num = 0;
		else if (yang_dnode_exists(cont_dnode, "count"))
			allow_num = yang_dnode_get_uint8(cont_dnode, "count");
		else
			allow_num = BGP_ALLOWAS_IN_DEFAULT;

		if (yang_dnode_exists(cont_dnode, "route-map"))
			rmap = yang_dnode_get_string(cont_dnode, "route-map");

		ret = peer_allowas_in_set(conf, afi, safi, allow_num, origin, rmap);
	}

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_allowas_in_set()/_unset() failed: %d", __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_count_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_origin_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_route_map_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						    safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_allowas_in_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						   safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_count_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_count_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_origin_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_route_map_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_allowas_in_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_allowas_in_apply(group ? group->conf : NULL, afi, safi,
						  yang_dnode_get_parent(args->dnode, "allowas-in"));
	}

	return NB_OK;
}

/*
 * weight (neighbor-af's plain 'weight' uint16 leaf, proteus-bgp.yang
 * 998-1002, no default) replaces legacy's neighbor_weight/no_... DEFUN pair
 * (bgp_vty.c, retained for the still-native BGP_NODE hidden aliases). A
 * plain independent leaf, no container rereading needed.
 */
int bgp_nb_neighbor_af_weight_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;
		ret = peer_weight_set(peer, afi, safi, yang_dnode_get_uint16(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_weight_set() failed: %d",
				 __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_weight_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			return NB_OK;
		ret = peer_weight_unset(peer, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_weight_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_weight_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;
		ret = peer_weight_set(group->conf, afi, safi,
				      yang_dnode_get_uint16(args->dnode, NULL));
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_weight_set() failed: %d",
				 __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_weight_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			return NB_OK;
		ret = peer_weight_unset(group->conf, afi, safi);
		if (ret != 0) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_weight_unset() failed: %d", __func__, ret);
			return NB_ERR_INCONSISTENCY;
		}
	}

	return NB_OK;
}

/*
 * M5 batch B7: addpath TX/RX knobs (proteus-bgp.yang's neighbor-af/addpath
 * container, 712-761: 'tx' three-way enumeration all-paths/best-per-as/
 * best-selected (no default) + its companion 'tx-best-selected' path count
 * (uint8 1..6, no default, YANG 'must ../tx = best-selected' pairs the
 * two), 'disable-rx' boolean (default false, Tier A plain flag), and
 * 'rx-paths-limit' uint16 1..65535 (no default)).
 *
 * tx (+tx-best-selected): legacy's three independent DEFUN/DEFPY pairs
 * (neighbor_addpath_tx_all_paths, neighbor_addpath_tx_bestpath_per_as,
 * neighbor_addpath_tx_best_selected_paths, bgp_vty.c, retired) all funnel
 * into the single bgp_addpath_set_peer_type() (bgp_addpath.c:408), which
 * already stores the choice as peer->addpath_type[afi][safi] -- an enum,
 * not a flag -- and owns peer-group member fan-out/session-reset/
 * deterministic-med side effects itself, so no new mutual-exclusion
 * bookkeeping is needed here, unlike remove-private-as's four independent
 * flags (M5 B5). Both leaves' MODIFY/DESTROY reroute to a single "reread
 * the addpath container, call bgp_addpath_set_peer_type() with whatever it
 * now says" helper, the B6 default-originate idiom: 'tx' absent (or
 * destroyed) -> BGP_ADDPATH_NONE, matching every legacy "no addpath-tx-..."
 * command's outcome (each of which also ultimately called
 * bgp_addpath_set_peer_type(..., NONE, 0)); 'tx' = best-selected with
 * 'tx-best-selected' absent -> paths=0, matching legacy's 'no
 * addpath-tx-best-selected [(1-6)]' (which keeps type BEST_SELECTED but
 * zeroes the count -- an existing legacy quirk reproduced as-is here since
 * the reread always re-derives 'paths' from whatever is left in the tree,
 * with no special-casing needed). The legacy "not currently configured to
 * transmit X" guard on the tx-all-paths/tx-bestpath-per-as negative forms
 * (comparing addpath_type against the exact variant being torn down before
 * allowing the destroy) is dropped: the enum-typed YANG leaf has exactly
 * one "off" state, the same simplification B5 made for remove-private-as/
 * orf-prefix-list's four/two-way negative forms.
 */
static void bgp_nb_af_addpath_tx_apply(struct peer *conf, afi_t afi, safi_t safi,
					const struct lyd_node *addpath_dnode)
{
	enum bgp_addpath_strat type = BGP_ADDPATH_NONE;
	uint16_t paths = 0;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return;

	if (yang_dnode_exists(addpath_dnode, "tx")) {
		const char *tx = yang_dnode_get_string(addpath_dnode, "tx");

		if (strmatch(tx, "all-paths"))
			type = BGP_ADDPATH_ALL;
		else if (strmatch(tx, "best-per-as"))
			type = BGP_ADDPATH_BEST_PER_AS;
		else if (strmatch(tx, "best-selected")) {
			type = BGP_ADDPATH_BEST_SELECTED;
			if (yang_dnode_exists(addpath_dnode, "tx-best-selected"))
				paths = yang_dnode_get_uint8(addpath_dnode, "tx-best-selected");
		}
	}

	bgp_addpath_set_peer_type(conf, afi, safi, type, paths);
}

int bgp_nb_neighbor_af_addpath_tx_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_addpath_tx_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_addpath_tx_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_addpath_tx_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_addpath_tx_best_selected_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_addpath_tx_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_addpath_tx_best_selected_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_addpath_tx_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_tx_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_addpath_tx_apply(group ? group->conf : NULL, afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_tx_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					    safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_addpath_tx_apply(group ? group->conf : NULL, afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_tx_best_selected_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_addpath_tx_apply(group ? group->conf : NULL, afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_tx_best_selected_destroy(struct nb_cb_destroy_args *args,
							  afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_addpath_tx_apply(group ? group->conf : NULL, afi, safi,
					   yang_dnode_get_parent(args->dnode, "addpath"));
	}

	return NB_OK;
}

/*
 * rx-paths-limit (proteus-bgp.yang's neighbor-af/addpath/rx-paths-limit
 * leaf, uint16 1..65535, no default) drives PEER_FLAG_ADDPATH_RX_PATHS_LIMIT
 * plus the numeric paths_limit.send field legacy set inline (no dedicated
 * setter -- neighbor_addpath_paths_limit/no_..., bgp_vty.c, retired -- both
 * called peer_af_flag_set_vty()/_unset_vty() directly and then poked
 * peer->addpath_paths_limit[afi][safi].send by hand), plus the same
 * unconditional bgp_capability_send() dynamic-capability renegotiation both
 * legacy DEFPYs issued on whatever peer_and_group_lookup_vty() returned (no
 * peer-group member fan-out, the same replicate-legacy-exactly reasoning as
 * capability orf prefix-list's identical call, M5 B5). Both the set and
 * default paths below issue CAPABILITY_ACTION_SET (never _UNSET) -- an
 * existing legacy quirk (both neighbor_addpath_paths_limit and
 * no_neighbor_addpath_paths_limit called bgp_capability_send() with
 * CAPABILITY_ACTION_SET) reproduced byte-for-byte.
 */
static int bgp_nb_af_addpath_rx_paths_limit_set(struct peer *conf, afi_t afi, safi_t safi,
						uint16_t paths_limit)
{
	int ret;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return NB_OK;

	ret = peer_af_flag_set(conf, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT);
	conf->addpath_paths_limit[afi][safi].send = paths_limit;

	bgp_capability_send(conf->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);

	if (ret != 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_af_flag_set() failed: %d",
			 __func__, ret);
		return NB_ERR_INCONSISTENCY;
	}

	return NB_OK;
}

static int bgp_nb_af_addpath_rx_paths_limit_default(struct peer *conf, afi_t afi, safi_t safi)
{
	if (!conf)
		return NB_OK;

	bgp_nb_af_flag_destroy(conf, afi, safi, PEER_FLAG_ADDPATH_RX_PATHS_LIMIT, false);
	conf->addpath_paths_limit[afi][safi].send = 0;

	bgp_capability_send(conf->connection, afi, safi, CAPABILITY_CODE_PATHS_LIMIT,
			    CAPABILITY_ACTION_SET);

	return NB_OK;
}

int bgp_nb_neighbor_af_addpath_rx_paths_limit_modify(struct nb_cb_modify_args *args, afi_t afi,
						     safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_addpath_rx_paths_limit_set(bgp_nb_neighbor_lookup(args->dnode),
							    afi, safi,
							    yang_dnode_get_uint16(args->dnode,
										  NULL));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_addpath_rx_paths_limit_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						      safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_addpath_rx_paths_limit_default(bgp_nb_neighbor_lookup(args->dnode),
								afi, safi);
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_rx_paths_limit_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_addpath_rx_paths_limit_set(group ? group->conf : NULL, afi, safi,
							    yang_dnode_get_uint16(args->dnode,
										  NULL));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_addpath_rx_paths_limit_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		return bgp_nb_af_addpath_rx_paths_limit_default(group ? group->conf : NULL, afi,
								safi);
	}

	return NB_OK;
}

/*
 * Per-neighbor dampening (proteus-bgp.yang's neighbor-af/dampening
 * container, M5 batch B8) replaces legacy's neighbor_damp/no_neighbor_damp
 * DEFPY pair (bgp_vty.c, retained for the still-native BGP_NODE hidden alias
 * only -- legacy installed this pair on BGP_NODE plus the six ipv4/ipv6
 * {unicast,multicast,labeled-unicast} nodes, never vpnv4/vpnv6/l2vpn-evpn,
 * so the mgmtd install set mirrors that asymmetric reach, matching B6's
 * weight precedent). The container's four number leaves form a "must"
 * all-or-nothing set independent of 'enabled'; legacy's own DEFPY always
 * filled in concrete defaults for every field it didn't receive on the
 * command line (bare 'dampening' -> DEFAULT_HALF_LIFE/_REUSE/_SUPPRESS/
 * half*4; 'dampening H' -> given half-life, defaults for the rest), so the
 * CLI (bgp_cli_neighbor.c) reproduces that by always issuing a concrete
 * MODIFY for all four number leaves plus 'enabled' on the positive form --
 * never a partial update -- the same "always rewrite from scratch" idiom B6
 * established for maximum-prefix/default-originate. All five leaves'
 * MODIFY/DESTROY reroute to a single "reread the whole dampening container,
 * call bgp_peer_damp_enable()/_disable()" helper: if 'enabled' is absent or
 * false the peer's dampening is torn down regardless of what the numeric
 * leaves say (matching the negative CLI form, which destroys the whole
 * container in one shot, same as B6's maximum-prefix); otherwise every
 * numeric leaf is read back with the same default-filling legacy itself
 * applied, so a reread after any single leaf's MODIFY/DESTROY still
 * recomputes a fully consistent set. Units: the YANG leaves are minutes
 * (matching the legacy CLI grammar's (1-45)/(1-255) ranges byte-for-byte);
 * the *60 conversion to bgp_peer_damp_enable()'s seconds parameters happens
 * here, exactly where legacy's own DEFUN did it.
 */
static void bgp_nb_af_dampening_apply(struct peer *conf, afi_t afi, safi_t safi,
				      const struct lyd_node *dnode)
{
	bool enabled;
	time_t half, max;
	unsigned int reuse, suppress;

	if (!conf)
		/* peer/group deleted underneath in this same commit */
		return;

	enabled = yang_dnode_exists(dnode, "enabled") && yang_dnode_get_bool(dnode, "enabled");
	if (!enabled) {
		bgp_peer_damp_disable(conf, afi, safi);
		return;
	}

	half = yang_dnode_exists(dnode, "half-life") ? yang_dnode_get_uint8(dnode, "half-life")
						     : DEFAULT_HALF_LIFE;
	if (yang_dnode_exists(dnode, "reuse-threshold")) {
		reuse = yang_dnode_get_uint16(dnode, "reuse-threshold");
		suppress = yang_dnode_get_uint16(dnode, "suppress-threshold");
		max = yang_dnode_exists(dnode, "max-suppress-time")
			      ? yang_dnode_get_uint8(dnode, "max-suppress-time")
			      : half * 4;
	} else {
		reuse = DEFAULT_REUSE;
		suppress = DEFAULT_SUPPRESS;
		max = half * 4;
	}

	bgp_peer_damp_enable(conf, afi, safi, half * 60, reuse, suppress, max * 60);
}

int bgp_nb_neighbor_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args,
							 afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args,
							   afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args,
							    afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args,
							  afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_neighbor_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_dampening_apply(bgp_nb_neighbor_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi,
						    safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						     safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args,
							  afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args,
							   afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args,
							     afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args,
							      afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args,
							    afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_peer_group_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args,
							     afi_t afi, safi_t safi)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		bgp_nb_af_dampening_apply(group ? group->conf : NULL, afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

/* M5 batch B9: instance-AF 'network' (af-network-ipv4/-ipv6 in
 * proteus-bgp.yang), the first instance-AF keyed-list conversion --
 * six containers (ipv4/ipv6 x unicast/multicast/labeled-unicast; ipv4/ipv6
 * -vpn use the separate RD-keyed af-network-vpn-* grouping, M7). Legacy is
 * a single dual-purpose setter, bgp_static_set() (bgp_route.c), taking a
 * negate flag instead of split set/unset entry points; it was refactored
 * to take a resolved 'struct bgp *' plus an errmsg buffer instead of a vty
 * (bgp_static_set_vty() in bgp_route.c is the new vty-facing wrapper for
 * the still-native VPN/EVPN 'network' DEFUNs and the bare-BGP_NODE
 * 'network' DEFPY) so it can be called directly from APPLY.
 *
 * route-map and label-index are independent no-default leaves (modify +
 * destroy); backdoor (ipv4 only) is a Tier A default-false boolean
 * (modify only). None of the three has a legacy setter of its own --
 * bgp_static_set() always takes the full option set at once -- so every
 * leaf callback rereads the other two from the sibling entry and reissues
 * a full bgp_static_set() call, the same "reread the whole container, call
 * the one legacy setter" idiom B6/B7/B8 established for
 * default-originate/addpath/dampening. destroy of an individual leaf
 * passes that leaf's "off" value explicitly rather than rereading it (the
 * dnode being destroyed may already be unlinked by APPLY time); destroy of
 * the whole list entry passes rmap=NULL/label_index=BGP_INVALID_LABEL_INDEX
 * so bgp_static_set()'s legacy "does the given rmap/label-index still
 * match?" guards (meant for a mismatched CLI 'no network ... route-map X')
 * are unconditionally bypassed, the same simplification B5/B7 made for
 * negative-form matching guards that don't apply to a keyed-list delete by
 * key.
 */
static const char *bgp_nb_af_network_rmap(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "route-map") ?
		       yang_dnode_get_string(entry_dnode, "route-map") : NULL;
}

static uint32_t bgp_nb_af_network_label_index(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "label-index") ?
		       yang_dnode_get_uint32(entry_dnode, "label-index") :
		       BGP_INVALID_LABEL_INDEX;
}

static bool bgp_nb_af_network_backdoor(const struct lyd_node *entry_dnode, afi_t afi)
{
	return afi == AFI_IP && yang_dnode_get_bool(entry_dnode, "backdoor");
}

static int bgp_nb_af_network_set(const struct lyd_node *entry_dnode, afi_t afi, safi_t safi,
				 const char *rmap, uint32_t label_index, bool backdoor)
{
	struct bgp *bgp;
	const char *prefix_str;
	char errmsg[256];
	int ret;

	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	prefix_str = yang_dnode_get_string(entry_dnode, "prefix");

	ret = bgp_static_set(bgp, false, prefix_str, NULL, NULL, afi, safi, rmap,
			     backdoor ? 1 : 0, label_index, 0, NULL, NULL, NULL, NULL,
			     errmsg, sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_static_set() failed for %s: %s", __func__, prefix_str,
			 errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_network_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	struct prefix p;
	const char *prefix_str;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Prefix syntax is already YANG-typed (inet:ipv4-prefix /
		 * inet:ipv6-prefix); only bgp_static_set()'s semantic
		 * link-local rejection needs an explicit check here,
		 * mirroring instance_peer_group_listen_range_create(). */
		if (afi == AFI_IP6) {
			prefix_str = yang_dnode_get_string(args->dnode, "prefix");
			if (str2prefix(prefix_str, &p) && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
				snprintf(args->errmsg, args->errmsg_len,
					 "Malformed prefix (link-local address)");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_network_set(args->dnode, afi, safi,
					     bgp_nb_af_network_rmap(args->dnode),
					     bgp_nb_af_network_label_index(args->dnode),
					     bgp_nb_af_network_backdoor(args->dnode, afi));
	}

	return NB_OK;
}

int bgp_nb_af_network_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	const char *prefix_str;
	char errmsg[256];
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	prefix_str = yang_dnode_get_string(args->dnode, "prefix");

	ret = bgp_static_set(bgp, true, prefix_str, NULL, NULL, afi, safi, NULL, 0,
			     BGP_INVALID_LABEL_INDEX, 0, NULL, NULL, NULL, NULL, errmsg,
			     sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_static_set() failed for %s: %s", __func__, prefix_str,
			 errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_network_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");

	return bgp_nb_af_network_set(entry_dnode, afi, safi,
				     yang_dnode_get_string(args->dnode, NULL),
				     bgp_nb_af_network_label_index(entry_dnode),
				     bgp_nb_af_network_backdoor(entry_dnode, afi));
}

int bgp_nb_af_network_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");

	return bgp_nb_af_network_set(entry_dnode, afi, safi, NULL,
				     bgp_nb_af_network_label_index(entry_dnode),
				     bgp_nb_af_network_backdoor(entry_dnode, afi));
}

int bgp_nb_af_network_label_index_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");

	return bgp_nb_af_network_set(entry_dnode, afi, safi, bgp_nb_af_network_rmap(entry_dnode),
				     yang_dnode_get_uint32(args->dnode, NULL),
				     bgp_nb_af_network_backdoor(entry_dnode, afi));
}

int bgp_nb_af_network_label_index_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");

	return bgp_nb_af_network_set(entry_dnode, afi, safi, bgp_nb_af_network_rmap(entry_dnode),
				     BGP_INVALID_LABEL_INDEX,
				     bgp_nb_af_network_backdoor(entry_dnode, afi));
}

int bgp_nb_af_network_backdoor_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "network");

	return bgp_nb_af_network_set(entry_dnode, afi, safi, bgp_nb_af_network_rmap(entry_dnode),
				     bgp_nb_af_network_label_index(entry_dnode),
				     yang_dnode_get_bool(args->dnode, NULL));
}

/* M5 batch B10: instance-AF 'aggregate-address' (af-aggregate-ipv4/-ipv6 in
 * proteus-bgp.yang), the six ipv4/ipv6 x unicast/multicast/labeled-unicast
 * containers -- the same AF set B9 established for 'network', sharing the
 * legacy bgp_config_write_network() emitter (bgp_route.c) with it. Legacy is
 * bgp_aggregate_set()/bgp_aggregate_unset() (bgp_route.c), refactored the
 * same way as bgp_static_set() in B9: both now take a resolved 'struct bgp *'
 * plus an errmsg buffer instead of a vty, so they can be called directly from
 * APPLY; bgp_aggregate_set_vty()/bgp_aggregate_unset_vty() are the new
 * vty-facing wrappers for the one remaining native call site, the
 * ipv4-unicast bgp_aggregate DEFPY reachable only via the bare BGP_NODE
 * install (bare-BGP_NODE precedent, B6-B9).
 *
 * None of the six option leaves (as-set, summary-only, route-map, origin,
 * matching-med-only, suppress-map) has a setter of its own -- like B9's
 * 'network', bgp_aggregate_set() always takes the full option set at once --
 * so every leaf callback rereads the other five from the sibling list entry
 * and reissues a full bgp_aggregate_set() call, the same "reread the whole
 * container, call the one legacy setter" idiom B6/B7/B8/B9 established.
 * as-set/summary-only/matching-med-only are Tier A default-false booleans
 * (modify only, no destroy, unconditionally reread via
 * yang_dnode_get_bool()); route-map/origin/suppress-map are no-default
 * leaves (modify + destroy). Destroying the whole list entry goes through
 * bgp_aggregate_unset(), which (unlike bgp_static_set()'s negate path) takes
 * no option arguments to begin with, so there is no "does the given option
 * still match?" guard to bypass here.
 */
static const char *bgp_nb_af_aggregate_rmap(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "route-map") ?
		       yang_dnode_get_string(entry_dnode, "route-map") : NULL;
}

static const char *bgp_nb_af_aggregate_suppress_map(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "suppress-map") ?
		       yang_dnode_get_string(entry_dnode, "suppress-map") : NULL;
}

static uint8_t bgp_nb_af_aggregate_origin_from_str(const char *origin_str)
{
	if (!origin_str)
		return BGP_ORIGIN_UNSPECIFIED;
	if (strmatch(origin_str, "egp"))
		return BGP_ORIGIN_EGP;
	if (strmatch(origin_str, "igp"))
		return BGP_ORIGIN_IGP;
	if (strmatch(origin_str, "incomplete"))
		return BGP_ORIGIN_INCOMPLETE;

	return BGP_ORIGIN_UNSPECIFIED;
}

static uint8_t bgp_nb_af_aggregate_origin(const struct lyd_node *entry_dnode)
{
	if (!yang_dnode_exists(entry_dnode, "origin"))
		return BGP_ORIGIN_UNSPECIFIED;

	return bgp_nb_af_aggregate_origin_from_str(yang_dnode_get_string(entry_dnode, "origin"));
}

static int bgp_nb_af_aggregate_set(const struct lyd_node *entry_dnode, afi_t afi, safi_t safi,
				   const char *rmap, bool summary_only, bool as_set,
				   uint8_t origin, bool match_med, const char *suppress_map)
{
	struct bgp *bgp;
	const char *prefix_str;
	char errmsg[256];
	int ret;

	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	prefix_str = yang_dnode_get_string(entry_dnode, "prefix");

	ret = bgp_aggregate_set(bgp, prefix_str, afi, safi, rmap, summary_only ? 1 : 0,
				as_set ? 1 : 0, origin, match_med, suppress_map, errmsg,
				sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_aggregate_set() failed for %s: %s", __func__, prefix_str,
			 errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_aggregate_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_aggregate_set(args->dnode, afi, safi,
					       bgp_nb_af_aggregate_rmap(args->dnode),
					       yang_dnode_get_bool(args->dnode, "summary-only"),
					       yang_dnode_get_bool(args->dnode, "as-set"),
					       bgp_nb_af_aggregate_origin(args->dnode),
					       yang_dnode_get_bool(args->dnode,
								   "matching-med-only"),
					       bgp_nb_af_aggregate_suppress_map(args->dnode));
	}

	return NB_OK;
}

int bgp_nb_af_aggregate_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	const char *prefix_str;
	char errmsg[256];
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	prefix_str = yang_dnode_get_string(args->dnode, "prefix");

	ret = bgp_aggregate_unset(bgp, prefix_str, afi, safi, errmsg, sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_aggregate_unset() failed for %s: %s", __func__, prefix_str,
			 errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_aggregate_as_set_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(args->dnode, NULL),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_summary_only_modify(struct nb_cb_modify_args *args, afi_t afi,
					    safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(args->dnode, NULL),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi,
				       yang_dnode_get_string(args->dnode, NULL),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, NULL,
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_origin_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(
		entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
		yang_dnode_get_bool(entry_dnode, "summary-only"),
		yang_dnode_get_bool(entry_dnode, "as-set"),
		bgp_nb_af_aggregate_origin_from_str(yang_dnode_get_string(args->dnode, NULL)),
		yang_dnode_get_bool(entry_dnode, "matching-med-only"),
		bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_origin_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       BGP_ORIGIN_UNSPECIFIED,
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_matching_med_only_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(args->dnode, NULL),
				       bgp_nb_af_aggregate_suppress_map(entry_dnode));
}

int bgp_nb_af_aggregate_suppress_map_modify(struct nb_cb_modify_args *args, afi_t afi,
					    safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"),
				       yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_aggregate_suppress_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "aggregate-address");

	return bgp_nb_af_aggregate_set(entry_dnode, afi, safi, bgp_nb_af_aggregate_rmap(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "summary-only"),
				       yang_dnode_get_bool(entry_dnode, "as-set"),
				       bgp_nb_af_aggregate_origin(entry_dnode),
				       yang_dnode_get_bool(entry_dnode, "matching-med-only"), NULL);
}

/*
 * M5 batch B11: instance-AF 'redistribute' (af-redistribute in
 * proteus-bgp.yang), the two unicast-only instance AFs -- ipv4-unicast and
 * ipv6-unicast; bgp_config_write_redistribute() (bgp_vty.c) returns
 * immediately for every other SAFI, and af-redistribute is only 'uses'
 * there. A keyed list (key 'protocol instance') with two option children
 * (metric, route-map).
 *
 * Unlike B9/B10's monolithic bgp_static_set()/bgp_aggregate_set(), legacy
 * already exposes per-field setters here -- bgp_redist_add()/_set()/
 * _rmap_set()/_metric_set()/_unset() (bgp_zebra.c), all already
 * afi-parameterized and vty-free, no refactor needed. CREATE reads whatever
 * metric/route-map siblings are already present in the same dnode subtree
 * (the CLI always enqueues the list CREATE and both option leaves together,
 * the B9/B10 idiom) and applies them with a single bgp_redistribute_set()
 * call, mirroring the legacy combined DEFUNs (e.g.
 * bgp_redistribute_ipv4_rmap_metric()). Each leaf's own MODIFY/DESTROY then
 * looks up the already-created 'struct bgp_redist' and calls only its own
 * setter, so a later standalone 'redistribute PROTO metric N' reconfigure
 * causes exactly one zebra re-register cycle, not a replay of every sibling.
 * bgp_redistribute_rmap_unset()/_metric_unset() (bgp_zebra.c) are new tiny
 * counterparts to the existing _set() calls, for a leaf DESTROY that keeps
 * the redistribute entry itself (unlike bgp_redistribute_unset(), which
 * tears the whole entry down on list DESTROY).
 *
 * proto_redistnum() (lib/log.c) is the vty-free protocol-name lookup legacy
 * DEFUNs already used via route type validation; the "Invalid route type"
 * rejection they did with vty_out() becomes a NB_EV_VALIDATE error here.
 * YANG's protocol enum is one shared list for both AFs -- the grouping's
 * description notes the v4-only/v6-only protocols (rip/ospf vs ripng/ospf6)
 * aren't cross-checked in the model itself ("FRR rejects the wrong ones at
 * load time") -- so a wrong-AF protocol (e.g. 'redistribute rip' under
 * ipv6-unicast) is exactly this VALIDATE rejection.
 */
static uint8_t bgp_nb_af_redistribute_type(const struct lyd_node *entry_dnode, afi_t afi)
{
	return proto_redistnum(afi, yang_dnode_get_string(entry_dnode, "protocol"));
}

static unsigned short bgp_nb_af_redistribute_instance(const struct lyd_node *entry_dnode)
{
	return yang_dnode_get_uint16(entry_dnode, "instance");
}

static bool bgp_nb_af_redistribute_have_metric(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "metric");
}

static uint32_t bgp_nb_af_redistribute_metric(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "metric") ?
		       yang_dnode_get_uint32(entry_dnode, "metric") : 0;
}

static const char *bgp_nb_af_redistribute_rmap(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "route-map") ?
		       yang_dnode_get_string(entry_dnode, "route-map") : NULL;
}

/* Apply the full metric/route-map option set for one already-added
 * 'struct bgp_redist' with a single bgp_redistribute_set() call, matching
 * the legacy combined DEFUNs' one-call-per-command shape. */
static void bgp_nb_af_redistribute_apply(struct bgp *bgp, struct bgp_redist *red, afi_t afi,
					 uint8_t type, unsigned short instance,
					 bool have_metric, uint32_t metric, const char *rmap)
{
	bool changed = false;

	if (have_metric)
		changed |= bgp_redistribute_metric_set(bgp, red, afi, type, metric);
	else
		changed |= bgp_redistribute_metric_unset(red);

	if (rmap)
		changed |= bgp_redistribute_rmap_set(red, rmap, route_map_lookup_by_name(rmap));
	else
		changed |= bgp_redistribute_rmap_unset(red);

	bgp_redistribute_set(bgp, afi, type, instance, changed);
}

int bgp_nb_af_redistribute_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	struct bgp_redist *red;
	uint8_t type;
	unsigned short instance;

	switch (args->event) {
	case NB_EV_VALIDATE:
		type = proto_redistnum(afi, yang_dnode_get_string(args->dnode, "protocol"));
		if (type == ZEBRA_ROUTE_ERROR || type == ZEBRA_ROUTE_BGP) {
			snprintf(args->errmsg, args->errmsg_len, "Invalid route type");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			return NB_OK;

		type = bgp_nb_af_redistribute_type(args->dnode, afi);
		instance = bgp_nb_af_redistribute_instance(args->dnode);

		red = bgp_redist_add(bgp, afi, type, instance);
		bgp_nb_af_redistribute_apply(bgp, red, afi, type, instance,
					     bgp_nb_af_redistribute_have_metric(args->dnode),
					     bgp_nb_af_redistribute_metric(args->dnode),
					     bgp_nb_af_redistribute_rmap(args->dnode));
		break;
	}

	return NB_OK;
}

int bgp_nb_af_redistribute_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_redistribute_unset(bgp, afi, bgp_nb_af_redistribute_type(args->dnode, afi),
			       bgp_nb_af_redistribute_instance(args->dnode));

	return NB_OK;
}

int bgp_nb_af_redistribute_metric_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;
	struct bgp *bgp;
	struct bgp_redist *red;
	uint8_t type;
	unsigned short instance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "redistribute");
	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	type = bgp_nb_af_redistribute_type(entry_dnode, afi);
	instance = bgp_nb_af_redistribute_instance(entry_dnode);
	red = bgp_redist_add(bgp, afi, type, instance);

	if (bgp_redistribute_metric_set(bgp, red, afi, type, yang_dnode_get_uint32(args->dnode, NULL)))
		bgp_redistribute_set(bgp, afi, type, instance, true);

	return NB_OK;
}

int bgp_nb_af_redistribute_metric_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;
	struct bgp *bgp;
	struct bgp_redist *red;
	uint8_t type;
	unsigned short instance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "redistribute");
	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	type = bgp_nb_af_redistribute_type(entry_dnode, afi);
	instance = bgp_nb_af_redistribute_instance(entry_dnode);
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return NB_OK;

	if (bgp_redistribute_metric_unset(red))
		bgp_redistribute_set(bgp, afi, type, instance, true);

	return NB_OK;
}

int bgp_nb_af_redistribute_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *entry_dnode;
	struct bgp *bgp;
	struct bgp_redist *red;
	uint8_t type;
	unsigned short instance;
	const char *rmap;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "redistribute");
	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	type = bgp_nb_af_redistribute_type(entry_dnode, afi);
	instance = bgp_nb_af_redistribute_instance(entry_dnode);
	red = bgp_redist_add(bgp, afi, type, instance);

	rmap = yang_dnode_get_string(args->dnode, NULL);
	if (bgp_redistribute_rmap_set(red, rmap, route_map_lookup_by_name(rmap)))
		bgp_redistribute_set(bgp, afi, type, instance, true);

	return NB_OK;
}

int bgp_nb_af_redistribute_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi)
{
	const struct lyd_node *entry_dnode;
	struct bgp *bgp;
	struct bgp_redist *red;
	uint8_t type;
	unsigned short instance;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "redistribute");
	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	type = bgp_nb_af_redistribute_type(entry_dnode, afi);
	instance = bgp_nb_af_redistribute_instance(entry_dnode);
	red = bgp_redist_lookup(bgp, afi, type, instance);
	if (!red)
		return NB_OK;

	if (bgp_redistribute_rmap_unset(red))
		bgp_redistribute_set(bgp, afi, type, instance, true);

	return NB_OK;
}

/*
 * M5 batch B12: instance-AF 'maximum-paths (1-N)' / 'maximum-paths ibgp
 * (1-N) [equal-cluster-length]' (proteus-bgp.yang's af-route-selection/
 * maximum-paths container), across the eight instance AFs that 'uses'
 * af-route-selection (ipv4/ipv6 x unicast/multicast/labeled-unicast/vpn).
 * The container's three leaves (ebgp, ibgp, ibgp-equal-cluster-length) are
 * independent -- no YANG 'must' ties them together -- but
 * ibgp-equal-cluster-length only ever has meaning alongside 'ibgp', exactly
 * as legacy's grammar only ever accepts 'equal-cluster-length' as a suffix
 * of 'maximum-paths ibgp N'. All three leaves' MODIFY/DESTROY reroute to a
 * single "reread the whole container, call
 * bgp_maximum_paths_set()/_unset()" helper (legacy's own setters,
 * bgp_mpath.c, already afi/safi/peertype-parameterized -- no refactor
 * needed) so a MODIFY of 'ibgp-equal-cluster-length' alone still reapplies
 * the current 'ibgp' value with the new cluster bit, and a DESTROY of
 * 'ibgp' also resets 'ibgp-equal-cluster-length' back to its false default
 * in the same call, matching bgp_maximum_paths_unset()'s own
 * same_clusterlen=false reset. bgp_recalculate_all_bestpaths() is called
 * once per reread, matching legacy's bgp_maxpaths_config_vty().
 */
static void bgp_nb_af_maximum_paths_apply(struct bgp *bgp, afi_t afi, safi_t safi,
					  const struct lyd_node *dnode)
{
	bool cluster;

	if (!bgp)
		/* instance deleted underneath in this same commit */
		return;

	if (yang_dnode_exists(dnode, "ebgp"))
		bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_EBGP,
				      yang_dnode_get_uint16(dnode, "ebgp"), false);
	else
		bgp_maximum_paths_unset(bgp, afi, safi, BGP_PEER_EBGP);

	cluster = yang_dnode_exists(dnode, "ibgp-equal-cluster-length") &&
		 yang_dnode_get_bool(dnode, "ibgp-equal-cluster-length");

	if (yang_dnode_exists(dnode, "ibgp"))
		bgp_maximum_paths_set(bgp, afi, safi, BGP_PEER_IBGP,
				      yang_dnode_get_uint16(dnode, "ibgp"), cluster);
	else
		bgp_maximum_paths_unset(bgp, afi, safi, BGP_PEER_IBGP);

	bgp_recalculate_all_bestpaths(bgp);
}

/* Shared VALIDATE: legacy's bgp_maxpaths_config_vty() rejects a value above
 * the runtime 'multipath_num' (set from MULTIPATH_NUM at daemon start, or
 * lower via the '-M'/'--multipath' bgpd command-line option) with "%%
 * Maxpaths Specified: ... is > than multipath num ..."; the YANG leaves are
 * deliberately unbounded uint16 ("modeled ... without a tighter range on
 * purpose") so this runtime bound is enforced here, not in the model. */
static int bgp_nb_af_maximum_paths_validate(struct nb_cb_modify_args *args)
{
	uint16_t maxpaths = yang_dnode_get_uint16(args->dnode, NULL);

	if (maxpaths > multipath_num) {
		snprintf(args->errmsg, args->errmsg_len,
			"Maxpaths Specified: %u is > than multipath num specified on bgp command line %u",
			maxpaths, multipath_num);
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int bgp_nb_af_maximum_paths_ebgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_af_maximum_paths_validate(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_maximum_paths_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					      yang_dnode_get_parent(args->dnode, "maximum-paths"));
	}

	return NB_OK;
}

int bgp_nb_af_maximum_paths_ebgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_maximum_paths_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				      yang_dnode_get_parent(args->dnode, "maximum-paths"));

	return NB_OK;
}

int bgp_nb_af_maximum_paths_ibgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_af_maximum_paths_validate(args);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_maximum_paths_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					      yang_dnode_get_parent(args->dnode, "maximum-paths"));
	}

	return NB_OK;
}

int bgp_nb_af_maximum_paths_ibgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_maximum_paths_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				      yang_dnode_get_parent(args->dnode, "maximum-paths"));

	return NB_OK;
}

int bgp_nb_af_maximum_paths_ibgp_equal_cluster_length_modify(struct nb_cb_modify_args *args,
							      afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_maximum_paths_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					      yang_dnode_get_parent(args->dnode, "maximum-paths"));
	}

	return NB_OK;
}

/*
 * M5 batch B12: instance-AF 'table-map WORD' (proteus-bgp.yang's
 * af-route-selection/table-map leaf), across the same eight instance AFs.
 * A plain string leaf (policy-attachment name, per the established
 * plain-string rule -- never a leafref); legacy's bgp_table_map_set()/
 * _unset() (bgp_route.c) were vty-taking statics, split the same way B9/B10
 * split bgp_static_set()/bgp_aggregate_set() into a vty-free 'struct bgp *'
 * core plus a thin _vty wrapper for the still-native DEFUNs.
 */
int bgp_nb_af_table_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_table_map_set(bgp, afi, safi, yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int bgp_nb_af_table_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_table_map_unset(bgp, afi, safi);

	return NB_OK;
}

/*
 * M5 batch B12: instance-AF 'bgp dampening [(1-45) [(1-20000) (1-50000)
 * (1-255)]]' (proteus-bgp.yang's af-route-selection/dampening container),
 * across the same eight instance AFs. Same container shape (and the same
 * all-or-nothing 'must' on the four number leaves) as B8's per-neighbor
 * dampening; this reuses that batch's "reread the whole container, call
 * bgp_damp_enable()/_disable()" idiom verbatim, with bgp_damp_enable()/
 * _disable() (bgp_damp.c, already afi/safi-parameterized and vty-free) in
 * place of B8's bgp_peer_damp_enable()/_disable(). The YANG leaves are
 * minutes (matching bgp_damp_set_cmd's (1-45)/(1-255) ranges
 * byte-for-byte); the *60 conversion to bgp_damp_enable()'s seconds
 * parameters happens here, exactly where legacy's own DEFUN did it.
 */
static void bgp_nb_af_instance_dampening_apply(struct bgp *bgp, afi_t afi, safi_t safi,
				      const struct lyd_node *dnode)
{
	bool enabled;
	time_t half, max;
	unsigned int reuse, suppress;

	if (!bgp)
		/* instance deleted underneath in this same commit */
		return;

	enabled = yang_dnode_exists(dnode, "enabled") && yang_dnode_get_bool(dnode, "enabled");
	if (!enabled) {
		bgp_damp_disable(bgp, afi, safi);
		return;
	}

	half = yang_dnode_exists(dnode, "half-life") ? yang_dnode_get_uint8(dnode, "half-life")
						     : DEFAULT_HALF_LIFE;
	if (yang_dnode_exists(dnode, "reuse-threshold")) {
		reuse = yang_dnode_get_uint16(dnode, "reuse-threshold");
		suppress = yang_dnode_get_uint16(dnode, "suppress-threshold");
		max = yang_dnode_exists(dnode, "max-suppress-time")
			      ? yang_dnode_get_uint8(dnode, "max-suppress-time")
			      : half * 4;
	} else {
		reuse = DEFAULT_REUSE;
		suppress = DEFAULT_SUPPRESS;
		max = half * 4;
	}

	bgp_damp_enable(bgp, afi, safi, half * 60, reuse, suppress, max * 60);
}

int bgp_nb_af_dampening_enabled_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_half_life_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_half_life_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_reuse_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
					       safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_reuse_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_suppress_threshold_modify(struct nb_cb_modify_args *args, afi_t afi,
						  safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_suppress_threshold_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						   safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_max_suppress_time_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

int bgp_nb_af_dampening_max_suppress_time_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp_nb_af_instance_dampening_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
					  yang_dnode_get_parent(args->dnode, "dampening"));
	}

	return NB_OK;
}

/*
 * M5 batch B13: instance-AF 'distance bgp (1-255) (1-255) (1-255)'
 * (af-distance-ipv4/-ipv6's distance/{ebgp,ibgp,local} in proteus-bgp.yang),
 * across the eight instance AFs that 'uses' af-distance (ipv4/ipv6 x
 * unicast/multicast/labeled-unicast/vpn; l2vpn-evpn does not use the
 * grouping -- M6). The container's 'must' enforces the legacy "all three
 * together or none" rule, so all three leaves' MODIFY/DESTROY reroute to a
 * single "reread the whole distance container, call bgp_distance_admin_set()"
 * helper (the B12 idiom): a MODIFY reapplies the full ebgp/ibgp/local triple
 * from the datastore, and a DESTROY of any leaf (the whole triple always
 * goes together) resets all three to zero. bgp_distance_admin_set()
 * (bgp_route.c, the vty-free core split from the legacy DEFUN) re-announces
 * the AF's routes exactly once per real change, matching legacy.
 */
static void bgp_nb_af_distance_admin_apply(struct bgp *bgp, afi_t afi, safi_t safi,
					   const struct lyd_node *dnode)
{
	if (!bgp)
		/* instance deleted underneath in this same commit */
		return;

	if (yang_dnode_exists(dnode, "ebgp"))
		bgp_distance_admin_set(bgp, afi, safi, yang_dnode_get_uint8(dnode, "ebgp"),
				       yang_dnode_get_uint8(dnode, "ibgp"),
				       yang_dnode_get_uint8(dnode, "local"));
	else
		bgp_distance_admin_set(bgp, afi, safi, 0, 0, 0);
}

int bgp_nb_af_distance_ebgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

int bgp_nb_af_distance_ebgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

int bgp_nb_af_distance_ibgp_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

int bgp_nb_af_distance_ibgp_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

int bgp_nb_af_distance_local_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

int bgp_nb_af_distance_local_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_distance_admin_apply(bgp_nb_instance_lookup(args->dnode), afi, safi,
				       yang_dnode_get_parent(args->dnode, "distance"));

	return NB_OK;
}

/*
 * M5 batch B13: instance-AF per-prefix 'distance (1-255) PREFIX
 * [ACCESSLIST_NAME]' (af-distance-*'s distance/prefix list in
 * proteus-bgp.yang), a keyed list (key 'prefix') with a mandatory 'distance'
 * child and an optional 'access-list' name (a policy-attachment name: plain
 * string, never a leafref). Reuses the B9 keyed-list idiom: the list CREATE
 * plus each option leaf's MODIFY/DESTROY all reread the whole entry and
 * reissue one full bgp_distance_prefix_set() (bgp_route.c's vty-free core),
 * which unconditionally overwrites the distance and access-list, so a
 * re-typed 'distance ...' line always rewrites the entry from scratch. The
 * whole-entry DESTROY calls bgp_distance_prefix_unset() with match_distance
 * == 0 (delete-by-key, bypassing legacy's "distance must match" guard, as
 * B9 did for keyed-list deletes). The override table is process-global, so
 * no bgp instance lookup is needed. Per-prefix distance changes do not
 * re-announce routes -- matching legacy, whose per-prefix setters never
 * did.
 */
static const char *bgp_nb_af_distance_prefix_acl(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "access-list")
		       ? yang_dnode_get_string(entry_dnode, "access-list")
		       : NULL;
}

static int bgp_nb_af_distance_prefix_set(const struct lyd_node *entry_dnode, afi_t afi,
					 safi_t safi, uint8_t distance, const char *acl)
{
	const char *prefix_str = yang_dnode_get_string(entry_dnode, "prefix");
	char errmsg[128] = {};

	if (bgp_distance_prefix_set(afi, safi, distance, prefix_str, acl, errmsg,
				    sizeof(errmsg)) < 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_distance_prefix_set() failed for %s: %s", __func__,
			 prefix_str, errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_distance_prefix_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_distance_prefix_set(args->dnode, afi, safi,
					     yang_dnode_get_uint8(args->dnode, "distance"),
					     bgp_nb_af_distance_prefix_acl(args->dnode));
}

int bgp_nb_af_distance_prefix_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	const char *prefix_str;
	char errmsg[128] = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	prefix_str = yang_dnode_get_string(args->dnode, "prefix");

	if (bgp_distance_prefix_unset(afi, safi, 0, prefix_str, errmsg, sizeof(errmsg)) < 0) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: bgp_distance_prefix_unset() failed for %s: %s", __func__,
			 prefix_str, errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int bgp_nb_af_distance_prefix_distance_modify(struct nb_cb_modify_args *args, afi_t afi,
					      safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "prefix");

	return bgp_nb_af_distance_prefix_set(entry_dnode, afi, safi,
					     yang_dnode_get_uint8(args->dnode, NULL),
					     bgp_nb_af_distance_prefix_acl(entry_dnode));
}

int bgp_nb_af_distance_prefix_access_list_modify(struct nb_cb_modify_args *args, afi_t afi,
						 safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "prefix");

	return bgp_nb_af_distance_prefix_set(entry_dnode, afi, safi,
					     yang_dnode_get_uint8(entry_dnode, "distance"),
					     yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_distance_prefix_access_list_destroy(struct nb_cb_destroy_args *args, afi_t afi,
						  safi_t safi)
{
	const struct lyd_node *entry_dnode;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* The access-list leaf being destroyed may already be unlinked at
	 * APPLY time (B9 lesson), so pass NULL explicitly rather than
	 * rereading it from the entry. */
	entry_dnode = yang_dnode_get_parent(args->dnode, "prefix");

	return bgp_nb_af_distance_prefix_set(entry_dnode, afi, safi,
					     yang_dnode_get_uint8(entry_dnode, "distance"), NULL);
}

/*
 * M7 batch B1: instance-AF VPN leaking, simple knobs (af-vpn-leaking in
 * proteus-bgp.yang: export-vpn/import-vpn/import-vrf/import-vrf-route-map,
 * ipv4/ipv6-unicast). These reproduce bgp_imexport_vpn / bgp_imexport_vrf /
 * af_import_vrf_route_map (bgp_vty.c). The critical semantic is the
 * vpn_leak_prechange()/vpn_leak_postchange() bracketing around every
 * leak-affecting mutation -- routes are withdrawn under the OLD config and
 * re-leaked under the NEW -- fired only on real transitions, exactly as the
 * legacy setters did.
 */

/* 'import vpn' / 'export vpn': toggle a single BGP_CONFIG_*_{IMPORT,EXPORT}
 * af_flag. Bracketing mirrors bgp_imexport_vpn(): on a real off->on
 * transition, postchange (re-)exports; on a real on->off transition,
 * prechange withdraws first and, unless the default instance retains all
 * route-targets, vpn_leak_no_retain() cleans up the leaked routes. The leaf
 * is a positive-only default-false boolean, so 'no' resolves to modify-false
 * here (never a destroy callback). */
static int bgp_nb_af_imexport_vpn_apply(struct nb_cb_modify_args *args, afi_t afi, safi_t safi,
					enum vpn_policy_direction dir, int flag)
{
	struct bgp *bgp;
	struct bgp *bgp_default;
	bool yes;
	int previous_state;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_default = bgp_get_default();
	yes = yang_dnode_get_bool(args->dnode, NULL);
	previous_state = CHECK_FLAG(bgp->af_flags[afi][safi], flag);

	if (yes) {
		SET_FLAG(bgp->af_flags[afi][safi], flag);
		if (!previous_state)
			vpn_leak_postchange(dir, afi, bgp_default, bgp);
	} else {
		if (previous_state)
			vpn_leak_prechange(dir, afi, bgp_default, bgp);
		UNSET_FLAG(bgp->af_flags[afi][safi], flag);
		if (previous_state && bgp_default &&
		    !CHECK_FLAG(bgp_default->af_flags[afi][SAFI_MPLS_VPN],
				BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL))
			vpn_leak_no_retain(bgp, bgp_default, afi);
	}

	bgp_snmp_init_stats_call(bgp);

	return NB_OK;
}

int bgp_nb_af_export_vpn_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	return bgp_nb_af_imexport_vpn_apply(args, afi, safi, BGP_VPN_POLICY_DIR_TOVPN,
					    BGP_CONFIG_VRF_TO_MPLSVPN_EXPORT);
}

int bgp_nb_af_import_vpn_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	return bgp_nb_af_imexport_vpn_apply(args, afi, safi, BGP_VPN_POLICY_DIR_FROMVPN,
					    BGP_CONFIG_MPLSVPN_TO_VRF_IMPORT);
}

/* 'import vrf NAME' (leaf-list entry create/destroy): mirrors
 * bgp_imexport_vrf(). vrf_import_from_vrf()/vrf_unimport_from_vrf()
 * (bgp_mplsvpn.c) carry the vpn_leak_prechange()/postchange() bracketing
 * internally and self-guard against double add / missing entry, so the
 * callback only resolves the instances plus the auto-created default
 * instance the shared VPN table hangs off. */
static int bgp_nb_af_import_vrf_apply(const struct lyd_node *dnode, afi_t afi, safi_t safi,
				      bool add)
{
	struct bgp *bgp;
	struct bgp *vrf_bgp;
	struct bgp *bgp_default;
	const char *import_name = yang_dnode_get_string(dnode, NULL);

	bgp = bgp_nb_instance_lookup(dnode);
	if (!bgp)
		return NB_OK;

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		as_t as = AS_UNSPECIFIED;

		/* Auto-create the default instance (AS filled in later) so the
		 * shared VPN table exists; mirrors bgp_imexport_vrf(). */
		if (bgp_get_vty(&bgp_default, &as, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
				ASNOTATION_UNDEFINED))
			return NB_OK;

		SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	}

	if (strcmp(import_name, VRF_DEFAULT_NAME) == 0)
		vrf_bgp = bgp_default;
	else
		vrf_bgp = bgp_lookup_by_name_filter(import_name, false);

	if (add)
		vrf_import_from_vrf(bgp, vrf_bgp, import_name, afi, safi);
	else
		vrf_unimport_from_vrf(bgp, vrf_bgp, import_name, afi, safi);

	return NB_OK;
}

int bgp_nb_af_import_vrf_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	const struct lyd_node *instance_dnode;
	const char *import_name;
	const char *self;

	switch (args->event) {
	case NB_EV_VALIDATE:
		import_name = yang_dnode_get_string(args->dnode, NULL);
		/* 'route-map' is the reserved leading token of the sibling
		 * 'import vrf route-map NAME' command (bgp_imexport_vrf()). */
		if (strcmp(import_name, "route-map") == 0) {
			snprintf(args->errmsg, args->errmsg_len, "Must include route-map name");
			return NB_ERR_VALIDATION;
		}
		/* A VRF cannot import from itself. The instance's own identity
		 * is its 'vrf' key (default instance -> VRF_DEFAULT_NAME). */
		instance_dnode = yang_dnode_get_parent(args->dnode, "instance");
		self = yang_dnode_get_string(instance_dnode, "vrf");
		if (strcmp(import_name, self) == 0) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Cannot import vrf %s into itself", import_name);
			return NB_ERR_VALIDATION;
		}
		return NB_OK;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_af_import_vrf_apply(args->dnode, afi, safi, true);
	}

	return NB_OK;
}

int bgp_nb_af_import_vrf_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_import_vrf_apply(args->dnode, afi, safi, false);
}

/* 'import vrf route-map NAME': mirrors af_import_vrf_route_map_cmd /
 * af_no_import_vrf_route_map_cmd. The route-map name lives in the shared
 * rmap_name[FROMVPN] slot (a YANG 'must' forbids co-setting 'route-map vpn
 * import', which occupies the same slot); setting it also flags the AF for
 * vrf-to-vrf import. Bracketed by prechange/postchange like the legacy DEFPYs;
 * the re-leak is deferred until the named route-map actually exists. */
int bgp_nb_af_import_vrf_route_map_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	struct bgp *bgp_default;
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;
	const char *rmap_name;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	bgp_default = bgp_get_default();
	if (!bgp_default) {
		as_t as = AS_UNSPECIFIED;

		if (bgp_get_vty(&bgp_default, &as, NULL, BGP_INSTANCE_TYPE_DEFAULT, NULL,
				ASNOTATION_UNDEFINED))
			return NB_OK;

		SET_FLAG(bgp_default->flags, BGP_FLAG_INSTANCE_HIDDEN);
	}

	rmap_name = yang_dnode_get_string(args->dnode, NULL);

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[dir]);
	bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
	bgp->vpn_policy[afi].rmap[dir] = route_map_lookup_by_name(rmap_name);

	SET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	if (!bgp->vpn_policy[afi].rmap[dir])
		return NB_OK;

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return NB_OK;
}

int bgp_nb_af_import_vrf_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	enum vpn_policy_direction dir = BGP_VPN_POLICY_DIR_FROMVPN;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[dir]);
	bgp->vpn_policy[afi].rmap[dir] = NULL;

	if (bgp->vpn_policy[afi].import_vrf->count == 0)
		UNSET_FLAG(bgp->af_flags[afi][safi], BGP_CONFIG_VRF_TO_VRF_IMPORT);

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return NB_OK;
}

/*
 * M7 batch B2: instance-AF VPN leaking, detailed vpn-policy block
 * (af-vpn-leaking's 'vpn' container: route-map-import/-export,
 * label-export, rd-export, nexthop-export, rt-import/rt-export). These
 * reproduce af_route_map_vpn_imexport / af_label_vpn_export{,
 * _allocation_mode} / af_rd_vpn_export / af_nexthop_vpn_export /
 * af_rt_vpn_imexport (bgp_vty.c), all bracketed by vpn_leak_prechange()/
 * vpn_leak_postchange() exactly like B1. 'route-map-import' shares the
 * rmap_name[FROMVPN] slot with B1's import-vrf-route-map -- the YANG 'must'
 * (:1895) already forbids co-setting the two, so no runtime guard is needed
 * here.
 */

/* 'route-map vpn import' / 'route-map vpn export': one direction each,
 * unlike legacy's single DEFPY that handles both via a direction token. The
 * route-map itself is looked up permissively (route_map_lookup_by_name(), no
 * northbound-side warning), same convention as B1's import-vrf-route-map. */
static int bgp_nb_af_vpn_route_map_apply(const struct lyd_node *dnode, afi_t afi,
					 enum vpn_policy_direction dir, const char *rmap_name)
{
	struct bgp *bgp;

	bgp = bgp_nb_instance_lookup(dnode);
	if (!bgp)
		return NB_OK;

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	XFREE(MTYPE_ROUTE_MAP_NAME, bgp->vpn_policy[afi].rmap_name[dir]);
	if (rmap_name) {
		bgp->vpn_policy[afi].rmap_name[dir] = XSTRDUP(MTYPE_ROUTE_MAP_NAME, rmap_name);
		bgp->vpn_policy[afi].rmap[dir] = route_map_lookup_by_name(rmap_name);
	} else {
		bgp->vpn_policy[afi].rmap[dir] = NULL;
	}

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);

	return NB_OK;
}

int bgp_nb_af_vpn_route_map_import_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_vpn_route_map_apply(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN,
					     yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_vpn_route_map_import_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_vpn_route_map_apply(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, NULL);
}

int bgp_nb_af_vpn_route_map_export_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_vpn_route_map_apply(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN,
					     yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_vpn_route_map_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_af_vpn_route_map_apply(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, NULL);
}

/* 'label vpn export <(0-1048575)|auto>': the choice's two cases (each a
 * single leaf) are re-derived from the whole 'label-export' container on
 * every touching callback, same "reread the whole choice, converge
 * regardless of case-switch ordering" idiom as bgp_nb_evpn_vni_rd_set()
 * (bgp_nb_evpn.c) -- a case switch fires a destroy on the old case's leaf and
 * a create/modify on the new one in the same commit, in schema order, and
 * northbound's target tree already holds the final state at APPLY time
 * regardless of which callback runs first. Reproduces af_label_vpn_export_cmd's
 * body: manual label release/registration, auto label release, and the
 * no-change guards that avoid a pointless prechange/postchange churn. */
static void bgp_nb_af_vpn_label_export_set(const struct lyd_node *label_export_dnode, afi_t afi)
{
	struct bgp *bgp;
	bool label_auto;
	mpls_label_t label = MPLS_LABEL_NONE;

	bgp = bgp_nb_instance_lookup(label_export_dnode);
	if (!bgp)
		return;

	if (yang_dnode_exists(label_export_dnode, "value")) {
		label_auto = false;
		label = (mpls_label_t)yang_dnode_get_uint32(label_export_dnode, "value");
	} else if (yang_dnode_exists(label_export_dnode, "auto") &&
		   yang_dnode_get_bool(label_export_dnode, "auto")) {
		label_auto = true;
	} else {
		label_auto = false;
	}

	if (label_auto && CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		/* no change */
		return;
	if (!label_auto && label == bgp->vpn_policy[afi].tovpn_label &&
	    !CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		/* no change */
		return;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG)) {
		bgp_zebra_release_label_range(bgp->vpn_policy[afi].tovpn_label,
					      bgp->vpn_policy[afi].tovpn_label);
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
	} else if (CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO))
		bgp_vpn_release_label(bgp, afi, false);

	if (label_auto) {
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
		bgp->vpn_policy[afi].tovpn_label = MPLS_LABEL_NONE;
	} else {
		bgp->vpn_policy[afi].tovpn_label = label;
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_AUTO);
		if (bgp->vpn_policy[afi].tovpn_label >= MPLS_LABEL_UNRESERVED_MIN &&
		    bgp_zebra_request_label_range(bgp->vpn_policy[afi].tovpn_label, 1, false))
			SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_MANUAL_REG);
	}

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp_snmp_update_last_changed_call(bgp);
}

int bgp_nb_af_vpn_label_export_value_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_label_export_set(yang_dnode_get_parent(args->dnode, "label-export"),
					       afi);

	return NB_OK;
}

int bgp_nb_af_vpn_label_export_value_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					     safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_label_export_set(yang_dnode_get_parent(args->dnode, "label-export"),
					       afi);

	return NB_OK;
}

int bgp_nb_af_vpn_label_export_auto_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_label_export_set(yang_dnode_get_parent(args->dnode, "label-export"),
					       afi);

	return NB_OK;
}

int bgp_nb_af_vpn_label_export_auto_destroy(struct nb_cb_destroy_args *args, afi_t afi,
					    safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_label_export_set(yang_dnode_get_parent(args->dnode, "label-export"),
					       afi);

	return NB_OK;
}

/* 'label vpn export allocation-mode <per-vrf|per-nexthop>': a no-default
 * enumeration (Tier B/profile tri-state per the modeling guidance) --
 * DESTROY resolves to the per-vrf default, matching af_label_vpn_export_allocation_mode_cmd's
 * 'no' form. */
int bgp_nb_af_vpn_label_export_allocation_mode_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi)
{
	struct bgp *bgp;
	bool per_nexthop;
	bool old_per_nexthop;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	per_nexthop = strmatch(yang_dnode_get_string(args->dnode, NULL), "per-nexthop");
	old_per_nexthop = !!CHECK_FLAG(bgp->vpn_policy[afi].flags,
				       BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	if (old_per_nexthop == per_nexthop)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	if (per_nexthop)
		SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	else
		UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp_snmp_update_last_changed_call(bgp);

	return NB_OK;
}

int bgp_nb_af_vpn_label_export_allocation_mode_destroy(struct nb_cb_destroy_args *args, afi_t afi,
							safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (!CHECK_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_LABEL_PER_NEXTHOP);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp_snmp_update_last_changed_call(bgp);

	return NB_OK;
}

/* 'rd vpn export <ASN:NN|A.B.C.D:NN>': the presence container's own
 * create/destroy bracket the RD as a whole (create is a no-op -- the
 * mandatory-leaved case container's own create, fired after the container's
 * per the same tree-order reasoning as bgp_nb_evpn_vni_rd_set(), does the
 * real work); destroy clears back to unconfigured. The 'mac' case is
 * permanently unreachable (YANG 'must "false()"' blocks it at the
 * datastore-edit layer before any northbound callback runs) and 'raw' has no
 * legacy parser (str2prefix_rd() only produces as2/as4/ipv4) -- both stay
 * reject-stubbed in bgp_nb_afi_safi_ipv4.c/ipv6.c, per the "mis-shaped ->
 * reject-stub" rule. */
static void bgp_nb_af_vpn_rd_export_set(const struct lyd_node *rd_export_dnode, afi_t afi)
{
	struct bgp *bgp;
	struct prefix_rd prd;
	char rd_pretty[64];

	bgp = bgp_nb_instance_lookup(rd_export_dnode);
	if (!bgp)
		return;

	memset(&prd, 0, sizeof(prd));
	prd.family = AF_UNSPEC;
	prd.prefixlen = 64;

	if (yang_dnode_exists(rd_export_dnode, "as2")) {
		uint16_t administrator = yang_dnode_get_uint16(rd_export_dnode, "as2/administrator");
		uint32_t assigned = yang_dnode_get_uint32(rd_export_dnode, "as2/assigned-number");

		prd.val[1] = RD_TYPE_AS;
		prd.val[2] = (administrator >> 8) & 0xff;
		prd.val[3] = administrator & 0xff;
		prd.val[4] = (assigned >> 24) & 0xff;
		prd.val[5] = (assigned >> 16) & 0xff;
		prd.val[6] = (assigned >> 8) & 0xff;
		prd.val[7] = assigned & 0xff;
		snprintf(rd_pretty, sizeof(rd_pretty), "%u:%u", administrator, assigned);
	} else if (yang_dnode_exists(rd_export_dnode, "as4")) {
		uint32_t administrator = yang_dnode_get_uint32(rd_export_dnode, "as4/administrator");
		uint16_t assigned = yang_dnode_get_uint16(rd_export_dnode, "as4/assigned-number");

		prd.val[1] = RD_TYPE_AS4;
		prd.val[2] = (administrator >> 24) & 0xff;
		prd.val[3] = (administrator >> 16) & 0xff;
		prd.val[4] = (administrator >> 8) & 0xff;
		prd.val[5] = administrator & 0xff;
		prd.val[6] = (assigned >> 8) & 0xff;
		prd.val[7] = assigned & 0xff;
		snprintf(rd_pretty, sizeof(rd_pretty), "%u:%u", administrator, assigned);
	} else if (yang_dnode_exists(rd_export_dnode, "ipv4")) {
		struct in_addr ip;
		uint16_t assigned = yang_dnode_get_uint16(rd_export_dnode, "ipv4/assigned-number");
		char ip_str[INET_ADDRSTRLEN];

		yang_dnode_get_ipv4(&ip, rd_export_dnode, "ipv4/administrator");

		prd.val[1] = RD_TYPE_IP;
		memcpy(&prd.val[2], &ip, 4);
		prd.val[6] = (assigned >> 8) & 0xff;
		prd.val[7] = assigned & 0xff;

		inet_ntop(AF_INET, &ip, ip_str, sizeof(ip_str));
		snprintf(rd_pretty, sizeof(rd_pretty), "%s:%u", ip_str, assigned);
	} else {
		/* Case not yet materialized (fired from the presence
		 * container's own create, or a case switch in progress) --
		 * the case's own create/modify (same commit) re-drives this. */
		return;
	}

	if (bgp->vpn_policy[afi].tovpn_rd_pretty &&
	    strmatch(rd_pretty, bgp->vpn_policy[afi].tovpn_rd_pretty))
		/* no change */
		return;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp_route_distinguisher_update_call(bgp, afi, true);

	XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd_pretty = XSTRDUP(MTYPE_BGP_NAME, rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd = prd;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);

	bgp_route_distinguisher_update_call(bgp, afi, false);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
}

int bgp_nb_af_vpn_rd_export_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	/* No-op: the mandatory-choice case's own create does the real work
	 * once the case's leaves exist in the target tree (see the doc
	 * comment above). */
	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp || !bgp->vpn_policy[afi].tovpn_rd_pretty)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp_route_distinguisher_update_call(bgp, afi, true);
	XFREE(MTYPE_BGP_NAME, bgp->vpn_policy[afi].tovpn_rd_pretty);
	bgp->vpn_policy[afi].tovpn_rd_pretty = NULL;
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_SET);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_RD_CLI_SET);
	bgp_route_distinguisher_update_call(bgp, afi, false);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	/* No-op: fires only on a case switch, see bgp_nb_af_vpn_rd_export_set()'s
	 * doc comment -- the new case's own create re-drives the setter. */
	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as2_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						      safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as2_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as4_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						      safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_as4_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_ipv4_administrator_modify(struct nb_cb_modify_args *args, afi_t afi,
						       safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

int bgp_nb_af_vpn_rd_export_ipv4_assigned_number_modify(struct nb_cb_modify_args *args, afi_t afi,
							 safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rd_export_set(
			yang_dnode_get_parent(args->dnode, "rd-export"), afi);

	return NB_OK;
}

/* 'nexthop vpn export <A.B.C.D|X:X::X:X>': the union leaf's string form is
 * exactly the legacy DEFPY's $nexthop_su token -- reuse str2sockunion()/
 * sockunion2hostprefix() verbatim, same idiom instance_neighbor_update_source_modify()
 * (bgp_nb_neighbor.c) uses for its own address-union leaf. */
int bgp_nb_af_vpn_nexthop_export_modify(struct nb_cb_modify_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;
	union sockunion su;
	struct prefix p;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	if (str2sockunion(yang_dnode_get_string(args->dnode, NULL), &su) != 0)
		return NB_OK;
	if (!sockunion2hostprefix(&su, &p))
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	bgp->vpn_policy[afi].tovpn_nexthop = p;
	SET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);

	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	return NB_OK;
}

int bgp_nb_af_vpn_nexthop_export_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	vpn_leak_prechange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);
	UNSET_FLAG(bgp->vpn_policy[afi].flags, BGP_VPN_POLICY_TOVPN_NEXTHOP_SET);
	vpn_leak_postchange(BGP_VPN_POLICY_DIR_TOVPN, afi, bgp_get_default(), bgp);

	return NB_OK;
}

/* 'rt vpn <import|export|both> RTLIST': unlike af_rt_vpn_imexport_cmd, which
 * replaces the whole ecommunity set in one call, the YANG models each RT as
 * its own keyed list entry -- bgp->vpn_policy[afi].rtlist[dir] is a single
 * opaque ecommunity blob (no per-entry identity), so each entry's
 * create/destroy is applied incrementally with ecommunity_add_val()/
 * ecommunity_del_val() directly on that blob (lazily allocated on the first
 * add, freed back to NULL when the last entry is removed), bracketed by
 * vpn_leak_prechange()/postchange() exactly like the legacy whole-set
 * replace. A create/destroy of a list entry is always a real content change
 * (northbound only calls these for genuine adds/removes at that xpath), so
 * there is no "no-op on unchanged value" guard here, unlike the scalar
 * leaves above. */
static void bgp_nb_af_vpn_rt_apply(const struct lyd_node *dnode, afi_t afi,
				   enum vpn_policy_direction dir, struct ecommunity_val *eval,
				   bool del)
{
	struct bgp *bgp;
	struct ecommunity *ecom;

	bgp = bgp_nb_instance_lookup(dnode);
	if (!bgp)
		return;

	vpn_leak_prechange(dir, afi, bgp_get_default(), bgp);

	ecom = bgp->vpn_policy[afi].rtlist[dir];
	if (del) {
		if (ecom) {
			ecommunity_del_val(ecom, eval);
			if (ecom->size == 0) {
				ecommunity_free(&ecom);
				bgp->vpn_policy[afi].rtlist[dir] = NULL;
			}
		}
	} else {
		if (!ecom) {
			ecom = ecommunity_new();
			bgp->vpn_policy[afi].rtlist[dir] = ecom;
		}
		ecommunity_add_val(ecom, eval, true, false);
	}

	vpn_leak_postchange(dir, afi, bgp_get_default(), bgp);
}

static void bgp_nb_af_vpn_rt_as2(const struct lyd_node *dnode, afi_t afi,
				 enum vpn_policy_direction dir, bool del)
{
	struct ecommunity_val eval;

	encode_route_target_as(yang_dnode_get_uint16(dnode, "global-admin"),
			       yang_dnode_get_uint32(dnode, "local-admin"), &eval, true);
	bgp_nb_af_vpn_rt_apply(dnode, afi, dir, &eval, del);
}

static void bgp_nb_af_vpn_rt_as4(const struct lyd_node *dnode, afi_t afi,
				 enum vpn_policy_direction dir, bool del)
{
	struct ecommunity_val eval;

	encode_route_target_as4(yang_dnode_get_uint32(dnode, "global-admin"),
				yang_dnode_get_uint16(dnode, "local-admin"), &eval, true);
	bgp_nb_af_vpn_rt_apply(dnode, afi, dir, &eval, del);
}

static void bgp_nb_af_vpn_rt_ipv4(const struct lyd_node *dnode, afi_t afi,
				  enum vpn_policy_direction dir, bool del)
{
	struct ecommunity_val eval;
	struct in_addr ip;

	yang_dnode_get_ipv4(&ip, dnode, "global-admin");
	encode_route_target_ip(&ip, yang_dnode_get_uint16(dnode, "local-admin"), &eval, true);
	bgp_nb_af_vpn_rt_apply(dnode, afi, dir, &eval, del);
}

int bgp_nb_af_vpn_rt_import_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as2(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_import_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as2(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, true);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_import_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as4(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_import_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as4(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, true);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_import_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_ipv4(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_import_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_ipv4(args->dnode, afi, BGP_VPN_POLICY_DIR_FROMVPN, true);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_as2_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as2(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as2(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, true);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_as4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as4(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_as4(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, true);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_ipv4_create(struct nb_cb_create_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_ipv4(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, false);

	return NB_OK;
}

int bgp_nb_af_vpn_rt_export_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi, safi_t safi)
{
	if (args->event == NB_EV_APPLY)
		bgp_nb_af_vpn_rt_ipv4(args->dnode, afi, BGP_VPN_POLICY_DIR_TOVPN, true);

	return NB_OK;
}

/* M7 batch B3: MPLS-VPN static 'network' statements (af-network-vpn-ipv4/
 * -ipv6 in proteus-bgp.yang), ipv4-vpn/ipv6-vpn only -- the RD-encoding
 * split (as2/ipv4/as4/raw) B2's 'rd vpn export' already established for
 * this module. Legacy is vpnv4_network[_route_map]/no_vpnv4_network and
 * vpnv6_network/no_vpnv6_network (bgp_mplsvpn.c), all thin wrappers around
 * the shared bgp_static_set() core (bgp_route.c) that M5 B9 already
 * refactored to take a resolved 'struct bgp *' plus an errmsg buffer
 * instead of a vty. 'label' is YANG-mandatory but not part of the list key
 * (prefix + rd components are); like B9's route-map/label-index/backdoor,
 * every callback rereads the sibling label/route-map values off the list
 * entry and reissues a full bgp_static_set() call -- by NB_EV_APPLY the
 * candidate tree already has every sibling change from the same CLI
 * transaction merged in, so this is safe even from the entry's own CREATE
 * callback. 'raw' has no legacy parser for an arbitrary RD string (same
 * reasoning as B2's rd-export/raw) and stays reject-stubbed permanently.
 */
static const char *bgp_nb_af_vpn_network_rmap(const struct lyd_node *entry_dnode)
{
	return yang_dnode_exists(entry_dnode, "route-map") ?
		       yang_dnode_get_string(entry_dnode, "route-map") : NULL;
}

/* Builds the ASN:NN_OR_IP-ADDRESS:NN pretty rd string bgp_static_set()
 * parses via str2prefix_rd(); buffer is function-scope in every caller
 * (nb_cli_enqueue_change/bgp_static_set do not retain the pointer past the
 * call), matching the value-pointer lifetime rule. */
static void bgp_nb_af_vpn_network_rd_as2(const struct lyd_node *entry_dnode, char *buf,
					 size_t buflen)
{
	snprintf(buf, buflen, "%u:%u", yang_dnode_get_uint16(entry_dnode, "administrator"),
		 yang_dnode_get_uint32(entry_dnode, "assigned-number"));
}

static void bgp_nb_af_vpn_network_rd_as4(const struct lyd_node *entry_dnode, char *buf,
					 size_t buflen)
{
	snprintf(buf, buflen, "%u:%u", yang_dnode_get_uint32(entry_dnode, "administrator"),
		 yang_dnode_get_uint16(entry_dnode, "assigned-number"));
}

static void bgp_nb_af_vpn_network_rd_ipv4(const struct lyd_node *entry_dnode, char *buf,
					  size_t buflen)
{
	snprintf(buf, buflen, "%s:%u", yang_dnode_get_string(entry_dnode, "administrator"),
		 yang_dnode_get_uint16(entry_dnode, "assigned-number"));
}

/* Common set/unset core: 'negate' true reproduces the 'no network ... rd
 * ...' path (only prefix + rd matter, bgp_static_set() ignores label/rmap
 * there); false (re)installs the static route with 'rmap' (the caller's
 * responsibility to pass NULL rather than reread route-map off the entry
 * when the route-map child dnode is itself the one being destroyed and may
 * already be unlinked by APPLY time, same discipline as B9's
 * bgp_nb_af_network_route_map_destroy()). */
static int bgp_nb_af_vpn_network_apply(const struct lyd_node *entry_dnode, afi_t afi,
					const char *rd_str, bool negate, const char *rmap)
{
	struct bgp *bgp;
	const char *prefix_str;
	char label_str[16];
	char errmsg[256];
	int ret;

	bgp = bgp_nb_instance_lookup(entry_dnode);
	if (!bgp)
		return NB_OK;

	prefix_str = yang_dnode_get_string(entry_dnode, "prefix");

	if (!negate)
		snprintf(label_str, sizeof(label_str), "%u",
			 yang_dnode_get_uint32(entry_dnode, "label"));

	ret = bgp_static_set(bgp, negate, prefix_str, rd_str, negate ? NULL : label_str, afi,
			     SAFI_MPLS_VPN, negate ? NULL : rmap, 0, BGP_INVALID_LABEL_INDEX, 0,
			     NULL, NULL, NULL, NULL, errmsg, sizeof(errmsg));
	if (ret) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: bgp_static_set() failed for %s: %s",
			 __func__, prefix_str, errmsg);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

static int bgp_nb_af_vpn_network_create_validate(struct nb_cb_create_args *args, afi_t afi)
{
	struct prefix p;
	const char *prefix_str;

	if (args->event != NB_EV_VALIDATE)
		return NB_OK;

	/* Prefix syntax is already YANG-typed; only bgp_static_set()'s
	 * semantic link-local rejection needs an explicit check here,
	 * mirroring bgp_nb_af_network_create() (B9). */
	if (afi == AFI_IP6) {
		prefix_str = yang_dnode_get_string(args->dnode, "prefix");
		if (str2prefix(prefix_str, &p) && IN6_IS_ADDR_LINKLOCAL(&p.u.prefix6)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Malformed prefix (link-local address)");
			return NB_ERR_VALIDATION;
		}
	}

	return NB_OK;
}

int bgp_nb_af_vpn_network_as2_create(struct nb_cb_create_args *args, afi_t afi)
{
	char rd[32];
	int ret;

	ret = bgp_nb_af_vpn_network_create_validate(args, afi);
	if (ret != NB_OK)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_as2(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(args->dnode));
}

int bgp_nb_af_vpn_network_as2_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_as2(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, true, NULL);
}

int bgp_nb_af_vpn_network_as2_label_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as2");
	bgp_nb_af_vpn_network_rd_as2(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(entry_dnode));
}

int bgp_nb_af_vpn_network_as2_route_map_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as2");
	bgp_nb_af_vpn_network_rd_as2(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_vpn_network_as2_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as2");
	bgp_nb_af_vpn_network_rd_as2(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false, NULL);
}

int bgp_nb_af_vpn_network_as4_create(struct nb_cb_create_args *args, afi_t afi)
{
	char rd[32];
	int ret;

	ret = bgp_nb_af_vpn_network_create_validate(args, afi);
	if (ret != NB_OK)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_as4(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(args->dnode));
}

int bgp_nb_af_vpn_network_as4_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_as4(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, true, NULL);
}

int bgp_nb_af_vpn_network_as4_label_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as4");
	bgp_nb_af_vpn_network_rd_as4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(entry_dnode));
}

int bgp_nb_af_vpn_network_as4_route_map_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as4");
	bgp_nb_af_vpn_network_rd_as4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_vpn_network_as4_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "as4");
	bgp_nb_af_vpn_network_rd_as4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false, NULL);
}

int bgp_nb_af_vpn_network_ipv4_create(struct nb_cb_create_args *args, afi_t afi)
{
	char rd[32];
	int ret;

	ret = bgp_nb_af_vpn_network_create_validate(args, afi);
	if (ret != NB_OK)
		return ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_ipv4(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(args->dnode));
}

int bgp_nb_af_vpn_network_ipv4_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_nb_af_vpn_network_rd_ipv4(args->dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(args->dnode, afi, rd, true, NULL);
}

int bgp_nb_af_vpn_network_ipv4_label_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "ipv4");
	bgp_nb_af_vpn_network_rd_ipv4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   bgp_nb_af_vpn_network_rmap(entry_dnode));
}

int bgp_nb_af_vpn_network_ipv4_route_map_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "ipv4");
	bgp_nb_af_vpn_network_rd_ipv4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false,
					   yang_dnode_get_string(args->dnode, NULL));
}

int bgp_nb_af_vpn_network_ipv4_route_map_destroy(struct nb_cb_destroy_args *args, afi_t afi)
{
	const struct lyd_node *entry_dnode;
	char rd[32];

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	entry_dnode = yang_dnode_get_parent(args->dnode, "ipv4");
	bgp_nb_af_vpn_network_rd_ipv4(entry_dnode, rd, sizeof(rd));
	return bgp_nb_af_vpn_network_apply(entry_dnode, afi, rd, false, NULL);
}

/* 'bgp retain route-target all' (retain-route-target-all in
 * proteus-bgp.yang, ipv4/ipv6-vpn): default-on boolean, so the positive
 * form resolves to the leaf's true default and only an explicit false ever
 * differs. Reproduces the retired bgp_retain_route_target DEFPY
 * (bgp_vty.c): on a real transition flip BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL
 * on the VPN AF and trigger a soft clear-in so the ADJ-RIB-in is
 * re-processed under the new retain policy -- disabling re-filters the VPN
 * table against the local VRF imports, enabling re-fetches everything.
 * Transition-only, exactly like the legacy setter. */
int bgp_nb_af_retain_route_target_all_modify(struct nb_cb_modify_args *args, afi_t afi)
{
	struct bgp *bgp;
	bool retain;
	bool check;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	if (!bgp)
		return NB_OK;

	retain = yang_dnode_get_bool(args->dnode, NULL);
	check = CHECK_FLAG(bgp->af_flags[afi][SAFI_MPLS_VPN], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	if (check == retain)
		return NB_OK;

	if (retain)
		SET_FLAG(bgp->af_flags[afi][SAFI_MPLS_VPN], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);
	else
		UNSET_FLAG(bgp->af_flags[afi][SAFI_MPLS_VPN], BGP_VPNVX_RETAIN_ROUTE_TARGET_ALL);

	/* trigger a flush to re-sync with ADJ-RIB-in */
	bgp_clear_soft_in(bgp, afi, SAFI_MPLS_VPN);

	return NB_OK;
}
