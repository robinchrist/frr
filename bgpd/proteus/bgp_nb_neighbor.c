// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for /proteus-bgp:instance/neighbor scalars (excluding per-afi-safi settings).
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
#include "lib/prefix.h"

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
#include "bgpd/bgp_bfd.h"
#include "bgpd/proteus/bgp_nb_local.h"

#include "lib/bfd.h"


int instance_neighbor_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	const char *address;
	bool is_if;

	switch (args->event) {
	case NB_EV_VALIDATE:
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;

		address = yang_dnode_get_string(args->dnode, "address");
		is_if = yang_dnode_exists(args->dnode, "interface-peer") &&
			yang_dnode_get_bool(args->dnode, "interface-peer");

		if (!is_if)
			/* Addressed neighbors have no legacy "create a bare
			 * neighbor" primitive: peer_remote_as() (via the
			 * remote-as leaf callback) or peer_group_bind() (via
			 * the peer-group leaf callback) -- whichever sibling
			 * leaf is present in this same commit, matching the
			 * neighbor list's YANG 'must' -- does the real
			 * peer_create(). Mirrors legacy, which likewise has
			 * no standalone "create bare addressed neighbor"
			 * command. */
			break;

		peer = peer_lookup_by_conf_if(bgp, address);
		if (peer)
			break; /* idempotent: replay or already applied */

		peer = peer_create(NULL, address, bgp, bgp->as, 0, AS_UNSPECIFIED, NULL, true,
				   NULL, CONNECTION_OUTGOING);
		if (!peer)
			return NB_ERR_RESOURCE;

		/* Unnumbered peers unconditionally get capability
		 * extended-nexthop forced on, locked via flags_invert +
		 * flags_override (peer_conf_interface_get(), bgp_vty.c,
		 * now converted here). */
		SET_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_invert, PEER_FLAG_CAPABILITY_ENHE);
		SET_FLAG(peer->flags_override, PEER_FLAG_CAPABILITY_ENHE);

		if (peer->ifp)
			bgp_zebra_initiate_radv(bgp, peer);

		bgp_need_listening(bgp, NULL);
		break;
	}

	return NB_OK;
}

int instance_neighbor_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct peer *other;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (peer_dynamic_neighbor(peer))
		/* dynamic peers never have a northbound neighbor list entry
		 * (PEER_FLAG_CONFIG_NODE is never set for them); defensive
		 * only. */
		return NB_OK;

	other = peer->doppelganger;

	if (peer->conf_if) {
		if (peer->ifp)
			bgp_zebra_terminate_radv(peer->bgp, peer);
	} else if (CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_ENHE)) {
		bgp_zebra_terminate_radv(peer->bgp, peer);
	}

	peer_notify_unconfig(peer->connection);
	peer_delete(peer);
	if (other && other->connection->status != Deleted) {
		peer_notify_unconfig(other->connection);
		peer_delete(other);
	}

	if (bgp)
		bgp_may_stop_listening(bgp, NULL);

	return NB_OK;
}

int instance_neighbor_interface_peer_modify(struct nb_cb_modify_args *args)
{
	/* consumed directly by instance_neighbor_create(): interface-peer is
	 * immutable after creation, there is no legacy operation that
	 * converts an existing addressed neighbor to/from unnumbered. */
	return NB_OK;
}

int instance_neighbor_v6only_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool v6only;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	v6only = yang_dnode_get_bool(args->dnode, NULL);

	if (v6only == !!CHECK_FLAG(peer->flags, PEER_FLAG_IFPEER_V6ONLY))
		return NB_OK;

	if (v6only)
		peer_flag_set(peer, PEER_FLAG_IFPEER_V6ONLY);
	else
		peer_flag_unset(peer, PEER_FLAG_IFPEER_V6ONLY);

	peer_set_last_reset(peer, PEER_DOWN_V6ONLY_CHANGE);
	if (!peer_notify_config_change(peer->connection))
		bgp_session_reset(peer);

	return NB_OK;
}

/* 'neighbor X peer-group PGNAME': bind. Coordinator-approved design (no
 * legacy unbind primitive exists, see peer_group_delete()/no_neighbor_*
 * in bgpd.c/bgp_vty.c):
 *  - MODIFY to a group different from the one currently bound rejects at
 *    VALIDATE, mirroring BGP_ERR_PEER_GROUP_CANT_CHANGE.
 *  - MODIFY to the same group is a no-op (peer_group_bind() itself
 *    returns 0 early for this case).
 *  - MODIFY when unbound (including the neighbor's first-ever commit,
 *    when instance_neighbor_create() deliberately did not create an
 *    addressed peer) binds, creating the peer if necessary. A first-time
 *    bind that would mix ebgp-multihop and ttl-security across the peer
 *    and its target group (M4 batch B6: both are northbound-modeled now,
 *    reachable independently before any bind) is rejected here too,
 *    mirroring peer_group_bind()'s (bgpd.c) own guard -- NB_EV_APPLY
 *    cannot fail a commit once the datastore write has already gone
 *    through (it can only flog_err/NB_ERR_RESOURCE after the fact), so the
 *    APPLY-side peer_group_bind() call below returning that same error
 *    code is a defensive backstop, not the real gate.
 *  - DESTROY of this leaf alone (not the whole neighbor entry) always
 *    rejects at VALIDATE: bgpd has no unbind. This cannot block 'no
 *    neighbor X peer-group PGNAME' (which destroys the whole neighbor
 *    entry, see bgp_cli.c) because nb_config_diff_deleted()
 *    (lib/northbound.c) does not recurse into child destroy callbacks
 *    unless F_NB_CB_DESTROY_RECURSE is set, which this node does not
 *    set.
 */
int instance_neighbor_peer_group_modify(struct nb_cb_modify_args *args)
{
	struct bgp *bgp;
	struct peer *peer;
	struct peer_group *group;
	const char *name;
	as_t as = 0;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		name = yang_dnode_get_string(args->dnode, NULL);

		if (peer_group_active(peer)) {
			if (strcmp(peer->group->name, name) != 0) {
				snprintf(args->errmsg, args->errmsg_len,
					 "Cannot change peer-group from %s to %s; deconfigure first",
					 peer->group->name, name);
				return NB_ERR_VALIDATION;
			}
			break;
		}

		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;

		group = peer_group_lookup(bgp, name);
		if (!group)
			break; /* leafref integrity already enforced */

		if ((CHECK_FLAG(peer->flags, PEER_FLAG_EBGP_MULTIHOP) &&
		     group->conf->gtsm_hops != BGP_GTSM_HOPS_DISABLED) ||
		    (peer->gtsm_hops != BGP_GTSM_HOPS_DISABLED && group->conf->cfg_ttl != 0)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ebgp-multihop and ttl-security cannot be configured together");
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
		group = peer_group_lookup(bgp, name);
		if (!group)
			break; /* leafref integrity already enforced */

		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer) {
			ret = peer_group_bind(bgp, NULL, peer, group, &as);
		} else {
			const struct lyd_node *nbr_dnode =
				yang_dnode_get_parent(args->dnode, "neighbor");
			union sockunion su;
			const char *address = yang_dnode_get_string(nbr_dnode, "address");

			if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
			    yang_dnode_get_bool(nbr_dnode, "interface-peer"))
				/* conf_if peers are always created by
				 * instance_neighbor_create(); unreachable. */
				break;

			if (str2sockunion(address, &su) < 0)
				break;

			ret = peer_group_bind(bgp, &su, NULL, group, &as);
		}

		if (ret) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_group_bind() failed for %s: %d", __func__, name, ret);
			return NB_ERR_RESOURCE;
		}

		/* Binding may just have created the instance's first peer;
		 * make sure the (per-VRF) listener exists - the retired
		 * native bind DEFUN did this via peer_remote_as_vty(). */
		bgp_need_listening(bgp, NULL);
		break;
	}

	return NB_OK;
}

int instance_neighbor_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		snprintf(args->errmsg, args->errmsg_len,
			 "removing peer-group membership requires deleting the neighbor; bgpd has no unbind");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int instance_neighbor_remote_as_plain_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_remote_as_plain_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_neighbor_remote_as_destroy_validate(args->dnode, args->errmsg,
								  args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_remote_as_destroy_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_remote_as_asdot_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_remote_as_asdot_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_neighbor_remote_as_destroy_validate(args->dnode, args->errmsg,
								  args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_remote_as_destroy_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_remote_as_asdot_high_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_remote_as_asdot_low_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_neighbor_remote_as_destroy_validate(args->dnode, args->errmsg,
								  args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_remote_as_destroy_apply(args->dnode);
	}

	return NB_OK;
}

/*
 * local-as (+ no-prepend, + replace-as, + dual-as) (M4 batch B9): the
 * plain/asdot ASN sub-choice shares bgp_nb_neighbor_local_as_apply()'s
 * "reread the whole container" APPLY and bgp_nb_local_as_validate()'s
 * same-as-BGP-AS VALIDATE guard (bgp_nb_util.c) across all four leaves
 * that can change the ASN; no-prepend/replace-as/dual-as are Tier A
 * (YANG default "false", modify-only, chosen because unlike the ASN they
 * have a genuine static default and no inheritance) but still route
 * through the same shared APPLY, since legacy's peer_local_as_set()
 * (bgpd.c) takes the ASN and all three modifiers together as one call --
 * there is no narrower legacy setter for a modifier alone.
 */
int instance_neighbor_local_as_plain_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_local_as_plain_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_local_as_destroy_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_local_as_asdot_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_local_as_destroy_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_local_as_asdot_high_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_low_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_neighbor_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_neighbor_local_as_no_prepend_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_local_as_replace_as_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_local_as_dual_as_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_description_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_description_set(peer, yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_description_unset(peer);

	return NB_OK;
}

/*
 * bfd container (M4 batch B10): the six bfd_config-data leaves (enabled,
 * detect-multiplier, min-rx, min-tx, check-control-plane-failure, profile)
 * all route their modify/destroy through the shared
 * bgp_nb_neighbor_bfd_apply() (bgp_nb_util.c), which rereads the whole
 * container and reconfigures the BFD session -- see that helper's comment
 * for the full rationale. strict/strict-hold-time (below) are handled
 * separately because they drive PEER_FLAG_BFD_STRICT / bfd_config->hold_time
 * rather than the session's timer/profile data path.
 */
int instance_neighbor_bfd_enabled_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_detect_multiplier_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_min_rx_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_min_tx_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_check_control_plane_failure_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

int instance_neighbor_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_neighbor_bfd_apply(args->dnode);

	return NB_OK;
}

/* 'neighbor X bfd strict' (bgpd/bgp_bfd.c neighbor_bfd_strict, retired):
 * a bare PEER_FLAG_BFD_STRICT set/unset, no bfd_config touch -- matching
 * legacy exactly (the flag lives on peer->flags, independent of the BFD
 * session's data). The strict-hold-time callback owns bfd_config->hold_time
 * only; it deliberately does not also toggle the flag, so the flag has a
 * single owner and no strict-vs-strict-hold-time apply-order dependency
 * within a commit.
 */
int instance_neighbor_bfd_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_BFD_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_BFD_STRICT);

	return NB_OK;
}

/* 'neighbor X bfd strict hold-time N' (bgpd/bgp_bfd.c
 * neighbor_bfd_strict_hold_time, retired): configures bfd (so bfd_config
 * exists regardless of the enabled leaf's own apply order), cancels any
 * pending hold timer, and stores hold_time. The strict flag itself is set
 * by the co-enqueued strict leaf (see the strict callback's comment).
 */
int instance_neighbor_bfd_strict_hold_time_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp_peer_configure_bfd(peer, true);
	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = yang_dnode_get_uint32(args->dnode, NULL);
	bgp_peer_config_apply(peer, peer->group);

	return NB_OK;
}

int instance_neighbor_bfd_strict_hold_time_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer || !peer->bfd_config)
		return NB_OK;

	event_cancel(&peer->bfd_config->t_hold_timer);
	peer->bfd_config->hold_time = BFD_DEF_STRICT_HOLD_TIME;
	bgp_peer_config_apply(peer, peer->group);

	return NB_OK;
}

/* peer_password_set()'s own PEER_PASSWORD_MINLEN/MAXLEN bounds check
 * (bgpd.c) fires too late to produce a useful VALIDATE-time error (APPLY
 * cannot reject a commit already past validation without leaving the
 * candidate/running datastores out of sync) -- reject here instead,
 * mirroring the message bgp_vty_return() gave for the legacy DEFUN's
 * BGP_ERR_INVALID_VALUE.
 */
int instance_neighbor_password_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const char *password;
	size_t len;

	switch (args->event) {
	case NB_EV_VALIDATE:
		password = yang_dnode_get_string(args->dnode, NULL);
		len = strlen(password);
		if (len < PEER_PASSWORD_MINLEN || len > PEER_PASSWORD_MAXLEN) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid value: password must be %d-%d characters",
				 PEER_PASSWORD_MINLEN, PEER_PASSWORD_MAXLEN);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (peer_password_set(peer, yang_dnode_get_string(args->dnode, NULL)) !=
		    BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_password_set() failed",
				 __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_neighbor_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_password_unset(peer);

	return NB_OK;
}

/* 'neighbor X solo': update_group_adjust_soloness() (bgp_updgrp.c) is the
 * real legacy entry point, not a bare peer_flag_set()/unset() -- for a
 * non-group peer it goes through peer_lonesoul_or_not() (update-group
 * bookkeeping, not the flag-action-table reset path), and for a
 * peer-group it explicitly walks and updates every current member,
 * exactly the fanout this leaf's northbound callback must reproduce
 * without reimplementing it.
 */
int instance_neighbor_solo_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	update_group_adjust_soloness(peer, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_port_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_port_set(peer, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_port_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_port_unset(peer);

	return NB_OK;
}

/* 'neighbor X interface IFNAME' (peer->ifname, the source-interface leaf --
 * distinct from update-source and from unnumbered/interface-peer
 * neighbors, see the YANG leaf's own description). Legacy's
 * peer_interface_vty() (bgp_vty.c, retired) rejects unnumbered peers
 * (peer->conf_if set) and never resolves peer-group names at all
 * (peer_lookup_vty(), not peer_and_group_lookup_vty()) -- reproduced here
 * at VALIDATE; the peer-group-scope callback below rejects unconditionally
 * for the latter reason.
 */
int instance_neighbor_source_interface_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *nbr_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		nbr_dnode = yang_dnode_get_parent(args->dnode, "neighbor");
		if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
		    yang_dnode_get_bool(nbr_dnode, "interface-peer")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "source-interface is not supported for unnumbered (interface) neighbors");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		peer_interface_set(peer, yang_dnode_get_string(args->dnode, NULL));
		break;
	}

	return NB_OK;
}

int instance_neighbor_source_interface_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_interface_unset(peer);

	return NB_OK;
}

int instance_neighbor_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tcp_mss_set(peer, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_tcp_mss_unset(peer);

	return NB_OK;
}

int instance_neighbor_passive_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_PASSIVE);
	else
		peer_flag_unset(peer, PEER_FLAG_PASSIVE);

	return NB_OK;
}

/* 'neighbor X ebgp-multihop [(1-255)]' (M4 batch B6): routes straight
 * through peer_ebgp_multihop_set(peer, ttl, true) -- record_cfg=true, same
 * as peer_ebgp_multihop_set_vty() (bgp_vty.c, retired), which just records
 * cfg_ttl and lets peer_cfg_ttl_set() (bgpd.c) do the actual propagation/
 * session-reset work. peer_ebgp_multihop_set_vty() additionally rejected
 * a directly connected (conf_if) peer up front with
 * BGP_ERR_INVALID_FOR_DIRECT_PEER and pre-checked peer_gtsm_configured()
 * to reject the mutual exclusion with ttl-security-hops before ever
 * calling the setter (peer_ebgp_multihop_set() itself skips that check on
 * its record_cfg=true/bare-form paths, so the vty-layer guard is the only
 * thing that actually enforces it for this direction) -- both replicated
 * here at NB_EV_VALIDATE so a rejected 'ebgp-multihop' never partially
 * applies. The YANG 'must "not(../ebgp-multihop)"' on ttl-security-hops
 * only catches same-entry co-configuration in one edit; it does not see a
 * peer-group's ttl-security-hops conflicting with a member's own
 * ebgp-multihop or vice versa, which is exactly what peer_gtsm_configured()
 * (group/member-aware) catches.
 */
int instance_neighbor_ebgp_multihop_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (peer->conf_if) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Operation not allowed on a directly connected neighbor");
			return NB_ERR_VALIDATION;
		}

		if (peer_gtsm_configured(peer)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ebgp-multihop and ttl-security cannot be configured together");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		ret = peer_ebgp_multihop_set(peer, yang_dnode_get_uint8(args->dnode, NULL), true);
		if (ret != BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_ebgp_multihop_set() failed", __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_neighbor_ebgp_multihop_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	ret = peer_ebgp_multihop_unset(peer, true);
	if (ret != BGP_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_ebgp_multihop_unset() failed",
			 __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int instance_neighbor_aigp_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_AIGP);
	else
		peer_flag_unset(peer, PEER_FLAG_AIGP);

	return NB_OK;
}

/* 'neighbor X local-role <role> [strict-mode]' / 'no neighbor X local-role
 * <role> [strict-mode]' (RFC 9234, M4 batch B12): reproduces
 * neighbor_role_cmd/neighbor_role_strict_cmd/no_neighbor_role_cmd
 * (bgp_vty.c, retired), which funnel into peer_role_set()/peer_role_unset()
 * (bgpd.c). Both role and strict-mode route through the shared
 * bgp_nb_neighbor_role_apply() (bgp_nb_util.c) -- see its doc comment for
 * the full container-reread/capability-send design, matching local-as's
 * (M4 batch B9) "every sibling leaf's modify calls the same shared apply"
 * discipline.
 */
int instance_neighbor_local_role_role_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_neighbor_role_apply(args->dnode);
}

/* 'no neighbor X local-role ...': reproduces peer_role_unset(), which
 * always resets the peer to ROLE_UNDEFINED/strict-mode-off regardless of
 * the 'no' form's own role/strict-mode tokens (bgpd.c, ignored the same way
 * legacy's DEFPY grammar accepts-but-ignores them). The CLI's 'no' form
 * (bgp_cli_neighbor.c) enqueues this DESTROY together with an explicit
 * MODIFY "false" on the sibling 'strict-mode' leaf (modify-only, no YANG
 * default's .destroy exists per this project's Tier A convention) --
 * destroys apply before modifies within a commit (lib/northbound.c), so by
 * the time that sibling MODIFY's own bgp_nb_neighbor_role_apply() call
 * runs, 'role' is already gone from the dnode and its reread is a safe
 * no-op (see bgp_nb_get_role()'s doc comment), leaving this single
 * peer_role_unset() call as the only real effect.
 */
int instance_neighbor_local_role_role_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	ret = peer_role_unset(peer);
	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_ROLE,
			    CAPABILITY_ACTION_UNSET);
	if (ret != CMD_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_role_unset() failed", __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int instance_neighbor_local_role_strict_mode_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	return bgp_nb_neighbor_role_apply(args->dnode);
}

/* 'neighbor X oad' (bgp_vty.c, retired): legacy silently no-ops (leaves
 * peer->sub_sort untouched) when the peer isn't eBGP-sorted rather than
 * rejecting -- the inventory calls this out as a cross-leaf dependency
 * worth encoding properly, so this VALIDATE rejects instead of silently
 * accepting a no-op, a deliberate improvement over the legacy silent
 * failure. The 'no' form (destroy-to-default MODIFY carrying "false") is
 * unconditional in both legacy and here, matching peer->sub_sort = 0
 * regardless of sort.
 */
int instance_neighbor_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer && yang_dnode_get_bool(args->dnode, NULL) && peer->sort != BGP_PEER_EBGP) {
			snprintf(args->errmsg, args->errmsg_len,
				 "oad is only valid for eBGP neighbors");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		peer->sub_sort = yang_dnode_get_bool(args->dnode, NULL) ? BGP_PEER_EBGP_OAD : 0;
		break;
	}

	return NB_OK;
}

/* 'neighbor X ttl-security hops (1-254)' (M4 batch B6): routes straight
 * through peer_ttl_security_hops_set()/_unset() (bgpd.c), which already
 * contain all the fan-out/session-reset logic
 * neighbor_ttl_security_cmd/no_neighbor_ttl_security_cmd (bgp_vty.c,
 * retired) relied on. Two legacy vty-layer guards are replicated at
 * NB_EV_VALIDATE, in the same order the retired DEFUN ran them:
 *
 *  - the directly-connected (conf_if) hop-count cap
 *    ('%s is directly connected peer, hops cannot exceed 1', a plain
 *    vty_out + CMD_WARNING_CONFIG_FAILED in the retired DEFUN, not a
 *    bgp_vty_return() error code -- BGP_GTSM_HOPS_CONNECTED is 1);
 *  - the ebgp-multihop mutual exclusion, which in legacy is actually
 *    enforced *inside* peer_ttl_security_hops_set() itself via the
 *    (now-exported) peer_ebgp_multihop_cfg() -- mirrored here up front so
 *    a rejected 'ttl-security hops' never partially applies, matching the
 *    ebgp-multihop callback's own peer_gtsm_configured() guard
 *    (bgp_nb_neighbor.c, this batch) for the other direction. The YANG
 *    'must "not(../ebgp-multihop)"' only catches same-entry
 *    co-configuration; this VALIDATE guard is the group/member-aware
 *    equivalent, per the inventory.
 */
int instance_neighbor_ttl_security_hops_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (peer->conf_if &&
		    yang_dnode_get_uint8(args->dnode, NULL) > BGP_GTSM_HOPS_CONNECTED) {
			snprintf(args->errmsg, args->errmsg_len,
				 "%s is directly connected peer, hops cannot exceed 1",
				 peer->conf_if);
			return NB_ERR_VALIDATION;
		}

		if (peer_ebgp_multihop_cfg(peer)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ebgp-multihop and ttl-security cannot be configured together");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		ret = peer_ttl_security_hops_set(peer, yang_dnode_get_uint8(args->dnode, NULL));
		if (ret != BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_ttl_security_hops_set() failed", __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_neighbor_ttl_security_hops_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	ret = peer_ttl_security_hops_unset(peer);
	if (ret != BGP_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_ttl_security_hops_unset() failed", __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int instance_neighbor_disable_connected_check_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	else
		peer_flag_unset(peer, PEER_FLAG_DISABLE_CONNECTED_CHECK);

	return NB_OK;
}

/* 'neighbor X enforce-first-as <enabled|disabled>' (M4 batch B12):
 * reproduces neighbor_enforce_first_as_cmd/no_neighbor_enforce_first_as_cmd
 * (bgp_vty.c, retired), which route through the generic peer_flag_set()/
 * peer_flag_unset() (bgpd.c:5938/5943) exactly like the six B8
 * capabilities container leaves -- inventory section 1.12 confirmed this leaf's
 * "inherits the instance-level setting" wording describes the same
 * profile-dependent-instance-default shape as B8's dynamic/software-version/
 * link-local capabilities (bgp->flags-derived, seeded onto peers at
 * creation by peer_new(), bgpd.c ~1792-1795, and re-seeded onto existing
 * peers during config load by the interim bridge in bgp_nb_instance.c), not
 * a bespoke second inheritance path: peer_flag_action_list's { PEER_FLAG_
 * ENFORCE_FIRST_AS, 0, peer_change_reset_in } entry needs no extra
 * renegotiation call beyond what peer_flag_set()/_unset() already performs,
 * the same "verify no extra call is needed" resolution reached for the six
 * B8 leaves.
 */
int instance_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_ENFORCE_FIRST_AS);
	else
		peer_flag_unset(peer, PEER_FLAG_ENFORCE_FIRST_AS);

	return NB_OK;
}

/* Same "revert to instance default, or inherit from peer-group" shape as
 * bgp_nb_capability_flag_destroy()'s six B8 callers (bgp_nb_util.c) --
 * instance_default here is bgp->flags' BGP_FLAG_ENFORCE_FIRST_AS, the
 * already-converted instance-level leaf (bgp_nb_instance.c, seeded/re-seeded
 * per the modify callback's comment above).
 */
int instance_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_ENFORCE_FIRST_AS,
				       bgp && CHECK_FLAG(bgp->flags, BGP_FLAG_ENFORCE_FIRST_AS));

	return NB_OK;
}

/* 'neighbor X update-source <A.B.C.D|X:X::X:X|WORD>' (peer->update_source /
 * peer->update_if, M4 batch B7). Legacy's peer_update_source_vty()
 * (bgp_vty.c, retired) tries str2sockunion() first (peer_update_source_
 * addr_set()); on failure it tries str2prefix() to distinguish an
 * address-with-mask (rejected: "Invalid update-source, remove prefix
 * length") from a plain interface name (peer_update_source_if_set()).
 * The YANG leaf is `union { inet:ip-address-no-zone; string }`
 * (proteus-bgp.yang) -- both union branches carry the same string form
 * legacy parsed, so the identical two-step str2sockunion()/str2prefix()
 * dispatch runs again here: at VALIDATE to reject the ambiguous
 * CIDR-looking form, and at APPLY to pick the setter. Legacy also
 * silently no-ops (bare CMD_WARNING, no message) for unnumbered
 * (peer->conf_if) peers -- reproduced as the same sibling-leaf VALIDATE
 * check instance_neighbor_source_interface_modify() above uses, reading
 * the candidate config's own 'interface-peer' leaf rather than the live
 * peer struct so same-commit ordering is safe.
 */
int instance_neighbor_update_source_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *nbr_dnode;
	const char *source_str;
	union sockunion su;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
		nbr_dnode = yang_dnode_get_parent(args->dnode, "neighbor");
		if (yang_dnode_exists(nbr_dnode, "interface-peer") &&
		    yang_dnode_get_bool(nbr_dnode, "interface-peer")) {
			snprintf(args->errmsg, args->errmsg_len,
				 "update-source is not supported for unnumbered (interface) neighbors");
			return NB_ERR_VALIDATION;
		}
		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2sockunion(source_str, &su) != 0 && str2prefix(source_str, &p)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid update-source, remove prefix length");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2sockunion(source_str, &su) == 0)
			peer_update_source_addr_set(peer, &su);
		else
			peer_update_source_if_set(peer, source_str);
		break;
	}

	return NB_OK;
}

int instance_neighbor_update_source_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_update_source_unset(peer);

	return NB_OK;
}

/* 'neighbor X ip-transparent' (PEER_FLAG_IP_TRANSPARENT, M4 batch B7).
 * Legacy's DEFPY (neighbor_ip_transparent, bgp_vty.c, retired) rejects the
 * positive form unless update-source is already configured
 * (peergroup_flag_check(peer, PEER_FLAG_UPDATE_SOURCE)) -- checking
 * flags_override when the peer is an active group member, i.e. whether
 * update-source is explicit on *this* peer/peer-group's own config, not
 * merely inherited from a bound peer-group. The northbound-native
 * equivalent is whether 'update-source' is present on this same list
 * entry's own dnode: our model only carries what was typed directly on
 * this neighbor/peer-group, since inheritance from a bound peer-group is
 * a runtime bgpd mechanism (PEER_ATTR_INHERIT), not reflected in the
 * candidate config tree -- so dnode presence here is the exact mirror of
 * legacy's flags_override bit. Only the positive ('true') direction is
 * checked, matching legacy's '!no && ...' guard. Tier A (default
 * "false", positive-only boolean): only .modify is registered, so both
 * the positive and 'no' CLI forms dispatch here (see neighbor_disable_
 * connected_check_modify() above for the same shape).
 */
int instance_neighbor_ip_transparent_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *nbr_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_get_bool(args->dnode, NULL)) {
			nbr_dnode = yang_dnode_get_parent(args->dnode, "neighbor");
			if (!yang_dnode_exists(nbr_dnode, "update-source")) {
				snprintf(args->errmsg, args->errmsg_len, "Missing update-source");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(peer, PEER_FLAG_IP_TRANSPARENT);
		else
			peer_flag_unset(peer, PEER_FLAG_IP_TRANSPARENT);
		break;
	}

	return NB_OK;
}

/* 'neighbor X advertisement-interval (0-600)' (M4 batch B5): unlike every
 * other destroy-to-default leaf converted so far in this series, the
 * unset value is NOT a fixed YANG default -- peer_advertise_interval_unset()
 * (bgpd.c) re-derives it from the peer's *current* sort (eBGP 30s / iBGP
 * 5s via BGP_DEFAULT_EBGP_ROUTEADV/BGP_DEFAULT_IBGP_ROUTEADV), matching
 * peer_new()'s own initializer. Routing straight through the existing
 * setter/unsetter reproduces this for free: peer->v_routeadv (the live
 * timer) is sort-dependent whenever the leaf is absent, in both legacy and
 * here, and stays that way even across a later 'remote-as' re-type that
 * changes peer->sort (neither legacy nor this callback re-evaluates
 * v_routeadv on a sort change by itself -- peer_remote_as_set() below
 * already re-triggers advertisement-interval's own unset path via its
 * existing peer_update_af_peer_type()-adjacent machinery in legacy, and
 * the northbound equivalent doesn't need any B5-specific change since
 * 'address' is immutable and 'remote-as' modify/destroy is B1's own
 * callback, not this one's concern).
 */
int instance_neighbor_advertisement_interval_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_advertise_interval_set(peer, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_advertisement_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_advertise_interval_unset(peer);

	return NB_OK;
}

/* 'neighbor X timers (0-65535) (0-65535)' (keepalive+holdtime, M4 batch
 * B5): both leaves converge on the same peer_timers_set() call (mirrors
 * the joint DEFPY grammar), so either leaf's modify applies both values --
 * matching M2's instance-level 'timers bgp' joint-emission precedent
 * (instance_timers_keepalive_modify()/_holdtime_modify(),
 * bgp_nb_instance.c). destroy is likewise joint: either leaf's destroy
 * calls peer_timers_unset(), which clears/inherits both at once, same as
 * legacy's 'no neighbor X timers' (no per-leaf granularity exists in
 * either grammar).
 */
int instance_neighbor_timers_keepalive_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *timers_dnode;
	uint16_t keepalive, holdtime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	timers_dnode = yang_dnode_get_parent(args->dnode, "timers");
	keepalive = yang_dnode_get_uint16(args->dnode, NULL);
	holdtime = yang_dnode_exists(timers_dnode, "holdtime")
			   ? yang_dnode_get_uint16(timers_dnode, "holdtime")
			   : peer->holdtime;

	peer_timers_set(peer, keepalive, holdtime);

	return NB_OK;
}

int instance_neighbor_timers_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_unset(peer);

	return NB_OK;
}

int instance_neighbor_timers_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	const struct lyd_node *timers_dnode;
	uint16_t keepalive, holdtime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	timers_dnode = yang_dnode_get_parent(args->dnode, "timers");
	holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	keepalive = yang_dnode_exists(timers_dnode, "keepalive")
			    ? yang_dnode_get_uint16(timers_dnode, "keepalive")
			    : peer->keepalive;

	peer_timers_set(peer, keepalive, holdtime);

	return NB_OK;
}

int instance_neighbor_timers_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_unset(peer);

	return NB_OK;
}

int instance_neighbor_timers_connect_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_connect_set(peer, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_timers_connect_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_connect_unset(peer);

	return NB_OK;
}

int instance_neighbor_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_delayopen_set(peer, yang_dnode_get_uint8(args->dnode, NULL));

	return NB_OK;
}

int instance_neighbor_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer_timers_delayopen_unset(peer);

	return NB_OK;
}

/*
 * capabilities container (M4 batch B8): dynamic, extended-nexthop,
 * software-version(+latest-encoding), link-local, fqdn -- Tier B, no YANG
 * default, unset inherits the bound peer-group's value (or, absent a
 * peer-group, the instance-level 'bgp default ...' setting / peer_new()'s
 * hardcoded seed -- see bgp_nb_capability_flag_destroy(), bgp_nb_util.c).
 * dont-capability-negotiate, override-capability, strict-capability-match
 * -- Tier A, default false, modify-only (table already generated this way;
 * no .destroy to delete).
 *
 * All six Tier B leaves route through the generic peer_flag_set()/
 * peer_flag_unset() (bgpd.c) that every DEFUN here used via
 * peer_flag_set_vty()/peer_flag_unset_vty() (retired) -- these already do
 * their own vty-free peer-group member fan-out internally. cli_show
 * (bgp_cli_write_session_scalars(), bgp_cli_neighbor.c) gates all nine on
 * this entry's own leaf presence, the "presence is exactly legacy's
 * ownership flag" principle already used since B6/B7 -- fqdn and
 * link-local both had a legacy config-write path that only value-compares
 * (fqdn: always inverted, so a re-enable to the default never renders;
 * link-local: an extra conf_if special case), both deliberately not
 * replicated for the same reason ttl-security-hops' value-comparison
 * wasn't in B6.
 */
int instance_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DYNAMIC_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_DYNAMIC_CAPABILITY);

	return NB_OK;
}

int instance_neighbor_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_DYNAMIC_CAPABILITY,
				       bgp && CHECK_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY));

	return NB_OK;
}

/* 'neighbor X capability extended-nexthop' (neighbor_capability_enhe/no_...,
 * bgp_vty.c, retired): unlike the other five Tier B leaves, unnumbered
 * (conf_if) peers have this flag locked permanently on
 * (instance_neighbor_create(), M4 batch B1) -- legacy's positive DEFUN
 * silently no-ops on a conf_if peer (CMD_SUCCESS without ever calling the
 * setter) and the negative DEFUN hard-rejects with "Peer %s cannot have
 * capability extended-nexthop turned off". Reproduced at VALIDATE for both
 * MODIFY-to-false and DESTROY (which would otherwise turn it off via
 * inheritance); MODIFY-to-true is allowed through unchanged (idempotent
 * on a conf_if peer, same as legacy's silent success). Also unlike the
 * other five, the dynamic-capability renegotiation message needs to reach
 * every live peer-group member's own TCP session (bgp_zebra_initiate_radv()-
 * style fan-out), not just the looked-up peer/group->conf -- that's what
 * bgp_nb_capability_send_dynamic_peer_group() (bgp_nb_util.c, moved
 * vty-free from bgp_vty.c's now-retired static helper) is for. The
 * DESTROY direction has no legacy equivalent (see
 * bgp_nb_capability_flag_destroy()'s doc comment) -- the capability
 * message sent afterward is computed from the resulting flag state rather
 * than assumed, extending legacy's single-direction (always-off) unset
 * fan-out to also cover a destroy that resolves to "inherited on".
 */
int instance_neighbor_capabilities_extended_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer && peer->conf_if && !yang_dnode_get_bool(args->dnode, NULL)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Peer %s cannot have capability extended-nexthop turned off",
				 peer->conf_if);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL)) {
			peer_flag_set(peer, PEER_FLAG_CAPABILITY_ENHE);
			bgp_nb_capability_send_dynamic_peer_group(peer, AFI_IP, SAFI_UNICAST,
								  CAPABILITY_CODE_ENHE,
								  CAPABILITY_ACTION_SET);
		} else {
			/* Send dynamic UNSET while the flag is still set:
			 * bgp_capability_send() only encodes ENHE TLVs when
			 * that flag is set.
			 */
			bgp_nb_capability_send_dynamic_peer_group(peer, AFI_IP, SAFI_UNICAST,
								  CAPABILITY_CODE_ENHE,
								  CAPABILITY_ACTION_UNSET);
			peer_flag_unset(peer, PEER_FLAG_CAPABILITY_ENHE);
		}
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_extended_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer && peer->conf_if) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Peer %s cannot have capability extended-nexthop turned off",
				 peer->conf_if);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		bgp_nb_capability_flag_destroy(peer, PEER_FLAG_CAPABILITY_ENHE, false);
		bgp_nb_capability_send_dynamic_peer_group(peer, AFI_IP, SAFI_UNICAST,
							  CAPABILITY_CODE_ENHE,
							  CHECK_FLAG(peer->flags,
								     PEER_FLAG_CAPABILITY_ENHE)
								  ? CAPABILITY_ACTION_SET
								  : CAPABILITY_ACTION_UNSET);
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_SOFT_VERSION,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD));

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_SOFT_VERSION,
			    CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_latest_encoding_modify(
	struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_SOFT_VERSION,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_latest_encoding_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW));

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_SOFT_VERSION,
			    CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_link_local_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL);

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LINK_LOCAL,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_link_local_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_CAPABILITY_LINK_LOCAL,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_LINK_LOCAL_CAPABILITY));

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_LINK_LOCAL,
			    CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_LINK_LOCAL)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_fqdn_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(peer, PEER_FLAG_CAPABILITY_FQDN);
	else
		peer_flag_unset(peer, PEER_FLAG_CAPABILITY_FQDN);

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_FQDN,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_fqdn_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	/* fqdn's "instance default" is unconditionally true -- peer_new()
	 * (bgpd.c) sets it with no bgp-> dependency at all.
	 */
	bgp_nb_capability_flag_destroy(peer, PEER_FLAG_CAPABILITY_FQDN, true);

	bgp_capability_send(peer->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_FQDN,
			    CHECK_FLAG(peer->flags, PEER_FLAG_CAPABILITY_FQDN)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_neighbor_capabilities_dont_capability_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_unset(peer, PEER_FLAG_DONT_CAPABILITY);

	return NB_OK;
}

/* 'neighbor X override-capability'/'strict-capability-match'
 * (neighbor_override_capability/neighbor_strict_capability + no_..., all
 * bgp_vty.c, retired): mutually exclusive, per peer_flag_modify()'s own
 * BGP_ERR_PEER_FLAG_CONFLICT check (bgpd.c) -- reproduced here at
 * NB_EV_VALIDATE, in the same style as B6's ebgp-multihop/ttl-security-hops
 * cross-check, so the reject happens before anything applies rather than
 * as an APPLY-time flog_err with no rollback. peer->flags is read directly
 * (not peergroup_flag_check()): peer_flag_modify()'s own member fan-out
 * already keeps peer->flags in sync with an inherited peer-group value, so
 * it's the correct "effective state" to cross-check regardless of whether
 * this peer owns the other flag explicitly or inherited it. The YANG
 * 'must "not(../override-capability)"' on strict-capability-match
 * (proteus-bgp.yang) only catches same-entry co-configuration in one edit;
 * this VALIDATE also catches a peer-group's setting conflicting with a
 * member's own (or vice versa), the same reason B6 kept both a 'must' and
 * a VALIDATE for ebgp-multihop/ttl-security-hops.
 */
int instance_neighbor_capabilities_override_capability_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer && yang_dnode_get_bool(args->dnode, NULL) &&
		    CHECK_FLAG(peer->flags, PEER_FLAG_STRICT_CAP_MATCH)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set override-capability and strict-capability-match at the same time");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
		else
			peer_flag_unset(peer, PEER_FLAG_OVERRIDE_CAPABILITY);
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_strict_capability_match_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (peer && yang_dnode_get_bool(args->dnode, NULL) &&
		    CHECK_FLAG(peer->flags, PEER_FLAG_OVERRIDE_CAPABILITY)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set override-capability and strict-capability-match at the same time");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(peer, PEER_FLAG_STRICT_CAP_MATCH);
		else
			peer_flag_unset(peer, PEER_FLAG_STRICT_CAP_MATCH);
		break;
	}

	return NB_OK;
}

/* rpki-strict, sender-as-path-loop-detection, send-nexthop-characteristics,
 * disable-link-bw-encoding-ieee, extended-link-bandwidth, extended-optional-
 * parameters (M4 batch B13): the last plain Tier A (YANG default "false")
 * session-level flags in the shared neighbor-session-parameters grouping.
 * All six are bare PEER_FLAG_* booleans in legacy -- neighbor_rpki_strict
 * (bare peer_flag_set/unset, bgp_vty.c, retired), neighbor_aspath_loop_detection/
 * no_... (peer_flag_set_vty/unset_vty wrapping PEER_FLAG_AS_LOOP_DETECTION),
 * neighbor_nhc_attribute (PEER_FLAG_SEND_NHC_ATTRIBUTE),
 * neighbor_disable_link_bw_encoding_ieee/no_... (PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE),
 * neighbor_extended_link_bw (PEER_FLAG_EXTENDED_LINK_BANDWIDTH),
 * neighbor_extended_optional_parameters/no_... (PEER_FLAG_EXTENDED_OPT_PARAMS)
 * -- same shape as B3's passive/B6's disable-connected-check: a bare
 * peer_flag_set()/unset() call, no special-casing (peer_flag_set_vty()'s
 * only extra behavior beyond peer_flag_set()/unset() is for
 * PEER_FLAG_DISABLE_CONNECTED_CHECK/PEER_FLAG_SHUTDOWN, neither of which
 * applies here). peer_flag_modify()'s own peer_flag_action_list
 * (bgpd.c) already drives the correct session-reset action for the two
 * flags that need one (AS_LOOP_DETECTION, EXTENDED_OPT_PARAMS) internally,
 * so no extra explicit reset call is needed here, matching legacy exactly.
 */
int instance_neighbor_rpki_strict_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_RPKI_STRICT);
	else
		peer_flag_unset(peer, PEER_FLAG_RPKI_STRICT);

	return NB_OK;
}

int instance_neighbor_sender_as_path_loop_detection_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_AS_LOOP_DETECTION);
	else
		peer_flag_unset(peer, PEER_FLAG_AS_LOOP_DETECTION);

	return NB_OK;
}

/* 'neighbor X path-attribute discard (1-255)...'/'no ... (1-255)' (M4 batch
 * B14): peer->discard_attrs[] is a bare per-attribute-number bool array (not
 * a PEER_FLAG_* / flags_override field), so create/destroy set/clear a single
 * index directly instead of routing through the legacy _vty() wrapper's
 * whole-line/whole-array replace semantics (bgp_path_attribute_discard_vty(),
 * bgp_attr.c, retired) -- that "clear every entry, then set the ones on this
 * line" behavior is specific to one CLI line carrying several numbers at
 * once and is undocumented (doc/user/bgp.rst); it isn't replicated here,
 * matching every other leaf-list in this conversion (e.g. B2's listen-range)
 * where each entry is independently created/destroyed. There is no
 * peer-group-to-member inheritance for this field: peer_group2peer_config_copy()
 * (bgpd.c) never touches discard_attrs/withdraw_attrs, so a peer-group-scope
 * command here (like legacy) only ever affects group->conf, with no fan-out
 * to member peers -- confirmed by inspection, not assumed.
 */
int instance_neighbor_path_attribute_discard_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		ret = bgp_nb_path_attribute_validate(peer, yang_dnode_get_uint8(args->dnode, NULL),
						     "discard", args->errmsg, args->errmsg_len);
		if (ret != NB_OK)
			return ret;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		peer->discard_attrs[yang_dnode_get_uint8(args->dnode, NULL)] = true;
		bgp_nb_path_attribute_soft_clear(peer);
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_discard_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->discard_attrs[yang_dnode_get_uint8(args->dnode, NULL)] = false;
	bgp_nb_path_attribute_soft_clear(peer);

	return NB_OK;
}

/* 'neighbor X path-attribute treat-as-withdraw (1-255)...'/'no ...
 * (1-255)' (M4 batch B14): peer->withdraw_attrs[]'s sibling array, same
 * per-index create/destroy and no-inheritance reasoning as discard above.
 */
int instance_neighbor_path_attribute_treat_as_withdraw_create(struct nb_cb_create_args *args)
{
	struct peer *peer;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		ret = bgp_nb_path_attribute_validate(peer, yang_dnode_get_uint8(args->dnode, NULL),
						     "treat-as-withdraw", args->errmsg,
						     args->errmsg_len);
		if (ret != NB_OK)
			return ret;
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		peer = bgp_nb_neighbor_lookup(args->dnode);
		if (!peer)
			break;

		peer->withdraw_attrs[yang_dnode_get_uint8(args->dnode, NULL)] = true;
		bgp_nb_path_attribute_soft_clear(peer);
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_treat_as_withdraw_destroy(struct nb_cb_destroy_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	peer->withdraw_attrs[yang_dnode_get_uint8(args->dnode, NULL)] = false;
	bgp_nb_path_attribute_soft_clear(peer);

	return NB_OK;
}

int instance_neighbor_send_nexthop_characteristics_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_SEND_NHC_ATTRIBUTE);
	else
		peer_flag_unset(peer, PEER_FLAG_SEND_NHC_ATTRIBUTE);

	return NB_OK;
}

int instance_neighbor_disable_link_bw_encoding_ieee_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE);
	else
		peer_flag_unset(peer, PEER_FLAG_DISABLE_LINK_BW_ENCODING_IEEE);

	return NB_OK;
}

int instance_neighbor_extended_link_bandwidth_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_EXTENDED_LINK_BANDWIDTH);
	else
		peer_flag_unset(peer, PEER_FLAG_EXTENDED_LINK_BANDWIDTH);

	return NB_OK;
}

int instance_neighbor_extended_optional_parameters_modify(struct nb_cb_modify_args *args)
{
	struct peer *peer;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	peer = bgp_nb_neighbor_lookup(args->dnode);
	if (!peer)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(peer, PEER_FLAG_EXTENDED_OPT_PARAMS);
	else
		peer_flag_unset(peer, PEER_FLAG_EXTENDED_OPT_PARAMS);

	return NB_OK;
}
