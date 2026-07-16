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

int instance_neighbor_local_as_plain_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/plain");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_plain_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/plain");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/asdot");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/asdot");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_high_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/asdot/high");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_asdot_low_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/asdot/low");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_no_prepend_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/no-prepend");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_replace_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/replace-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_as_dual_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-as/dual-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

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

int instance_neighbor_bfd_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/bfd/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_bfd_check_control_plane_failure_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/bfd/check-control-plane-failure");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/bfd/profile");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/bfd/profile");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

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

int instance_neighbor_local_role_role_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-role/role");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_role_role_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-role/role");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_local_role_strict_mode_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/local-role/strict-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
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

int instance_neighbor_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/enforce-first-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/enforce-first-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_update_source_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/update-source");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_update_source_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/update-source");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_ip_transparent_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/ip-transparent");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
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

int instance_neighbor_capabilities_dynamic_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/dynamic");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/dynamic");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_extended_nexthop_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/extended-nexthop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_extended_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/extended-nexthop");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/software-version");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/software-version");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_latest_encoding_modify(
	struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/software-version-latest-encoding");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_software_version_latest_encoding_destroy(
	struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/software-version-latest-encoding");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_link_local_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/link-local");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_link_local_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/link-local");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_fqdn_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/fqdn");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_fqdn_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/fqdn");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_dont_capability_negotiate_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/dont-capability-negotiate");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_override_capability_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/override-capability");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_capabilities_strict_capability_match_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/capabilities/strict-capability-match");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_rpki_strict_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/rpki-strict");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_sender_as_path_loop_detection_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/sender-as-path-loop-detection");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_discard_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/path-attribute-discard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_discard_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/path-attribute-discard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_treat_as_withdraw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/path-attribute-treat-as-withdraw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_path_attribute_treat_as_withdraw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/path-attribute-treat-as-withdraw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_send_nexthop_characteristics_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/send-nexthop-characteristics");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_disable_link_bw_encoding_ieee_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/disable-link-bw-encoding-ieee");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_extended_link_bandwidth_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/extended-link-bandwidth");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_neighbor_extended_optional_parameters_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/neighbor/extended-optional-parameters");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}
