// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound callbacks for /proteus-bgp:instance/peer-group scalars (excluding per-afi-safi settings).
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
#include "bgpd/proteus/bgp_nb_local.h"


int instance_peer_group_create(struct nb_cb_create_args *args)
{
	struct bgp *bgp;
	const char *name;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		bgp = bgp_nb_instance_lookup(args->dnode);
		if (!bgp)
			break;

		name = yang_dnode_get_string(args->dnode, "name");
		if (peer_lookup_by_conf_if(bgp, name)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Name conflict with interface: %s", name);
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

		name = yang_dnode_get_string(args->dnode, "name");
		group = peer_group_get(bgp, name);
		if (!group)
			return NB_ERR_RESOURCE;
		break;
	}

	return NB_OK;
}

int instance_peer_group_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE: {
		afi_t afi;
		const struct lyd_node *instance_dnode;
		const char *name;
		uint32_t member_count;

		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		/* Stricter-than-legacy northbound semantics: peer_group_delete()
		 * (bgpd.c) implicitly peer_delete()s every bound member with no
		 * unbind primitive, but reconciling the members' now-stale
		 * northbound 'neighbor' list entries after the fact is not
		 * something a plain VALIDATE/APPLY pair can do cleanly (a
		 * destroy callback cannot itself mutate sibling list entries in
		 * the same transaction). Reject here instead, forcing explicit
		 * neighbor deletion first so the datastore never disagrees with
		 * runtime; bgp_cli.c's 'no neighbor WORD peer-group' CLI
		 * restores the legacy one-command UX by enqueuing the member
		 * destroys itself before this one.
		 */
		name = yang_dnode_get_string(args->dnode, "name");
		instance_dnode = yang_dnode_get_parent(args->dnode, "instance");
		member_count = yang_dnode_count(instance_dnode, "./neighbor[peer-group='%s']", name);
		if (member_count) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Peer-group %s still has %u neighbor(s) bound to it, delete them first",
				 name, member_count);
			return NB_ERR_VALIDATION;
		}

		for (afi = AFI_IP; afi < AFI_MAX; afi++) {
			if (listcount(group->listen_range[afi])) {
				snprintf(args->errmsg, args->errmsg_len,
					 "Peer-group %s is attached to %d listen-range(s), delete them first",
					 group->name, listcount(group->listen_range[afi]));
				return NB_ERR_VALIDATION;
			}
		}
		break;
	}
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		bgp = bgp_nb_instance_lookup(args->dnode);
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		/* No members can remain bound at this point (VALIDATE above
		 * rejects otherwise), so peer_group_delete() has nothing left
		 * to implicitly tear down beyond the group's own conf peer. */
		peer_group_notify_unconfig(group);
		peer_group_delete(group);
		if (bgp)
			bgp_may_stop_listening(bgp, NULL);
		break;
	}

	return NB_OK;
}

int instance_peer_group_remote_as_plain_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_plain_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_delete_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_asdot_create(struct nb_cb_create_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_asdot_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_delete_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_asdot_high_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_asdot_low_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_type_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_remote_as_type_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_remote_as_delete_apply(args->dnode);

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c, M4 batch
 * B9) for the full rationale; peer-group scope calls the same shared
 * bgp_nb_peer_group_local_as_apply()/_destroy_apply() helpers
 * (bgp_nb_util.c) on group->conf.
 */
int instance_peer_group_local_as_plain_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_peer_group_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_peer_group_local_as_plain_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_local_as_destroy_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_local_as_asdot_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_peer_group_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_peer_group_local_as_asdot_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_local_as_destroy_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_local_as_asdot_high_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_peer_group_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_peer_group_local_as_asdot_low_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		return bgp_nb_local_as_validate(args->dnode, args->errmsg, args->errmsg_len);
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		return bgp_nb_peer_group_local_as_apply(args->dnode);
	}

	return NB_OK;
}

int instance_peer_group_local_as_no_prepend_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_local_as_replace_as_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_local_as_dual_as_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_APPLY)
		return bgp_nb_peer_group_local_as_apply(args->dnode);

	return NB_OK;
}

int instance_peer_group_description_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_description_set(group->conf, yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_description_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_description_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_bfd_enabled_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/bfd/enabled");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_bfd_check_control_plane_failure_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/bfd/check-control-plane-failure");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_bfd_profile_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/bfd/profile");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_bfd_profile_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/bfd/profile");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for why
 * the bounds check happens at VALIDATE rather than relying on
 * peer_password_set()'s own PEER_PASSWORD_MINLEN/MAXLEN check.
 */
int instance_peer_group_password_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
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
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (peer_password_set(group->conf, yang_dnode_get_string(args->dnode, NULL)) !=
		    BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_password_set() failed",
				 __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_peer_group_password_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_password_unset(group->conf);

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for why
 * update_group_adjust_soloness() (bgp_updgrp.c), not a bare
 * peer_flag_set()/unset(), is the correct entry point -- it already
 * detects group->conf via PEER_STATUS_GROUP and fans out to every current
 * member itself.
 */
int instance_peer_group_solo_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	update_group_adjust_soloness(group->conf, yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_port_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_port_set(group->conf, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_port_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_port_unset(group->conf);

	return NB_OK;
}

/* Legacy's peer_interface_vty() (bgp_vty.c, retired) resolves its target
 * with peer_lookup_vty(), which never matches a peer-group name -- there
 * is no legacy 'neighbor GROUP interface IFNAME' at all. Reject
 * unconditionally rather than inventing group-level semantics that never
 * existed.
 */
int instance_peer_group_source_interface_modify(struct nb_cb_modify_args *args)
{
	if (args->event == NB_EV_VALIDATE) {
		snprintf(args->errmsg, args->errmsg_len,
			 "source-interface is not supported on peer-groups; bgpd has no 'neighbor GROUP interface IFNAME'");
		return NB_ERR_VALIDATION;
	}

	return NB_OK;
}

int instance_peer_group_source_interface_destroy(struct nb_cb_destroy_args *args)
{
	return NB_OK;
}

int instance_peer_group_tcp_mss_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_tcp_mss_set(group->conf, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_tcp_mss_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_tcp_mss_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_passive_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_PASSIVE);
	else
		peer_flag_unset(group->conf, PEER_FLAG_PASSIVE);

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for the
 * full rationale; peer-group scope calls the same legacy setters on
 * group->conf, which already carries PEER_STATUS_GROUP and so takes the
 * fan-out-to-members branch inside peer_ebgp_multihop_set()/_unset() and
 * peer_gtsm_configured() itself (mirroring peer_and_group_lookup_vty()
 * resolving a peer-group name to group->conf in the retired DEFUN).
 */
int instance_peer_group_ebgp_multihop_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (peer_gtsm_configured(group->conf)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ebgp-multihop and ttl-security cannot be configured together");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		ret = peer_ebgp_multihop_set(group->conf, yang_dnode_get_uint8(args->dnode, NULL),
					     true);
		if (ret != BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_ebgp_multihop_set() failed", __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_peer_group_ebgp_multihop_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	ret = peer_ebgp_multihop_unset(group->conf, true);
	if (ret != BGP_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID, "%s: peer_ebgp_multihop_unset() failed",
			 __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int instance_peer_group_aigp_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_AIGP);
	else
		peer_flag_unset(group->conf, PEER_FLAG_AIGP);

	return NB_OK;
}

int instance_peer_group_local_role_role_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/local-role/role");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_local_role_role_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/local-role/role");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_local_role_strict_mode_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/local-role/strict-mode");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for why
 * the VALIDATE-time rejection is a deliberate improvement over legacy's
 * silent no-op on a non-eBGP-sorted peer-group.
 */
int instance_peer_group_oad_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (group && yang_dnode_get_bool(args->dnode, NULL) &&
		    group->conf->sort != BGP_PEER_EBGP) {
			snprintf(args->errmsg, args->errmsg_len,
				 "oad is only valid for eBGP neighbors");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		group->conf->sub_sort = yang_dnode_get_bool(args->dnode, NULL) ? BGP_PEER_EBGP_OAD
									       : 0;
		break;
	}

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for the
 * full rationale. Peer-group entries are never conf_if peers
 * (peer_group_get() never sets it on group->conf), so unlike the
 * neighbor-scope callback there is no directly-connected hop-count cap to
 * replicate here.
 */
int instance_peer_group_ttl_security_hops_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (peer_ebgp_multihop_cfg(group->conf)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "ebgp-multihop and ttl-security cannot be configured together");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		ret = peer_ttl_security_hops_set(group->conf,
						 yang_dnode_get_uint8(args->dnode, NULL));
		if (ret != BGP_SUCCESS) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_ttl_security_hops_set() failed", __func__);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_peer_group_ttl_security_hops_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	int ret;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	ret = peer_ttl_security_hops_unset(group->conf);
	if (ret != BGP_SUCCESS) {
		flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
			 "%s: peer_ttl_security_hops_unset() failed", __func__);
		return NB_ERR_RESOURCE;
	}

	return NB_OK;
}

int instance_peer_group_disable_connected_check_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_DISABLE_CONNECTED_CHECK);
	else
		peer_flag_unset(group->conf, PEER_FLAG_DISABLE_CONNECTED_CHECK);

	return NB_OK;
}

int instance_peer_group_enforce_first_as_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/enforce-first-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_enforce_first_as_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/enforce-first-as");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for the
 * str2sockunion()/str2prefix() dispatch this mirrors -- group->conf is the
 * peer-group's own 'struct peer *' (same idiom as password/tcp-mss above),
 * and there is no 'interface-peer' sibling at peer-group scope so that
 * VALIDATE guard is skipped (unnumbered peer-groups don't exist).
 */
int instance_peer_group_update_source_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	const char *source_str;
	union sockunion su;
	struct prefix p;

	switch (args->event) {
	case NB_EV_VALIDATE:
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
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		source_str = yang_dnode_get_string(args->dnode, NULL);
		if (str2sockunion(source_str, &su) == 0)
			peer_update_source_addr_set(group->conf, &su);
		else
			peer_update_source_if_set(group->conf, source_str);
		break;
	}

	return NB_OK;
}

int instance_peer_group_update_source_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_update_source_unset(group->conf);

	return NB_OK;
}

/* See the neighbor-scope callback's comment (bgp_nb_neighbor.c) for the
 * "Missing update-source" dependency this mirrors on group->conf's own
 * dnode.
 */
int instance_peer_group_ip_transparent_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	const struct lyd_node *pg_dnode;

	switch (args->event) {
	case NB_EV_VALIDATE:
		if (yang_dnode_get_bool(args->dnode, NULL)) {
			pg_dnode = yang_dnode_get_parent(args->dnode, "peer-group");
			if (!yang_dnode_exists(pg_dnode, "update-source")) {
				snprintf(args->errmsg, args->errmsg_len, "Missing update-source");
				return NB_ERR_VALIDATION;
			}
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(group->conf, PEER_FLAG_IP_TRANSPARENT);
		else
			peer_flag_unset(group->conf, PEER_FLAG_IP_TRANSPARENT);
		break;
	}

	return NB_OK;
}

/* See the neighbor-scope callbacks' comments (bgp_nb_neighbor.c) for the
 * advertisement-interval sort-dependent-default and joint timers/keepalive
 * +holdtime rationale -- identical here via group->conf.
 */
int instance_peer_group_advertisement_interval_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_advertise_interval_set(group->conf, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_advertisement_interval_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_advertise_interval_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_timers_keepalive_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	const struct lyd_node *timers_dnode;
	uint16_t keepalive, holdtime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	timers_dnode = yang_dnode_get_parent(args->dnode, "timers");
	keepalive = yang_dnode_get_uint16(args->dnode, NULL);
	holdtime = yang_dnode_exists(timers_dnode, "holdtime")
			   ? yang_dnode_get_uint16(timers_dnode, "holdtime")
			   : group->conf->holdtime;

	peer_timers_set(group->conf, keepalive, holdtime);

	return NB_OK;
}

int instance_peer_group_timers_keepalive_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_timers_holdtime_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	const struct lyd_node *timers_dnode;
	uint16_t keepalive, holdtime;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	timers_dnode = yang_dnode_get_parent(args->dnode, "timers");
	holdtime = yang_dnode_get_uint16(args->dnode, NULL);
	keepalive = yang_dnode_exists(timers_dnode, "keepalive")
			    ? yang_dnode_get_uint16(timers_dnode, "keepalive")
			    : group->conf->keepalive;

	peer_timers_set(group->conf, keepalive, holdtime);

	return NB_OK;
}

int instance_peer_group_timers_holdtime_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_timers_connect_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_connect_set(group->conf, yang_dnode_get_uint16(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_timers_connect_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_connect_unset(group->conf);

	return NB_OK;
}

int instance_peer_group_timers_delayopen_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_delayopen_set(group->conf, yang_dnode_get_uint8(args->dnode, NULL));

	return NB_OK;
}

int instance_peer_group_timers_delayopen_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	peer_timers_delayopen_unset(group->conf);

	return NB_OK;
}

/*
 * capabilities container (M4 batch B8): shares the same shape as the
 * neighbor-scope callbacks (bgp_nb_neighbor.c) -- see that file's leading
 * comment for the full design rationale. group->conf (a real 'struct
 * peer *') is the target throughout, mirroring B3/B4/B5's idiom;
 * group->conf is never a conf_if peer, so extended-nexthop has no
 * conf_if VALIDATE guard at this scope (B6's ebgp-multihop/ttl-security-hops
 * precedent for the same asymmetry).
 */
int instance_peer_group_capabilities_dynamic_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_DYNAMIC_CAPABILITY);
	else
		peer_flag_unset(group->conf, PEER_FLAG_DYNAMIC_CAPABILITY);

	return NB_OK;
}

int instance_peer_group_capabilities_dynamic_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_DYNAMIC_CAPABILITY,
				       bgp && CHECK_FLAG(bgp->flags, BGP_FLAG_DYNAMIC_CAPABILITY));

	return NB_OK;
}

int instance_peer_group_capabilities_extended_nexthop_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL)) {
		peer_flag_set(group->conf, PEER_FLAG_CAPABILITY_ENHE);
		bgp_nb_capability_send_dynamic_peer_group(group->conf, AFI_IP, SAFI_UNICAST,
							  CAPABILITY_CODE_ENHE,
							  CAPABILITY_ACTION_SET);
	} else {
		bgp_nb_capability_send_dynamic_peer_group(group->conf, AFI_IP, SAFI_UNICAST,
							  CAPABILITY_CODE_ENHE,
							  CAPABILITY_ACTION_UNSET);
		peer_flag_unset(group->conf, PEER_FLAG_CAPABILITY_ENHE);
	}

	return NB_OK;
}

int instance_peer_group_capabilities_extended_nexthop_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_CAPABILITY_ENHE, false);
	bgp_nb_capability_send_dynamic_peer_group(group->conf, AFI_IP, SAFI_UNICAST,
						  CAPABILITY_CODE_ENHE,
						  CHECK_FLAG(group->conf->flags,
							     PEER_FLAG_CAPABILITY_ENHE)
							  ? CAPABILITY_ACTION_SET
							  : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_software_version_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);
	else
		peer_flag_unset(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD);

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_SOFT_VERSION,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_software_version_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_SOFT_VERSION_CAPABILITY_OLD));

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_SOFT_VERSION,
			    CHECK_FLAG(group->conf->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_OLD)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_software_version_latest_encoding_modify(
	struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);
	else
		peer_flag_unset(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW);

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_SOFT_VERSION,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_software_version_latest_encoding_destroy(
	struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_SOFT_VERSION_CAPABILITY_NEW));

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_SOFT_VERSION,
			    CHECK_FLAG(group->conf->flags, PEER_FLAG_CAPABILITY_SOFT_VERSION_NEW)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_link_local_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(group->conf, PEER_FLAG_CAPABILITY_LINK_LOCAL);
	else
		peer_flag_unset(group->conf, PEER_FLAG_CAPABILITY_LINK_LOCAL);

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_LINK_LOCAL,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_link_local_destroy(struct nb_cb_destroy_args *args)
{
	struct bgp *bgp;
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_CAPABILITY_LINK_LOCAL,
				       bgp && CHECK_FLAG(bgp->flags,
							 BGP_FLAG_LINK_LOCAL_CAPABILITY));

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST,
			    CAPABILITY_CODE_LINK_LOCAL,
			    CHECK_FLAG(group->conf->flags, PEER_FLAG_CAPABILITY_LINK_LOCAL)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_fqdn_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;
	bool val;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	val = yang_dnode_get_bool(args->dnode, NULL);
	if (val)
		peer_flag_set(group->conf, PEER_FLAG_CAPABILITY_FQDN);
	else
		peer_flag_unset(group->conf, PEER_FLAG_CAPABILITY_FQDN);

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_FQDN,
			    val ? CAPABILITY_ACTION_SET : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_fqdn_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	bgp_nb_capability_flag_destroy(group->conf, PEER_FLAG_CAPABILITY_FQDN, true);

	bgp_capability_send(group->conf->connection, AFI_IP, SAFI_UNICAST, CAPABILITY_CODE_FQDN,
			    CHECK_FLAG(group->conf->flags, PEER_FLAG_CAPABILITY_FQDN)
				    ? CAPABILITY_ACTION_SET
				    : CAPABILITY_ACTION_UNSET);

	return NB_OK;
}

int instance_peer_group_capabilities_dont_capability_negotiate_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	if (yang_dnode_get_bool(args->dnode, NULL))
		peer_flag_set(group->conf, PEER_FLAG_DONT_CAPABILITY);
	else
		peer_flag_unset(group->conf, PEER_FLAG_DONT_CAPABILITY);

	return NB_OK;
}

int instance_peer_group_capabilities_override_capability_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (group && yang_dnode_get_bool(args->dnode, NULL) &&
		    CHECK_FLAG(group->conf->flags, PEER_FLAG_STRICT_CAP_MATCH)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set override-capability and strict-capability-match at the same time");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(group->conf, PEER_FLAG_OVERRIDE_CAPABILITY);
		else
			peer_flag_unset(group->conf, PEER_FLAG_OVERRIDE_CAPABILITY);
		break;
	}

	return NB_OK;
}

int instance_peer_group_capabilities_strict_capability_match_modify(struct nb_cb_modify_args *args)
{
	struct peer_group *group;

	switch (args->event) {
	case NB_EV_VALIDATE:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (group && yang_dnode_get_bool(args->dnode, NULL) &&
		    CHECK_FLAG(group->conf->flags, PEER_FLAG_OVERRIDE_CAPABILITY)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Can't set override-capability and strict-capability-match at the same time");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		if (yang_dnode_get_bool(args->dnode, NULL))
			peer_flag_set(group->conf, PEER_FLAG_STRICT_CAP_MATCH);
		else
			peer_flag_unset(group->conf, PEER_FLAG_STRICT_CAP_MATCH);
		break;
	}

	return NB_OK;
}

int instance_peer_group_rpki_strict_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/rpki-strict");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_sender_as_path_loop_detection_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/sender-as-path-loop-detection");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_path_attribute_discard_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/path-attribute-discard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_path_attribute_discard_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/path-attribute-discard");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_path_attribute_treat_as_withdraw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/path-attribute-treat-as-withdraw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_path_attribute_treat_as_withdraw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/path-attribute-treat-as-withdraw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_send_nexthop_characteristics_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/send-nexthop-characteristics");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_disable_link_bw_encoding_ieee_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/disable-link-bw-encoding-ieee");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_extended_link_bandwidth_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/extended-link-bandwidth");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int instance_peer_group_extended_optional_parameters_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp:instance/peer-group/extended-optional-parameters");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/* 'bgp listen range <A.B.C.D/M|X:X::X:X/M> peer-group PGNAME': dynamic
 * neighbor listen range, keyed on the range itself as a leaf-list under
 * the owning peer-group (bgp_config_write_listen(), bgp_vty.c). Only the
 * purely syntactic checks (malformed prefix, IPv6 link-local) run at
 * VALIDATE -- the legacy CLI's "peer-group must already have remote-as"
 * and cross-group same-range/overlap rejections both depend on other
 * peer-groups' live state, which is not settled until APPLY when this
 * range's own peer-group is being created in the same commit (the B1
 * create/remote-as-leaf ordering issue). peer_group_listen_range_add()
 * itself still enforces the remote-as precondition; a same-commit
 * cross-group duplicate/overlap is the one legacy check not replicated
 * here (documented gap, not a scope-drop: the legacy check lived in the
 * now-retired DEFUN, not in the setter).
 */
int instance_peer_group_listen_range_create(struct nb_cb_create_args *args)
{
	struct peer_group *group;
	struct prefix range;
	const char *range_str;
	afi_t afi;
	int ret;

	switch (args->event) {
	case NB_EV_VALIDATE:
		range_str = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix(range_str, &range)) {
			snprintf(args->errmsg, args->errmsg_len, "Malformed listen range: %s",
				 range_str);
			return NB_ERR_VALIDATION;
		}

		afi = family2afi(range.family);
		if (afi == AFI_IP6 && IN6_IS_ADDR_LINKLOCAL(&range.u.prefix6)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Malformed listen range (link-local address)");
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		group = bgp_nb_peer_group_lookup(args->dnode);
		if (!group)
			break;

		range_str = yang_dnode_get_string(args->dnode, NULL);
		if (!str2prefix(range_str, &range))
			break;
		apply_mask(&range);

		bgp_need_listening(group->bgp, NULL);

		ret = peer_group_listen_range_add(group, &range);
		if (ret) {
			flog_err(EC_BGP_INVALID_BGP_INSTANCE_ID,
				 "%s: peer_group_listen_range_add() failed for %s on %s: %d",
				 __func__, range_str, group->name, ret);
			return NB_ERR_RESOURCE;
		}
		break;
	}

	return NB_OK;
}

int instance_peer_group_listen_range_destroy(struct nb_cb_destroy_args *args)
{
	struct peer_group *group;
	struct prefix range;
	const char *range_str;
	struct bgp *bgp;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp = bgp_nb_instance_lookup(args->dnode);
	group = bgp_nb_peer_group_lookup(args->dnode);
	if (!group)
		return NB_OK;

	range_str = yang_dnode_get_string(args->dnode, NULL);
	if (!str2prefix(range_str, &range))
		return NB_OK;
	apply_mask(&range);

	/* peer_group_listen_range_del() also tears down every live dynamic
	 * peer that fell inside this range (bgpd.c) -- must be called
	 * rather than just dropping the prefix from a local list. */
	peer_group_listen_range_del(group, &range);

	if (bgp)
		bgp_may_stop_listening(bgp, NULL);

	return NB_OK;
}
