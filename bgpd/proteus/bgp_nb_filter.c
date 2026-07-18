// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp-filter northbound apply callbacks (M7 batches B6/B7).
 *
 * B6 brought the module from dead schema to live callbacks: bgp_nb.c flips
 * the module registration from its ignore_cfg_cbs stub to the real
 * callback table (whole-module activation -- the complete table must land
 * in the same commit as the flip, or nb_validate_callbacks() exit(1)s at
 * startup; the M6 B9 / M7 B4 regenerate-and-flip rule at module
 * granularity). B6 converted only the community-alias list; B7 (this
 * batch) converts as-path-access-list. The community, large-community and
 * extcommunity list surfaces stay reject-stubbed until M7 B8.
 */
#include <zebra.h>
#include "lib/northbound.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_filter.h"
#include "bgpd/bgp_regex.h"
#include "bgpd/bgp_nb.h"

/*
 * as-path-access-list (M7 batch B7).
 *
 * One 'bgp as-path access-list NAME [seq SEQ] <deny|permit> LINE...' line
 * per entry[sequence], replacing the retired bgp_filter.c DEFUNs. The
 * runtime state stays bgp_filter.c's as_list_master (same struct as_list /
 * struct as_filter, same add_hook/delete_hook wiring into
 * peer_aslist_add()/peer_aslist_del() -- bgpd.c -- for update-group
 * re-evaluation and route-map dependency notification); the northbound
 * entry points added there for this batch (as_list_filter_set()/_unset()/
 * as_list_delete_all()) are exactly the bodies of those DEFUNs minus CLI
 * argument parsing.
 *
 * Sequence-key vs. legacy content-match: the YANG entry list is keyed by
 * sequence, but the legacy DEFUNs resolved a 'no' command's target entry
 * by (action, regex) content match, silently ignoring any seq token the
 * user typed, and legacy's create silently discarded a content-duplicate
 * insert instead of erroring. Both of those content-based resolutions
 * belong to the CLI layer, which is the only place that still sees the
 * raw tokens without a sequence key (bgpd/proteus/bgp_cli_filter.c mirrors
 * lib/filter_cli.c's acl_get_seq()/acl_is_dup() pattern for the same
 * reason). By the time a change reaches here the sequence is already
 * resolved, so entry lookups below are straight bgp_aslist_seq_check()
 * calls, not content scans.
 *
 * Regex lifetime: bgp_regcomp() is called twice per entry -- once at
 * NB_EV_VALIDATE purely to reject an uncompilable pattern (freed
 * immediately, never stashed on args->resource: nothing here needs the
 * compiled object again before NB_EV_APPLY, and VALIDATE can run more than
 * once for the same edit), once at NB_EV_APPLY to build the object that
 * as_list_filter_set() actually links into the as_filter (ownership
 * transfers there, freed by as_filter_free() on delete/replace).
 */

int as_path_access_list_create(struct nb_cb_create_args *args)
{
	/* Lazily created by as_list_filter_set() when the first entry
	 * lands (mirrors as_list_get() inside the retired DEFUN, called
	 * unconditionally whether or not the list already existed). A
	 * list created with no entries at all -- unreachable from the CLI,
	 * which always pairs 'as-path-access-list create' with an entry --
	 * has nothing to do here. */
	return NB_OK;
}

int as_path_access_list_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Guts of the retired no_bgp_as_path_all_cmd: deletes every entry
	 * and fires the delete_hook once with the list's name (as_list_delete()
	 * itself doesn't fire it -- see as_list_delete_all()'s comment). No
	 * F_NB_CB_DESTROY_RECURSE on this node, so the child 'entry' list's
	 * own destroy callback never runs for a whole-list delete; tearing
	 * down every as_filter is this callback's job alone. */
	as_list_delete_all(yang_dnode_get_string(args->dnode, "name"));

	return NB_OK;
}

int as_path_access_list_entry_create(struct nb_cb_create_args *args)
{
	/* Real work happens in the regex leaf's modify below, once both
	 * mandatory sibling leaves (action, regex) are readable off the
	 * full candidate tree -- mirrors B6's community-alias entry_create/
	 * alias-name_modify split. */
	return NB_OK;
}

int as_path_access_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	struct as_list *aslist;
	struct as_filter *asfilter;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	aslist = as_list_lookup(yang_dnode_get_string(args->dnode, "../name"));
	if (!aslist)
		return NB_OK;

	asfilter = bgp_aslist_seq_check(aslist, yang_dnode_get_uint32(args->dnode, "sequence"));
	if (!asfilter)
		return NB_OK;

	as_list_filter_unset(aslist, asfilter);

	return NB_OK;
}

/* Shared by action_modify/regex_modify below: whichever mandatory sibling
 * leaf's value actually changed in a given commit re-applies the whole
 * entry off both siblings' current values. Unlike community-alias's single
 * mandatory leaf (B6's alias-name), an as-path entry has two (action,
 * regex), and a config line can be re-entered reusing the same sequence
 * while changing only one of them -- e.g. same regex, seq reused with the
 * other action, exercised by the bgp_aspath_list_policy_change topotest --
 * in which case the diff only carries a modify for that one leaf. Calling
 * this from both sides means a commit that changes both leaves re-applies
 * twice (idempotent: as_list_filter_set()'s bgp_aslist_seq_check() replace
 * path and the hook hierarchy underneath it tolerate being run twice with
 * the same end state), which is preferable to missing the change when only
 * one leaf's diff is present. */
static void as_path_access_list_entry_apply(const struct lyd_node *leaf_dnode)
{
	const struct lyd_node *entry_dnode = yang_dnode_get_parent(leaf_dnode, "entry");
	const char *name = yang_dnode_get_string(entry_dnode, "../name");
	const char *action = yang_dnode_get_string(entry_dnode, "action");
	const char *regex = yang_dnode_get_string(entry_dnode, "regex");
	uint32_t seq = yang_dnode_get_uint32(entry_dnode, "sequence");
	enum as_filter_type type = strcmp(action, "deny") == 0 ? AS_FILTER_DENY : AS_FILTER_PERMIT;
	struct frregex *compiled;

	/* Already proven compilable at NB_EV_VALIDATE (regex_modify below)
	 * whenever the regex leaf is part of this commit; if only action
	 * changed, this recompiles the entry's unchanged, already-valid
	 * regex text -- cheap and avoids stashing a compiled object across
	 * events for a leaf that isn't even part of this diff. */
	compiled = bgp_regcomp(regex);
	as_list_filter_set(name, (int64_t)seq, type, regex, compiled);
}

int as_path_access_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	as_path_access_list_entry_apply(args->dnode);

	return NB_OK;
}

int as_path_access_list_entry_regex_modify(struct nb_cb_modify_args *args)
{
	const char *regex;
	struct frregex *compiled;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Same order as the retired bgp_as_path_cmd: compile first,
		 * then the character-class check. */
		regex = yang_dnode_get_string(args->dnode, NULL);

		compiled = bgp_regcomp(regex);
		if (!compiled) {
			snprintf(args->errmsg, args->errmsg_len, "can't compile regexp %s", regex);
			return NB_ERR_VALIDATION;
		}
		bgp_regex_free(compiled);

		if (!config_bgp_aspath_validate(regex)) {
			snprintf(args->errmsg, args->errmsg_len,
				 "Invalid character in as-path access-list %s", regex);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
		break;
	case NB_EV_APPLY:
		as_path_access_list_entry_apply(args->dnode);
		break;
	}

	return NB_OK;
}

/*
 * Reject stubs: not-yet-converted proteus-bgp-filter surfaces (M7 B8).
 */

int community_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_type_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/type");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/action");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_member_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/member");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_member_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/member");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_well_known_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/well-known");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_well_known_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/well-known");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_raw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_communities_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/communities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_regex_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int community_list_entry_regex_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:community-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_type_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/type");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/action");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_member_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities/member");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_member_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities/member");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_raw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_large_communities_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/large-communities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_regex_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int large_community_list_entry_regex_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:large-community-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_type_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/type");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/action");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_target_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-target/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_as2_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_as2_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as2");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_as4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_as4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/as4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_ipv4_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_route_origin_ipv4_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/route-origin/ipv4");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_raw_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_extcommunities_raw_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/extcommunities/raw");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_regex_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int extcommunity_list_entry_regex_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:extcommunity-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

/*
 * community-alias (M7 batch B6).
 *
 * One 'bgp community alias COMMUNITY ALIAS' line, replacing the retired
 * bgp_vty.c DEFPY. The runtime state stays the pair of hashes in
 * bgp_community_alias.c (bgp_ca_community_insert() and friends): one keyed
 * by the community text (display substitution via bgp_community2alias()),
 * one keyed by the alias (route-map 'match alias' and reverse translation).
 * Uniqueness in both directions is the schema's job (list key on community,
 * 'unique' on alias-name), so apply only has to keep the two hashes in
 * step with the list.
 */

int community_alias_create(struct nb_cb_create_args *args)
{
	const char *community;
	struct community *comm;
	struct lcommunity *lcomm;
	uint8_t invalid = 0;

	switch (args->event) {
	case NB_EV_VALIDATE:
		/* Same acceptance check as the retired DEFPY: the text must
		 * parse as a community or as a large community. */
		community = yang_dnode_get_string(args->dnode, "community");
		comm = community_str2com(community);
		if (!comm)
			invalid++;
		community_free(&comm);

		lcomm = lcommunity_str2com(community);
		if (!lcomm)
			invalid++;
		lcommunity_free(&lcomm);

		if (invalid > 1) {
			snprintf(args->errmsg, args->errmsg_len, "Invalid community format: %s",
				 community);
			return NB_ERR_VALIDATION;
		}
		break;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		/* The mandatory alias-name leaf's modify does the insert. */
		break;
	}

	return NB_OK;
}

/* Drop the hash pair mapping this community, if any (both hashes hold their
 * own allocation for the pair, released separately). */
static void community_alias_drop(struct community_alias *ca)
{
	struct community_alias *found = bgp_ca_community_lookup(ca);
	struct community_alias pair;

	if (!found)
		return;

	pair = *found;
	bgp_ca_alias_delete(&pair);
	bgp_ca_community_delete(&pair);
}

int community_alias_destroy(struct nb_cb_destroy_args *args)
{
	struct community_alias ca = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	strlcpy(ca.community, yang_dnode_get_string(args->dnode, "community"),
		sizeof(ca.community));
	community_alias_drop(&ca);

	return NB_OK;
}

int community_alias_alias_name_modify(struct nb_cb_modify_args *args)
{
	struct community_alias ca = {};

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	strlcpy(ca.community, yang_dnode_get_string(args->dnode, "../community"),
		sizeof(ca.community));

	/* Re-aliasing an already-aliased community replaces its mapping. */
	community_alias_drop(&ca);

	strlcpy(ca.alias, yang_dnode_get_string(args->dnode, NULL), sizeof(ca.alias));
	bgp_ca_alias_insert(&ca);
	bgp_ca_community_insert(&ca);

	return NB_OK;
}
