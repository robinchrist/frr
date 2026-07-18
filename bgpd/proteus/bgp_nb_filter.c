// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp-filter northbound apply callbacks (M7 batch B6).
 *
 * First live batch for the proteus-bgp-filter module: bgp_nb.c flips the
 * module registration from its ignore_cfg_cbs stub to the real callback
 * table (whole-module activation -- the complete table must land in the
 * same commit as the flip, or nb_validate_callbacks() exit(1)s at
 * startup; the M6 B9 / M7 B4 regenerate-and-flip rule at module
 * granularity).
 *
 * This batch converts only the community-alias list. The as-path,
 * community, large-community and extcommunity list surfaces stay
 * reject-stubbed until their own batches (M7 B7/B8).
 */
#include <zebra.h>
#include "lib/northbound.h"
#include "bgpd/bgpd.h"
#include "bgpd/bgp_community.h"
#include "bgpd/bgp_lcommunity.h"
#include "bgpd/bgp_community_alias.h"
#include "bgpd/bgp_nb.h"

/*
 * Reject stubs: not-yet-converted proteus-bgp-filter surfaces (M7 B7/B8).
 */

int as_path_access_list_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int as_path_access_list_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int as_path_access_list_entry_create(struct nb_cb_create_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int as_path_access_list_entry_destroy(struct nb_cb_destroy_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list/entry");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int as_path_access_list_entry_action_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list/entry/action");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

int as_path_access_list_entry_regex_modify(struct nb_cb_modify_args *args)
{
	switch (args->event) {
	case NB_EV_VALIDATE:
		snprintf(args->errmsg, args->errmsg_len, "not yet implemented: %s",
			 "/proteus-bgp-filter:as-path-access-list/entry/regex");
		return NB_ERR_VALIDATION;
	case NB_EV_PREPARE:
	case NB_EV_ABORT:
	case NB_EV_APPLY:
		break;
	}

	return NB_OK;
}

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
