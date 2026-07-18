// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound apply callbacks for the proteus-bgp-dump module (MRT dump
 * configuration, M7 batch B9), registered by the proteus_bgp_dump_info
 * table in bgpd/bgp_nb.c.
 *
 * Each of the module's three presence containers ('all' / 'updates' /
 * 'routes-mrt') is one atomic legacy command whose application always
 * restarts the dump stream from scratch (reopen the file, reschedule the
 * interval timer), so the whole container converts through a single
 * apply_finish callback: it fires once per commit, after every other
 * callback, with the container from the NEW tree, rereading the complete
 * (path, interval, extended-timestamp) tuple and handing it to
 * bgp_dump_target_set() (bgp_dump.c, the extracted legacy transition
 * machinery). The per-leaf callbacks below therefore accept every event
 * and do nothing. The container's destroy tears the stream down;
 * northbound skips a destroyed container's own apply_finish, so 'no dump
 * bgp ...' cannot transiently re-apply. Interval validation is entirely
 * the schema's (the dump-interval typedef's two patterns admit exactly
 * the strings the legacy parser accepted with a non-zero result), so no
 * VALIDATE-phase work is needed here.
 */
#include <zebra.h>

#include "northbound.h"

#include "bgpd/bgp_dump.h"
#include "bgpd/bgp_nb.h"

static void bgp_nb_dump_target_apply_finish(const struct lyd_node *dnode,
					    enum bgp_dump_target target, bool has_et)
{
	const char *interval_str = NULL;
	bool extended_timestamp = false;

	if (yang_dnode_exists(dnode, "interval"))
		interval_str = yang_dnode_get_string(dnode, "interval");
	if (has_et)
		extended_timestamp = yang_dnode_get_bool(dnode, "extended-timestamp");

	bgp_dump_target_set(target, yang_dnode_get_string(dnode, "path"), interval_str,
			    extended_timestamp);
}

/*
 * XPath: /proteus-bgp-dump:dump/all
 */
int dump_all_create(struct nb_cb_create_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_all_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_dump_target_unset(BGP_DUMP_TARGET_ALL);

	return NB_OK;
}

void dump_all_apply_finish(struct nb_cb_apply_finish_args *args)
{
	bgp_nb_dump_target_apply_finish(args->dnode, BGP_DUMP_TARGET_ALL, true);
}

/*
 * XPath: /proteus-bgp-dump:dump/all/path
 */
int dump_all_path_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/all/interval
 */
int dump_all_interval_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_all_interval_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/all/extended-timestamp
 */
int dump_all_extended_timestamp_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/updates
 */
int dump_updates_create(struct nb_cb_create_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_updates_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_dump_target_unset(BGP_DUMP_TARGET_UPDATES);

	return NB_OK;
}

void dump_updates_apply_finish(struct nb_cb_apply_finish_args *args)
{
	bgp_nb_dump_target_apply_finish(args->dnode, BGP_DUMP_TARGET_UPDATES, true);
}

/*
 * XPath: /proteus-bgp-dump:dump/updates/path
 */
int dump_updates_path_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/updates/interval
 */
int dump_updates_interval_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_updates_interval_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/updates/extended-timestamp
 */
int dump_updates_extended_timestamp_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/routes-mrt
 */
int dump_routes_mrt_create(struct nb_cb_create_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_routes_mrt_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bgp_dump_target_unset(BGP_DUMP_TARGET_ROUTES);

	return NB_OK;
}

void dump_routes_mrt_apply_finish(struct nb_cb_apply_finish_args *args)
{
	bgp_nb_dump_target_apply_finish(args->dnode, BGP_DUMP_TARGET_ROUTES, false);
}

/*
 * XPath: /proteus-bgp-dump:dump/routes-mrt/path
 */
int dump_routes_mrt_path_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp-dump:dump/routes-mrt/interval
 */
int dump_routes_mrt_interval_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}

int dump_routes_mrt_interval_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the container's apply_finish does the work, see above. */
	return NB_OK;
}
