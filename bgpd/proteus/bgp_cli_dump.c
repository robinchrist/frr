// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* MRT dump CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-dump module, compiled into mgmtd alongside its bgp_cli_*
 * siblings (M7 batch B9, replacing bgpd/bgp_dump.c's DEFUNs).
 */
#include <zebra.h>

#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_dump_clippy.c"

/* The five type tokens collapse onto the module's three presence
 * containers: '-et' is the packet-dump kinds' extended-timestamp leaf,
 * not a stream of its own. Re-entering a command replaces that stream's
 * whole tuple (an omitted INTERVAL deletes a previously configured one,
 * like the legacy unset+set did); the 'no' form deletes the container
 * and, like the legacy command, ignores any PATH/INTERVAL arguments.
 */
static const char *bgp_dump_type_container(const char *type, const char **extended_timestamp)
{
	*extended_timestamp = NULL;

	if (strmatch(type, "all") || strmatch(type, "all-et")) {
		*extended_timestamp = strmatch(type, "all-et") ? "true" : "false";
		return "all";
	}
	if (strmatch(type, "updates") || strmatch(type, "updates-et")) {
		*extended_timestamp = strmatch(type, "updates-et") ? "true" : "false";
		return "updates";
	}
	return "routes-mrt";
}

DEFPY_YANG (dump_bgp,
	    dump_bgp_cli_cmd,
	    "dump bgp <all|all-et|updates|updates-et|routes-mrt>$type PATH$path [INTERVAL$interval]",
	    "Dump packet\n"
	    "BGP packet dump\n"
	    "Dump all BGP packets\nDump all BGP packets (Extended Timestamp Header)\n"
	    "Dump BGP updates only\nDump BGP updates only (Extended Timestamp Header)\n"
	    "Dump whole BGP routing table\n"
	    "Output filename\n"
	    "Interval of output\n")
{
	const char *extended_timestamp;
	const char *container = bgp_dump_type_container(type, &extended_timestamp);
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-dump:dump/%s", container);

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-dump:dump/%s/path", container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, path);

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-dump:dump/%s/interval", container);
	nb_cli_enqueue_change(vty, xpath, interval ? NB_OP_MODIFY : NB_OP_DESTROY, interval);

	if (extended_timestamp) {
		snprintf(xpath, sizeof(xpath), "/proteus-bgp-dump:dump/%s/extended-timestamp",
			 container);
		nb_cli_enqueue_change(vty, xpath, NB_OP_MODIFY, extended_timestamp);
	}

	return nb_cli_apply_changes(vty, NULL);
}

DEFPY_YANG (no_dump_bgp,
	    no_dump_bgp_cli_cmd,
	    "no dump bgp <all|all-et|updates|updates-et|routes-mrt>$type [PATH [INTERVAL]]",
	    NO_STR
	    "Stop dump packet\n"
	    "Stop BGP packet dump\n"
	    "Stop dump process all\n"
	    "Stop dump process all-et\n"
	    "Stop dump process updates\n"
	    "Stop dump process updates-et\n"
	    "Stop dump process route-mrt\n"
	    "Output filename\n"
	    "Interval of output\n")
{
	const char *extended_timestamp;
	const char *container = bgp_dump_type_container(type, &extended_timestamp);
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-dump:dump/%s", container);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* One emitter for all three containers: the container's schema name is
 * the type token, except that the packet-dump kinds render their '-et'
 * spelling when extended-timestamp is set.
 */
static void dump_target_cli_write(struct vty *vty, const struct lyd_node *dnode)
{
	const char *type_str = dnode->schema->name;

	if (yang_dnode_exists(dnode, "extended-timestamp") &&
	    yang_dnode_get_bool(dnode, "extended-timestamp")) {
		if (strmatch(type_str, "all"))
			type_str = "all-et";
		else
			type_str = "updates-et";
	}

	vty_out(vty, "dump bgp %s %s", type_str, yang_dnode_get_string(dnode, "path"));
	if (yang_dnode_exists(dnode, "interval"))
		vty_out(vty, " %s", yang_dnode_get_string(dnode, "interval"));
	vty_out(vty, "\n");
}

static void dump_all_cli_write(struct vty *vty, const struct lyd_node *dnode, bool show_defaults)
{
	dump_target_cli_write(vty, dnode);
}

static void dump_updates_cli_write(struct vty *vty, const struct lyd_node *dnode,
				   bool show_defaults)
{
	dump_target_cli_write(vty, dnode);
}

static void dump_routes_mrt_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	dump_target_cli_write(vty, dnode);
}

/* clang-format off */
const struct frr_yang_module_info proteus_bgp_dump_cli_info = {
	.name = "proteus-bgp-dump",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp-dump:dump/all",
			.cbs = {
				.cli_show = dump_all_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-dump:dump/updates",
			.cbs = {
				.cli_show = dump_updates_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-dump:dump/routes-mrt",
			.cbs = {
				.cli_show = dump_routes_mrt_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void bgp_cli_dump_init(void)
{
	install_element(CONFIG_NODE, &dump_bgp_cli_cmd);
	install_element(CONFIG_NODE, &no_dump_bgp_cli_cmd);
}
