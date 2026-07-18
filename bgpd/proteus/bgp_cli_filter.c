// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Global-filter CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-filter module, compiled into mgmtd alongside its bgp_cli_*
 * siblings.
 *
 * M7 batch B6 converts only 'bgp community alias'; the as-path /
 * community / large-community / extcommunity list commands follow in
 * their own batches (M7 B7/B8) and are still bgpd-native.
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_cli_filter_clippy.c"

/* The community text is the list key; the alias direction is unique via
 * the schema, so re-entering the command with the same community and a
 * new alias re-aliases that community. The 'no' form removes whatever
 * alias the community carries; like the legacy command, it does not
 * require the given alias to match. */
DEFPY_YANG(bgp_community_alias, bgp_community_alias_cli_cmd,
	   "[no$no] bgp community alias WORD$community ALIAS_NAME$alias_name",
	   NO_STR BGP_STR
	   "Add community specific parameters\n"
	   "Create an alias for a community\n"
	   "Community (AA:BB or AA:BB:CC)\n"
	   "Alias name\n")
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:community-alias[community='%s']",
		 community);

	if (no) {
		nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);
	} else {
		char xpath_alias[XPATH_MAXLEN];

		snprintf(xpath_alias, sizeof(xpath_alias),
			 "/proteus-bgp-filter:community-alias[community='%s']/alias-name",
			 community);
		nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
		nb_cli_enqueue_change(vty, xpath_alias, NB_OP_MODIFY, alias_name);
	}

	return nb_cli_apply_changes(vty, NULL);
}

static void community_alias_cli_write(struct vty *vty, const struct lyd_node *dnode,
				      bool show_defaults)
{
	vty_out(vty, "bgp community alias %s %s\n", yang_dnode_get_string(dnode, "community"),
		yang_dnode_get_string(dnode, "alias-name"));
}

/* clang-format off */
const struct frr_yang_module_info proteus_bgp_filter_cli_info = {
	.name = "proteus-bgp-filter",
	.ignore_cfg_cbs = true,
	.nodes = {
		{
			.xpath = "/proteus-bgp-filter:community-alias",
			.cbs = {
				.cli_show = community_alias_cli_write,
			}
		},
		{
			.xpath = NULL,
		},
	}
};
/* clang-format on */

void bgp_cli_filter_init(void)
{
	install_element(CONFIG_NODE, &bgp_community_alias_cli_cmd);
}
