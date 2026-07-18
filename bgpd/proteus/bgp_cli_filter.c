// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Global-filter CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-filter module, compiled into mgmtd alongside its bgp_cli_*
 * siblings.
 *
 * M7 batch B6 converted 'bgp community alias'; B7 (this batch) adds
 * as-path-access-list. The community / large-community / extcommunity
 * list commands follow in M7 B8 and are still bgpd-native.
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

/*
 * as-path-access-list (M7 batch B7).
 *
 * This CLI file runs in mgmtd's process, not bgpd's -- there is no
 * as_list_master here, only the candidate datastore (see the design note
 * at the top of bgp_cli_neighbor.c). Every disambiguation that the retired
 * bgp_filter.c DEFUNs did against the native as_list/as_filter structures
 * is done here instead against vty->candidate_config, mirroring
 * lib/filter_cli.c's acl_get_seq()/acl_is_dup() pattern for the same
 * legacy-CLI-content-addressing problem (Cisco-style access-lists are also
 * keyed by sequence in YANG but resolved by content in their legacy 'no'
 * form).
 */

struct as_path_entry_match_ctx {
	const char *action;
	const char *regex;
	bool found;
	uint32_t sequence;
};

static int as_path_entry_match_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct as_path_entry_match_ctx *ctx = arg;

	if (strcmp(yang_dnode_get_string(dnode, "action"), ctx->action) != 0)
		return YANG_ITER_CONTINUE;
	if (strcmp(yang_dnode_get_string(dnode, "regex"), ctx->regex) != 0)
		return YANG_ITER_CONTINUE;

	ctx->found = true;
	ctx->sequence = yang_dnode_get_uint32(dnode, "sequence");

	return YANG_ITER_STOP;
}

/* Mirrors as_list_dup_check()/as_filter_lookup() (bgp_filter.c, retired):
 * both matched by (action, regex) content, not by sequence. Returns the
 * matching entry's sequence key via 'sequence' (may be NULL). */
static bool as_path_entry_find(struct vty *vty, const char *name, const char *action,
			       const char *regex, uint32_t *sequence)
{
	struct as_path_entry_match_ctx ctx = { .action = action, .regex = regex };

	yang_dnode_iterate(as_path_entry_match_iter_cb, &ctx, vty->candidate_config->dnode,
			   "/proteus-bgp-filter:as-path-access-list[name='%s']/entry", name);

	if (ctx.found && sequence)
		*sequence = ctx.sequence;

	return ctx.found;
}

static int as_path_entry_max_seq_iter_cb(const struct lyd_node *dnode, void *arg)
{
	int64_t *maxseq = arg;
	int64_t cur = yang_dnode_get_uint32(dnode, "sequence");

	if (cur > *maxseq)
		*maxseq = cur;

	return YANG_ITER_CONTINUE;
}

/* bgp_alist_new_seq_get()'s formula (bgp_filter.c, retired): round the
 * current max sequence down to a multiple of 5, then add 5. */
static uint32_t as_path_next_seq(struct vty *vty, const char *name)
{
	int64_t maxseq = 0;
	int64_t newseq;

	yang_dnode_iterate(as_path_entry_max_seq_iter_cb, &maxseq, vty->candidate_config->dnode,
			   "/proteus-bgp-filter:as-path-access-list[name='%s']/entry", name);

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT32_MAX) ? UINT32_MAX : (uint32_t)newseq;
}

DEFPY_YANG(
	bgp_as_path_access_list, bgp_as_path_access_list_cli_cmd,
	"bgp as-path access-list AS_PATH_FILTER_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	"BGP autonomous system path filter\n"
	"Specify an access list name\n"
	"Regular expression access list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify packets to reject\n"
	"Specify packets to forward\n"
	"A regular-expression (1234567890_^|[,{}() ]$*+.?-\\) to match the BGP AS paths\n")
{
	int idx = 0;
	char *regstr;
	char xpath[XPATH_MAXLEN];
	char xpath_entry[XPATH_MAXLEN + 32];
	int ret;

	argv_find(argv, argc, "LINE", &idx);
	regstr = argv_concat(argv, argc, idx);

	/* Backward compatibility: a content-duplicate insert is silently
	 * absorbed, not an error (as_list_dup_check() in the retired
	 * bgp_as_path_cmd). */
	if (as_path_entry_find(vty, name, action, regstr, NULL)) {
		XFREE(MTYPE_TMP, regstr);
		return CMD_SUCCESS;
	}

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:as-path-access-list[name='%s']", name);

	if (seq_str != NULL)
		snprintf(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%s']", xpath,
			 seq_str);
	else
		snprintf(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%u']", xpath,
			 as_path_next_seq(vty, name));

	nb_cli_enqueue_change(vty, xpath, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nb_cli_enqueue_change(vty, "./regex", NB_OP_MODIFY, regstr);

	/* nb_cli_apply_changes() reads the enqueued value strings, so the
	 * free has to come after -- freeing regstr before use here caused a
	 * heap-use-after-free in mgmt_vty_read_configs() (topotest ASAN). */
	ret = nb_cli_apply_changes(vty, "%s", xpath_entry);

	XFREE(MTYPE_TMP, regstr);

	return ret;
}

DEFPY_YANG(
	no_bgp_as_path_access_list, no_bgp_as_path_access_list_cli_cmd,
	"no bgp as-path access-list AS_PATH_FILTER_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR BGP_STR
	"BGP autonomous system path filter\n"
	"Specify an access list name\n"
	"Regular expression access list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify packets to reject\n"
	"Specify packets to forward\n"
	"A regular-expression (1234567890_^|[,{}() ]$*+.?-\\) to match the BGP AS paths\n")
{
	int idx = 0;
	char *regstr;
	uint32_t sequence;
	char xpath[XPATH_MAXLEN];
	int ret;

	if (!yang_dnode_existsf(vty->candidate_config->dnode,
				"/proteus-bgp-filter:as-path-access-list[name='%s']", name)) {
		vty_out(vty, "bgp as-path access-list %s doesn't exist\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	argv_find(argv, argc, "LINE", &idx);
	regstr = argv_concat(argv, argc, idx);

	/* Same as the retired no_bgp_as_path_cmd: the seq token (if given)
	 * is accepted syntactically but ignored -- the entry to remove is
	 * always resolved by (action, regex) content match. */
	if (!as_path_entry_find(vty, name, action, regstr, &sequence)) {
		vty_out(vty, "Regex entered %s does not exist\n", regstr);
		XFREE(MTYPE_TMP, regstr);
		return CMD_WARNING_CONFIG_FAILED;
	}

	XFREE(MTYPE_TMP, regstr);

	snprintf(xpath, sizeof(xpath),
		 "/proteus-bgp-filter:as-path-access-list[name='%s']/entry[sequence='%u']", name,
		 sequence);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

DEFPY_YANG(no_bgp_as_path_access_list_all, no_bgp_as_path_access_list_all_cli_cmd,
	   "no bgp as-path access-list AS_PATH_FILTER_NAME$name",
	   NO_STR BGP_STR
	   "BGP autonomous system path filter\n"
	   "Specify an access list name\n"
	   "Regular expression access list name\n")
{
	char xpath[XPATH_MAXLEN];
	int ret;

	if (!yang_dnode_existsf(vty->candidate_config->dnode,
				"/proteus-bgp-filter:as-path-access-list[name='%s']", name)) {
		vty_out(vty, "bgp as-path access-list %s doesn't exist\n", name);
		return CMD_WARNING_CONFIG_FAILED;
	}

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:as-path-access-list[name='%s']", name);
	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	ret = nb_cli_apply_changes(vty, NULL);

	return ret;
}

/* One line per entry, no separate line for the list container -- matches
 * the retired config_write_as_list()'s flat per-filter emission. */
static void as_path_access_list_entry_cli_write(struct vty *vty, const struct lyd_node *dnode,
						bool show_defaults)
{
	vty_out(vty, "bgp as-path access-list %s seq %s %s %s\n",
		yang_dnode_get_string(dnode, "../name"), yang_dnode_get_string(dnode, "sequence"),
		yang_dnode_get_string(dnode, "action"), yang_dnode_get_string(dnode, "regex"));
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
			.xpath = "/proteus-bgp-filter:as-path-access-list/entry",
			.cbs = {
				.cli_show = as_path_access_list_entry_cli_write,
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

	install_element(CONFIG_NODE, &bgp_as_path_access_list_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_access_list_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_as_path_access_list_all_cli_cmd);
}
