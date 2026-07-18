// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Global-filter CLI (DEFPYs + northbound cli_show callbacks) for the
 * proteus-bgp-filter module, compiled into mgmtd alongside its bgp_cli_*
 * siblings.
 *
 * M7 batch B6 converted 'bgp community alias', B7 as-path-access-list,
 * B8 the community / large-community / extcommunity lists -- the module
 * has no bgpd-native config commands left.
 */
#include <zebra.h>
#include "command.h"
#include "northbound.h"
#include "northbound_cli.h"
#include "vty.h"

#include "bgpd/bgp_vty.h"
#include "bgpd/bgp_cli.h"
#include "bgpd/proteus/bgp_cli_local.h"
#include "bgpd/proteus/bgp_filter_value.h"
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

/*
 * community-list / large-community-list / extcommunity-list (M7 batch B8).
 *
 * Shared machinery for the three list kinds: the legacy commands differ
 * only in their value grammar (community tokens, GA:LD1:LD2 large
 * communities, keyword-tagged rt/soo extended communities, or a regex for
 * the expanded styles), so each DEFPY parses its values into entry-relative
 * xpath fragments (or the regex string) and hands off to clist_cli_add() /
 * clist_cli_del() / clist_cli_del_all().
 *
 * Legacy content semantics, reproduced here against the candidate config
 * (the B7 as-path pattern -- mgmtd has no bgp_clist runtime state):
 *
 * - Create silently absorbs a content duplicate (same action + same value
 *   set, ANY sequence -- bgp_clist.c's community_list_dup_check() ran
 *   before its sequence-replace check), and re-entering an existing
 *   sequence replaces that entry wholly (the enqueue destroys the old
 *   entry first so stale value children cannot linger).
 * - An omitted 'seq' takes bgp_clist_new_seq_get()'s formula,
 *   ((maxseq/5)*5)+5, computed over the candidate entries.
 * - 'no' with a value resolves its target entry by (action, value) content
 *   match, silently ignoring any seq token typed, and is silently
 *   accepted when nothing matches (the retired community_list_unset()
 *   family returned void); removing a list's last entry removes the list,
 *   as community_list_entry_delete() did natively.
 * - Mixing styles under one name is refused with the legacy
 *   community_list_perror() texts.
 *
 * Value canonicalization: standard values are parsed into the schema's
 * typed sets right here (the structured-values philosophy of the module;
 * numeric tokens carrying a well-known community value are canonicalized
 * to their name, exactly as community_str() re-emitted them), so content
 * comparison is a set comparison over the candidate entry's children --
 * order-insensitive and duplicate-free like the legacy binary sets.
 * Extended-community values FRR parses but the schema does not structure
 * (nt / color / rt6 keywords) ride the raw leaf-list as verbatim
 * 'KEYWORD VALUE' pairs. Overflowing admin values are rejected outright
 * rather than silently wrapped (the EVPN route-target precedent from M6
 * B9b applies to ecommunity_gettoken()'s unchecked accumulator here too).
 *
 * NUMBERED LISTS ARE NORMALIZED TO NAMED (approved 2026-07-18): the
 * legacy numbered grammars -- '(1-99)' standard, '(100-500)' expanded,
 * written without the style keyword and excluded from the YANG (module
 * description) -- survive as deprecated, hidden aliases that write a
 * NAMED list whose name is the number's decimal string, inferring the
 * style from the range exactly as the legacy DEFUNs did. One model shape;
 * a numbered config line round-trips as its named spelling ('bgp
 * community-list 42 ...' re-emits as 'bgp community-list standard 42
 * ...', which parses back into the same list).
 */

/* "community-list" keyword help strings (legacy bgp_vty.c). */
#define COMMUNITY_LIST_STR    "Add a community list entry\n"
#define LCOMMUNITY_LIST_STR   "Add a large community list entry\n"
#define LCOMMUNITY_VAL_STR    "large community in 'aa:bb:cc' format\n"
#define EXTCOMMUNITY_LIST_STR "Add a extended community list entry\n"
#define EXTCOMMUNITY_VAL_STR                                                                      \
	"Extended community attribute in 'rt aa:nn_or_IPaddr:nn' OR 'soo aa:nn_or_IPaddr:nn' format\n"

enum clist_kind { CLIST_COMMUNITY, CLIST_LARGE, CLIST_EXT };

static const char *const clist_list_name[] = {
	[CLIST_COMMUNITY] = "community-list",
	[CLIST_LARGE] = "large-community-list",
	[CLIST_EXT] = "extcommunity-list",
};

static const char *const clist_value_container[] = {
	[CLIST_COMMUNITY] = "communities",
	[CLIST_LARGE] = "large-communities",
	[CLIST_EXT] = "extcommunities",
};

/* One parsed standard value: the xpath fragment below the entry it maps
 * to (member / well-known / raw list instance). */
#define CLIST_FRAG_LEN 256

/* Parse one community token (community_gettoken()'s exact acceptance:
 * a well-known name or 'AA:NN' with both halves decimal <= 65535; note
 * plain 'NN' without a colon is NOT accepted by community_valid()). */
static bool clist_community_token_frag(const char *token, char *frag, size_t frag_len)
{
	unsigned long ga, la;
	const char *lstart;
	const char *name;
	char *endptr;
	uint32_t val;

	if (bgp_filter_well_known_community(token, &val)) {
		snprintf(frag, frag_len, "communities/well-known[.='%s']", token);
		return true;
	}

	if (!isdigit((unsigned char)token[0]))
		return false;
	errno = 0;
	ga = strtoul(token, &endptr, 10);
	if (errno || *endptr != ':' || ga > UINT16_MAX)
		return false;
	lstart = endptr + 1;
	if (!isdigit((unsigned char)*lstart))
		return false;
	errno = 0;
	la = strtoul(lstart, &endptr, 10);
	if (errno || *endptr != '\0' || la > UINT16_MAX)
		return false;

	/* Numeric spelling of a well-known value canonicalizes to the name,
	 * as community_str() re-emitted it. */
	val = ((uint32_t)ga << 16) | (uint32_t)la;
	name = bgp_filter_well_known_community_name(val);
	if (name)
		snprintf(frag, frag_len, "communities/well-known[.='%s']", name);
	else
		snprintf(frag, frag_len,
			 "communities/member[global-admin='%lu'][local-admin='%lu']", ga, la);

	return true;
}

/* Parse one 'GA:LD1:LD2' large-community token (lcommunity_list_valid()'s
 * acceptance: exactly three all-digit parts, each <= 4294967295). */
static bool clist_large_token_frag(const char *token, char *frag, size_t frag_len)
{
	unsigned long part[3];
	const char *p = token;
	char *endptr;

	for (int i = 0; i < 3; i++) {
		if (!isdigit((unsigned char)*p))
			return false;
		errno = 0;
		part[i] = strtoul(p, &endptr, 10);
		if (errno || part[i] > UINT32_MAX)
			return false;
		if (i < 2) {
			if (*endptr != ':')
				return false;
			p = endptr + 1;
		} else if (*endptr != '\0') {
			return false;
		}
	}

	snprintf(frag, frag_len,
		 "large-communities/member[global-admin='%lu'][local-data-1='%lu'][local-data-2='%lu']",
		 part[0], part[1], part[2]);

	return true;
}

static const char *const clist_rt_case_name[] = {
	[BGP_CLI_SOO_AS2] = "as2",
	[BGP_CLI_SOO_AS4] = "as4",
	[BGP_CLI_SOO_IPV4] = "ipv4",
};

/* Parse the standard value tokens of one config line (argv[idx..argc-1])
 * into a deduplicated fragment array (XCALLOC'd, caller frees). Community
 * and large-community lines are one token per value; extcommunity lines
 * alternate KEYWORD VALUE strictly (ecommunity_str2com() with
 * keyword_included resets its keyword state after every value). Returns
 * false (nothing allocated, legacy 'Malformed community-list value'
 * printed) on any unparseable token. */
static bool clist_parse_values(struct vty *vty, enum clist_kind kind, struct cmd_token **argv,
			       int argc, int idx, char (**frags_out)[CLIST_FRAG_LEN],
			       int *nfrags_out)
{
	char (*frags)[CLIST_FRAG_LEN];
	int nfrags = 0;

	frags = XCALLOC(MTYPE_TMP, (size_t)(argc - idx) * sizeof(*frags));

	for (int i = idx; i < argc; i++) {
		const char *token = argv[i]->arg;
		bool ok;

		if (kind == CLIST_COMMUNITY) {
			ok = clist_community_token_frag(token, frags[nfrags], CLIST_FRAG_LEN);
		} else if (kind == CLIST_LARGE) {
			ok = clist_large_token_frag(token, frags[nfrags], CLIST_FRAG_LEN);
		} else if (strmatch(token, "rt") || strmatch(token, "soo")) {
			enum bgp_cli_soo_case rt_case;
			char global_admin[INET_ADDRSTRLEN], local_admin[12];

			ok = i + 1 < argc && bgp_cli_soo_parse(argv[i + 1]->arg, &rt_case,
							       global_admin, sizeof(global_admin),
							       local_admin, sizeof(local_admin));
			if (ok) {
				snprintf(frags[nfrags], CLIST_FRAG_LEN,
					 "extcommunities/%s/%s[global-admin='%s'][local-admin='%s']",
					 strmatch(token, "rt") ? "route-target" : "route-origin",
					 clist_rt_case_name[rt_case], global_admin, local_admin);
				i++;
			}
		} else if (strmatch(token, "nt") || strmatch(token, "color") ||
			   strmatch(token, "rt6")) {
			/* FRR parses these keyword-tagged values but the schema
			 * does not structure them: verbatim raw pairs, validated
			 * by the northbound side with ecommunity_str2com(). */
			ok = i + 1 < argc;
			if (ok) {
				snprintf(frags[nfrags], CLIST_FRAG_LEN,
					 "extcommunities/raw[.='%s %s']", token, argv[i + 1]->arg);
				i++;
			}
		} else {
			ok = false;
		}

		if (!ok) {
			vty_out(vty, "%% Malformed community-list value\n");
			XFREE(MTYPE_TMP, frags);
			return false;
		}

		/* The legacy parsers deduplicated (community_uniq_sort() /
		 * the sorted-insert add_val duplicate checks). */
		bool dup = false;

		for (int j = 0; j < nfrags; j++) {
			if (strcmp(frags[j], frags[nfrags]) == 0) {
				dup = true;
				break;
			}
		}
		if (!dup)
			nfrags++;
	}

	*frags_out = frags;
	*nfrags_out = nfrags;

	return true;
}

/* Content match over the candidate entries -- the CLI-layer stand-in for
 * community_list_dup_check() and community_list_entry_lookup() (both
 * matched by (direct, value), never by sequence). A standard entry
 * matches when the action matches, the value-child count matches and
 * every parsed fragment exists (set equality against the deduplicated
 * fragment set); an expanded entry matches on the verbatim regex. */
struct clist_entry_match_ctx {
	const char *value_container;
	const char *action;
	const char *regex;
	char (*frags)[CLIST_FRAG_LEN];
	int nfrags;
	bool found;
	uint32_t sequence;
};

static int clist_entry_match_iter_cb(const struct lyd_node *dnode, void *arg)
{
	struct clist_entry_match_ctx *ctx = arg;

	if (!strmatch(yang_dnode_get_string(dnode, "action"), ctx->action))
		return YANG_ITER_CONTINUE;

	if (ctx->regex) {
		if (!yang_dnode_exists(dnode, "regex") ||
		    strcmp(yang_dnode_get_string(dnode, "regex"), ctx->regex) != 0)
			return YANG_ITER_CONTINUE;
	} else {
		const struct lyd_node *container = yang_dnode_get(dnode, ctx->value_container);
		const struct lyd_node *child;
		int count = 0;

		if (!container)
			return YANG_ITER_CONTINUE;

		LY_LIST_FOR (lyd_child(container), child)
			count++;
		if (count != ctx->nfrags)
			return YANG_ITER_CONTINUE;

		for (int i = 0; i < ctx->nfrags; i++)
			if (!yang_dnode_exists(dnode, ctx->frags[i]))
				return YANG_ITER_CONTINUE;
	}

	ctx->found = true;
	ctx->sequence = yang_dnode_get_uint32(dnode, "sequence");

	return YANG_ITER_STOP;
}

static bool clist_entry_find(struct vty *vty, enum clist_kind kind, const char *name,
			     struct clist_entry_match_ctx *ctx)
{
	ctx->value_container = clist_value_container[kind];
	ctx->found = false;

	yang_dnode_iterate(clist_entry_match_iter_cb, ctx, vty->candidate_config->dnode,
			   "/proteus-bgp-filter:%s[name='%s']/entry", clist_list_name[kind], name);

	return ctx->found;
}

static int clist_entry_count_iter_cb(const struct lyd_node *dnode, void *arg)
{
	(*(int *)arg)++;
	return YANG_ITER_CONTINUE;
}

static int clist_entry_count(struct vty *vty, enum clist_kind kind, const char *name)
{
	int count = 0;

	yang_dnode_iterate(clist_entry_count_iter_cb, &count, vty->candidate_config->dnode,
			   "/proteus-bgp-filter:%s[name='%s']/entry", clist_list_name[kind], name);

	return count;
}

static int clist_entry_max_seq_iter_cb(const struct lyd_node *dnode, void *arg)
{
	int64_t *maxseq = arg;
	int64_t cur = yang_dnode_get_uint32(dnode, "sequence");

	if (cur > *maxseq)
		*maxseq = cur;

	return YANG_ITER_CONTINUE;
}

/* bgp_clist_new_seq_get()'s formula (bgp_clist.c): round the current max
 * sequence down to a multiple of 5, then add 5. */
static uint32_t clist_next_seq(struct vty *vty, enum clist_kind kind, const char *name)
{
	int64_t maxseq = 0;
	int64_t newseq;

	yang_dnode_iterate(clist_entry_max_seq_iter_cb, &maxseq, vty->candidate_config->dnode,
			   "/proteus-bgp-filter:%s[name='%s']/entry", clist_list_name[kind], name);

	newseq = ((maxseq / 5) * 5) + 5;

	return (newseq > UINT32_MAX) ? UINT32_MAX : (uint32_t)newseq;
}

/* Refuse mixing styles under one name with the legacy
 * community_list_perror() texts. */
static bool clist_type_conflict(struct vty *vty, enum clist_kind kind, const char *name,
				bool standard)
{
	char xpath[XPATH_MAXLEN];
	const struct lyd_node *list;

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:%s[name='%s']", clist_list_name[kind],
		 name);
	list = yang_dnode_get(vty->candidate_config->dnode, xpath);
	if (!list)
		return false;

	if (strmatch(yang_dnode_get_string(list, "type"), standard ? "standard" : "expanded"))
		return false;

	if (standard)
		vty_out(vty,
			"%% Community name conflict, previously defined as expanded community\n");
	else
		vty_out(vty,
			"%% Community name conflict, previously defined as standard community\n");

	return true;
}

/* Shared 'add one entry' body: exactly one of frags (standard) or regex
 * (expanded) is given. A line's value set can exceed one transaction's
 * change budget (VTY_MAXCFGCHANGES), so the fragments are applied in
 * batches; the first batch carries the entry skeleton (including the
 * destroy of a replaced same-sequence entry), later ones only more value
 * fragments of the already-created entry. */
static int clist_cli_add(struct vty *vty, enum clist_kind kind, bool standard, const char *name,
			 const char *seq_str, const char *action, char (*frags)[CLIST_FRAG_LEN],
			 int nfrags, const char *regex)
{
	char xpath_list[XPATH_MAXLEN], xpath_type[XPATH_MAXLEN + 8];
	char xpath_entry[XPATH_MAXLEN + 32];
	char frag_rel[CLIST_FRAG_LEN + 2];
	struct clist_entry_match_ctx ctx = {
		.action = action,
		.regex = regex,
		.frags = frags,
		.nfrags = nfrags,
	};
	int nqueued, ret;

	if (clist_type_conflict(vty, kind, name, standard))
		return CMD_WARNING_CONFIG_FAILED;

	/* Backward compatibility: a content-duplicate insert is silently
	 * absorbed, not an error, whatever sequence was typed. */
	if (clist_entry_find(vty, kind, name, &ctx))
		return CMD_SUCCESS;

	snprintf(xpath_list, sizeof(xpath_list), "/proteus-bgp-filter:%s[name='%s']",
		 clist_list_name[kind], name);
	snprintf(xpath_type, sizeof(xpath_type), "%s/type", xpath_list);
	if (seq_str != NULL)
		snprintf(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%s']", xpath_list,
			 seq_str);
	else
		snprintf(xpath_entry, sizeof(xpath_entry), "%s/entry[sequence='%u']", xpath_list,
			 clist_next_seq(vty, kind, name));

	/* Legacy same-sequence replace (community_list_entry_replace()):
	 * reset the entry so stale value children don't linger. */
	if (yang_dnode_get(vty->candidate_config->dnode, xpath_entry))
		nb_cli_enqueue_change(vty, xpath_entry, NB_OP_DESTROY, NULL);

	nb_cli_enqueue_change(vty, xpath_list, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, xpath_type, NB_OP_MODIFY, standard ? "standard" : "expanded");
	nb_cli_enqueue_change(vty, xpath_entry, NB_OP_CREATE, NULL);
	nb_cli_enqueue_change(vty, "./action", NB_OP_MODIFY, action);
	nqueued = 5;

	if (regex) {
		nb_cli_enqueue_change(vty, "./regex", NB_OP_MODIFY, regex);
		return nb_cli_apply_changes(vty, "%s", xpath_entry);
	}

	for (int i = 0; i < nfrags; i++) {
		if (nqueued == VTY_MAXCFGCHANGES) {
			ret = nb_cli_apply_changes(vty, "%s", xpath_entry);
			if (ret != CMD_SUCCESS)
				return ret;
			nqueued = 0;
		}
		snprintf(frag_rel, sizeof(frag_rel), "./%s", frags[i]);
		nb_cli_enqueue_change(vty, frag_rel, NB_OP_CREATE, NULL);
		nqueued++;
	}

	return nb_cli_apply_changes(vty, "%s", xpath_entry);
}

/* Shared 'no' body with a value: content-matched like the legacy
 * community_list_entry_lookup() (any seq token was accepted and
 * ignored), silent no-op when nothing matches, list removed with its
 * last entry. */
static int clist_cli_del(struct vty *vty, enum clist_kind kind, const char *name,
			 const char *action, char (*frags)[CLIST_FRAG_LEN], int nfrags,
			 const char *regex)
{
	char xpath[XPATH_MAXLEN + 32];
	struct clist_entry_match_ctx ctx = {
		.action = action,
		.regex = regex,
		.frags = frags,
		.nfrags = nfrags,
	};

	if (!clist_entry_find(vty, kind, name, &ctx))
		return CMD_SUCCESS;

	if (clist_entry_count(vty, kind, name) == 1)
		snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:%s[name='%s']",
			 clist_list_name[kind], name);
	else
		snprintf(xpath, sizeof(xpath),
			 "/proteus-bgp-filter:%s[name='%s']/entry[sequence='%u']",
			 clist_list_name[kind], name, ctx.sequence);

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Shared name-only 'no' body: whole-list delete, silent when the list
 * doesn't exist (legacy *_list_unset() returned void), and -- like
 * legacy's str == NULL path -- regardless of which style keyword the
 * command carried. */
static int clist_cli_del_all(struct vty *vty, enum clist_kind kind, const char *name)
{
	char xpath[XPATH_MAXLEN];

	snprintf(xpath, sizeof(xpath), "/proteus-bgp-filter:%s[name='%s']", clist_list_name[kind],
		 name);
	if (!yang_dnode_get(vty->candidate_config->dnode, xpath))
		return CMD_SUCCESS;

	nb_cli_enqueue_change(vty, xpath, NB_OP_DESTROY, NULL);

	return nb_cli_apply_changes(vty, NULL);
}

/* Standard-form create/delete shared by the named DEFPYs and the
 * deprecated numbered aliases. */
static int clist_cli_add_standard(struct vty *vty, enum clist_kind kind, const char *name,
				  const char *seq_str, const char *action, struct cmd_token **argv,
				  int argc, int idx)
{
	char (*frags)[CLIST_FRAG_LEN];
	int nfrags, ret;

	if (!clist_parse_values(vty, kind, argv, argc, idx, &frags, &nfrags))
		return CMD_WARNING_CONFIG_FAILED;

	ret = clist_cli_add(vty, kind, true, name, seq_str, action, frags, nfrags, NULL);

	XFREE(MTYPE_TMP, frags);

	return ret;
}

static int clist_cli_del_standard(struct vty *vty, enum clist_kind kind, const char *name,
				  const char *action, struct cmd_token **argv, int argc, int idx)
{
	char (*frags)[CLIST_FRAG_LEN];
	int nfrags, ret;

	if (!clist_parse_values(vty, kind, argv, argc, idx, &frags, &nfrags))
		return CMD_WARNING_CONFIG_FAILED;

	ret = clist_cli_del(vty, kind, name, action, frags, nfrags, NULL);

	XFREE(MTYPE_TMP, frags);

	return ret;
}

/* Expanded-form create/delete: the regex is the argv_concat() of every
 * value token; freed only AFTER nb_cli_apply_changes() has consumed the
 * enqueued value pointer (the B7 lesson). */
static int clist_cli_add_expanded(struct vty *vty, enum clist_kind kind, const char *name,
				  const char *seq_str, const char *action, struct cmd_token **argv,
				  int argc, int idx)
{
	char *regex = argv_concat(argv, argc, idx);
	int ret;

	ret = clist_cli_add(vty, kind, false, name, seq_str, action, NULL, 0, regex);

	XFREE(MTYPE_TMP, regex);

	return ret;
}

static int clist_cli_del_expanded(struct vty *vty, enum clist_kind kind, const char *name,
				  const char *action, struct cmd_token **argv, int argc, int idx)
{
	char *regex = argv_concat(argv, argc, idx);
	int ret;

	ret = clist_cli_del(vty, kind, name, action, NULL, 0, regex);

	XFREE(MTYPE_TMP, regex);

	return ret;
}

/* community-list, named forms. */

DEFPY_YANG(
	bgp_community_list_standard, bgp_community_list_standard_cli_cmd,
	"bgp community-list standard COMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	COMMUNITY_LIST_STR
	"Add an standard community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_add_standard(vty, CLIST_COMMUNITY, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	bgp_community_list_expanded, bgp_community_list_expanded_cli_cmd,
	"bgp community-list expanded COMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	COMMUNITY_LIST_STR
	"Add an expanded community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_add_expanded(vty, CLIST_COMMUNITY, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_community_list_standard, no_bgp_community_list_standard_cli_cmd,
	"no bgp community-list standard COMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Add an standard community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_del_standard(vty, CLIST_COMMUNITY, name, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_community_list_expanded, no_bgp_community_list_expanded_cli_cmd,
	"no bgp community-list expanded COMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Add an expanded community-list entry\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_del_expanded(vty, CLIST_COMMUNITY, name, action, argv, argc, idx);
}

DEFPY_YANG(no_bgp_community_list_standard_all, no_bgp_community_list_standard_all_cli_cmd,
	   "no bgp community-list standard COMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   COMMUNITY_LIST_STR
	   "Add an standard community-list entry\n"
	   "Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_COMMUNITY, name);
}

DEFPY_YANG(no_bgp_community_list_expanded_all, no_bgp_community_list_expanded_all_cli_cmd,
	   "no bgp community-list expanded COMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   COMMUNITY_LIST_STR
	   "Add an expanded community-list entry\n"
	   "Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_COMMUNITY, name);
}

/* community-list, deprecated numbered aliases (normalized to named). */

DEFPY_ATTR(
	bgp_community_list_number, bgp_community_list_number_cli_cmd,
	"bgp community-list <(1-99)|(100-500)>$number [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (standard)\n"
	"Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	bool standard = number <= 99;
	int idx = 0;

	vty_out(vty,
		"%% \"bgp community-list %s\" is deprecated, use \"bgp community-list %s %s\"\n",
		number_str, standard ? "standard" : "expanded", number_str);

	argv_find(argv, argc, "AA:NN", &idx);

	if (standard)
		return clist_cli_add_standard(vty, CLIST_COMMUNITY, number_str, seq_str, action,
					      argv, argc, idx);
	return clist_cli_add_expanded(vty, CLIST_COMMUNITY, number_str, seq_str, action, argv,
				      argc, idx);
}

DEFPY_ATTR(
	no_bgp_community_list_number, no_bgp_community_list_number_cli_cmd,
	"no bgp community-list <(1-99)|(100-500)>$number [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	COMMUNITY_LIST_STR
	"Community list number (standard)\n"
	"Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	COMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	bool standard = number <= 99;
	int idx = 0;

	vty_out(vty,
		"%% \"no bgp community-list %s\" is deprecated, use \"no bgp community-list %s %s\"\n",
		number_str, standard ? "standard" : "expanded", number_str);

	argv_find(argv, argc, "AA:NN", &idx);

	if (standard)
		return clist_cli_del_standard(vty, CLIST_COMMUNITY, number_str, action, argv, argc,
					      idx);
	return clist_cli_del_expanded(vty, CLIST_COMMUNITY, number_str, action, argv, argc, idx);
}

DEFPY_ATTR(no_bgp_community_list_number_all, no_bgp_community_list_number_all_cli_cmd,
	   "no bgp community-list <(1-99)|(100-500)>$number",
	   NO_STR
	   BGP_STR
	   COMMUNITY_LIST_STR
	   "Community list number (standard)\n"
	   "Community list number (expanded)\n",
	   CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	vty_out(vty,
		"%% \"no bgp community-list %s\" is deprecated, use \"no bgp community-list <standard|expanded> %s\"\n",
		number_str, number_str);

	return clist_cli_del_all(vty, CLIST_COMMUNITY, number_str);
}

/* large-community-list, named forms. Unlike legacy's
 * lcommunity_list_set_vty() (reject_all_digit_name), all-digit names are
 * accepted here: they are exactly how the deprecated numbered forms
 * round-trip as named lists. */

DEFPY_YANG(
	bgp_lcommunity_list_standard, bgp_lcommunity_list_standard_cli_cmd,
	"bgp large-community-list standard LCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:BB:CC...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Specify standard large-community-list\n"
	"Large Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:BB:CC", &idx);

	return clist_cli_add_standard(vty, CLIST_LARGE, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	bgp_lcommunity_list_expanded, bgp_lcommunity_list_expanded_cli_cmd,
	"bgp large-community-list expanded LCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Specify expanded large-community-list\n"
	"Large Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_add_expanded(vty, CLIST_LARGE, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_lcommunity_list_standard, no_bgp_lcommunity_list_standard_cli_cmd,
	"no bgp large-community-list standard LCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:AA:NN...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Specify standard large-community-list\n"
	"Large Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:AA:NN", &idx);

	return clist_cli_del_standard(vty, CLIST_LARGE, name, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_lcommunity_list_expanded, no_bgp_lcommunity_list_expanded_cli_cmd,
	"no bgp large-community-list expanded LCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Specify expanded large-community-list\n"
	"Large community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_del_expanded(vty, CLIST_LARGE, name, action, argv, argc, idx);
}

DEFPY_YANG(no_bgp_lcommunity_list_all, no_bgp_lcommunity_list_all_cli_cmd,
	   "no bgp large-community-list LCOMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   LCOMMUNITY_LIST_STR
	   "Large Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_LARGE, name);
}

DEFPY_YANG(no_bgp_lcommunity_list_standard_all, no_bgp_lcommunity_list_standard_all_cli_cmd,
	   "no bgp large-community-list standard LCOMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   LCOMMUNITY_LIST_STR
	   "Specify standard large-community-list\n"
	   "Large Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_LARGE, name);
}

DEFPY_YANG(no_bgp_lcommunity_list_expanded_all, no_bgp_lcommunity_list_expanded_all_cli_cmd,
	   "no bgp large-community-list expanded LCOMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   LCOMMUNITY_LIST_STR
	   "Specify expanded large-community-list\n"
	   "Large Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_LARGE, name);
}

/* large-community-list, deprecated numbered aliases. */

DEFPY_ATTR(
	bgp_lcommunity_list_number_standard, bgp_lcommunity_list_number_standard_cli_cmd,
	"bgp large-community-list (1-99)$number [seq (0-4294967295)$seq] <deny|permit>$action AA:BB:CC...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large Community list number (standard)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	int idx = 0;

	vty_out(vty,
		"%% \"bgp large-community-list %s\" is deprecated, use \"bgp large-community-list standard %s\"\n",
		number_str, number_str);

	argv_find(argv, argc, "AA:BB:CC", &idx);

	return clist_cli_add_standard(vty, CLIST_LARGE, number_str, seq_str, action, argv, argc,
				      idx);
}

DEFPY_ATTR(
	bgp_lcommunity_list_number_expanded, bgp_lcommunity_list_number_expanded_cli_cmd,
	"bgp large-community-list (100-500)$number [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	int idx = 0;

	vty_out(vty,
		"%% \"bgp large-community-list %s\" is deprecated, use \"bgp large-community-list expanded %s\"\n",
		number_str, number_str);

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_add_expanded(vty, CLIST_LARGE, number_str, seq_str, action, argv, argc,
				      idx);
}

DEFPY_ATTR(
	no_bgp_lcommunity_list_number_standard, no_bgp_lcommunity_list_number_standard_cli_cmd,
	"no bgp large-community-list (1-99)$number [seq (0-4294967295)$seq] <deny|permit>$action AA:AA:NN...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large Community list number (standard)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	LCOMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	int idx = 0;

	vty_out(vty,
		"%% \"no bgp large-community-list %s\" is deprecated, use \"no bgp large-community-list standard %s\"\n",
		number_str, number_str);

	argv_find(argv, argc, "AA:AA:NN", &idx);

	return clist_cli_del_standard(vty, CLIST_LARGE, number_str, action, argv, argc, idx);
}

DEFPY_ATTR(
	no_bgp_lcommunity_list_number_expanded, no_bgp_lcommunity_list_number_expanded_cli_cmd,
	"no bgp large-community-list (100-500)$number [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	LCOMMUNITY_LIST_STR
	"Large Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify large community to reject\n"
	"Specify large community to accept\n"
	"An ordered list as a regular-expression\n",
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	int idx = 0;

	vty_out(vty,
		"%% \"no bgp large-community-list %s\" is deprecated, use \"no bgp large-community-list expanded %s\"\n",
		number_str, number_str);

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_del_expanded(vty, CLIST_LARGE, number_str, action, argv, argc, idx);
}

/* extcommunity-list, named forms. */

DEFPY_YANG(
	bgp_extcommunity_list_standard, bgp_extcommunity_list_standard_cli_cmd,
	"bgp extcommunity-list standard EXTCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Specify standard extcommunity-list\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	EXTCOMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_add_standard(vty, CLIST_EXT, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	bgp_extcommunity_list_expanded, bgp_extcommunity_list_expanded_cli_cmd,
	"bgp extcommunity-list expanded EXTCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Specify expanded extcommunity-list\n"
	"Extended Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_add_expanded(vty, CLIST_EXT, name, seq_str, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_extcommunity_list_standard, no_bgp_extcommunity_list_standard_cli_cmd,
	"no bgp extcommunity-list standard EXTCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Specify standard extcommunity-list\n"
	"Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	EXTCOMMUNITY_VAL_STR)
{
	int idx = 0;

	argv_find(argv, argc, "AA:NN", &idx);

	return clist_cli_del_standard(vty, CLIST_EXT, name, action, argv, argc, idx);
}

DEFPY_YANG(
	no_bgp_extcommunity_list_expanded, no_bgp_extcommunity_list_expanded_cli_cmd,
	"no bgp extcommunity-list expanded EXTCOMMUNITY_LIST_NAME$name [seq (0-4294967295)$seq] <deny|permit>$action LINE...",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Specify expanded extcommunity-list\n"
	"Extended Community list name\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	"An ordered list as a regular-expression\n")
{
	int idx = 0;

	argv_find(argv, argc, "LINE", &idx);

	return clist_cli_del_expanded(vty, CLIST_EXT, name, action, argv, argc, idx);
}

DEFPY_YANG(no_bgp_extcommunity_list_standard_all, no_bgp_extcommunity_list_standard_all_cli_cmd,
	   "no bgp extcommunity-list standard EXTCOMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   EXTCOMMUNITY_LIST_STR
	   "Specify standard extcommunity-list\n"
	   "Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_EXT, name);
}

DEFPY_YANG(no_bgp_extcommunity_list_expanded_all, no_bgp_extcommunity_list_expanded_all_cli_cmd,
	   "no bgp extcommunity-list expanded EXTCOMMUNITY_LIST_NAME$name",
	   NO_STR
	   BGP_STR
	   EXTCOMMUNITY_LIST_STR
	   "Specify expanded extcommunity-list\n"
	   "Extended Community list name\n")
{
	return clist_cli_del_all(vty, CLIST_EXT, name);
}

/* extcommunity-list, deprecated numbered aliases. */

DEFPY_ATTR(
	bgp_extcommunity_list_number, bgp_extcommunity_list_number_cli_cmd,
	"bgp extcommunity-list <(1-99)|(100-500)>$number [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extended Community list number (standard)\n"
	"Extended Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	EXTCOMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	bool standard = number <= 99;
	int idx = 0;

	vty_out(vty,
		"%% \"bgp extcommunity-list %s\" is deprecated, use \"bgp extcommunity-list %s %s\"\n",
		number_str, standard ? "standard" : "expanded", number_str);

	argv_find(argv, argc, "AA:NN", &idx);

	if (standard)
		return clist_cli_add_standard(vty, CLIST_EXT, number_str, seq_str, action, argv,
					      argc, idx);
	return clist_cli_add_expanded(vty, CLIST_EXT, number_str, seq_str, action, argv, argc, idx);
}

DEFPY_ATTR(
	no_bgp_extcommunity_list_number, no_bgp_extcommunity_list_number_cli_cmd,
	"no bgp extcommunity-list <(1-99)|(100-500)>$number [seq (0-4294967295)$seq] <deny|permit>$action AA:NN...",
	NO_STR
	BGP_STR
	EXTCOMMUNITY_LIST_STR
	"Extended Community list number (standard)\n"
	"Extended Community list number (expanded)\n"
	"Sequence number of an entry\n"
	"Sequence number\n"
	"Specify community to reject\n"
	"Specify community to accept\n"
	EXTCOMMUNITY_VAL_STR,
	CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	bool standard = number <= 99;
	int idx = 0;

	vty_out(vty,
		"%% \"no bgp extcommunity-list %s\" is deprecated, use \"no bgp extcommunity-list %s %s\"\n",
		number_str, standard ? "standard" : "expanded", number_str);

	argv_find(argv, argc, "AA:NN", &idx);

	if (standard)
		return clist_cli_del_standard(vty, CLIST_EXT, number_str, action, argv, argc, idx);
	return clist_cli_del_expanded(vty, CLIST_EXT, number_str, action, argv, argc, idx);
}

DEFPY_ATTR(no_bgp_extcommunity_list_number_all, no_bgp_extcommunity_list_number_all_cli_cmd,
	   "no bgp extcommunity-list <(1-99)|(100-500)>$number",
	   NO_STR
	   BGP_STR
	   EXTCOMMUNITY_LIST_STR
	   "Extended Community list number (standard)\n"
	   "Extended Community list number (expanded)\n",
	   CMD_ATTR_YANG | CMD_ATTR_DEPRECATED | CMD_ATTR_HIDDEN)
{
	vty_out(vty,
		"%% \"no bgp extcommunity-list %s\" is deprecated, use \"no bgp extcommunity-list <standard|expanded> %s\"\n",
		number_str, number_str);

	return clist_cli_del_all(vty, CLIST_EXT, number_str);
}

/* One line per entry, always with the style keyword and 'seq' -- the
 * named-list loop of the retired community_list_config_write(). The
 * numbered lists' keyword-less spelling is gone by design (normalized to
 * named, see the section comment): a numbered list re-emits as 'bgp
 * <kind>-list <standard|expanded> <number> ...', which parses back into
 * the same list. The VALUE serialization (canonical sorted order,
 * well-known names, verbatim raws) is bgp_filter_value.c, shared with
 * bgpd's northbound apply side. */
static void clist_entry_cli_write(struct vty *vty, const struct lyd_node *dnode)
{
	char value[VTY_BUFSIZ];

	bgp_filter_entry_value_str(dnode, value, sizeof(value));

	vty_out(vty, "bgp %s %s %s seq %s %s %s\n", lyd_parent(dnode)->schema->name,
		yang_dnode_get_string(dnode, "../type"), yang_dnode_get_string(dnode, "../name"),
		yang_dnode_get_string(dnode, "sequence"), yang_dnode_get_string(dnode, "action"),
		value);
}

static void community_list_entry_cli_write(struct vty *vty, const struct lyd_node *dnode,
					   bool show_defaults)
{
	clist_entry_cli_write(vty, dnode);
}

static void large_community_list_entry_cli_write(struct vty *vty, const struct lyd_node *dnode,
						 bool show_defaults)
{
	clist_entry_cli_write(vty, dnode);
}

static void extcommunity_list_entry_cli_write(struct vty *vty, const struct lyd_node *dnode,
					      bool show_defaults)
{
	clist_entry_cli_write(vty, dnode);
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
			.xpath = "/proteus-bgp-filter:community-list/entry",
			.cbs = {
				.cli_show = community_list_entry_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:large-community-list/entry",
			.cbs = {
				.cli_show = large_community_list_entry_cli_write,
			}
		},
		{
			.xpath = "/proteus-bgp-filter:extcommunity-list/entry",
			.cbs = {
				.cli_show = extcommunity_list_entry_cli_write,
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

	/* community-list (M7 batch B8). */
	install_element(CONFIG_NODE, &bgp_community_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &bgp_community_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_expanded_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_community_list_number_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_number_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_community_list_number_all_cli_cmd);

	/* large-community-list (M7 batch B8). */
	install_element(CONFIG_NODE, &bgp_lcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_all_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_expanded_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_number_standard_cli_cmd);
	install_element(CONFIG_NODE, &bgp_lcommunity_list_number_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_number_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_lcommunity_list_number_expanded_cli_cmd);

	/* extcommunity-list (M7 batch B8). */
	install_element(CONFIG_NODE, &bgp_extcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &bgp_extcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_standard_all_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_expanded_all_cli_cmd);
	install_element(CONFIG_NODE, &bgp_extcommunity_list_number_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_number_cli_cmd);
	install_element(CONFIG_NODE, &no_bgp_extcommunity_list_number_all_cli_cmd);
}
