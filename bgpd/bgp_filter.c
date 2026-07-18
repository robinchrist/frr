// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path filter list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#include <zebra.h>

#include "command.h"
#include "log.h"
#include "memory.h"
#include "buffer.h"
#include "queue.h"
#include "filter.h"
#include "frregex_real.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_aspath.h"
#include "bgpd/bgp_regex.h"

/* List of AS list. */
struct as_list_list {
	struct as_list *head;
	struct as_list *tail;
};

/* AS path filter master. */
struct as_list_master {
	/* List of access_list which name is string. */
	struct as_list_list str;

	/* Hook function which is executed when new access_list is added. */
	void (*add_hook)(char *);

	/* Hook function which is executed when access_list is deleted. */
	void (*delete_hook)(const char *);
};



/* Return as-list entry which has same seq number. */
struct as_filter *bgp_aslist_seq_check(struct as_list *list, int64_t seq)
{
	struct as_filter *entry;

	for (entry = list->head; entry; entry = entry->next)
		if (entry->seq == seq)
			return entry;

	return NULL;
}

/* as-path access-list 10 permit AS1. */

static struct as_list_master as_list_master = {{NULL, NULL},
					       NULL,
					       NULL};

/* Allocate new AS filter. */
static struct as_filter *as_filter_new(void)
{
	return XCALLOC(MTYPE_AS_FILTER, sizeof(struct as_filter));
}

/* Free allocated AS filter. */
static void as_filter_free(struct as_filter *asfilter)
{
	if (asfilter->reg)
		bgp_regex_free(asfilter->reg);
	XFREE(MTYPE_AS_FILTER_STR, asfilter->reg_str);
	XFREE(MTYPE_AS_FILTER, asfilter);
}

/* Make new AS filter. */
static struct as_filter *as_filter_make(struct frregex *reg, const char *reg_str,
					enum as_filter_type type)
{
	struct as_filter *asfilter;

	asfilter = as_filter_new();
	asfilter->reg = reg;
	asfilter->type = type;
	asfilter->reg_str = XSTRDUP(MTYPE_AS_FILTER_STR, reg_str);

	return asfilter;
}

static void as_filter_entry_replace(struct as_list *list,
				    struct as_filter *replace,
				    struct as_filter *entry)
{
	if (replace->next) {
		entry->next = replace->next;
		replace->next->prev = entry;
	} else {
		entry->next = NULL;
		list->tail = entry;
	}

	if (replace->prev) {
		entry->prev = replace->prev;
		replace->prev->next = entry;
	} else {
		entry->prev = NULL;
		list->head = entry;
	}

	as_filter_free(replace);
}

static void as_list_filter_add(struct as_list *aslist,
			       struct as_filter *asfilter)
{
	struct as_filter *point;
	struct as_filter *replace;

	if (aslist->tail && asfilter->seq > aslist->tail->seq)
		point = NULL;
	else {
		replace = bgp_aslist_seq_check(aslist, asfilter->seq);
		if (replace) {
			as_filter_entry_replace(aslist, replace, asfilter);
			goto hook;
		}

		/* Check insert point. */
		for (point = aslist->head; point; point = point->next)
			if (point->seq >= asfilter->seq)
				break;
	}

	asfilter->next = point;

	if (point) {
		if (point->prev)
			point->prev->next = asfilter;
		else
			aslist->head = asfilter;

		asfilter->prev = point->prev;
		point->prev = asfilter;
	} else {
		if (aslist->tail)
			aslist->tail->next = asfilter;
		else
			aslist->head = asfilter;

		asfilter->prev = aslist->tail;
		aslist->tail = asfilter;
	}

hook:
	/* Run hook function. */
	if (as_list_master.add_hook)
		(*as_list_master.add_hook)(aslist->name);
}

/* Lookup as_list from list of as_list by name. */
struct as_list *as_list_lookup(const char *name)
{
	struct as_list *aslist;

	if (name == NULL)
		return NULL;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		if (strcmp(aslist->name, name) == 0)
			return aslist;
	return NULL;
}

static struct as_list *as_list_new(void)
{
	return XCALLOC(MTYPE_AS_LIST, sizeof(struct as_list));
}

static void as_list_free(struct as_list *aslist)
{

	XFREE (MTYPE_AS_STR, aslist->name);
	XFREE (MTYPE_AS_LIST, aslist);
}

/* Insert new AS list to list of as_list.  Each as_list is sorted by
   the name. */
static struct as_list *as_list_insert(const char *name)
{
	struct as_list *aslist;
	struct as_list *point;
	struct as_list_list *list;

	/* Allocate new access_list and copy given name. */
	aslist = as_list_new();
	aslist->name = XSTRDUP(MTYPE_AS_STR, name);
	assert(aslist->name);

	/* Set access_list to string list. */
	list = &as_list_master.str;

	/* Set point to insertion point. */
	for (point = list->head; point; point = point->next)
		if (strcmp(point->name, name) >= 0)
			break;

	/* In case of this is the first element of master. */
	if (list->head == NULL) {
		list->head = list->tail = aslist;
		return aslist;
	}

	/* In case of insertion is made at the tail of access_list. */
	if (point == NULL) {
		aslist->prev = list->tail;
		list->tail->next = aslist;
		list->tail = aslist;
		return aslist;
	}

	/* In case of insertion is made at the head of access_list. */
	if (point == list->head) {
		aslist->next = list->head;
		list->head->prev = aslist;
		list->head = aslist;
		return aslist;
	}

	/* Insertion is made at middle of the access_list. */
	aslist->next = point;
	aslist->prev = point->prev;

	if (point->prev)
		point->prev->next = aslist;
	point->prev = aslist;

	return aslist;
}

static struct as_list *as_list_get(const char *name)
{
	struct as_list *aslist;

	aslist = as_list_lookup(name);
	if (aslist == NULL)
		aslist = as_list_insert(name);

	return aslist;
}

static const char *filter_type_str(enum as_filter_type type)
{
	switch (type) {
	case AS_FILTER_PERMIT:
		return "permit";
	case AS_FILTER_DENY:
		return "deny";
	default:
		return "";
	}
}

static void as_list_delete(struct as_list *aslist)
{
	struct as_list_list *list;
	struct as_filter *filter, *next;

	for (filter = aslist->head; filter; filter = next) {
		next = filter->next;
		as_filter_free(filter);
	}

	list = &as_list_master.str;

	if (aslist->next)
		aslist->next->prev = aslist->prev;
	else
		list->tail = aslist->prev;

	if (aslist->prev)
		aslist->prev->next = aslist->next;
	else
		list->head = aslist->next;

	as_list_free(aslist);
}

static bool as_list_empty(struct as_list *aslist)
{
	return aslist->head == NULL && aslist->tail == NULL;
}

static void as_list_filter_delete(struct as_list *aslist,
				  struct as_filter *asfilter)
{
	char *name = XSTRDUP(MTYPE_AS_STR, aslist->name);

	if (asfilter->next)
		asfilter->next->prev = asfilter->prev;
	else
		aslist->tail = asfilter->prev;

	if (asfilter->prev)
		asfilter->prev->next = asfilter->next;
	else
		aslist->head = asfilter->next;

	as_filter_free(asfilter);

	/* If access_list becomes empty delete it from access_master. */
	if (as_list_empty(aslist))
		as_list_delete(aslist);

	/* Run hook function. */
	if (as_list_master.delete_hook)
		(*as_list_master.delete_hook)(name);
	XFREE(MTYPE_AS_STR, name);
}

static bool as_filter_match(struct as_filter *asfilter, struct aspath *aspath)
{
	return bgp_regexec(asfilter->reg, aspath) != REG_NOMATCH;
}

/* Apply AS path filter to AS. */
enum as_filter_type as_list_apply(struct as_list *aslist, void *object)
{
	struct as_filter *asfilter;
	struct aspath *aspath;

	aspath = (struct aspath *)object;

	if (aslist == NULL)
		return AS_FILTER_DENY;

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (as_filter_match(asfilter, aspath))
			return asfilter->type;
	}
	return AS_FILTER_DENY;
}

/* Add hook function. */
void as_list_add_hook(void (*func)(char *))
{
	as_list_master.add_hook = func;
}

/* Delete hook function. */
void as_list_delete_hook(void (*func)(const char *))
{
	as_list_master.delete_hook = func;
}

static bool as_list_dup_check(struct as_list *aslist, struct as_filter *new)
{
	struct as_filter *asfilter;

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (asfilter->type == new->type
		    && strcmp(asfilter->reg_str, new->reg_str) == 0)
			return true;
	}
	return false;
}

bool config_bgp_aspath_validate(const char *regstr)
{
	char valid_chars[] = "1234567890_^|[,{}() ]$*+.?-\\";

	if (strspn(regstr, valid_chars) == strlen(regstr))
		return true;
	return false;
}

/*
 * Northbound entry points (M7 batch B7, bgpd/proteus/bgp_nb_filter.c): the
 * guts of the retired bgp_as_path_cmd / no_bgp_as_path_cmd /
 * no_bgp_as_path_all_cmd DEFUNs, minus CLI argument parsing, minus regex
 * compile/character validation (an NB_EV_VALIDATE job now, and minus the
 * legacy content-based asfilter lookup, since the northbound entry list is
 * keyed by sequence and the caller already resolved which sequence to act
 * on -- content-based duplicate/no-match resolution moved to the CLI layer
 * (bgpd/proteus/bgp_cli_filter.c), which is the only place that still sees
 * the raw <permit|deny> LINE... tokens without a sequence key.
 */

/* Guts of bgp_as_path_cmd from the regex compile onward. Takes ownership of
 * 'regex' (as as_filter_make() did) and 'name'/'regstr' are only read, not
 * retained beyond this call.
 *
 * Deviation from the retired DEFUN: the DEFUN called
 * as_list_list_init(&aslist->exclude_rule) unconditionally on every single
 * invocation, including ones that only add a second (or later) entry to an
 * already-linked list -- harmless there only because as_list_list_init()
 * re-zeroes the DLIST's circular sentinel rather than freeing anything, so
 * it silently detaches (not frees) any aspath_exclude already linked via a
 * route-map's 'set as-path exclude as-path-access-list NAME' without
 * un-setting that struct's own exclude_aspath_acl back-pointer -- a latent
 * dangling-pointer hazard once the list is later deleted (its exclude_rule
 * no longer lists the detached entry, so the delete path's own orphan
 * sweep below skips it). This entry point is called up to twice per CLI
 * line (both mandatory sibling leaves modify -- see
 * bgpd/proteus/bgp_nb_filter.c's as_path_access_list_entry_apply()), which
 * turned this from a latent, hard-to-hit legacy bug into a routinely-hit
 * one (topotest bgp_set_aspath_exclude ASAN use-after-free). Fixed here by
 * only initializing/relinking exclude_rule when the list is being created
 * for the first time -- an already-existing list's exclude_rule (empty or
 * linked) is left untouched by a later entry add, which is what the
 * orphan-relink logic was already trying to guarantee. */
void as_list_filter_set(const char *name, int64_t seq, enum as_filter_type type,
			const char *regstr, struct frregex *regex)
{
	struct as_list *aslist;
	struct as_filter *asfilter;
	struct aspath_exclude *ase;
	bool new_list = as_list_lookup(name) == NULL;

	aslist = as_list_get(name);

	asfilter = as_filter_make(regex, regstr, type);
	asfilter->seq = seq;

	/* Duplicate insertion check. */
	if (as_list_dup_check(aslist, asfilter))
		as_filter_free(asfilter);
	else
		as_list_filter_add(aslist, asfilter);

	if (!new_list)
		return;

	/* init the exclude rule list*/
	as_list_list_init(&aslist->exclude_rule);

	/* get aspath orphan exclude that are using this acl */
	ase = as_exclude_lookup_orphan(name);
	if (ase) {
		as_list_list_add_head(&aslist->exclude_rule, ase);
		/* set reverse pointer */
		ase->exclude_aspath_acl = aslist;
		/* set list of aspath excludes using that acl */
		while ((ase = as_exclude_lookup_orphan(name))) {
			as_list_list_add_head(&aslist->exclude_rule, ase);
			ase->exclude_aspath_acl = aslist;
		}
	}
}

/* Guts of no_bgp_as_path_cmd from the asfilter lookup onward. */
void as_list_filter_unset(struct as_list *aslist, struct as_filter *asfilter)
{
	struct aspath_exclude *ase;

	/* put aspath exclude list into orphan */
	if (as_list_list_count(&aslist->exclude_rule))
		while ((ase = as_list_list_pop(&aslist->exclude_rule)))
			as_exclude_set_orphan(ase);

	as_list_list_fini(&aslist->exclude_rule);
	as_list_filter_delete(aslist, asfilter);
}

/* Guts of no_bgp_as_path_all_cmd. Returns false if the named list doesn't
 * exist (defensive only -- a destroy callback only fires on an entry that
 * existed in the datastore). */
bool as_list_delete_all(const char *name)
{
	struct as_list *aslist;

	aslist = as_list_lookup(name);
	if (!aslist)
		return false;

	as_list_delete(aslist);

	/* Run hook function. as_list_delete() itself doesn't -- it's also
	 * used internally by as_list_filter_delete() for the "list became
	 * empty after removing one entry" case, which fires its own hook
	 * call with the pre-deletion name already in hand. */
	if (as_list_master.delete_hook)
		(*as_list_master.delete_hook)(name);

	return true;
}

static void as_list_show(struct vty *vty, struct as_list *aslist,
			 json_object *json)
{
	struct as_filter *asfilter;
	json_object *json_aslist = NULL;

	if (json) {
		json_aslist = json_object_new_array();
		json_object_object_add(json, aslist->name, json_aslist);
	} else
		vty_out(vty, "AS path access list %s\n", aslist->name);

	for (asfilter = aslist->head; asfilter; asfilter = asfilter->next) {
		if (json) {
			json_object *json_asfilter = json_object_new_object();

			json_object_int_add(json_asfilter, "sequenceNumber",
					    asfilter->seq);
			json_object_string_add(json_asfilter, "type",
					       filter_type_str(asfilter->type));
			json_object_string_add(json_asfilter, "regExp",
					       asfilter->reg_str);

			json_object_array_add(json_aslist, json_asfilter);
		} else
			vty_out(vty, "    %s %s\n",
				filter_type_str(asfilter->type),
				asfilter->reg_str);
	}
}

static void as_list_show_all(struct vty *vty, json_object *json)
{
	struct as_list *aslist;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		as_list_show(vty, aslist, json);
}

DEFUN (show_as_path_access_list,
       show_bgp_as_path_access_list_cmd,
       "show bgp as-path-access-list AS_PATH_FILTER_NAME [json]",
       SHOW_STR
       BGP_STR
       "List AS path access lists\n"
       "AS path access list name\n"
       JSON_STR)
{
	int idx_word = 3;
	struct as_list *aslist;
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	aslist = as_list_lookup(argv[idx_word]->arg);
	if (aslist)
		as_list_show(vty, aslist, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

ALIAS (show_as_path_access_list,
       show_ip_as_path_access_list_cmd,
       "show ip as-path-access-list AS_PATH_FILTER_NAME [json]",
       SHOW_STR
       IP_STR
       "List AS path access lists\n"
       "AS path access list name\n"
       JSON_STR)

DEFUN (show_as_path_access_list_all,
       show_bgp_as_path_access_list_all_cmd,
       "show bgp as-path-access-list [json]",
       SHOW_STR
       BGP_STR
       "List AS path access lists\n"
       JSON_STR)
{
	bool uj = use_json(argc, argv);
	json_object *json = NULL;

	if (uj)
		json = json_object_new_object();

	as_list_show_all(vty, json);

	if (uj)
		vty_json(vty, json);

	return CMD_SUCCESS;
}

ALIAS (show_as_path_access_list_all,
       show_ip_as_path_access_list_all_cmd,
       "show ip as-path-access-list [json]",
       SHOW_STR
       IP_STR
       "List AS path access lists\n"
       JSON_STR)

/* Config emission is mgmtd-owned (M7 B7, proteus-bgp-filter): the
 * as_list_master state above is runtime state fed by the northbound apply
 * callbacks in bgpd/proteus/bgp_nb_filter.c (as_list_filter_set() et al.),
 * and rendered by bgpd/proteus/bgp_cli_filter.c's cli_show. AS_LIST_NODE
 * (lib/command.h) is no longer installed by bgpd -- vtysh still uses the
 * enum value on its own side to file "bgp as-path access-list" lines by
 * prefix regardless of which daemon emitted them (vtysh_config.c). */

static void bgp_aspath_filter_cmd_completion(vector comps,
					     struct cmd_token *token)
{
	struct as_list *aslist;

	for (aslist = as_list_master.str.head; aslist; aslist = aslist->next)
		vector_set(comps, XSTRDUP(MTYPE_COMPLETION, aslist->name));
}

static const struct cmd_variable_handler aspath_filter_handlers[] = {
	{.tokenname = "AS_PATH_FILTER_NAME",
	 .completions = bgp_aspath_filter_cmd_completion},
	{.completions = NULL}};

/* Register functions. */
void bgp_filter_init(void)
{
	install_element(VIEW_NODE, &show_bgp_as_path_access_list_cmd);
	install_element(VIEW_NODE, &show_ip_as_path_access_list_cmd);
	install_element(VIEW_NODE, &show_bgp_as_path_access_list_all_cmd);
	install_element(VIEW_NODE, &show_ip_as_path_access_list_all_cmd);

	cmd_variable_handler_register(aspath_filter_handlers);
}

void bgp_filter_reset(void)
{
	struct as_list *aslist;
	struct as_list *next;

	for (aslist = as_list_master.str.head; aslist; aslist = next) {
		next = aslist->next;
		as_list_delete(aslist);
	}

	assert(as_list_master.str.head == NULL);
	assert(as_list_master.str.tail == NULL);
}
