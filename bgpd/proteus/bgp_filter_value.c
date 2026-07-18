// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp-filter structured entry values -> legacy one-line value
 * strings (M7 batch B8).
 *
 * The YANG models standard community / large-community / extcommunity
 * list entries as typed sets (proteus-types groupings), but everything
 * around them still speaks the legacy single-line form: the config write
 * emits one 'bgp <kind>-list ... <deny|permit> VALUE' line per entry, and
 * bgpd's native setters (community_list_set() and friends,
 * bgpd/bgp_clist.c) take the whole space-joined VALUE string. This file
 * is the one serializer both sides share -- it is compiled into bgpd
 * (northbound apply/validate, bgp_nb_filter.c) and into mgmtd (cli_show,
 * bgp_cli_filter.c), which run in different processes and cannot share a
 * static helper. It depends only on libyang data-tree accessors, not on
 * any bgpd runtime state.
 *
 * Canonical ordering: the legacy parsers sort and deduplicate standard
 * values (community_str2com() ends in community_uniq_sort();
 * lcommunity_add_val()/ecommunity_add_val() insert memcmp-sorted), so the
 * retired native emitters printed each entry's set in ascending binary
 * order regardless of input order. The renderers below reproduce that:
 * communities ascending by their u32 value with well-known values
 * emitted by name (community_str()'s exact name set), large communities
 * ascending by (global-admin, local-data-1, local-data-2), extended
 * communities ascending by their encoded (type, subtype, value) bytes --
 * i.e. 2-byte-AS before IPv4 before 4-byte-AS, 'rt' before 'soo' within
 * an encoding, values ascending within that. The raw fallback tokens
 * (values outside the structured forms) follow the structured values
 * verbatim, in datastore order.
 */
#include <zebra.h>

#include "memory.h"
#include "yang.h"

#include "bgpd/proteus/bgp_filter_value.h"

/* Mirrors the well-known community values of bgpd/bgp_community.h
 * (COMMUNITY_GSHUT ... COMMUNITY_NO_PEER) without pulling in that
 * header's bgp_route.h/bgp_attr.h dependency chain, which does not
 * compile in mgmtd. The name set is exactly what community_gettoken()
 * accepts and community_str() re-emits (bgpd/bgp_community.c) --
 * COMMUNITY_INTERNET (0) is deliberately absent from both, hence also
 * here and in proteus-types' well-known-community enum. */
static const struct {
	const char *name;
	uint32_t value;
} bgp_filter_wk_communities[] = {
	{ "graceful-shutdown", 0xFFFF0000 },	      /* COMMUNITY_GSHUT */
	{ "accept-own", 0xFFFF0001 },		      /* COMMUNITY_ACCEPT_OWN */
	{ "route-filter-translated-v4", 0xFFFF0002 }, /* COMMUNITY_ROUTE_FILTER_TRANSLATED_v4 */
	{ "route-filter-v4", 0xFFFF0003 },	      /* COMMUNITY_ROUTE_FILTER_v4 */
	{ "route-filter-translated-v6", 0xFFFF0004 }, /* COMMUNITY_ROUTE_FILTER_TRANSLATED_v6 */
	{ "route-filter-v6", 0xFFFF0005 },	      /* COMMUNITY_ROUTE_FILTER_v6 */
	{ "llgr-stale", 0xFFFF0006 },		      /* COMMUNITY_LLGR_STALE */
	{ "no-llgr", 0xFFFF0007 },		      /* COMMUNITY_NO_LLGR */
	{ "accept-own-nexthop", 0xFFFF0008 },	      /* COMMUNITY_ACCEPT_OWN_NEXTHOP */
	{ "blackhole", 0xFFFF029A },		      /* COMMUNITY_BLACKHOLE */
	{ "no-export", 0xFFFFFF01 },		      /* COMMUNITY_NO_EXPORT */
	{ "no-advertise", 0xFFFFFF02 },		      /* COMMUNITY_NO_ADVERTISE */
	{ "local-AS", 0xFFFFFF03 },		      /* COMMUNITY_LOCAL_AS */
	{ "no-peer", 0xFFFFFF04 },		      /* COMMUNITY_NO_PEER */
};

bool bgp_filter_well_known_community(const char *name, uint32_t *value)
{
	for (size_t i = 0; i < array_size(bgp_filter_wk_communities); i++) {
		if (strcmp(name, bgp_filter_wk_communities[i].name) == 0) {
			if (value)
				*value = bgp_filter_wk_communities[i].value;
			return true;
		}
	}
	return false;
}

const char *bgp_filter_well_known_community_name(uint32_t value)
{
	for (size_t i = 0; i < array_size(bgp_filter_wk_communities); i++) {
		if (bgp_filter_wk_communities[i].value == value)
			return bgp_filter_wk_communities[i].name;
	}
	return NULL;
}

static void bgp_filter_value_append(char *buf, size_t size, const char *token)
{
	if (buf[0] != '\0')
		strlcat(buf, " ", size);
	strlcat(buf, token, size);
}

/* Append the raw leaf-list's tokens verbatim, in datastore order. */
static void bgp_filter_value_append_raws(const struct lyd_node *parent, char *buf, size_t size)
{
	const struct lyd_node *child;

	LY_LIST_FOR (lyd_child(parent), child) {
		if (strmatch(child->schema->name, "raw"))
			bgp_filter_value_append(buf, size, yang_dnode_get_string(child, NULL));
	}
}

static int bgp_filter_u32_cmp(const void *a, const void *b)
{
	uint32_t va = *(const uint32_t *)a, vb = *(const uint32_t *)b;

	if (va < vb)
		return -1;
	return va > vb;
}

void bgp_filter_communities_value_str(const struct lyd_node *communities, char *buf, size_t size)
{
	const struct lyd_node *child;
	uint32_t *vals;
	size_t nvals = 0, cap = 0;

	buf[0] = '\0';

	LY_LIST_FOR (lyd_child(communities), child)
		cap++;
	if (cap == 0)
		return;

	vals = XCALLOC(MTYPE_TMP, cap * sizeof(*vals));

	LY_LIST_FOR (lyd_child(communities), child) {
		if (strmatch(child->schema->name, "member"))
			vals[nvals++] = ((uint32_t)yang_dnode_get_uint16(child, "global-admin")
					 << 16) |
					yang_dnode_get_uint16(child, "local-admin");
		else if (strmatch(child->schema->name, "well-known"))
			bgp_filter_well_known_community(yang_dnode_get_string(child, NULL),
							&vals[nvals++]);
	}

	qsort(vals, nvals, sizeof(*vals), bgp_filter_u32_cmp);

	for (size_t i = 0; i < nvals; i++) {
		const char *name;
		char token[24];

		if (i > 0 && vals[i] == vals[i - 1])
			continue;

		name = bgp_filter_well_known_community_name(vals[i]);
		if (!name) {
			snprintf(token, sizeof(token), "%u:%u", vals[i] >> 16, vals[i] & 0xFFFF);
			name = token;
		}
		bgp_filter_value_append(buf, size, name);
	}

	XFREE(MTYPE_TMP, vals);

	bgp_filter_value_append_raws(communities, buf, size);
}

struct bgp_filter_lc_val {
	uint32_t global_admin;
	uint32_t local_data_1;
	uint32_t local_data_2;
};

static int bgp_filter_lc_cmp(const void *a, const void *b)
{
	const struct bgp_filter_lc_val *la = a, *lb = b;

	if (la->global_admin != lb->global_admin)
		return la->global_admin < lb->global_admin ? -1 : 1;
	if (la->local_data_1 != lb->local_data_1)
		return la->local_data_1 < lb->local_data_1 ? -1 : 1;
	if (la->local_data_2 != lb->local_data_2)
		return la->local_data_2 < lb->local_data_2 ? -1 : 1;
	return 0;
}

void bgp_filter_large_communities_value_str(const struct lyd_node *large_communities, char *buf,
					    size_t size)
{
	const struct lyd_node *child;
	struct bgp_filter_lc_val *vals;
	size_t nvals = 0, cap = 0;

	buf[0] = '\0';

	LY_LIST_FOR (lyd_child(large_communities), child)
		cap++;
	if (cap == 0)
		return;

	vals = XCALLOC(MTYPE_TMP, cap * sizeof(*vals));

	LY_LIST_FOR (lyd_child(large_communities), child) {
		if (!strmatch(child->schema->name, "member"))
			continue;
		vals[nvals].global_admin = yang_dnode_get_uint32(child, "global-admin");
		vals[nvals].local_data_1 = yang_dnode_get_uint32(child, "local-data-1");
		vals[nvals].local_data_2 = yang_dnode_get_uint32(child, "local-data-2");
		nvals++;
	}

	qsort(vals, nvals, sizeof(*vals), bgp_filter_lc_cmp);

	for (size_t i = 0; i < nvals; i++) {
		char token[36];

		if (i > 0 && bgp_filter_lc_cmp(&vals[i], &vals[i - 1]) == 0)
			continue;

		snprintf(token, sizeof(token), "%u:%u:%u", vals[i].global_admin,
			 vals[i].local_data_1, vals[i].local_data_2);
		bgp_filter_value_append(buf, size, token);
	}

	XFREE(MTYPE_TMP, vals);

	bgp_filter_value_append_raws(large_communities, buf, size);
}

/* One structured extended-community value with its binary-order sort key:
 * 'encoding' is the RFC 4360 type byte (0x00 2-byte-AS, 0x01 IPv4, 0x02
 * 4-byte-AS), 'subtype' the rt/soo subtype byte (0x02/0x03), so sorting
 * by (encoding, subtype, global-admin, local-admin) reproduces
 * ecommunity_add_val()'s memcmp order over the encoded 8 bytes. */
struct bgp_filter_ec_val {
	uint8_t encoding;
	uint8_t subtype;
	uint64_t global_admin;
	uint32_t local_admin;
	char text[80];
};

static int bgp_filter_ec_cmp(const void *a, const void *b)
{
	const struct bgp_filter_ec_val *ea = a, *eb = b;

	if (ea->encoding != eb->encoding)
		return ea->encoding < eb->encoding ? -1 : 1;
	if (ea->subtype != eb->subtype)
		return ea->subtype < eb->subtype ? -1 : 1;
	if (ea->global_admin != eb->global_admin)
		return ea->global_admin < eb->global_admin ? -1 : 1;
	if (ea->local_admin != eb->local_admin)
		return ea->local_admin < eb->local_admin ? -1 : 1;
	return 0;
}

static size_t bgp_filter_ec_collect(const struct lyd_node *set_container, uint8_t subtype,
				    const char *keyword, struct bgp_filter_ec_val *vals,
				    size_t nvals)
{
	const struct lyd_node *child;

	if (!set_container)
		return nvals;

	LY_LIST_FOR (lyd_child(set_container), child) {
		struct bgp_filter_ec_val *val = &vals[nvals];

		/* local-admin's width follows the encoding (as2 pairs a
		 * 2-byte AS with a 4-byte local administrator, as4/ipv4 a
		 * 4-byte global administrator with a 2-byte one). */
		if (strmatch(child->schema->name, "as2")) {
			val->encoding = 0x00;
			val->global_admin = yang_dnode_get_uint16(child, "global-admin");
			val->local_admin = yang_dnode_get_uint32(child, "local-admin");
		} else if (strmatch(child->schema->name, "as4")) {
			val->encoding = 0x02;
			val->global_admin = yang_dnode_get_uint32(child, "global-admin");
			val->local_admin = yang_dnode_get_uint16(child, "local-admin");
		} else if (strmatch(child->schema->name, "ipv4")) {
			struct in_addr addr;

			val->encoding = 0x01;
			yang_dnode_get_ipv4(&addr, child, "global-admin");
			val->global_admin = ntohl(addr.s_addr);
			val->local_admin = yang_dnode_get_uint16(child, "local-admin");
		} else {
			continue;
		}

		val->subtype = subtype;
		snprintf(val->text, sizeof(val->text), "%s %s:%s", keyword,
			 yang_dnode_get_string(child, "global-admin"),
			 yang_dnode_get_string(child, "local-admin"));
		nvals++;
	}

	return nvals;
}

void bgp_filter_extcommunities_value_str(const struct lyd_node *extcommunities, char *buf,
					 size_t size)
{
	const struct lyd_node *route_target = yang_dnode_get(extcommunities, "route-target");
	const struct lyd_node *route_origin = yang_dnode_get(extcommunities, "route-origin");
	const struct lyd_node *child;
	struct bgp_filter_ec_val *vals;
	size_t nvals = 0, cap = 0;

	buf[0] = '\0';

	if (route_target)
		LY_LIST_FOR (lyd_child(route_target), child)
			cap++;
	if (route_origin)
		LY_LIST_FOR (lyd_child(route_origin), child)
			cap++;

	if (cap > 0) {
		vals = XCALLOC(MTYPE_TMP, cap * sizeof(*vals));

		nvals = bgp_filter_ec_collect(route_target, 0x02, "rt", vals, nvals);
		nvals = bgp_filter_ec_collect(route_origin, 0x03, "soo", vals, nvals);

		qsort(vals, nvals, sizeof(*vals), bgp_filter_ec_cmp);

		for (size_t i = 0; i < nvals; i++)
			bgp_filter_value_append(buf, size, vals[i].text);

		XFREE(MTYPE_TMP, vals);
	}

	bgp_filter_value_append_raws(extcommunities, buf, size);
}

void bgp_filter_entry_value_str(const struct lyd_node *entry, char *buf, size_t size)
{
	const struct lyd_node *value;
	const char *list_name = lyd_parent(entry)->schema->name;

	if (yang_dnode_exists(entry, "regex")) {
		strlcpy(buf, yang_dnode_get_string(entry, "regex"), size);
		return;
	}

	buf[0] = '\0';

	if (strmatch(list_name, "community-list")) {
		value = yang_dnode_get(entry, "communities");
		if (value)
			bgp_filter_communities_value_str(value, buf, size);
	} else if (strmatch(list_name, "large-community-list")) {
		value = yang_dnode_get(entry, "large-communities");
		if (value)
			bgp_filter_large_communities_value_str(value, buf, size);
	} else if (strmatch(list_name, "extcommunity-list")) {
		value = yang_dnode_get(entry, "extcommunities");
		if (value)
			bgp_filter_extcommunities_value_str(value, buf, size);
	}
}
