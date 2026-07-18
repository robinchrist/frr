// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* proteus-bgp-filter structured entry values -> legacy one-line value
 * strings (M7 batch B8). See bgp_filter_value.c for why this is a file of
 * its own: it is compiled into both bgpd (northbound apply/validate,
 * bgp_nb_filter.c) and mgmtd (cli_show, bgp_cli_filter.c).
 */
#ifndef _FRR_PROTEUS_BGP_FILTER_VALUE_H
#define _FRR_PROTEUS_BGP_FILTER_VALUE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct lyd_node;

/* Well-known community names <-> values, exactly the set
 * community_gettoken() accepts and community_str() re-emits
 * (bgpd/bgp_community.c), which is also proteus-types'
 * well-known-community enum. */
extern bool bgp_filter_well_known_community(const char *name, uint32_t *value);
extern const char *bgp_filter_well_known_community_name(uint32_t value);

/* Serialize one entry's value ('communities' / 'large-communities' /
 * 'extcommunities' container for standard entries, the regex leaf
 * verbatim for expanded ones) back into the single space-joined VALUE
 * string of the 'bgp <kind>-list <standard|expanded> NAME seq SEQ
 * <deny|permit> VALUE' config line. 'entry' is the entry list element
 * dnode of any of the three lists. */
extern void bgp_filter_entry_value_str(const struct lyd_node *entry, char *buf, size_t size);

extern void bgp_filter_communities_value_str(const struct lyd_node *communities, char *buf,
					     size_t size);
extern void bgp_filter_large_communities_value_str(const struct lyd_node *large_communities,
						   char *buf, size_t size);
extern void bgp_filter_extcommunities_value_str(const struct lyd_node *extcommunities, char *buf,
						size_t size);

#endif /* _FRR_PROTEUS_BGP_FILTER_VALUE_H */
