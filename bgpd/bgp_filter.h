// SPDX-License-Identifier: GPL-2.0-or-later
/* AS path filter list.
 * Copyright (C) 1999 Kunihiro Ishiguro
 */

#ifndef _QUAGGA_BGP_FILTER_H
#define _QUAGGA_BGP_FILTER_H

#include <typesafe.h>

struct frregex;

enum as_filter_type { AS_FILTER_DENY, AS_FILTER_PERMIT };

/* Element of AS path filter. */
struct as_filter {
	struct as_filter *next;
	struct as_filter *prev;

	enum as_filter_type type;

	struct frregex *reg;
	char *reg_str;

	/* Sequence number. */
	int64_t seq;
};

PREDECL_DLIST(as_list_list);
/* AS path filter list. */
struct as_list {
	char *name;

	struct as_list *next;
	struct as_list *prev;

	struct as_filter *head;
	struct as_filter *tail;

	/* Changes in AS path */
	struct as_list_list_head exclude_rule;
};


extern void bgp_filter_init(void);
extern void bgp_filter_reset(void);

extern enum as_filter_type as_list_apply(struct as_list *aslist, void *object);

extern struct as_list *as_list_lookup(const char *);
extern void as_list_add_hook(void (*func)(char *));
extern void as_list_delete_hook(void (*func)(const char *));
extern bool config_bgp_aspath_validate(const char *regstr);

/* Northbound entry points (M7 batch B7, bgpd/proteus/bgp_nb_filter.c). */
extern struct as_filter *bgp_aslist_seq_check(struct as_list *list, int64_t seq);
extern void as_list_filter_set(const char *name, int64_t seq, enum as_filter_type type,
			       const char *regstr, struct frregex *regex);
extern void as_list_filter_unset(struct as_list *aslist, struct as_filter *asfilter);
extern bool as_list_delete_all(const char *name);

#endif /* _QUAGGA_BGP_FILTER_H */
