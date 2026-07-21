// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * bgp_rpki code
 * Copyright (C) 2021 NVIDIA Corporation and Mellanox Technologies, LTD
 *                    All Rights Reserved
 *               Donald Sharp
 */
#ifndef __BGP_RPKI_H__
#define __BGP_RPKI_H__

#include "hook.h"

extern struct zebra_privs_t bgpd_privs;

enum rpki_states {
	RPKI_NOT_BEING_USED,
	RPKI_VALID,
	RPKI_NOTFOUND,
	RPKI_INVALID
};

/* Desired-state payload of the bgp_rpki_config_apply hook (TODO #31 B1):
 * bgpd's core northbound callbacks (bgpd/proteus/bgp_nb_rpki.c) build one
 * of these per proteus-bgp-rpki instance from the applied tree and the
 * bgpd_rpki plugin converges its runtime against it, so the plugin never
 * needs datastore access. All strings point into the applied tree and are
 * only valid for the duration of the hook call.
 */
struct bgp_rpki_cache_config {
	uint8_t preference;
	bool is_ssh;
	const char *host;
	/* TCP transport: port is a service-name string. */
	const char *tcp_port;
	/* SSH transport. */
	uint16_t ssh_port;
	const char *ssh_user;
	const char *ssh_privkey;
	const char *ssh_known_hosts; /* optional, may be NULL */
	/* Both transports: optional source address, may be NULL. */
	const char *source;
};

struct bgp_rpki_config {
	uint32_t polling_period;
	uint32_t expire_interval;
	uint16_t retry_interval;
	size_t cache_count;
	const struct bgp_rpki_cache_config *caches;
};

/* vrfname is NULL for the default VRF. */
DECLARE_HOOK(bgp_rpki_config_apply, (const char *vrfname, const struct bgp_rpki_config *cfg),
	     (vrfname, cfg));
DECLARE_HOOK(bgp_rpki_config_destroy, (const char *vrfname), (vrfname));

#endif
