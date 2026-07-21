// SPDX-License-Identifier: GPL-2.0-or-later
/* Copyright (C) 2026 Robin Christ, partimus GmbH */
/* Northbound apply callbacks for the proteus-bgp-bmp module (TODO #31
 * batch B2), registered by the proteus_bgp_bmp_info table in
 * bgpd/bgp_nb.c. Compiled unconditionally into bgpd; the runtime lives
 * in the dlopen'd bmp plugin, which subscribes to the hooks declared in
 * bgp_bmp.h at module load.
 *
 * Convergence model: unlike rpki's single desired-state hook, bmp keeps
 * the legacy per-operation granularity - each hook corresponds 1:1 to
 * one legacy configuration command's runtime effect. Two composite spots
 * converge through apply_finish instead of per-leaf events:
 *  - a connect list entry rereads its whole tuple (retry bounds, source
 *    interface) into one bgp_bmp_connect_set call, and
 *  - a monitor list entry folds its three view-point booleans into one
 *    BMP_MON_* flag mask for bgp_bmp_monitor_set.
 * Leaves whose state converges through such an apply_finish (or, for
 * 'no bmp targets', through the target-level teardown) register accept-
 * everything no-op callbacks.
 *
 * When bgpd runs without '-M bmp' the hooks have no listeners: the
 * entry-point callbacks (targets create, mirror-buffer-limit) degrade to
 * a warning and the config stays stored but inactive. VALIDATE never
 * rejects for plugin absence - a reject would fail the whole startup
 * init-push and drop the entire bgp config.
 */
#include <zebra.h>

#include "northbound.h"
#include "sockunion.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"
#include "bgpd/bgp_errors.h"
#include "bgpd/bgp_nb.h"
#include "bgpd/proteus/bgp_nb_local.h"
#include "bgpd/bgp_bmp.h"

DEFINE_HOOK(bgp_bmp_target_add, (struct bgp * bgp, const char *targetname), (bgp, targetname));
DEFINE_HOOK(bgp_bmp_target_del, (struct bgp * bgp, const char *targetname), (bgp, targetname));
DEFINE_HOOK(bgp_bmp_listener_add,
	    (struct bgp * bgp, const char *targetname, const union sockunion *addr, uint16_t port),
	    (bgp, targetname, addr, port));
DEFINE_HOOK(bgp_bmp_listener_del,
	    (struct bgp * bgp, const char *targetname, const union sockunion *addr, uint16_t port),
	    (bgp, targetname, addr, port));
DEFINE_HOOK(bgp_bmp_connect_set,
	    (struct bgp * bgp, const char *targetname, const char *hostname, uint16_t port,
	     uint32_t minretry, uint32_t maxretry, const char *srcif),
	    (bgp, targetname, hostname, port, minretry, maxretry, srcif));
DEFINE_HOOK(bgp_bmp_connect_del,
	    (struct bgp * bgp, const char *targetname, const char *hostname, uint16_t port),
	    (bgp, targetname, hostname, port));
DEFINE_HOOK(bgp_bmp_acl_set,
	    (struct bgp * bgp, const char *targetname, bool ipv6, const char *aclname),
	    (bgp, targetname, ipv6, aclname));
DEFINE_HOOK(bgp_bmp_stats_set, (struct bgp * bgp, const char *targetname, uint32_t interval_msec),
	    (bgp, targetname, interval_msec));
DEFINE_HOOK(bgp_bmp_stats_send_experimental_set,
	    (struct bgp * bgp, const char *targetname, bool send), (bgp, targetname, send));
DEFINE_HOOK(bgp_bmp_monitor_set,
	    (struct bgp * bgp, const char *targetname, afi_t afi, safi_t safi, uint8_t flags),
	    (bgp, targetname, afi, safi, flags));
DEFINE_HOOK(bgp_bmp_mirror_set, (struct bgp * bgp, const char *targetname, bool mirror),
	    (bgp, targetname, mirror));
DEFINE_HOOK(bgp_bmp_mirror_limit_set, (struct bgp * bgp, bool limited, uint32_t limit),
	    (bgp, limited, limit));
DEFINE_HOOK(bgp_bmp_import_vrf_add, (struct bgp * bgp, const char *targetname, const char *vrfname),
	    (bgp, targetname, vrfname));
DEFINE_HOOK(bgp_bmp_import_vrf_del, (struct bgp * bgp, const char *targetname, const char *vrfname),
	    (bgp, targetname, vrfname));

static void bmp_plugin_absent_warn(void)
{
	flog_warn(EC_BGP_BMP_PLUGIN_ABSENT,
		  "bmp configuration present but bgpd was started without -M bmp; config accepted but inactive");
}

/* The enclosing bgp instance and targets-group name of any node below a
 * targets list entry. */
static struct bgp *bmp_nb_bgp(const struct lyd_node *dnode)
{
	return bgp_nb_instance_lookup(dnode);
}

static const char *bmp_nb_targetname(const struct lyd_node *dnode)
{
	return yang_dnode_get_string(yang_dnode_get_parent(dnode, "targets"), "name");
}

/* The afi-safi enumeration values are '<afi2str_lower>-<safi2str>' of
 * exactly the family combinations the legacy grammar accepted. */
static void bmp_nb_monitor_afi_safi(const struct lyd_node *monitor_dnode, afi_t *afi, safi_t *safi)
{
	const char *value = yang_dnode_get_string(monitor_dnode, "afi-safi");
	const char *safi_str = strchr(value, '-') + 1;

	if (!strncmp(value, "ipv4", 4))
		*afi = AFI_IP;
	else if (!strncmp(value, "ipv6", 4))
		*afi = AFI_IP6;
	else
		*afi = AFI_L2VPN;

	if (strmatch(safi_str, "unicast"))
		*safi = SAFI_UNICAST;
	else if (strmatch(safi_str, "multicast"))
		*safi = SAFI_MULTICAST;
	else if (strmatch(safi_str, "vpn"))
		*safi = SAFI_MPLS_VPN;
	else
		*safi = SAFI_EVPN;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/mirror-buffer-limit
 */
int bmp_mirror_buffer_limit_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!hook_have_hooks(bgp_bmp_mirror_limit_set)) {
		bmp_plugin_absent_warn();
		return NB_OK;
	}

	hook_call(bgp_bmp_mirror_limit_set, bmp_nb_bgp(args->dnode), true,
		  yang_dnode_get_uint32(args->dnode, NULL));

	return NB_OK;
}

int bmp_mirror_buffer_limit_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_mirror_limit_set, bmp_nb_bgp(args->dnode), false, 0);

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets
 */
int bmp_targets_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (!hook_have_hooks(bgp_bmp_target_add)) {
		bmp_plugin_absent_warn();
		return NB_OK;
	}

	hook_call(bgp_bmp_target_add, bmp_nb_bgp(args->dnode),
		  yang_dnode_get_string(args->dnode, "name"));

	return NB_OK;
}

int bmp_targets_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* Tears down the whole group: sessions are closed, listeners and
	 * outbound connections are removed (the legacy 'no bmp targets'
	 * body). The children's own destroy callbacks are not called for
	 * a deleted subtree. */
	hook_call(bgp_bmp_target_del, bmp_nb_bgp(args->dnode),
		  yang_dnode_get_string(args->dnode, "name"));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/ipv6-access-list
 */
int bmp_targets_ipv6_access_list_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_acl_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode), true,
		  yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int bmp_targets_ipv6_access_list_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_acl_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode), true,
		  NULL);

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/ipv4-access-list
 */
int bmp_targets_ipv4_access_list_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_acl_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode), false,
		  yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int bmp_targets_ipv4_access_list_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_acl_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode), false,
		  NULL);

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/stats-send-experimental
 */
int bmp_targets_stats_send_experimental_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_stats_send_experimental_set, bmp_nb_bgp(args->dnode),
		  bmp_nb_targetname(args->dnode), yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/stats
 */
int bmp_targets_stats_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	/* The interval leaf's effective value; its default when the
	 * presence container was created bare. */
	hook_call(bgp_bmp_stats_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_uint32(args->dnode, "interval"));

	return NB_OK;
}

int bmp_targets_stats_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_stats_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode), 0);

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/stats/interval
 */
int bmp_targets_stats_interval_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_stats_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_uint32(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/mirror
 */
int bmp_targets_mirror_modify(struct nb_cb_modify_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_mirror_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_bool(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/monitor
 */
int bmp_targets_monitor_create(struct nb_cb_create_args *args)
{
	/* No-op: the entry's apply_finish converges the flag mask. */
	return NB_OK;
}

int bmp_targets_monitor_destroy(struct nb_cb_destroy_args *args)
{
	afi_t afi;
	safi_t safi;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	bmp_nb_monitor_afi_safi(args->dnode, &afi, &safi);
	hook_call(bgp_bmp_monitor_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  afi, safi, 0);

	return NB_OK;
}

void bmp_targets_monitor_apply_finish(struct nb_cb_apply_finish_args *args)
{
	afi_t afi;
	safi_t safi;
	uint8_t flags = 0;

	bmp_nb_monitor_afi_safi(args->dnode, &afi, &safi);
	if (yang_dnode_get_bool(args->dnode, "rib-in-pre-policy"))
		SET_FLAG(flags, BMP_MON_PREPOLICY);
	if (yang_dnode_get_bool(args->dnode, "rib-in-post-policy"))
		SET_FLAG(flags, BMP_MON_POSTPOLICY);
	if (yang_dnode_get_bool(args->dnode, "loc-rib"))
		SET_FLAG(flags, BMP_MON_LOC_RIB);

	hook_call(bgp_bmp_monitor_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  afi, safi, flags);
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/monitor/rib-in-pre-policy
 */
int bmp_targets_monitor_rib_in_pre_policy_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish converges the flag mask. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/monitor/rib-in-post-policy
 */
int bmp_targets_monitor_rib_in_post_policy_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish converges the flag mask. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/monitor/loc-rib
 */
int bmp_targets_monitor_loc_rib_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish converges the flag mask. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/import-vrf-view
 */
int bmp_targets_import_vrf_view_create(struct nb_cb_create_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_import_vrf_add, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

int bmp_targets_import_vrf_view_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_import_vrf_del, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_string(args->dnode, NULL));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/listener
 */
int bmp_targets_listener_create(struct nb_cb_create_args *args)
{
	union sockunion su;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (str2sockunion(yang_dnode_get_string(args->dnode, "address"), &su))
		return NB_OK;

	hook_call(bgp_bmp_listener_add, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  &su, yang_dnode_get_uint16(args->dnode, "port"));

	return NB_OK;
}

int bmp_targets_listener_destroy(struct nb_cb_destroy_args *args)
{
	union sockunion su;

	if (args->event != NB_EV_APPLY)
		return NB_OK;

	if (str2sockunion(yang_dnode_get_string(args->dnode, "address"), &su))
		return NB_OK;

	hook_call(bgp_bmp_listener_del, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  &su, yang_dnode_get_uint16(args->dnode, "port"));

	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/connect
 */
int bmp_targets_connect_create(struct nb_cb_create_args *args)
{
	/* No-op: the entry's apply_finish rereads the whole tuple. */
	return NB_OK;
}

int bmp_targets_connect_destroy(struct nb_cb_destroy_args *args)
{
	if (args->event != NB_EV_APPLY)
		return NB_OK;

	hook_call(bgp_bmp_connect_del, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_string(args->dnode, "hostname"),
		  yang_dnode_get_uint16(args->dnode, "port"));

	return NB_OK;
}

void bmp_targets_connect_apply_finish(struct nb_cb_apply_finish_args *args)
{
	const char *srcif = NULL;

	if (yang_dnode_exists(args->dnode, "source-interface"))
		srcif = yang_dnode_get_string(args->dnode, "source-interface");

	hook_call(bgp_bmp_connect_set, bmp_nb_bgp(args->dnode), bmp_nb_targetname(args->dnode),
		  yang_dnode_get_string(args->dnode, "hostname"),
		  yang_dnode_get_uint16(args->dnode, "port"),
		  yang_dnode_get_uint32(args->dnode, "min-retry"),
		  yang_dnode_get_uint32(args->dnode, "max-retry"), srcif);
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/connect/min-retry
 */
int bmp_targets_connect_min_retry_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish rereads the whole tuple. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/connect/max-retry
 */
int bmp_targets_connect_max_retry_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish rereads the whole tuple. */
	return NB_OK;
}

/*
 * XPath: /proteus-bgp:instance/proteus-bgp-bmp:bmp/targets/connect/source-interface
 */
int bmp_targets_connect_source_interface_modify(struct nb_cb_modify_args *args)
{
	/* No-op: the entry's apply_finish rereads the whole tuple. */
	return NB_OK;
}

int bmp_targets_connect_source_interface_destroy(struct nb_cb_destroy_args *args)
{
	/* No-op: the entry's apply_finish rereads the whole tuple. */
	return NB_OK;
}
