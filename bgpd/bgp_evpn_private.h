// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN internal definitions
 * Copyright (C) 2017 Cumulus Networks, Inc.
 */

#ifndef _BGP_EVPN_PRIVATE_H
#define _BGP_EVPN_PRIVATE_H

#include "vxlan.h"
#include "zebra.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_ecommunity.h"

/* Maximum length of a formatted EVPN Route Target
 * Worst case route target: IPv4 + 2-byte local admin, e.g. 255.255.255.255:65535 
 * -> 15 (IPv4) + 1 (colon) + 5 (max uint16) + null terminator = 22
 */
#define BGP_EVPN_RT_STR_LEN 22

/* EVPN prefix lengths. This represents the sizeof struct evpn_addr
 * in bits  */
#define EVPN_ROUTE_PREFIXLEN (sizeof(struct evpn_addr) * 8)

/* EVPN route RD buffer length */
#define BGP_EVPN_PREFIX_RD_LEN 100

/* packet sizes for EVPN routes */
/* Type-1 route should be 25 bytes
 *  RD (8), ESI (10), eth-tag (4), vni (3)
 */
#define BGP_EVPN_TYPE1_PSIZE 25
/* Type-4 route should be either 23 or 35 bytes
 *  RD (8), ESI (10), ip-len (1), ip (4 or 16)
 */
#define BGP_EVPN_TYPE4_V4_PSIZE 23
#define BGP_EVPN_TYPE4_V6_PSIZE 35

enum bgp_evpn_rt_direction {
	BGP_EVPN_RT_DIRECTION_IMPORT = 1,
	BGP_EVPN_RT_DIRECTION_EXPORT = 2,
	BGP_EVPN_RT_DIRECTION_BOTH   = 3
};

enum bgp_evpn_rt_origin {
	/* implicitly generated auto route target (when no other route target is configured) */
    BGP_EVPN_RT_ORIGIN_AUTO_IMPLICIT   = 0,
	/* explicitly generated auto route target, e.g. `route-target import auto` in config */
    BGP_EVPN_RT_ORIGIN_AUTO_EXPLICIT   = 1,
	/* manually specified, e.g. regular `route-target import 123:456` in config */
    BGP_EVPN_RT_ORIGIN_MANUAL          = 2,
};

/* type discriminator for non-autoderived user configured route targets */
enum bgp_evpn_cfgd_rt_type {
	/* Wildcard Route Target, *:<uint32> e.g. *:98765432 */
	BGP_EVPN_CFGD_RT_TYPE_WILDCARD = 1,
	/* 2-byte AS Route Target, <AS2>:<uint32>, e.g. 64496:98765432, BGP Extended Community Type 0x00 */
	BGP_EVPN_CFGD_RT_TYPE_AS2 = 2,
	/* IPv4 Route Target, <IPv4>:<uint16>, e.g. 192.0.2.255:12345, BGP Extended Community Type 0x01 */
	BGP_EVPN_CFGD_RT_TYPE_IP4 = 3,
	/* 4-byte AS Route Target, <AS4>:<uint16>, e.g. 65551:12345, BGP Extended Community Type 0x02 */
	BGP_EVPN_CFGD_RT_TYPE_AS4 = 4,
};

/* User configured wildcard Route Target */
struct bgp_evpn_cfgd_wildcard_rt {
	uint32_t local_admin;
};
/* User configured 2-byte AS Route Target  */
struct bgp_evpn_cfgd_as2_rt {
	uint16_t as;
	uint32_t local_admin;
};
/* User configured IPv4 Route Target */
struct bgp_evpn_cfgd_ip4_rt {
	struct in_addr ip;
	uint16_t local_admin;
};
/* User configured 4-byte AS Route Target */
struct bgp_evpn_cfgd_as4_rt {
	uint32_t as;
	uint16_t local_admin;
};

PREDECL_SORTLIST_UNIQ(bgp_evpn_cfgd_rt_slu);


/* User configured Route Target, used for both VRF and EVI
 * If you make changes to this type which are not 100% compatible with
 * VRF or EVI, consider splitting this into two separate types!
 */
struct bgp_evpn_cfgd_rt {
	enum bgp_evpn_cfgd_rt_type type;
	union {
		struct bgp_evpn_cfgd_wildcard_rt wildcard_rt;
		struct bgp_evpn_cfgd_as2_rt as2_rt;
		struct bgp_evpn_cfgd_ip4_rt ip4_rt;
		struct bgp_evpn_cfgd_as4_rt as4_rt;
	} payload;

	struct bgp_evpn_cfgd_rt_slu_item slu_item;
};

extern int bgp_evpn_cfgd_rt_cmp(const struct bgp_evpn_cfgd_rt *rt1, const struct bgp_evpn_cfgd_rt *rt2);
extern struct bgp_evpn_cfgd_rt *bgp_evpn_cfgd_rt_from_ecom(const struct ecommunity *ecom, bool is_wildcard);


DECLARE_SORTLIST_UNIQ(bgp_evpn_cfgd_rt_slu, struct bgp_evpn_cfgd_rt, slu_item, bgp_evpn_cfgd_rt_cmp);



/*
 * We store both, import and export separately in order to not
 * modify the user config on store (e.g. split `route-target both` into two separate
 * `route-target import` and `route-target export` statements)...
 */
enum bgp_evpn_autort_cfgd {
	BGP_EVPN_AUTORT_NOT_CFGD = 0,
	BGP_EVPN_AUTORT_AUTO_CFGD = 1,
	BGP_EVPN_AUTORT_DISABLE_CFGD = 2
};

/*
 * We store both, import and export separately in order to not
 * modify the user config on store (e.g. split `route-target both` into two separate
 * `route-target import` and `route-target export` statements)...
 * Duplicates between "both" and "import"/"export" are not allowed
 * Note that it is technically possibly to construct RTs that appear as equal when printed but
 * are actually different (e.g. 2-byte AS RT and 4-byte AS RT with same 2-byte as and same 2-byte
 * local admin value would not compare equal but likely be rendered identically)
 * Configuration routines are expected to handle this and only ever pass us sensible route targets.
 * There can also be overlap (local-admin) between a fully qualified route-target and a wildcard!
 *
 * Used for both VRFs and EVIs! If you make changes to this type which are not 100% compatible with
 * VRF or EVI, consider splitting this into two separate types!
 */
struct bgp_evpn_rt_config {

	/*
	 * Auto RT config - consistency is difficult to represent in a data structure, invariants
	 * are maintained by config code
	 */
	enum bgp_evpn_autort_cfgd autort_cfgd_both;
	enum bgp_evpn_autort_cfgd autort_cfgd_import;
	enum bgp_evpn_autort_cfgd autort_cfgd_export;


	/*
	 * Route Targets configured as route-target both ...
	 * No wildcard RTs allowed (as export cannot have wildcard RTs)
	 */
	struct bgp_evpn_cfgd_rt_slu_head cfgd_both;
	/*
	 * Route Targets configured as route-target import ...
	 */
	struct bgp_evpn_cfgd_rt_slu_head cfgd_import;
	/*
	 * Route Targets configured as route-target export ...
	 * No wildcard RTs allowed!
	 */
	struct bgp_evpn_cfgd_rt_slu_head cfgd_export;
};





struct bgp_evpn_effective_wildcard_rt {
	/* local_admin value in network byte order (so it's parallel with ecommunity_val) */
	uint32_t local_admin_nbo;

	struct bgp_evpn_effective_wildcard_rt_slu_item slu_item;
};

extern int bgp_evpn_effective_wildcard_rt_cmp(const struct bgp_evpn_effective_wildcard_rt *rt1, const struct bgp_evpn_effective_wildcard_rt *rt2);

DECLARE_SORTLIST_UNIQ(bgp_evpn_effective_wildcard_rt_slu, struct bgp_evpn_effective_wildcard_rt, slu_item, bgp_evpn_effective_wildcard_rt_cmp);


struct bgp_evpn_effective_fq_rt {
	struct ecommunity_val ecom_val;

	struct bgp_evpn_effective_fq_rt_slu_item slu_item;
};

extern int bgp_evpn_effective_fq_rt_cmp(const struct bgp_evpn_effective_fq_rt *rt1, const struct bgp_evpn_effective_fq_rt *rt2);

DECLARE_SORTLIST_UNIQ(bgp_evpn_effective_fq_rt_slu, struct bgp_evpn_effective_fq_rt, slu_item, bgp_evpn_effective_fq_rt_cmp);



static const struct message bgp_evpn_route_type_str[] = { { BGP_EVPN_AD_ROUTE, "AD" },
							  { BGP_EVPN_MAC_IP_ROUTE, "MACIP" },
							  { BGP_EVPN_IMET_ROUTE, "IMET" },
							  { BGP_EVPN_ES_ROUTE, "ES" },
							  { BGP_EVPN_IP_PREFIX_ROUTE, "IP-PREFIX" },
							  { 0 } };

RB_HEAD(bgp_es_evi_rb_head, bgp_evpn_es_evi);
RB_PROTOTYPE(bgp_es_evi_rb_head, bgp_evpn_es_evi, rb_node,
		bgp_es_evi_rb_cmp);

/* EVPN Service Interface type of an EVI (RFC 7432 section 6).
 * The type is part of the EVI's identity and immutable for its lifetime
 * (it is encoded in the config keyword, e.g. `vlan-based-evi`).
 */
enum bgp_evpn_evi_type {
	/* VLAN-Based Service Interface: one broadcast domain per EVI */
	BGP_EVPN_EVI_TYPE_VLAN_BASED = 0,
	/* Future: VLAN Bundle / VLAN-Aware Bundle Service Interfaces */
};

/* How an EVI object came into existence */
enum bgp_evpn_evi_origin {
	/* Explicitly configured via the new `vlan-based-evi NAME` syntax */
	BGP_EVPN_EVI_ORIGIN_CFG = 0,
	/* Created through the legacy `vni X` configuration (default instance
	 * only); tenant VRF is dataplane-derived unless `tenant-vrf` is set
	 */
	BGP_EVPN_EVI_ORIGIN_LEGACY_VNI,
	/* Auto-discovered from the dataplane via zebra (advertise-all-vni /
	 * auto-discover-vnis); not part of the configuration
	 */
	BGP_EVPN_EVI_ORIGIN_AUTO_DISCOVERED,
};

/*
 * An EVI (EVPN Instance) is the instantiation of an EVPN Service Interface.
 * EVIs are identified by their name (scoped to their registry: the tenant
 * VRF's `evis_by_name` for configured EVIs, bgp_evpn_global.global_evis for
 * tenant-less / legacy / auto-discovered ones). A VNI is an *optional*
 * dataplane binding of an EVI - NOT its identity: an EVI may exist and import
 * routes without any VNI (it then simply cannot originate routes).
 * Currently `vni` is still mandatory at creation; this is lifted with the
 * origination-l2vni decoupling.
 */
struct bgp_evpn_evi {
	/* Identity: name, unique within the owning registry. Legacy-`vni X`
	 * EVIs are named "vni-X"; auto-discovered EVIs "vni!X" ('!' is not
	 * allowed in user-assigned names, so generated names never collide).
	 */
	char *name;
	enum bgp_evpn_evi_type type;
	enum bgp_evpn_evi_origin origin;

	/* intrusive hash item for the owning name registry (tenant VRF's
	 * evis_by_name or bgp_evpn_global.global_evis, see origin)
	 */
	struct evi_name_hash_item evi_name_item;

	/* Legacy `vni X` EVIs only: explicit tenant VRF binding
	 * (`tenant-vrf NAME`, resolved by name) - or dataplane-derived tenancy
	 * (`auto-tenant-vrf`, the default; DEPRECATED, will be removed).
	 * New-style configured EVIs get their tenant from their config
	 * location instead.
	 */
	char *cfgd_tenant_vrf_name;
	bool auto_tenant_vrf;

	/* Configured underlay VRF binding (`underlay-vrf NAME`, stored by
	 * name): the underlay this EVI originates its routes into. NULL =
	 * unbound (the EVI cannot originate routes). While the
	 * single-underlay limitation is in place, the master instance is what
	 * is used operatively.
	 */
	char *cfgd_underlay_vrf_name;

	vni_t vni;
	vrf_id_t tenant_vrf_id;
	ifindex_t svi_ifindex;

	/* Last dataplane report for the VNI (diagnostics) */
	struct bgp_evpn_vni_dp_info dp;
	uint32_t flags;
#define EVI_FLAG_USER_CFGD              0x1  /* EVI is user configured */
#define EVI_FLAG_LIVE              0x2  /* EVI is "live" */
#define EVI_FLAG_RD_CFGD           0x4  /* EVI's RD is user configured. */
#define EVI_FLAG_IMPRT_CFGD        0x8  /* EVI's Import RT is user configured */
#define EVI_FLAG_EXPRT_CFGD        0x10 /* EVI's Export RT is user configured */
/* Attach both L2VNI and L3VNI if needed for this EVI (symmetric IRB) */
#define EVI_FLAG_USE_TWO_LABELS 0x20
#define EVI_FLAG_ADD		0x40 /* L2VNI Add */

	struct bgp *bgp_vrf; /* back pointer to the vrf instance */

	/* Per-EVI flag - if this flag is set, we announce a MAC/IP route for the SVI of this EVI */
	bool advertise_svi_macip;

	/* This flag was completely undocumented, the following was derived from a code analysis:
	 * so take it with a grain of salt
	 *
	 * Per-EVI EVPN flag - If this flag is set, we announce a MAC/IP route for each anycast gateway
	 * (MACVLAN on top of SVI) and SVI in this EVI **with the Default Gateway Extended Community set**
	 * 
	 * Difference to advertise_svi_macip:
	 * - MAC/IP for anycast gateway is advertised
	 * - MAC/IP for anycast gateway and SVI are advertised with the Default Gateway Extended Community set
	 */
	bool advertise_gw_macip;

	/* Hidden / Debug! Per EVI flag - if this flag is set
	 * we advertise a Type 5 Route for the SVI's subnet
	 */
	bool advertise_subnet;

	/* Id for deriving the RD
	 * automatically for this VNI */
	uint16_t rd_id;

	/* RD for this VNI. */
	struct prefix_rd prd;
	char *prd_pretty;

	/* Route type 3 field */
	struct ipaddr originator_ip;

	/* PIM-SM MDT group for BUM flooding */
	struct in_addr mcast_grp;

	/* Wrapper struct to group EVI route target config (intended state) */
	struct bgp_evpn_rt_config *evi_rt_config;

	/* Effective import RTs derived from rt_config (wildcard = auto,
	 * fq = manually configured or auto-generated fully-qualified).
	 * Effective export RTs are always fully-qualified.
	 */
	struct bgp_evpn_effective_wildcard_rt_slu_head effective_wildcard_import_rts;
	struct bgp_evpn_effective_fq_rt_slu_head effective_fq_import_rts;
	struct bgp_evpn_effective_fq_rt_slu_head effective_fq_export_rts;

	/*
	 * EVPN route that uses gateway IP overlay index as its nexthop
	 * needs to do a recursive lookup.
	 * A remote MAC/IP entry should be present for the gateway IP.
	 * Maintain a hash of the addresses received via remote MAC/IP routes
	 * for efficient gateway IP recursive lookup in this EVI
	 */
	struct hash *remote_ip_hash;

	/* Route tables for EVPN routes for
	 * this VNI. */
	struct bgp_table *ip_table;
	struct bgp_table *mac_table;

	/* RB tree of ES-EVIs */
	struct bgp_es_evi_rb_head es_evi_rb_tree;

	/* List of local ESs */
	struct list *local_es_evi_list;

	struct zebra_l2_vni_item zl2vni;

	/* intrusive list item for bgp->evis */
	struct bgp_evis_slu_item bgp_evis_item;

	/* intrusive hash item for bgp_evpn_global.evihash */
	struct evihash_item evihash_item;

	/* intrusive hash item for bgp_evpn_global.evi_svi_hash */
	struct evi_svi_hash_item evi_svi_hash_item;

	enum vxlan_flood_control vxlan_flood_ctrl;

	QOBJ_FIELDS;
};

DECLARE_QOBJ_TYPE(bgp_evpn_evi);

DECLARE_LIST(zebra_l2_vni, struct bgp_evpn_evi, zl2vni);

static inline int bgp_evis_slu_cmp(const struct bgp_evpn_evi *a,
			       const struct bgp_evpn_evi *b)
{
	/* Keyed by name (the EVI identity) - NOT by VNI, since the VNI is an
	 * optional dataplane binding and may be absent (0) on several EVIs
	 */
	return strcmp(a->name, b->name);
}

DECLARE_SORTLIST_UNIQ(bgp_evis_slu, struct bgp_evpn_evi, bgp_evis_item,
		      bgp_evis_slu_cmp);

static inline uint32_t evihash_key(const struct bgp_evpn_evi *evi)
{
	return jhash_1word(evi->vni, 0);
}

static inline int evihash_cmp(const struct bgp_evpn_evi *a,
			      const struct bgp_evpn_evi *b)
{
	return a->vni > b->vni ? 1 : (a->vni < b->vni ? -1 : 0);
}

DECLARE_HASH(evihash, struct bgp_evpn_evi, evihash_item, evihash_cmp,
	     evihash_key);

static inline uint32_t evi_svi_hash_key(const struct bgp_evpn_evi *evi)
{
	return jhash_1word(evi->svi_ifindex, 0);
}

static inline int evi_svi_hash_cmp(const struct bgp_evpn_evi *a,
				  const struct bgp_evpn_evi *b)
{
	return a->svi_ifindex > b->svi_ifindex ? 1
		: (a->svi_ifindex < b->svi_ifindex ? -1 : 0);
}

DECLARE_HASH(evi_svi_hash, struct bgp_evpn_evi, evi_svi_hash_item, evi_svi_hash_cmp, evi_svi_hash_key);

static inline uint32_t evi_name_hash_key(const struct bgp_evpn_evi *evi)
{
	return jhash(evi->name, strlen(evi->name), 0x45564921);
}

static inline int evi_name_hash_cmp(const struct bgp_evpn_evi *a,
				    const struct bgp_evpn_evi *b)
{
	return strcmp(a->name, b->name);
}

DECLARE_HASH(evi_name_hash, struct bgp_evpn_evi, evi_name_item,
	     evi_name_hash_cmp, evi_name_hash_key);

PREDECL_SORTLIST_UNIQ(vrf_mapped_bgp_instance_slu);

/* Wrapper struct to maintain a sorted unique list of VRFs mapped to something
 * (something is currently vrf_..._irt_node)
 */
struct vrf_mapped_bgp_instance {
	struct bgp *bgp;

	struct vrf_mapped_bgp_instance_slu_item slu_item;
};

static inline int vrf_mapped_bgp_instance_cmp(const struct vrf_mapped_bgp_instance *a,
					    const struct vrf_mapped_bgp_instance *b)
{
	/* simply compare pointer values */
	void* bgp_a = (void*)a->bgp;
	void* bgp_b = (void*)b->bgp;
	return bgp_a > bgp_b ? 1 : (bgp_a < bgp_b ? -1 : 0);
}

DECLARE_SORTLIST_UNIQ(vrf_mapped_bgp_instance_slu, struct vrf_mapped_bgp_instance, slu_item, vrf_mapped_bgp_instance_cmp);

/* Mapping of Import RT to VRFs.
 * The Import RTs of all VRFs are maintained in a hash table with each
 * RT linking to all VRFs that will import routes matching this RT.
 */
struct vrf_fq_irt_node {
	/* typesafe hash item */
	struct vrf_fq_irt_nodes_item hash_item;

	/* Key */
	/* Actual RT value */
	struct ecommunity_val rt;

	/* Value */
	/* List of VRFs importing routes matching this RT. */
	// struct list *vrfs;
	struct vrf_mapped_bgp_instance_slu_head vrfs;
};

extern int vrf_fq_irt_node_hash_cmp(const struct vrf_fq_irt_node *a, const struct vrf_fq_irt_node *b);
extern uint32_t vrf_fq_irt_node_hash_key(const struct vrf_fq_irt_node *irt);

DECLARE_HASH(vrf_fq_irt_nodes, struct vrf_fq_irt_node, hash_item, vrf_fq_irt_node_hash_cmp, vrf_fq_irt_node_hash_key);


struct vrf_wildcard_irt_node {
	/* typesafe hash item */
	struct vrf_wildcard_irt_nodes_item hash_item;

	/* Key */
	/* Actual RT value */
	uint32_t local_admin_nbo;

	/* Value */
	/* List of VRFs importing routes matching this RT. */
	// struct list *vrfs;
	struct vrf_mapped_bgp_instance_slu_head vrfs;
};

extern int vrf_wildcard_irt_node_hash_cmp(const struct vrf_wildcard_irt_node *a, const struct vrf_wildcard_irt_node *b);
extern uint32_t vrf_wildcard_irt_node_hash_key(const struct vrf_wildcard_irt_node *irt);

DECLARE_HASH(vrf_wildcard_irt_nodes, struct vrf_wildcard_irt_node, hash_item, vrf_wildcard_irt_node_hash_cmp, vrf_wildcard_irt_node_hash_key);


PREDECL_SORTLIST_UNIQ(evi_mapped_evi_slu);

/* Wrapper struct to maintain a sorted unique list of EVIs mapped to something
 * (something is currently evi_..._irt_node)
 */
struct evi_mapped_evi {
	struct bgp_evpn_evi *evi;

	struct evi_mapped_evi_slu_item slu_item;
};

static inline int evi_mapped_evi_cmp(const struct evi_mapped_evi *a, const struct evi_mapped_evi *b)
{
	/* simply compare pointer values */
	void* evi_a = (void*)a->evi;
	void* evi_b = (void*)b->evi;
	return evi_a > evi_b ? 1 : (evi_a < evi_b ? -1 : 0);
}

DECLARE_SORTLIST_UNIQ(evi_mapped_evi_slu, struct evi_mapped_evi, slu_item, evi_mapped_evi_cmp);

/* Mapping of Import RT to EVIs.
 * The Import RTs of all EVIs are maintained in a hash table with each
 * RT linking to all EVIs that will import routes matching this RT.
 */
struct evi_fq_irt_node {
	/* typesafe hash item */
	struct evi_fq_irt_nodes_item hash_item;

	/* Key */
	/* Actual RT value */
	struct ecommunity_val rt;

	/* Value */
	/* List of EVIs importing routes matching this RT. */
	// struct list *evis;
	struct evi_mapped_evi_slu_head evis;
};

extern int evi_fq_irt_node_hash_cmp(const struct evi_fq_irt_node *a, const struct evi_fq_irt_node *b);
extern uint32_t evi_fq_irt_node_hash_key(const struct evi_fq_irt_node *irt);

DECLARE_HASH(evi_fq_irt_nodes, struct evi_fq_irt_node, hash_item, evi_fq_irt_node_hash_cmp, evi_fq_irt_node_hash_key);


struct evi_wildcard_irt_node {
	/* typesafe hash item */
	struct evi_wildcard_irt_nodes_item hash_item;

	/* Key */
	/* Actual RT value */
	uint32_t local_admin_nbo;

	/* Value */
	/* List of EVIs importing routes matching this RT. */
	// struct list *evis;
	struct evi_mapped_evi_slu_head evis;
};

extern int evi_wildcard_irt_node_hash_cmp(const struct evi_wildcard_irt_node *a, const struct evi_wildcard_irt_node *b);
extern uint32_t evi_wildcard_irt_node_hash_key(const struct evi_wildcard_irt_node *irt);

DECLARE_HASH(evi_wildcard_irt_nodes, struct evi_wildcard_irt_node, hash_item, evi_wildcard_irt_node_hash_cmp, evi_wildcard_irt_node_hash_key);



#define EVPN_DAD_DEFAULT_TIME 180 /* secs */
#define EVPN_DAD_DEFAULT_MAX_MOVES 5 /* default from RFC 7432 */
#define EVPN_DAD_DEFAULT_AUTO_RECOVERY_TIME 1800 /* secs */

struct bgp_evpn_info {
	/* enable disable dup detect */
	bool dup_addr_detect;

	/* Detection time(M) */
	int dad_time;
	/* Detection max moves(N) */
	uint32_t dad_max_moves;
	/* Permanent freeze */
	bool dad_freeze;
	/* Recovery time */
	uint32_t dad_freeze_time;

	/* Per-VRF flag - if this flag is set, we announce a MAC/IP route for the SVIs of all EVIs
	 * assigned to this VRF
	 * 
	 * Basically enables advertise_svi_macip for each EVI in the VRF (see struct bgp_evpn_evi)
	 */
	bool advertise_svi_macip;

	/* MAC-VRF Site-of-Origin
	 * - added to all routes exported from L2VNI
	 * - Type-2/3 routes with matching SoO not imported into L2VNI
	 * - Type-2/5 routes with matching SoO not imported into L3VNI
	 */
	struct ecommunity *soo;

	/* PIP feature knob */
	bool advertise_pip;
	/* PIP IP (sys ip) */
	struct ipaddr pip_ip;
	struct ipaddr pip_ip_static;
	/* PIP MAC (sys MAC) */
	struct ethaddr pip_rmac;
	struct ethaddr pip_rmac_static;
	struct ethaddr pip_rmac_zebra;
	bool is_anycast_mac;
};

/* This structure defines an entry in remote_ip_hash */
struct evpn_remote_ip {
	struct ipaddr addr;
	struct list *macip_path_list;
};

static inline int is_vrf_rd_configured(struct bgp *bgp_vrf)
{
	return (CHECK_FLAG(bgp_vrf->vrf_flags, BGP_EVPN_VRF_RD_CFGD));
}

static inline int bgp_evpn_vrf_rd_matches_existing(struct bgp *bgp_vrf,
						   struct prefix_rd *prd)
{
	return (memcmp(&bgp_vrf->vrf_prd.val, prd->val, ECOMMUNITY_SIZE) == 0);
}

static inline vni_t bgp_evpn_evi_get_l3vni(struct bgp_evpn_evi *evi)
{
	return evi->bgp_vrf ? evi->bgp_vrf->l3vni : 0;
}

static inline void bgp_evpn_evi_get_rmac(struct bgp_evpn_evi *evi, struct ethaddr *rmac)
{
	memset(rmac, 0, sizeof(struct ethaddr));
	if (!evi->bgp_vrf)
		return;
	memcpy(rmac, &evi->bgp_vrf->rmac, sizeof(struct ethaddr));
}

/* Apparently an EVI can exist without a linked VRF?? */
static inline struct bgp_evpn_effective_fq_rt_slu_head *bgp_evpn_evi_get_vrf_export_rts(struct bgp_evpn_evi *evi)
{
	if (!evi->bgp_vrf)
		return NULL;

	return &evi->bgp_vrf->effective_fq_export_rts;
}

extern void bgp_evpn_es_handle_evi_linked_to_vrf(struct bgp_evpn_evi *evi);
extern void bgp_evpn_es_handle_evi_unlinked_from_vrf(struct bgp_evpn_evi *evi);

extern void bgp_evpn_evi_link_to_vrf(struct bgp_evpn_evi *evi);
extern void bgp_evpn_evi_unlink_from_vrf(struct bgp_evpn_evi *evi);

static inline int bgp_evpn_evi_is_user_configured(const struct bgp_evpn_evi *evi)
{
	return (CHECK_FLAG(evi->flags, EVI_FLAG_USER_CFGD));
}

static inline int bgp_evpn_evi_is_live(const struct bgp_evpn_evi *evi)
{
	return (CHECK_FLAG(evi->flags, EVI_FLAG_LIVE));
}

static inline int bgp_evpn_evi_is_rd_configured(const struct bgp_evpn_evi *evi)
{
	return (CHECK_FLAG(evi->flags, EVI_FLAG_RD_CFGD));
}

static inline bool bgp_evpn_vrf_has_l3vni(const struct bgp *bgp_vrf)
{
	return (bgp_vrf->l3vni);
}

/* L3VNI used for control-plane derivation (auto-RTs): the configured intent
 * (`origination-l3vni`) wins; the zebra-reported (dataplane) L3VNI is the
 * fallback for legacy configs where the L3VNI is only configured in zebra
 * (`vrf X vni Y`). Using the intent means auto-RTs (and hence the import
 * behavior) do not flap with dataplane events.
 */
static inline vni_t bgp_evpn_vrf_get_intent_l3vni(const struct bgp *bgp_vrf)
{
	return bgp_vrf->evpn_cfgd_l3vni ? bgp_vrf->evpn_cfgd_l3vni : bgp_vrf->l3vni;
}

static inline int bgp_evpn_vrf_is_l3vni_live(const struct bgp *bgp_vrf)
{
	return (bgp_vrf->l3vni && bgp_vrf->l3vni_svi_ifindex);
}

static inline int bgp_evpn_rd_matches_existing(struct bgp_evpn_evi *evi,
					       struct prefix_rd *prd)
{
	return (memcmp(&evi->prd.val, prd->val, ECOMMUNITY_SIZE) == 0);
}

static inline int is_import_rt_configured(struct bgp_evpn_evi *evi)
{
	return (CHECK_FLAG(evi->flags, EVI_FLAG_IMPRT_CFGD));
}

static inline int is_export_rt_configured(struct bgp_evpn_evi *evi)
{
	return (CHECK_FLAG(evi->flags, EVI_FLAG_EXPRT_CFGD));
}

static inline void encode_es_rt_extcomm(struct ecommunity_val *eval,
					struct ethaddr *mac)
{
	memset(eval, 0, sizeof(struct ecommunity_val));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ES_IMPORT_RT;
	memcpy(&eval->val[2], mac, ETH_ALEN);
}

static inline void encode_df_elect_extcomm(struct ecommunity_val *eval,
					   uint16_t pref)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_DF_ELECTION;
	eval->val[2] = EVPN_MH_DF_ALG_PREF;
	eval->val[6] = (pref >> 8) & 0xff;
	eval->val[7] = pref & 0xff;
}

static inline void encode_esi_label_extcomm(struct ecommunity_val *eval,
					bool single_active)
{
	memset(eval, 0, sizeof(struct ecommunity_val));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ESI_LABEL;
	if (single_active)
		eval->val[2] |= (1 << 0);
}

static inline void encode_rmac_extcomm(struct ecommunity_val *eval,
				       struct ethaddr *rmac)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ROUTERMAC;
	memcpy(&eval->val[2], rmac, ETH_ALEN);
}

/* Encode Default Gateway Extended Community 
 * It is a Transitive Opaque Extended Community, type = 0x03, sub-type = 0x0d
 */
static inline void encode_default_gw_extcomm(struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_OPAQUE;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_DEF_GW;
}

static inline void encode_mac_mobility_extcomm(int static_mac, uint32_t seq,
					       struct ecommunity_val *eval)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY;
	if (static_mac)
		eval->val[2] = ECOMMUNITY_EVPN_SUBTYPE_MACMOBILITY_FLAG_STICKY;
	eval->val[4] = (seq >> 24) & 0xff;
	eval->val[5] = (seq >> 16) & 0xff;
	eval->val[6] = (seq >> 8) & 0xff;
	eval->val[7] = seq & 0xff;
}

static inline void encode_na_flag_extcomm(struct ecommunity_val *eval,
					  bool na_flag, bool proxy)
{
	memset(eval, 0, sizeof(*eval));
	eval->val[0] = ECOMMUNITY_ENCODE_EVPN;
	eval->val[1] = ECOMMUNITY_EVPN_SUBTYPE_ND;
	if (na_flag)
		eval->val[2] |= ECOMMUNITY_EVPN_SUBTYPE_ND_ROUTER_FLAG;
	if (proxy)
		eval->val[2] |= ECOMMUNITY_EVPN_SUBTYPE_PROXY_FLAG;
}

static inline void ip_prefix_from_type5_prefix(const struct prefix_evpn *evp,
					       struct prefix *ip)
{
	memset(ip, 0, sizeof(struct prefix));
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		ip->family = AF_INET;
		ip->prefixlen = evp->prefix.prefix_addr.ip_prefix_length;
		memcpy(&(ip->u.prefix4), &(evp->prefix.prefix_addr.ip.ip),
		       IPV4_MAX_BYTELEN);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		ip->family = AF_INET6;
		ip->prefixlen = evp->prefix.prefix_addr.ip_prefix_length;
		memcpy(&(ip->u.prefix6), &(evp->prefix.prefix_addr.ip.ip),
		       IPV6_MAX_BYTELEN);
	}
}

static inline bool is_evpn_prefix_default(const struct prefix *evp)
{
	if (evp->family != AF_EVPN)
		return false;

	/*
	 * EVPN default type-5 route
	 * RD:[5]:[0]:[0.0.0.0/0]/352 or RD:[5]:[0]:[::/0]/352
	 */
	if ((evp->u.prefix_evpn.route_type == BGP_EVPN_IP_PREFIX_ROUTE) &&
	    (evp->u.prefix_evpn.prefix_addr.ip_prefix_length == 0))
		return true;

	return false;
}

static inline void ip_prefix_from_type2_prefix(const struct prefix_evpn *evp,
					       struct prefix *ip)
{
	memset(ip, 0, sizeof(struct prefix));
	if (is_evpn_prefix_ipaddr_v4(evp)) {
		ip->family = AF_INET;
		ip->prefixlen = IPV4_MAX_BITLEN;
		memcpy(&(ip->u.prefix4), &(evp->prefix.macip_addr.ip.ip),
		       IPV4_MAX_BYTELEN);
	} else if (is_evpn_prefix_ipaddr_v6(evp)) {
		ip->family = AF_INET6;
		ip->prefixlen = IPV6_MAX_BITLEN;
		memcpy(&(ip->u.prefix6), &(evp->prefix.macip_addr.ip.ip),
		       IPV6_MAX_BYTELEN);
	}
}

static inline void ip_prefix_from_evpn_prefix(const struct prefix_evpn *evp,
					      struct prefix *ip)
{
	if (evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE)
		ip_prefix_from_type2_prefix(evp, ip);
	else if (evp->prefix.route_type == BGP_EVPN_IP_PREFIX_ROUTE)
		ip_prefix_from_type5_prefix(evp, ip);
}

static inline void build_evpn_type2_prefix(struct prefix_evpn *p,
					   struct ethaddr *mac,
					   struct ipaddr *ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_MAC_IP_ROUTE;
	memcpy(&p->prefix.macip_addr.mac.octet, mac->octet, ETH_ALEN);
	p->prefix.macip_addr.ip.ipa_type = IPADDR_NONE;
	memcpy(&p->prefix.macip_addr.ip, ip, sizeof(*ip));
}

static inline void
bgp_evpn_build_type5_prefix_evpn_from_ip_prefix(struct prefix_evpn *evp,
				  const struct prefix *ip_prefix)
{
	struct ipaddr ip;

	memset(&ip, 0, sizeof(struct ipaddr));
	if (ip_prefix->family == AF_INET) {
		ip.ipa_type = IPADDR_V4;
		memcpy(&ip.ipaddr_v4, &ip_prefix->u.prefix4,
		       sizeof(struct in_addr));
	} else {
		ip.ipa_type = IPADDR_V6;
		memcpy(&ip.ipaddr_v6, &ip_prefix->u.prefix6,
		       sizeof(struct in6_addr));
	}

	memset(evp, 0, sizeof(struct prefix_evpn));
	evp->family = AF_EVPN;
	evp->prefixlen = EVPN_ROUTE_PREFIXLEN;
	evp->prefix.route_type = BGP_EVPN_IP_PREFIX_ROUTE;
	evp->prefix.prefix_addr.ip_prefix_length = ip_prefix->prefixlen;
	evp->prefix.prefix_addr.ip.ipa_type = ip.ipa_type;
	memcpy(&evp->prefix.prefix_addr.ip, &ip, sizeof(struct ipaddr));
}

static inline void build_evpn_type3_prefix(struct prefix_evpn *p,
					   struct ipaddr *originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_IMET_ROUTE;
	if (IS_IPADDR_V4(originator_ip))
		p->prefix.imet_addr.ip_prefix_length = IPV4_MAX_BITLEN;
	else if (IS_IPADDR_V6(originator_ip))
		p->prefix.imet_addr.ip_prefix_length = IPV6_MAX_BITLEN;
	p->prefix.imet_addr.ip = *originator_ip;
}

static inline void build_evpn_type4_prefix(struct prefix_evpn *p, esi_t *esi,
					   struct ipaddr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_ES_ROUTE;
	/* Set IP prefix length and address based on originator_ip type */
	if (IS_IPADDR_V4(&originator_ip))
		p->prefix.es_addr.ip_prefix_length = IPV4_MAX_BITLEN;
	else if (IS_IPADDR_V6(&originator_ip))
		p->prefix.es_addr.ip_prefix_length = IPV6_MAX_BITLEN;
	else
		p->prefix.es_addr.ip_prefix_length = IPADDR_NONE;

	p->prefix.es_addr.ip = originator_ip;
	memcpy(&p->prefix.es_addr.esi, esi, sizeof(esi_t));
}

static inline void build_evpn_type1_prefix(struct prefix_evpn *p, uint32_t eth_tag, esi_t *esi,
					   struct ipaddr originator_ip)
{
	memset(p, 0, sizeof(struct prefix_evpn));
	p->family = AF_EVPN;
	p->prefixlen = EVPN_ROUTE_PREFIXLEN;
	p->prefix.route_type = BGP_EVPN_AD_ROUTE;
	p->prefix.ead_addr.eth_tag = eth_tag;
	/* Set IP address and type based on originator_ip */
	if (IS_IPADDR_V4(&originator_ip)) {
		SET_IPADDR_V4(&p->prefix.ead_addr.ip);
		IPV4_ADDR_COPY(&p->prefix.ead_addr.ip.ipaddr_v4, &originator_ip.ipaddr_v4);
	} else if (IS_IPADDR_V6(&originator_ip)) {
		SET_IPADDR_V6(&p->prefix.ead_addr.ip);
		IPV6_ADDR_COPY(&p->prefix.ead_addr.ip.ipaddr_v6, &originator_ip.ipaddr_v6);
	} else {
		/* IPADDR_NONE - should not happen, but handle gracefully */
		p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		memset(&p->prefix.ead_addr.ip.ipaddr_v4, 0,
		       sizeof(p->prefix.ead_addr.ip.ipaddr_v4));
	}
	memcpy(&p->prefix.ead_addr.esi, esi, sizeof(esi_t));
}

static inline void evpn_type1_prefix_global_copy(struct prefix_evpn *global_p,
		const struct prefix_evpn *vni_p)
{
	memcpy(global_p, vni_p, sizeof(*global_p));
	/* EAD prefix in global table doesn't include VTEP IP - zero it out
	 * but preserve ipa_type to maintain address family information
	 */
	if (IS_IPADDR_V4(&vni_p->prefix.ead_addr.ip)) {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_V4;
		global_p->prefix.ead_addr.ip.ipaddr_v4.s_addr = INADDR_ANY;
	} else if (IS_IPADDR_V6(&vni_p->prefix.ead_addr.ip)) {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_V6;
		/* Use standard IPv6 "any" address (::) via IN6ADDR_ANY_INIT */
		global_p->prefix.ead_addr.ip.ipaddr_v6 = (struct in6_addr)IN6ADDR_ANY_INIT;
	} else {
		global_p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		/* ipa_type is IPADDR_NONE, zero everything */
		memset(&global_p->prefix.ead_addr.ip, 0, sizeof(struct ipaddr));
	}
	global_p->prefix.ead_addr.frag_id = 0;
}

/* EAD prefix in the global table doesn't include the VTEP-IP so
 * we need to create a different copy for the VNI
 */
static inline struct prefix_evpn *
evpn_type1_prefix_vni_ip_copy(struct prefix_evpn *vni_p,
			      const struct prefix_evpn *global_p,
			      const struct attr *attr)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	/* Extract originator IP from attr based on nexthop length */
	if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV4 ||
	    attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV4) {
		/* IPv4 nexthop */
		SET_IPADDR_V4(&vni_p->prefix.ead_addr.ip);
		IPV4_ADDR_COPY(&vni_p->prefix.ead_addr.ip.ipaddr_v4, &attr->nexthop);
	} else if (attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_IPV6_GLOBAL_AND_LL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL ||
		   attr->mp_nexthop_len == BGP_ATTR_NHLEN_VPNV6_GLOBAL_AND_LL) {
		/* IPv6 nexthop - use global address */
		SET_IPADDR_V6(&vni_p->prefix.ead_addr.ip);
		IPV6_ADDR_COPY(&vni_p->prefix.ead_addr.ip.ipaddr_v6, &attr->mp_nexthop_global);
	} else {
		/* IPADDR_NONE - should not happen, but handle gracefully */
		vni_p->prefix.ead_addr.ip.ipa_type = IPADDR_NONE;
		memset(&vni_p->prefix.ead_addr.ip, 0, sizeof(vni_p->prefix.ead_addr.ip));
	}

	return vni_p;
}

static inline void evpn_type2_prefix_global_copy(
	struct prefix_evpn *global_p, const struct prefix_evpn *vni_p,
	const struct ethaddr *mac, const struct ipaddr *ip)
{
	memcpy(global_p, vni_p, sizeof(*global_p));

	if (mac)
		global_p->prefix.macip_addr.mac = *mac;

	if (ip)
		global_p->prefix.macip_addr.ip = *ip;
}

static inline void
evpn_type2_prefix_vni_ip_copy(struct prefix_evpn *vni_p,
			      const struct prefix_evpn *global_p)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	memset(&vni_p->prefix.macip_addr.mac, 0, sizeof(struct ethaddr));
}

static inline void
evpn_type2_prefix_vni_mac_copy(struct prefix_evpn *vni_p,
			       const struct prefix_evpn *global_p)
{
	memcpy(vni_p, global_p, sizeof(*vni_p));
	memset(&vni_p->prefix.macip_addr.ip, 0, sizeof(struct ipaddr));
}

/* Get MAC of path_info prefix */
static inline struct ethaddr *
evpn_type2_path_info_get_mac(const struct bgp_path_info *local_pi)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	return &local_pi->extra->evpn->vni_info.mac;
}

/* Get IP of path_info prefix */
static inline struct ipaddr *
evpn_type2_path_info_get_ip(const struct bgp_path_info *local_pi)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	return &local_pi->extra->evpn->vni_info.ip;
}

/* Set MAC of path_info prefix */
static inline void evpn_type2_path_info_set_mac(struct bgp_path_info *local_pi,
						const struct ethaddr mac)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	local_pi->extra->evpn->vni_info.mac = mac;
}

/* Set IP of path_info prefix */
static inline void evpn_type2_path_info_set_ip(struct bgp_path_info *local_pi,
					       const struct ipaddr ip)
{
	assert(local_pi->extra && local_pi->extra->evpn);
	local_pi->extra->evpn->vni_info.ip = ip;
}

/* Is the IP empty for the RT's dest? */
static inline bool is_evpn_type2_dest_ipaddr_none(const struct bgp_dest *dest)
{
	const struct prefix_evpn *evp =
		(const struct prefix_evpn *)bgp_dest_get_prefix(dest);

	assert(evp->prefix.route_type == BGP_EVPN_MAC_IP_ROUTE);
	return is_evpn_prefix_ipaddr_none(evp);
}

static inline int evpn_default_originate_set(struct bgp *bgp, afi_t afi,
					     safi_t safi)
{
	if (afi == AFI_IP &&
	    CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
		       BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV4))
		return 1;
	else if (afi == AFI_IP6 &&
		 CHECK_FLAG(bgp->af_flags[AFI_L2VPN][SAFI_EVPN],
			    BGP_L2VPN_EVPN_DEFAULT_ORIGINATE_IPV6))
		return 1;
	return 0;
}

static inline void es_get_system_mac(esi_t *esi,
				     struct ethaddr *mac)
{
	/*
	 * for type-1 and type-3 ESIs,
	 * the system mac starts at val[1]
	 */
	memcpy(mac, &esi->val[1], ETH_ALEN);
}

static inline bool bgp_evpn_is_svi_macip_enabled(struct bgp_evpn_evi *evi)
{
	struct bgp *bgp_evpn_mi = NULL;

	bgp_evpn_mi = bgp_get_evpn_master_instance();

	return (bgp_evpn_mi->evpn_info->advertise_svi_macip ||
		evi->advertise_svi_macip);
}

static inline bool bgp_evpn_is_path_local(struct bgp *bgp,
		struct bgp_path_info *pi)
{
	return (pi->peer == bgp->peer_self
			&& pi->type == ZEBRA_ROUTE_BGP
			&& pi->sub_type == BGP_ROUTE_STATIC);
}

/* Legacy function to compare route target extended communities, DO NOT USE*/
extern int bgp_evpn_route_target_ecom_cmp(struct ecommunity *ecom1, struct ecommunity *ecom2);
extern void bgp_evpn_install_uninstall_default_route(struct bgp *bgp_vrf, afi_t afi, safi_t safi,
						     struct bgp_path_info *originator, bool add);

extern struct bgp_evpn_rt_config* bgp_evpn_rt_config_new(void);
extern void bgp_evpn_rt_config_free(struct bgp_evpn_rt_config *rt_config);

extern void bgp_evpn_format_wildcard_rt_local_admin(char *buf, size_t buflen,
						    uint32_t local_admin_nbo);
extern void bgp_evpn_format_fq_rt_ecom_val(char *buf, size_t buflen,
					   struct ecommunity_val eval);
extern void bgp_evpn_format_cfgd_rt(char *buf, size_t buflen,
				    const struct bgp_evpn_cfgd_rt *cfgd_rt);

extern void bgp_evpn_configure_evpn_autort_rfc8365_compatible(struct bgp *bgp, bool evpn_autort_rfc8365_compatible);

extern int bgp_evpn_vrf_configure_rt_manual(struct bgp *bgp_vrf, enum bgp_evpn_rt_direction direction,
				     struct bgp_evpn_cfgd_rt *cfgd_rt);
extern int bgp_evpn_vrf_unconfigure_rt_manual(struct bgp *bgp_vrf, enum bgp_evpn_rt_direction direction,
				       struct bgp_evpn_cfgd_rt *to_delete);
extern int bgp_evpn_vrf_configure_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_rt_direction direction,
				   enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_vrf_configure_both_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_vrf_configure_both_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_vrf_configure_import_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_vrf_configure_import_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_vrf_configure_export_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_vrf_configure_export_auto_rt(struct bgp *bgp_vrf, enum bgp_evpn_autort_cfgd cfg);


extern int bgp_evpn_vrf_unconfigure_both_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete);

extern int bgp_evpn_vrf_unconfigure_import_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete);

extern int bgp_evpn_vrf_unconfigure_export_rt_manual(struct bgp *bgp_vrf, struct bgp_evpn_cfgd_rt* to_delete);


extern int bgp_evpn_evi_configure_rt_manual(struct bgp_evpn_evi *evi, enum bgp_evpn_rt_direction direction,
				     struct bgp_evpn_cfgd_rt *cfgd_rt);
extern int bgp_evpn_evi_unconfigure_rt_manual(struct bgp_evpn_evi *evi, enum bgp_evpn_rt_direction direction,
				       struct bgp_evpn_cfgd_rt *to_delete);
extern int bgp_evpn_evi_configure_auto_rt(struct bgp_evpn_evi *evi, enum bgp_evpn_rt_direction direction,
				   enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_evi_configure_both_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_evi_configure_both_auto_rt(struct bgp_evpn_evi* evi, enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_evi_configure_import_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_evi_configure_import_auto_rt(struct bgp_evpn_evi* evi, enum bgp_evpn_autort_cfgd cfg);

extern int bgp_evpn_evi_configure_export_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* cfgd_rt);
extern int bgp_evpn_evi_configure_export_auto_rt(struct bgp_evpn_evi* evi, enum bgp_evpn_autort_cfgd cfg);


extern int bgp_evpn_evi_unconfigure_both_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* to_delete);

extern int bgp_evpn_evi_unconfigure_import_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* to_delete);

extern int bgp_evpn_evi_unconfigure_export_rt_manual(struct bgp_evpn_evi* evi, struct bgp_evpn_cfgd_rt* to_delete);				   


extern void bgp_evpn_vrf_handle_import_rt_change(struct bgp *bgp_vrf);
extern void bgp_evpn_vrf_handle_export_rt_change(struct bgp *bgp_vrf);
extern void bgp_evpn_evi_handle_import_rt_change(struct bgp_evpn_evi *evi);
extern void bgp_evpn_evi_handle_export_rt_change(struct bgp_evpn_evi *evi);

extern void bgp_evpn_vrf_configure_rd(struct bgp *bgp_vrf, struct prefix_rd *rd,
				  const char *rd_pretty);
extern void bgp_evpn_vrf_unconfigure_rd(struct bgp *bgp_vrf);

extern void bgp_evpn_evi_configure_rd(struct bgp *bgp, struct bgp_evpn_evi *evi,
			      struct prefix_rd *rd, const char *rd_pretty);
extern void bgp_evpn_evi_unconfigure_rd(struct bgp *bgp, struct bgp_evpn_evi *evi);

extern void bgp_evpn_vrf_handle_rd_change(struct bgp *bgp_vrf, int withdraw);
extern void bgp_evpn_evi_handle_rd_change(struct bgp *bgp, struct bgp_evpn_evi *evi,
				      int withdraw);
void bgp_evpn_handle_global_macvrf_soo_change(struct bgp *bgp,
					      struct ecommunity *new_soo);
extern int bgp_evpn_evi_install_global_routes(struct bgp_evpn_evi *evi);
extern int bgp_evpn_evi_uninstall_global_routes(struct bgp_evpn_evi *evi);
extern int bgp_evpn_vrf_install_global_routes(struct bgp *bgp_vrf);
extern int bgp_evpn_vrf_uninstall_global_routes(struct bgp *bgp_vrf);
extern void bgp_evpn_vrf_map_to_vrf_irt_nodes(struct bgp *bgp_vrf);
extern void bgp_evpn_vrf_unmap_from_vrf_irt_nodes(struct bgp *bgp_vrf);
extern void bgp_evpn_evi_map_to_evi_irt_nodes(struct bgp_evpn_evi *evi);
extern void bgp_evpn_evi_unmap_from_evi_irt_nodes(struct bgp_evpn_evi *evi);
extern void bgp_evpn_vrf_setup_import(struct bgp *bgp_vrf);
extern void bgp_evpn_vrf_teardown_import(struct bgp *bgp_vrf);
extern void bgp_evpn_evi_setup_import(struct bgp_evpn_evi *evi);
extern void bgp_evpn_evi_teardown_import(struct bgp_evpn_evi *evi);

extern void bgp_evpn_evi_derive_auto_rd(struct bgp *bgp, struct bgp_evpn_evi *evi);
extern void bgp_evpn_vrf_derive_auto_rd(struct bgp *bgp);
extern struct bgp_evpn_evi *bgp_evpn_lookup_evi_by_vni(struct bgp *bgp, vni_t vni);
extern struct bgp_evpn_evi *bgp_evpn_evi_lookup_by_name(struct bgp *tenant_scope,
							const char *name);
extern bool bgp_evpn_evi_name_is_valid(const char *name);
extern struct bgp_evpn_evi *bgp_evpn_evi_new(struct bgp *bgp, vni_t vni,
		struct ipaddr *originator_ip,
		vrf_id_t tenant_vrf_id,
		struct in_addr mcast_grp,
		ifindex_t svi_ifindex,
		enum bgp_evpn_evi_origin origin);
extern struct bgp_evpn_evi *bgp_evpn_evi_new_cfgd(struct bgp *tenant_bgp, const char *name);
extern void bgp_evpn_cfgd_evi_delete(struct bgp_evpn_evi *evi);
extern int bgp_evpn_evi_set_origination_l2vni(struct bgp_evpn_evi *evi, vni_t vni);
extern void bgp_evpn_evi_legacy_set_configured(struct bgp_evpn_evi *evi, bool configured);
extern void bgp_evpn_evi_apply_tenant_vrf_id(struct bgp_evpn_evi *evi, vrf_id_t tenant_vrf_id);
extern void bgp_evpn_evi_set_cfgd_tenant_vrf(struct bgp_evpn_evi *evi, const char *vrfname);
extern void bgp_evpn_evi_delete_and_free(struct bgp *bgp, struct bgp_evpn_evi *evi);
extern bool bgp_evpn_lookup_l3vni_l2vni_table(vni_t vni);
extern int bgp_evpn_evi_update_type_1_2_3_routes(struct bgp *bgp, struct bgp_evpn_evi *evi);
extern struct bgp_path_info *bgp_evpn_delete_route_entry(struct bgp *bgp, afi_t afi, safi_t safi,
						     struct bgp_dest *dest,
						     const struct bgp_path_info *originator,
						     uint32_t addpaht_id);

extern int evpn_route_select_install(struct bgp *bgp, struct bgp_evpn_evi *evi,
				     struct bgp_dest *dest,
				     struct bgp_path_info *pi);
extern struct bgp_dest *
bgp_evpn_global_node_get(const struct prefix_evpn *evp, struct prefix_rd *prd,
			 const struct bgp_path_info *local_pi);
extern struct bgp_dest *bgp_evpn_global_node_lookup(
	struct bgp_table *table, safi_t safi, const struct prefix_evpn *evp,
	struct prefix_rd *prd, const struct bgp_path_info *local_pi);
extern struct bgp_dest *
bgp_evpn_vni_ip_node_get(struct bgp_table *const table,
			 const struct prefix_evpn *evp,
			 const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_ip_node_lookup(const struct bgp_table *const table,
			    const struct prefix_evpn *evp,
			    const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_mac_node_get(struct bgp_table *const table,
			  const struct prefix_evpn *evp,
			  const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_mac_node_lookup(const struct bgp_table *const table,
			     const struct prefix_evpn *evp,
			     const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_node_get(struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
		      const struct bgp_path_info *parent_pi);
extern struct bgp_dest *
bgp_evpn_vni_node_lookup(const struct bgp_evpn_evi *evi, const struct prefix_evpn *p,
			 const struct bgp_path_info *parent_pi);

extern void bgp_evpn_evi_update_all_type2_routes(struct bgp *bgp, struct bgp_evpn_evi *evi);
extern void bgp_evpn_evi_update_type2_route_entry(struct bgp *bgp,
					      struct bgp_evpn_evi *evi,
					      struct bgp_dest *rn,
					      struct bgp_path_info *local_pi,
					      const char *caller);
extern int bgp_evpn_vrf_install_uninstall_route_entry_if_match(struct bgp *bgp_vrf,
						     struct bgp_path_info *pi,
						     int install);
extern void bgp_evpn_import_type2_route(struct bgp_path_info *pi, int import);
extern void bgp_evpn_xxport_delete_ecomm(void *val);
extern void bgp_evpn_handle_deferred_bestpath_for_vnis(struct bgp *bgp, uint16_t cnt);
extern uint16_t bgp_deferred_path_selection(struct bgp *bgp, afi_t afi, safi_t safi,
					    struct bgp_table *table, uint16_t cnt,
					    struct bgp_evpn_evi *evi, bool evpn_select);

#endif /* _BGP_EVPN_PRIVATE_H */
