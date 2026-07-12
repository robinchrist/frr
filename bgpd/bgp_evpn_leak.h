// SPDX-License-Identifier: GPL-2.0-or-later
/* BGP EVPN local auto route leak (`local-auto-route-leak-<export|import>`)
 *
 * Direct VRF-to-VRF unicast route leaking between local BGP instances,
 * driven by EVPN route-target intersection (the source VRF's effective
 * export RTs vs the sibling's effective import RTs) - Juniper auto-export
 * style. No transit through the default instance's MPLS-VPN RIB, no
 * RD/label involvement.
 *
 * Copyright (C) 2026 Robin Christ
 */

#ifndef _FRR_BGP_EVPN_LEAK_H
#define _FRR_BGP_EVPN_LEAK_H

#include "bgpd/bgpd.h"

/* Effective on/off state of the knobs: a tenant VRF's explicit tristate
 * wins, otherwise the default instance's process-wide setting applies.
 * Only tenant VRF instances participate in local auto leak - on the
 * default instance itself the knobs carry the process-wide default and
 * do not make it a leak source/destination.
 */
extern bool bgp_lal_export_effective(struct bgp *bgp_vrf);
extern bool bgp_lal_import_effective(struct bgp *bgp_vrf);

/* Compute the set of destination instances `src` should currently leak
 * into (RT intersection via the process-global VRF import-RT tables).
 * `out` must be an initialized, empty list; entries are owned by the
 * caller.
 */
extern void bgp_lal_compute_dests(struct bgp *src,
				  struct vrf_mapped_bgp_instance_slu_head *out);

/* Diff src->lal_dests against a fresh computation: leak the source RIB
 * into added destinations, flush it from removed ones.
 */
extern void bgp_lal_reconcile_source(struct bgp *src);

/* Reconcile every instance - for events with process-wide effect
 * (default-instance knob changes, import RT changes, import knob
 * changes, VRF up/down).
 */
extern void bgp_lal_reconcile_all(void);

/* Full-table walkers backing reconciliation (leak engine). */
extern void bgp_lal_leak_rib_to_dest(struct bgp *src, struct bgp *dst);
extern void bgp_lal_flush_dest_from_source(struct bgp *dst, struct bgp *src);

/* Per-path triggers, called from the same points as the classic
 * vpn_leak_from_vrf_update/withdraw (hooked inside those functions).
 * Cheap early-out when the source has no leak destinations.
 */
struct bgp_path_info;
extern void bgp_lal_from_vrf_update(struct bgp *from_bgp, struct bgp_path_info *pi);
extern void bgp_lal_from_vrf_withdraw(struct bgp *from_bgp, struct bgp_path_info *pi);

/* Is this a locally auto-leaked path (parent lives in another local
 * instance's unicast table)?
 */
extern bool bgp_lal_path_is_lal(struct bgp_path_info *pi);

/* Synchronous full teardown for bgp_delete(). */
extern void bgp_lal_instance_down(struct bgp *bgp);

#endif /* _FRR_BGP_EVPN_LEAK_H */
