# EVPN: referencing underlay VRFs that do not yet exist

Status: DECIDED and implemented - Approach 2, generalized as *instance
claims* (see `doc/developer/bgp-instance-claims.rst`). Overlay objects hold
claimed pointers (`bgp_instance_claim()`): the referenced instance is
auto-created when absent, promoted in place when the user configures it,
demoted (never freed) while claims remain, and freed on the last unclaim.
The three edges below are all closed: resolution fails closed for a
bound-but-not-underlay instance (never falls through to the default
underlay), binding changes and `vxlan-underlay` set/unset re-drive the bound
overlay objects, and the raw `evpn_underlay_vrf` pointer is now a claimed
reference (`evpn_dp_underlay`) instead of an unlocked use-after-free.
The rest of this document is kept as the record of the trade-off discussion.

Branch: `route-targets-refactor`
Scope: how overlay objects (tenant VRFs, EVIs) point at their underlay VRF
instance when that instance may be configured later, never, or removed
out from under them.

## Problem

In the multi-underlay EVPN model an overlay object binds to an underlay VRF:

```
router bgp 65000 vrf tenant-a
 address-family l2vpn evpn
  underlay-vrf red          <-- names instance "red"
```

`red` need not exist yet. Configuration order is not guaranteed (a tenant
can be configured before its underlay), the underlay can be deleted while
the tenant still references it, and a typo (`underlay-vrf rde`) is
indistinguishable from "not configured yet". The question is how the
reference is stored and resolved across those lifecycle events.

The same shape exists in MPLS L3VPN (`import vrf NAME`), so the established
FRR idiom is the natural starting point.

## How MPLS L3VPN actually does it (the reference idiom)

It is **not** "just names". It is a hybrid, and the split is the
interesting part:

- **Arbitrary VRF references are stored by name.** `import vrf NAME` appends
  `NAME` to `vpn_policy[afi].import_vrf` (a list of vnames) and to the
  source VRF's `export_vrf` list (`vrf_import_from_vrf()`,
  bgp_mplsvpn.c:3137). The pointer (`vrf_bgp`) is resolved at command time
  via `bgp_lookup_by_name_filter()` and may be `NULL`; the *name* is the
  durable record. Leak direction is re-driven from the name lists when an
  instance later appears.

- **The default instance is auto-created, hidden, and locked-in-effect.**
  When `import vrf` needs a default instance that does not exist, it is
  auto-created and flagged `BGP_FLAG_INSTANCE_HIDDEN`
  (bgp_vty.c:11461-11477). A hidden instance is a real `struct bgp` that is
  not advertised, not written to config, and is "promoted" to a normal
  instance when the user actually configures `router bgp <as>` for it
  (`bgp_lookup_by_as_name_type()` clears the flag, bgpd.c:4110-4146).

So MPLS already answers our question twice, differently, depending on the
referent: **names for the many, an auto-created hidden singleton for the
one** (the default instance, which everything hangs off and which is a
natural singleton).

## What the EVPN branch does today

A weak hybrid of both, with two sharp edges.

1. **Configured bindings are stored by name.** `cfgd_underlay_vrf_name` on
   both the EVI (bgp_evpn_private.h:258) and the tenant
   (`evpn_cfgd_underlay_vrf_name`, bgpd.h:1116). Resolution is lazy against
   the live underlay registry (`bgp_evpn_underlays` dlist) via
   `bgp_evpn_lookup_underlay_vrf_by_name()` (bgp_evpn.c:1108). This part is
   clean: no stored pointer, no stale state, resolves correctly whenever it
   is called.

2. **There is also a raw resolved pointer.** `bgp->evpn_underlay_vrf`
   (bgpd.h:1110) is set from the zebra L3VNI report
   (`bgp_evpn_local_l3vni_add()`, bgp_evpn.c:9462) and used as a fallback in
   `bgp_evpn_vrf_get_underlay()` (bgp_evpn.c:1151).

### Edge 1 — resolution is dataplane-driven, not name-driven

When an underlay appears, `evpn_set_vxlan_underlay()` (bgp_evpn_vty.c:3386)
adds it to the registry and calls `bgp_zebra_advertise_all_vni(bgp, true)`.
It does **not** walk the overlay objects that name it. Re-origination only
happens as a side effect of zebra re-reporting the VNIs that physically
live in that underlay's VRF, which re-drives origination through the local
VNI add path.

Consequence: an overlay bound by `underlay-vrf NAME` is only re-originated
when `NAME` appears **if** it also has a dataplane VNI inside `NAME`. A
binding that is ahead of its dataplane (configured, no local VNI yet, or
the VNI lands in a different VRF) is not re-driven by the name reference
itself.

### Edge 2 — unresolved name silently falls through to the default underlay

`bgp_evpn_evi_get_underlay()` (bgp_evpn.c:1160) and
`bgp_evpn_vrf_get_underlay()` (bgp_evpn.c:1143):

```c
if (evi->cfgd_underlay_vrf_name)
        underlay = bgp_evpn_lookup_underlay_vrf_by_name(evi->cfgd_underlay_vrf_name);
if (!underlay)
        underlay = bgp_get_evpn_default_underlay_vrf();   /* <-- silent fallback */
return underlay;
```

`underlay-vrf red` while `red` is not (yet) an underlay resolves to the
**default** underlay, not to "pending". A typo and a not-yet-configured
underlay both originate routes into the wrong instance, silently, with no
operational signal. This is a fail-open behavior.

### Edge 3 — the raw pointer is a latent use-after-free

`bgp->evpn_underlay_vrf` is a plain pointer with no `bgp_lock()`. It is
cleared only on the tenant's *own* L3VNI-del (bgp_evpn.c:9722). When the
underlay instance itself is deleted, `bgp_evpn_instance_down()`
(bgp_evpn.c:9876) cleans up only that instance's own L3VNI; nothing walks
other tenants to clear an `evpn_underlay_vrf` still pointing at the
instance being freed. `no router bgp <as> vrf red` while a tenant points at
`red` (without first tearing down the tenant's L3VNI dataplane) leaves a
dangling pointer that the next `bgp_evpn_vrf_get_underlay()` dereferences.

The name-lookup half (Edge-1 path) is safe across this — it re-resolves
against the registry, which no longer contains `red`. Only the raw-pointer
fallback is unsafe. The half-built pointer model already in the tree is the
concrete evidence for what a full pointer model costs.

---

## The two approaches

### Approach 1 — weak references by name only

Store only `cfgd_underlay_vrf_name`. Resolve lazily against the underlay
registry on every use. Delete the `evpn_underlay_vrf` raw pointer (or
demote it to a cache that is always re-derived, never authoritative). This
is the MPLS `import_vrf`-vname idiom applied uniformly.

To be correct it needs two things the branch does not have yet:

- **Fail closed on unresolved names.** When the name does not resolve,
  return "pending" (do not originate), not the default underlay. The
  default underlay must be reachable only via its own explicit
  configuration (`default-underlay-vrf`) or the documented implicit
  default, never as a fallback for a *named-but-absent* binding.
- **An explicit re-resolution trigger keyed on the name.** On underlay
  add/delete, walk the overlay objects whose `cfgd_underlay_vrf_name`
  matches and re-drive origination/withdrawal, independent of the dataplane
  re-report. The registries to walk already exist (`global_evis`,
  `evis_by_name`, the tenant instance list).

Cost: bookkeeping is trivial (one string, freed at delete). Resolution is
O(registry) per call but the registry is tiny (count of underlays). The
work is concentrated in the re-resolution walk and in auditing every
`get_underlay()` caller for correct "pending" handling.

### Approach 2 — auto-create the underlay instance, reference by locked pointer

When `underlay-vrf red` is configured and `red` does not exist, auto-create
a hidden `struct bgp` for it (mirroring `BGP_FLAG_INSTANCE_HIDDEN`), take a
`bgp_lock()` from each referencing overlay, and store the resolved pointer
in the overlay. Promote the hidden instance to a real one when the user
configures it; on `no underlay-vrf` / overlay delete, drop the lock; the
instance is freed when the last reference and its own config are gone.

Cost: this is the MPLS hidden-default mechanism generalized to arbitrary
named instances. It brings the full lifecycle surface — promotion,
ref-count teardown, "don't write hidden instances to config", "don't show
them in operational output unless asked", interaction with `bgp_delete()`'s
existing hidden/`DELETE_IN_PROGRESS` handling, and the locking discipline
that Edge 3 shows is mandatory the moment a pointer is stored. In exchange,
references are O(1) pointer chases and "pending" becomes a real object you
can attach state and diagnostics to.

---

## Recommendation (for discussion with the team)

Go with Approach 1 — names only — and treat the three edges above as the
actual work, not as reasons to switch to pointers.

The reasoning, concretely:

- **It is the idiom we already follow.** MPLS stores arbitrary VRF
  references by name (`import_vrf` vnames) and only auto-creates an instance
  for the *default* — a singleton that everything depends on. An underlay
  VRF is not that singleton; it is one of N peers. Approach 2 generalizes
  the special case to the general case and inherits the special case's
  whole lifecycle surface (hidden-vs-real, promotion, config/show
  suppression, ref-count teardown) for references that a name handles
  without any of it.

- **The pointer model's cost is not hypothetical — it is already a bug in
  the tree.** `evpn_underlay_vrf` (Edge 3) is exactly the half of Approach 2
  that stores a resolved pointer, and it is a use-after-free because it is
  unlocked and not reverse-indexed. Choosing Approach 1 lets us *delete*
  that pointer instead of hardening it with `bgp_lock()` plus a
  clear-on-underlay-delete walk — which is most of Approach 2's cost for one
  field.

- **The name model's gaps are smaller and local.** Edge 2 (fail-closed) is a
  two-line change in two functions plus an audit of `get_underlay()`
  callers. Edge 1 (name-keyed re-resolution walk) is one walk on underlay
  add and one on delete over registries that already exist. Neither
  introduces new lifecycle state. Both are required for correctness under
  Approach 2 as well — Approach 2 just adds the instance lifecycle on top.

What Approach 1 must deliver to be done:

1. Delete `bgp->evpn_underlay_vrf` as an authoritative source. If a resolved
   cache is wanted for hot paths, derive it on demand and never trust it
   across an underlay add/delete.
2. `get_underlay()` returns "unresolved" for a named-but-absent underlay.
   Originators skip (and withdraw) on unresolved; they do not fall through
   to the default underlay. The default underlay applies only when *no*
   `underlay-vrf` is configured.
3. On `vxlan-underlay` set/unset, walk overlays by
   `cfgd_underlay_vrf_name` and re-drive origination/withdrawal. This is the
   trigger that makes "configured before the underlay exists" and "underlay
   deleted under a live tenant" correct without a stored pointer.

Open question worth settling in the same discussion: do we want an
operational signal for an unresolved binding (e.g. a state/reason on the
overlay, the way the L3VNI dataplane state already carries
`MISCONFIGURED`/reason), so `underlay-vrf rde` is visible in `show` rather
than silently inert? That is the user-facing half of "fail closed" and is
cheap to add once resolution returns an explicit "pending".
