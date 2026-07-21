.. _nb-bgpd-proteus:

bgpd Proteus YANG Conversion
=============================

.. contents:: Table of contents
    :local:
    :backlinks: entry
    :depth: 2

Overview
--------

bgpd is being converted to the northbound/mgmtd architecture using a
separate, self-contained YANG model suite (``yang/proteus/``,
``proteus-*.yang``) instead of FRR's superseded ``frr-bgp*.yang`` stack.
The proteus models are augment-free, strongly typed, and CLI-mirrored
(every leaf description cites the emitting legacy ``*_config_write*``
function), which makes them a better fit for an incremental,
command-by-command conversion than the existing frr-bgp stack. The
proteus models now cover all of bgpd's configuration surface except
route-maps; the frr-bgp stack has been archived to ``yang/archive/``
(kept for reference, not built), while the already-converted
``frr-bgp-route-map.yang`` stays live and was improved in place.

Milestone 1 is a thin vertical slice proving the whole pipeline end to
end: bgpd becomes an ``mgmt_be_client`` backend, ``bgpd/bgp_cli.c`` is
compiled into mgmtd (the zebra/staticd split-CLI pattern), and four
commands are converted: ``router bgp ASN [<view|vrf> NAME]
[as-notation ...]``, ``no router bgp ...``, ``bgp router-id``, and
``bgp log-neighbor-changes <enabled|disabled>`` (see "The tri-state
``enabled``/``disabled`` convention" below for why this leaf isn't a
plain boolean).

Generator invocation
---------------------

The northbound callback table and stub bodies for ``proteus-bgp`` were
generated with::

   tools/gen_northbound_callbacks -p yang/proteus proteus-bgp

then split ripd-style into ``bgp_nb.h`` (prototypes and
``frr_yang_module_info`` externs), ``bgp_nb.c`` (the
``proteus_bgp_nb_info`` table), and ``bgp_nb_config.c`` (callback
bodies). The generated table covers every config-bearing node in
``proteus-bgp.yang`` (~1,700 nodes), not just the milestone 1 slice --
see "Stub-rejection posture" below for why.

Post-flip architecture (M9): mgmtd owns the config file
--------------------------------------------------------

As of M9 bgpd sets ``FRR_NO_SPLIT_CONFIG`` (``bgp_main.c``): bgpd never
reads ``bgpd.conf``. mgmtd reads it (bgpd is listed in
``mgmt_daemons[]``), northbound-commits it, and delivers the result to
bgpd - at boot and on every bgpd (re)connect - as one priority-ordered
backend transaction (``txn_cfg_be_client_connect``,
``mgmtd/mgmt_txn_cfg.c``). This is the staticd model. Node priorities
order the replay: the instance-default leaves that ``peer_new()`` copies
into new peers carry ``NB_DFLT_PRIORITY - 1`` so they apply before the
neighbor CREATEs, and ``bgp default shutdown`` carries
``NB_DFLT_PRIORITY + 1`` so it applies after them (FRR #2286 semantics),
both in ``bgp_nb.c``.

The native config-command surface was deleted in the same milestone:
the only config commands left in bgpd's own graph are the node-entry
NOSHes (``router bgp``, the address-family entries,
``segment-routing srv6`` - kept for bgpd's own vty and the VNC
plugin context) plus the plugin surfaces themselves. bgpd does not set
a host config file, so vtysh's per-daemon ``write memory`` is answered
by mgmtd (which holds the full modeled view), never by bgpd.

Flat-style compatibility: legacy accepted per-AF lines directly under
``router bgp`` (hidden aliases, ipv4-unicast semantics). mgmtd keeps
accepting that style through the ``bgp_afi_safi_map`` entry mapping
``BGP_NODE`` to ``ipv4-unicast`` plus BGP_NODE installs of the
converted per-AF commands (``bgp_cli_neighbor.c``,
``bgp_cli_instance.c``).

Plugin config (TODO #31): RPKI is converted (batch B1, module
``proteus-bgp-rpki``): the CLI lives in mgmtd
(``bgpd/proteus/bgp_cli_rpki.c``), bgpd core registers the northbound
callbacks unconditionally (``bgpd/proteus/bgp_nb_rpki.c``) and delivers
the desired state per instance through the
``bgp_rpki_config_apply``/``bgp_rpki_config_destroy`` hooks the
``bgpd_rpki`` plugin subscribes to at load; with the plugin absent the
config is accepted, stored and warned about, never rejected. RPKI
config therefore persists through mgmtd's ``bgpd.conf`` again. BMP is
converted the same way (batch B2, module ``proteus-bgp-bmp`` augmenting
the proteus-bgp instance): the CLI lives in mgmtd
(``bgpd/proteus/bgp_cli_bmp.c``, including the mgmtd-side ``BMP_NODE``),
bgpd core registers the northbound callbacks unconditionally
(``bgpd/proteus/bgp_nb_bmp.c``) and fires one ``bgp_bmp_*`` hook per
legacy operation (``bgp_bmp.h``); the ``bmp`` plugin subscribes at load.
Only VNC remains support-dropped: its commands work interactively on
bgpd's vty and persist under integrated ``frr.conf`` (vtysh collects
bgpd's native ``config_write``), but they do **not** persist in
split-config mode: mgmtd cannot parse their lines from ``bgpd.conf``,
and bgpd no longer reads that file.

Backend daemons must not run mgmtd-owned northbound CLI locally
----------------------------------------------------------------

A backend daemon has a single northbound transaction
(``transaction_in_progress``, ``lib/northbound.c``). During config
load, mgmtd races through the file first and pushes committed config
to the daemon over the backend channel; if the daemon's own vty
concurrently executes a northbound-backed command as a local commit,
one side fails with ``NB_ERR_LOCKED`` and ``vty_read_file()``'s
stop-on-first-error drops the rest of the daemon's config replay.
This is why the mgmtd-dev.rst checklist has converted backends remove
``if_cmd_init()``/``vrf_cmd_init()``.

bgpd can't remove them outright: it still owns legacy subcommands
under ``INTERFACE_NODE`` (``mpls bgp forwarding``) and, until TODO #31
B1 moved the rpki node entry to mgmtd, ``VRF_NODE`` (``rpki``). The
pattern for this mixed state:

- register the nodes with the node-only lib entry points
  (``if_cmd_init_node()``, ``vrf_cmd_init_node()``), which skip lib's
  northbound create/destroy commands;
- give the daemon local ``DEFPY_NOSH`` node-entry commands (idempotent
  get + ``VTY_PUSH_CONTEXT``, no northbound operation), same shape as
  the surviving legacy ``router_bgp`` DEFUN_NOSH;
- route lib's northbound commands away from the daemon in
  ``python/xref2vtysh.py`` (``lib/if.c``/``lib/vrf.c`` →
  ``VTYSH_INTERFACE_SUBSET``), while leaving vtysh.h's
  ``VTYSH_INTERFACE``/``VTYSH_VRF`` masks alone -- those drive the
  node entry/exit DEFUNSHes, which must keep reaching the daemon for
  its vty node tracking.

**Resolved: route-map and access-/prefix-list CLI (Milestone 3,
batches B-RM1/B-RM2).** lib's route-map and filter CLI
(``lib/routemap_cli.c``, ``lib/filter_cli.c``) used to be northbound-
backed but still routed to and run inside bgpd, the same race shape
as above. Unlike interface/vrf, this could not be closed with the
node-only pattern (register the node, give the daemon its own
idempotent local node-entry command): lib's real ``route-map NAME
<deny|permit> SEQ`` node-entry command performs a genuine northbound
``CREATE`` on entry (``lib/routemap_cli.c``'s
``DEFPY_YANG_NOSH(route_map, ...)``), unlike ``if_get_by_name()``/
``vrf_get()``, which are pure local data-structure gets with no
northbound transaction of their own. A bgpd-local copy of that
command would still race mgmtd's copy for every route-map creation,
reproducing the exact problem being fixed.

The resolution instead follows the ripd/zebra/staticd model all the
way: ``bgp_route_map_init()`` (``bgpd/bgp_routemap.c``) switches from
``route_map_init()`` to ``route_map_init_new(true)``, and
``bgpd.c``'s BGP init switches from ``access_list_init()`` to
``access_list_init_new(true)``, exactly like ``rip_route_map_init()``/
``ripd.c``. bgpd subscribes to ``/frr-route-map:lib`` and
``/frr-filter:lib`` in ``bgpd_config_xpaths[]`` (``bgp_main.c``) so
the config mgmtd commits still reaches bgpd's existing
``frr_route_map_info``/``frr_filter_info``/``frr_bgp_route_map_info``
northbound callbacks over the backend channel. ``vtysh.h``'s
``VTYSH_RMAP_CONFIG``/``VTYSH_ACL_CONFIG`` masks drop ``VTYSH_BGPD``
outright (no ``_SUBSET`` split needed, unlike
``VTYSH_INTERFACE``/``VTYSH_VRF``): bgpd has no legacy subcommands of
its own under ``ACCESS_NODE``/``PREFIX_*_NODE``, and after this
change it has none under ``RMAP_NODE`` either, so nothing needs to
keep reaching bgpd's local vty for these nodes at all.

That last point covers bgpd's own 143 ``frr-bgp-route-map`` match/set
commands too. Milestone 3's earlier batch (B-RM3) had split them out
of ``bgp_routemap.c`` into ``bgp_routemap_cli.c``, compiled into both
bgpd and mgmtd as an interim step, and left nine of them
(``match``/``no match alias``, ``set as-path prepend``, ``set as-path
exclude``, ``set community``, ``set``/``no set vpn-nexthop``,
``set``/``no set ipv4|ipv6 vpn next-hop``) installed only in bgpd
because their CLI bodies called validation helpers living in
bgpd-only compilation units (the live community-alias table in
``bgp_community_alias.c``; ``bgp_aspath.c``/``bgp_community.c``'s
syntax parsers; ``bgp_vty.c``/``bgp_mplsvpn.c``'s argv token
matchers). B-RM1 finishes the move: ``bgp_routemap_cli.c`` now
compiles only into mgmtd (``bgpd/subdir.am`` no longer lists it,
matching ``bgp_cli.c``), and the nine commands move there too, with
their bgpd-only calls dropped or inlined:

- ``match``/``no match alias``: the eager CLI-side alias-existence
  check is dropped. The northbound apply path never validated this
  (``route_match_alias_compile()`` just stores the string; an unknown
  alias simply never matches any route), so this makes ``match
  alias`` a forward reference like every other name-based match
  clause in this file, not a special case -- apply-time behavior is
  unchanged, so this is not a validation regression.
- ``set as-path prepend``/``set as-path exclude``/``set community``:
  the eager CLI-side syntax pre-check (``route_aspath_compile()``/
  ``community_str2com()``) is dropped. The northbound apply path
  (``generic_set_add()`` calling ``route_set_aspath_prepend_cmd``/
  ``route_set_community_cmd``'s compile hooks, both still bgpd-only
  and unchanged) already re-validates with the same compile functions
  and fails the transaction on malformed input, so no unvalidated
  value can reach running config -- the failure just surfaces at
  apply time instead of CLI-parse time, same as every other command
  in this file. ``set community``'s stored string is the raw,
  space-joined token text rather than ``community_str2com()``'s
  canonical pretty-printed form (a ``show running-config`` cosmetic
  difference only).
- the four VPN-nexthop commands: their only "validation" was CLI
  token matching (``vpnv4``/``vpnv6``/``ipv4``/``ipv6``) via thin
  ``bgp_vty.c``/``bgp_mplsvpn.c`` wrappers around
  ``lib/command.c``'s ``argv_find()``; inlined directly with no
  behavior change.

Two-tier boolean convention: default-at-the-root vs. tri-state
------------------------------------------------------------------

**Core principle: a YANG ``default`` statement lives only at the root
of an inheritance chain.** ``default`` and inheritance are mutually
exclusive on a single leaf -- a leaf cannot both carry its own static
default *and* fall back to another leaf's value, because the
northbound layer would have no way to tell "unset, use my own
default" apart from "unset, use the parent's current value". Every
boolean leaf in ``proteus-bgp.yang`` falls into exactly one of two
shapes as a result:

**Tier A -- static default-on boolean, no inheritance.** The leaf's
value never depends on anything outside itself (no profile, no parent
leaf), and the legacy ``bgp_config_write`` persisted it as a bare ``no
<cmd>`` line (default: on). These are modeled as ``leaf x { type
boolean; default "true"; }``. libyang's own persistence does the
work: an explicit ``false`` is a real node in the datastore and gets
written back; the implicit ``true`` default is not. ``cli_show``
follows the same value-checked shape everywhere -- print the legacy
``no ...`` line iff the leaf reads ``false``, print nothing iff it
reads ``true``. The CLI keeps the **unmodified legacy grammar**: no
``enabled``/``disabled`` keywords and no deprecated aliases, because
the legacy grammar already *is* the canonical, unambiguous form.
Positive ``<cmd>`` maps to ``NB_OP_DESTROY`` (return to the ``true``
default -- the northbound layer resolves a destroy on a
default-bearing leaf to a modify-with-default, which is exactly the
legacy behavior); ``no <cmd>`` maps to ``NB_OP_MODIFY`` "false".
Current Tier A leaves: ``/proteus-bgp:process/ipv6-auto-ra`` (the
inheritance-chain root for the instance override below),
``/proteus-bgp:instance/fast-external-failover``,
``/proteus-bgp:instance/client-to-client-reflection``,
``/proteus-bgp:instance/reject-as-sets``,
``/proteus-bgp:instance/default/ipv4-unicast``, and, since the M6 EVPN
batches, ``/proteus-bgp:instance/afi-safis/l2vpn-evpn/dup-addr-detection/enabled``,
``.../l2vpn-evpn/advertise-pip/enabled`` and
``.../l2vpn-evpn/multihoming/use-es-l3nhg`` (all default-on and rendered as
the tri-state ``enabled|disabled`` form; their static defaults mirror
compiled constants, not build profiles). The positive default-on
``.../l2vpn-evpn/multihoming/ead-evi-rx`` and ``ead-evi-tx`` share that
tri-state Tier A shape; their C backend inverts the sense onto the
``enable_ead_evi_*`` fields.

**Tier B -- tri-state: inheriting leaves and profile-dependent
defaults.** Two situations force a leaf out of Tier A and into an
optional leaf with *no* YANG default, where absence means "inherit"
rather than "off": (1) the leaf's effective value depends on a parent
leaf (``/proteus-bgp:instance/ipv6-auto-ra`` inherits from the process
leaf above when unset -- it cannot carry its own static default
without breaking the mutual-exclusion principle); (2) the leaf's
compiled-in default itself varies by ``FRR_CFG_DEFAULT_*`` build
profile and so cannot be expressed as a single static YANG ``default``
at all (``/proteus-bgp:instance/log-neighbor-changes``: on for the
datacenter profile, off for traditional). For these, the CLI has three
parts:

- **Canonical form**, always what ``cli_show`` emits: ``<cmd>
  <enabled|disabled>`` maps to ``NB_OP_MODIFY`` "true"/"false"; ``no
  <cmd> <enabled|disabled>`` maps to ``NB_OP_DESTROY`` (the token is
  accepted but ignored on the ``no`` form -- it exists so ``no bgp
  log-neighbor-changes disabled`` reads naturally when a user is
  toggling back and forth, not because the value changes the
  operation). ``cli_show`` is presence-based: whenever the leaf exists
  in the datastore it renders the explicit value, ``<cmd> enabled`` or
  ``<cmd> disabled``, never a bare bare-word or a suppressed line. This
  works even when the explicit value equals the runtime/inherited
  default, because there is no YANG default to fall back to and thus
  nothing for the explicit value to collide with.
- **Deprecated bare aliases**, kept as separate ``CMD_ATTR_DEPRECATED``
  command definitions so configs saved before a leaf grew this scheme
  keep loading with their original meaning: bare ``<cmd>`` maps to
  ``NB_OP_MODIFY`` "true", bare ``no <cmd>`` maps to ``NB_OP_MODIFY``
  "false" (explicit, not a delete -- this is what the legacy negative
  form actually persisted).
- Every Tier B leaf's YANG description states whether it inherits from
  a parent leaf or a build profile, and cites the legacy
  ``bgp_config_write`` (or setter ``DEFUN``/``DEFPY``) function it
  replaces.

Leaves converted with a YANG ``default`` statement and a legacy
positive-only emission (e.g. ``bgp default ipv4-multicast``, off by
default, only ever written when on) are the simplest Tier A case:
``no <cmd>`` deletes back to that ``false`` default, there is no
``enabled``/``disabled`` grammar, and neither of the two schemes above
needs a dedicated positive/negative-form writeup for them. This
follows the project's CLI naming preferences: verbose, dashed
multi-word keywords, the value spelled out in the keyword itself, no
bare ``no`` standing in for a stored value on the leaves where that
would be ambiguous -- and, per the core principle above, never a YANG
leaf name that is itself phrased negatively (the legacy negative CLI
string is a ``cli_show``-layer wart only, not something the leaf name
should encode).

Stub-rejection posture
------------------------

Every config node outside the current milestone's slice is registered
with a callback that rejects at ``NB_EV_VALIDATE`` with
``NB_ERR_VALIDATION`` and a "not yet implemented: <xpath>" message,
rather than being silently accepted and dropped. This is required by
``nb_validate_callbacks()`` (``lib/northbound.c``), which ``exit(1)``s
at daemon startup if any registered module has config-bearing nodes
without callbacks -- so the generated table must be complete, not
trimmed to the slice. It also means attempting to configure an
unconverted proteus-bgp leaf through mgmtd fails loudly and
immediately instead of appearing to succeed while doing nothing.

Per-milestone rule
--------------------

Every converted command's legacy ``DEFUN``/``DEFPY`` and its
``bgp_config_write`` emission are removed in the **same commit** that
adds the real northbound callback and CLI wiring for that command (or
immediately after, if there's a reason to land the two adjacent rather
than squashed -- e.g. testing for vtysh double-definition issues in the
interim). Do not leave a command converted-but-still-legacy across
multiple commits; the single-implementation invariant only holds as
long as each command has exactly one implementation reachable from the
CLI at a time.

M9 status: flipped
-------------------

M9 executed the residue-elimination gate (2026-07-19): the
peer-seeding-priority patch is applied and the seed-bridge deleted (the
priority-ordered init transaction replaced it), the link-state and
unreachability address families and the BGP-LS link identifiers are
converted (the last testable native surfaces), ``FRR_NO_SPLIT_CONFIG``
is set, and the native config-command surface is deleted. See
"Post-flip architecture" above. The per-milestone rule still applies to
every future conversion (RPKI/BMP, #31).

M9 dispositions (ruled 2026-07-19)
------------------------------------

- **RPKI and BMP plugin config: file-config support is dropped for the
  M9 flip, conversion is TODO** (roadmap #31). Under
  ``FRR_NO_SPLIT_CONFIG`` the plugins' CLI config (RPKI cache servers
  and timers, BMP targets) does not persist across a bgpd restart until
  the plugin CLI is converted to a mgmtd-linked TU with a
  backend-in-plugin apply path. This limitation must be called out in
  the user-facing release notes when the flip ships.

  *Update (TODO #31 batch B1):* the RPKI half of this hole is closed;
  see "Plugin config" in the post-flip architecture section above. The
  B1 batch also fixed the plugin startup crash it inherited from the
  M3 route-map conversion (the plugin still installed ``match rpki``
  at bgpd's no-longer-existing ``RMAP_NODE``; those commands now live
  in the mgmtd-hosted ``bgp_routemap_cli.c``).

  *Update (TODO #31 batch B2):* the BMP half is closed as well; see
  "Plugin config" in the post-flip architecture section above. Both
  plugin persistence holes of this disposition are resolved.
- **VNC/rfapi: documented support-drop.** Its ~133-command CLI surface
  is not converted; file-config support ends at the flip and the
  feature is deprecated-for-removal upstream-side. As a direct
  consequence, ``bgp_rfapi_basic_sanity``,
  ``bgp_rfapi_basic_sanity_config2`` and ``bgp_l3vpn_to_bgp_direct``
  topotests are expected red under split config: mgmtd rejects their
  ``vnc``/``rfp``/``vrf-policy``/``redistribute vnc-direct`` lines from
  ``bgpd.conf`` with "No such command", so the nve-group and
  vrf-policy config never reaches bgpd. All three suites are skipped
  at module level citing this disposition.
- **SRv6, flowspec (full grammar) and ``bgp snmp traps`` are converted
  in M8.5** ahead of the flip; the M8 mgmtd parse shims for the
  ``segment-routing srv6`` and link-state blocks are replaced by real
  implementations there.
