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
``proteus-*.yang``) instead of FRR's dormant ``frr-bgp*.yang`` stack.
The proteus models are augment-free, strongly typed, and CLI-mirrored
(every leaf description cites the emitting legacy ``*_config_write*``
function), which makes them a better fit for an incremental,
command-by-command conversion than the existing frr-bgp stack. The
proteus models will eventually replace all of bgpd's configuration
surface, including route-maps and filters; until then the dormant
frr-bgp stack and the already-converted ``frr-bgp-route-map.yang``
remain untouched and unrelated to this effort.

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

Coexistence with the legacy CLI
--------------------------------

**Split config: both daemons read** ``bgpd.conf``. bgpd is listed in
mgmtd's ``mgmt_daemons[]`` (``mgmtd/mgmt_vty_frontend.c``), so in
split-config mode mgmtd reads ``bgpd.conf`` at startup and applies the
converted lines through the datastore (the staticd pattern), while
bgpd keeps reading the same file for the lines it still owns (it does
not set ``FRR_NO_SPLIT_CONFIG``). Each side warns about the other's
lines -- mgmtd logs errors for legacy lines it doesn't recognize, bgpd
logs "No such command" for converted lines -- which is cosmetic and
expected in the mixed state; neither parser aborts the file. Config
sourced this way round-trips through ``show running-config`` because
the converted lines live in mgmtd's datastore, where ``cli_show``
renders them. Integrated ``frr.conf`` (``vtysh -b``) works unchanged.

**Dual header emission, single merged block.** bgpd keeps its legacy
``router bgp ...`` header and ``exit``/``!`` trailer in
``bgp_config_write`` (it still owns every unconverted line inside the
block); mgmtd's ``cli_show`` for ``/proteus-bgp:instance`` reproduces
that exact same header. vtysh's ``show running-config`` merges
same-context blocks by **byte-identical header text**
(``vtysh/vtysh_config.c``), so the two emissions fold into one
``router bgp`` block instead of splitting into two. This invariant
applies to every future node-entry command conversion in bgpd, not
just this milestone: any change to how bgpd renders the ``router bgp``
header line must be mirrored in ``bgp_cli.c``'s ``instance_cli_write``,
and vice versa.

**Legacy ``router_bgp`` DEFUN_NOSH stays.** Interactive commits are
synchronous through mgmtd (it defers the CLI response until the
backend applies the change), but file loads batch mgmtd commits until
the ``XFRR_start_configuration`` end marker while legacy lines hit
bgpd immediately. The legacy DEFUN_NOSH has to remain so a bgp
instance exists for legacy subcommands to attach to mid-load;
``bgp_get()`` is idempotent, so both the legacy and northbound paths
creating the same instance is safe. vtysh's ``router_bgp`` DEFUNSH
routes to both ``VTYSH_BGPD`` and ``VTYSH_MGMTD``.

**Legacy neighbor/peer-group lifecycle DEFUNs stay.** Same reasoning as
``router_bgp`` above, one level down: ``neighbor <addr|WORD>
remote-as ...`` (all forms), ``neighbor WORD interface ...`` (all
forms), ``neighbor WORD peer-group`` (create), ``neighbor <addr|WORD>
peer-group PGNAME`` (bind), and their ``no`` forms stay in
``bgp_vty.c`` even though ``instance_neighbor_create()`` /
``instance_peer_group_create()`` and the ``remote-as``/peer-group-bind
leaf callbacks in ``bgp_nb_config.c`` (M4 batch B1) are the real
northbound implementation -- config_write for these lines is mgmtd-only
(``peer_group_cli_write()``/``neighbor_cli_write()`` in
``bgp_cli.c``). Without the legacy DEFUNs, a peer or peer-group
created only through mgmtd's batched, end-of-file-triggered backend
push does not exist yet when a legacy line later in the same file
(e.g. ``neighbor X timers 3 10``, still unconverted) tries to
configure it, and bgpd rejects it ("Specify remote-as or peer-group
commands first"), aborting the rest of the block.

vtysh dual-routes each of these exactly like ``router_bgp``: defining
the same CLI grammar in both ``bgp_vty.c`` (picked up under
``VTYSH_BGPD``) and ``bgp_cli.c`` (``VTYSH_MGMTD``) makes
``python/xref2vtysh.py`` merge the two ``CommandEntry`` objects (same
normalized command string, in the same CLI node) into one dual-daemon
install rather than erroring on a duplicate -- this is the general
mechanism the ``router_bgp`` DEFUNSH double-definition relies on too,
just automated instead of hand-written in ``vtysh.c``. For interactive
use, ``vtysh_client[]`` lists ``mgmtd`` before ``bgpd``, so mgmtd's
northbound callback typically applies first and bgpd's legacy DEFUN
runs against an already-converged (or, for destroy, already-absent)
target. Every legacy setter here (``peer_remote_as()``,
``peer_group_remote_as()``, ``peer_group_bind()``, ``peer_group_get()``,
``peer_create()`` via the interface path) is idempotent by
construction, so creates/modifies converge regardless of ordering; the
``no ...`` DEFUNs additionally had to be changed to tolerate "peer or
peer-group already gone" as a silent no-op instead of the pre-B1
``CMD_WARNING_CONFIG_FAILED``, since that is now the common case rather
than a user error. The hidden address-family-context aliases for
``neighbor ... peer-group PGNAME`` are not reinstalled (pure CLI
convenience, no functional loss); reconciling a peer-group member's
stale northbound ``neighbor`` list entry after ``peer_group_delete()``
remains a known gap, per the M4 batch B1 commit message.

**mgmtd log noise.** Split-config mode logs errors for legacy
``bgpd.conf`` lines mgmtd doesn't recognize. This is cosmetic and
expected during the transition; it does not indicate a conversion bug.

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
under ``INTERFACE_NODE`` (``mpls bgp forwarding``) and ``VRF_NODE``
(``rpki``). The pattern for this mixed state:

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

Known remaining instance of the same race shape: lib's route-map and
access-/prefix-list CLI (``VTYSH_RMAP_CONFIG``/``VTYSH_ACL_CONFIG``)
is northbound-backed and still routed to bgpd. Converting bgpd off
its local copies is milestone-scale (bgpd extends route-maps via
``frr-bgp-route-map``) and deferred; a flakiness risk during config
replay, not a deterministic startup failure.

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
``/proteus-bgp:instance/reject-as-sets``, and
``/proteus-bgp:instance/default/ipv4-unicast``.

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
multiple commits; the coexistence rules above only hold as long as
each command has exactly one implementation reachable from the CLI at
a time.
