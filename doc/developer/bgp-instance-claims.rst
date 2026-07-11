.. _bgp-instance-claims:

Auto-created BGP instances and instance claims
==============================================

Several subsystems need a ``struct bgp`` instance to exist for a VRF even
though the user has not (yet) configured ``router bgp`` for it. Classic
example: VRF<->VRF route leaking (``import vrf ...``) transits the default
instance's VPN RIB, so configuring an import in any VRF requires a default
instance. Historically this was handled ad hoc (an undocumented "hidden"
default instance plus a never-set ``BGP_VRF_AUTO`` flag), with no tracking of
*why* such an instance existed and therefore no way to ever free it.

The claim API (``bgpd.h``) replaces that:

.. code-block:: c

   struct bgp *bgp_instance_claim(const char *vrf_name,
                                  enum bgp_instance_use use);
   void bgp_instance_unclaim(struct bgp **bgp, enum bgp_instance_use use);
   bool bgp_instance_has_claims(const struct bgp *bgp);

A *claim* expresses "this code path needs the instance for VRF ``vrf_name``
to exist". Claims are counted per use (``enum bgp_instance_use``), so
independent subsystems - or independent objects within one subsystem - never
need to coordinate: each simply claims and unclaims its own reference, and
the instance lives until user config *and* all claims are gone.

Lifecycle
---------

* **Auto-creation.** ``bgp_instance_claim()`` on a VRF with no instance
  creates one with ``AS_UNSPECIFIED`` and flags it
  ``BGP_FLAG_INSTANCE_AUTO_CREATED``. Auto-created instances are invisible:
  config-write and show commands skip them, and ``bgp_lookup_by_name()``
  does not return them (``bgp_lookup_by_name_filter(name, false)`` does).

* **Stable pointers.** The returned pointer is ``bgp_lock()``-ed and stays
  valid until the matching ``bgp_instance_unclaim()`` - across user config
  being added or removed for the instance. Store the pointer; do not
  re-resolve by name.

* **Promotion.** When the user configures ``router bgp AS vrf X`` for an
  auto-created instance, ``bgp_lookup_by_as_name_type()`` re-initializes the
  existing struct in place (``bgp_create(..., promote_auto = true)``) and
  clears the auto flag. Claimants notice nothing; their pointers remain
  valid.

* **Demotion.** ``bgp_delete()`` on an instance that still has claims (or a
  default instance whose VPN RIB still holds routes) does not free it: the
  instance is demoted back to auto-created and the teardown steps that would
  make the struct unusable are skipped.

* **Deferred free.** When the last claim is released while the instance is
  auto-created, ``bgp_instance_unclaim()`` runs the real ``bgp_delete()``.
  At daemon termination (``bm->terminating``) the shutdown loop instead
  tears down every instance, claimed or not.

Current uses
------------

``BGP_INSTANCE_USE_VPN_RIB``
   Held (per afi) by a VRF with VRF<->VRF import config on the default
   instance. Taken with ``vpn_leak_vpn_rib_claim()`` when
   ``BGP_CONFIG_VRF_TO_VRF_IMPORT`` is set, released when the flag is
   cleared or the claiming VRF instance is deleted. This fixes the historic
   leak where an auto-created default instance survived ``no import vrf``
   forever.

Adding a new use
----------------

#. Add an ``enum bgp_instance_use`` value and its ``bgp_instance_use2str()``
   name.
#. Claim where the config/object that needs the instance is created; store
   the returned pointer in that object.
#. Unclaim where that object is destroyed - including daemon-internal
   destruction paths such as ``bgp_delete()`` of an owning instance, not
   just the CLI ``no`` path.
#. Never keep a raw (unclaimed) ``struct bgp *`` across events that can
   delete instances.
