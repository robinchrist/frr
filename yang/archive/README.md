# Archived YANG models

These are FRR's superseded native BGP models. They are kept in the tree
for reference and diffing only: they are not built, not embedded into any
daemon, and not installed.

They are superseded by the BGP-owned modules `proteus-bgp` and
`proteus-bgp-filter` (see `yang/proteus/`). The exception is
`frr-bgp-route-map`, which was kept live and improved in place instead of
being replaced; it now imports `proteus-bgp-filter` rather than the
archived `frr-bgp-filter`.

The shared modules `frr-route-map`, `frr-filter` and `frr-interface`
also remain live; the archive covers only the BGP-specific set:

- frr-bgp.yang
- frr-bgp-types.yang
- frr-bgp-common.yang
- frr-bgp-common-structure.yang
- frr-bgp-common-multiprotocol.yang
- frr-bgp-neighbor.yang
- frr-bgp-peer-group.yang
- frr-bgp-rpki.yang
- frr-bgp-bmp.yang
- frr-deviations-bgp-datacenter.yang
- frr-bgp-filter.yang

The set is self-contained: these modules only import each other and the
shared modules, so archiving them breaks no live import.
