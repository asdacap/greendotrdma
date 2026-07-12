# Using both initiator NIC ports for one NVMe-oF volume

Status: **design only, not implemented.**

## Situation

- Initiator: one **dual-port ConnectX-4**, 2×25G, hardware RoCE (mlx5).
- Target: the greendotrdma box (Meta-locked ConnectX-6, Soft-RoCE — see
  `deploy-target-host` memory). Single ZFS host.
- Switch: MikroTik **CRS504-4XQ** (4×100G QSFP28, RouterOS 7); the 25G links
  come off a QSFP28→4×SFP28 breakout. Supports 802.3ad LACP, hardware-offloaded
  on the Marvell chip.
- Goal: both initiator ports carry traffic to one volume — link redundancy and
  ~50G aggregate, not target-node HA (the target is a single box; nothing here
  survives losing it).

## Decision: RoCE LAG (bond), native multipath as fallback

Because both ports are on the **same** CX-4 ASIC and the CRS504 can form an
LACP port-channel, RoCE LAG is the primary design. It needs **no greendot code**
— it is host + switch network config — and dissolves the same-subnet routing
problem that multipath would otherwise impose.

|                     | RoCE LAG (chosen)                       | Native multipath (fallback)              |
|---------------------|-----------------------------------------|------------------------------------------|
| Networking          | one IP, one subnet — nothing special    | two source IPs, needs ARP/rp_filter tuning |
| greendot code       | none                                    | connect-twice + `host_traddr` + `iopolicy` |
| Aggregation         | mlx5 hashes QPs across ports            | `iopolicy=round-robin`                   |
| Switch requirement  | LACP port-channel (active-active)       | none                                     |
| Works w/o HW RoCE   | no                                      | yes (incl. Soft-RoCE, separate cards)    |

Fall back to multipath only if LAG cannot engage: switch can't do LACP, or the
card is running SR-IOV (see caveats).

## RoCE LAG setup

### Initiator (host)

1. Bond the two CX-4 ports, mode `802.3ad` (LACP). systemd-networkd / netplan /
   `ip link add bond0 type bond mode 802.3ad`.
2. mlx5 detects both ports of one card in the bond and creates a single bonded
   RDMA device, `mlx5_bond_0`. NVMe-oF connects over that one device / one IP.
3. NVMe-oF opens one QP per queue (≈ per CPU); mlx5 hashes QPs across the two
   physical ports, so a single subsystem connection spreads.

### Switch (CRS504, RouterOS 7)

- `/interface bonding add slaves=<p1>,<p2> mode=802.3ad
  transmit-hash-policy=layer-3-and-4`.
- `layer-3-and-4` matters: RoCEv2 is UDP, and per-QP source ports let the switch
  distribute **return** traffic across both members. `layer-2` would pin
  target→initiator to one port and kill RX aggregation.
- Confirm the bond is **hardware-offloaded** (`/interface bonding print` — not
  running on the switch CPU), or throughput collapses to the control-plane path.

### Verify (this becomes greendot's diagnostic — see below)

- `rdma link show` shows `mlx5_bond_0` with state ACTIVE.
- `/sys/class/net/bond0/bonding/slaves` lists both ports; each in
  `.../lower_<port>/bonding_slave/mii_status = up`.
- `cat /sys/class/net/bond0/bonding/mode` = `802.3ad`.
- Both members show LACP `ad_actor_oper_port_state` churn = none / collecting +
  distributing.

## Caveats that decide whether LAG actually aggregates

1. **Switch must run LACP active-active.** Active-backup bonds give failover but
   only one port carries traffic — not the goal. If the CRS504 side isn't a
   real port-channel, you get backup, not aggregation.
2. **SR-IOV disables RoCE LAG.** mlx5 turns LAG off when VFs are active on the
   card. The initiator's CX-4 must be bare-metal (no VFs) for LAG to engage. (If
   the initiator ever needs SR-IOV, LAG is out and multipath is the only path.)
3. **RX aggregation depends on the far side's hash**, hence `layer-3-and-4` on
   the switch and multi-queue on the volume. Single-queue traffic pins to one
   port regardless.

## greendot's role under the LAG design

Per repo rules (diagnostics are a key feature; no NIC-vendor terms in
greendot-web), greendot does **not** configure the bond — that is host/switch
setup. greendot's job is a **diagnostic**, helper-side (where hardware knowledge
is allowed, behind the `NetworkHardware` trait), that reports:

- a bonded RDMA device is present and ACTIVE,
- both physical ports are up and distributing (not active-backup, not one port
  down),
- the transport actually negotiated RoCE on the bond.

The web renders that opaque result; the `mlx5_bond` specifics stay in the
helper's hardware layer. This mirrors the existing `rdma link` / ACTIVE-port
reads (`greendot-client status.rs:143`, helper `RdmaResources`).

## Fallback design: native NVMe multipath

If LAG can't be used, connect twice — one controller per port — and let kernel
native multipath fuse them. This is the only initiator-side code work, and it
is the same mechanism for both initiators (`greendot-client` privops.rs and the
CSI node fabrics.go); both already tear down all controllers per NQN and both
already fold the `nvme0c0n1` multipath device in their status readers.

1. `connect_nvme` (`privops.rs:64`) / `Connector.Connect` (`fabrics.go:60`) gain
   a source binding and emit it:
   - RoCE: `,host_traddr=<local-port-IP>`.
   - (TCP would use `,host_iface=<ifname>`.)
2. Caller loops over the two port source IPs, one connect each, same NQN +
   hostnqn/hostid. The kernel groups the controllers because the NQN matches.
3. Write `round-robin` to
   `/sys/class/nvme-subsystem/nvme-subsysN/iopolicy` (default `numa` pins one
   path → redundancy but no aggregation).
4. **Same-subnet prerequisite** (both port IPs on one subnet, one target IP):
   ```
   net.ipv4.conf.all.arp_ignore   = 1
   net.ipv4.conf.all.arp_announce = 2
   net.ipv4.conf.all.rp_filter    = 2
   ```
   `host_traddr` pins egress (source GID → physical port), so full per-NIC
   policy routing is usually unnecessary for RoCE; the sysctls fix the L2 return
   path. A same-subnet diagnostic (two RDMA ports, one subnet, `arp_ignore=0`)
   should flag this before it half-works.

Teardown and status need no change under either design.
