# greendot-csi

The Kubernetes CSI driver for a GreenDotRDMA box: dynamic NVMe-oF/RDMA
PersistentVolumes backed by ZFS zvols, with **per-node host-NQN fencing**.

## How it connects

```
KUBERNETES                                        GREENDOT BOX
controller pod ──ssh (pubkey, pinned hostkey)──▶  sshd → greendot-csi user
  gRPC over the session's stdio                     └─ forced command: greendotctl pipe
                                                        └─ /run/greendotrdma/helper.sock
node DaemonSet ──NVMe/RDMA (4421)──────────────▶  nvmet CSI port
```

- The controller holds **no root credential**: the SSH login is the packaged
  `greendot-csi` user, whose authorized_keys forces `greendotctl pipe`
  (`restrict`), and the daemon's typed allowlist re-validates every request.
  The SSH host key is always verified against a pinned known_hosts.
- CSI subsystems live under `nqn.2026-06.io.greendot.csi:` on dedicated nvmet
  port 61000 (trsvcid 4421) — a sibling namespace the web UI's reconcile never
  touches; they appear on the Exports page as **External** with live RDMA dots.
- Exports are **lazy**: no subsystem exists until a node attaches.
  `ControllerPublishVolume` (re)creates the volume's subsystem **closed**
  (`allow_any_host=0`, empty ACL) and grants exactly the attaching node's host
  NQN. `ControllerUnpublishVolume` fences — ACL revoke → port unlink (severs
  live controllers; the kernel then DNR-rejects the fenced host's reconnect) →
  relink — and then tears the subsystem down, since single-node access means the
  volume is no longer in use. The controller's export reconcile re-creates
  subsystems a target reboot wiped for still-attached volumes, and prunes any
  export left behind by an ungraceful node loss.

## Provenance

The node service is forked from
[kubernetes-csi/csi-driver-nvmf](https://github.com/kubernetes-csi/csi-driver-nvmf)
(Apache-2.0, see NOTICE) with fixes: NodeStage/NodeUnstage do the fabric
connect/format once per node (upstream conflated stage into publish, letting a
failed second pod disconnect a live mount), rollbacks run on the named return
error, and the connector path is traversal-guarded. The controller is original
(upstream ships stubs).

## Deploy

1. On the box: `zfs create tank/csi` (each StorageClass names its pool via the
   `datasetParent` parameter — create one dataset per class), then paste the
   controller's **public** key into greendot-web's **SSH access** page
   (`/ssh-access`). The daemon writes the `command="…greendotctl pipe",restrict`
   options itself — the web never supplies them — and the page renders the
   box's `known_hosts` block for the next step, so there is no `ssh-keyscan`
   TOFU.
2. In the cluster:
   ```sh
   kubectl -n kube-system create secret generic greendot-csi-ssh --from-file=id_ed25519=…
   kubectl -n kube-system create configmap greendot-csi-known-hosts --from-file=known_hosts=…
   kubectl apply -f deploy/
   ```
3. Nothing else on the workers: the node plugin loads the fabric module
   (`nvme-rdma`/`nvme-tcp`) itself at stage time — the DaemonSet mounts
   `/lib/modules` for that — and writes /dev/nvme-fabrics directly (no nvme-cli).
   Workers *without* a hardware RDMA NIC pass `--soft-roce-netdev <dev>` to the
   node plugin, which stands up a Soft-RoCE (`rxe`) link on that netdev when no
   RDMA device is present.

## Testing

- `make test` — unit tests (controller decision tables, task-stream mapping).
- `make sanity` — csi-sanity against the controller with a stateful fake
  daemon (skips documented in sanity/sanity_test.go).
- `nix build ..#checks.x86_64-linux.vmTestCsi` — the end-to-end fence proof on
  real kernels + Soft-RoCE (create → publish → connect → fence → severed →
  delete).

## Audit trail

Ops driven through this controller do not appear on greendot-web's Tasks page
(the web records only tasks it dispatches). The controller logs every daemon
subtask and its output to the pod log, and the daemon traces each op to the
journal — that pair is the audit trail for CSI operations.


### Attachment-generation fencing and upgrade

Upgrade the CSI controller and `greendotctl` together. The controller now requires
Kubernetes API access to resolve immutable `VolumeAttachment` UIDs; an older helper
lacks the generation-fenced lifecycle RPCs and attach fails closed. Existing volume
handles and namespace UUIDs do not change. A legacy live export can be adopted only
when its sole allowed host matches the requested node; conflicting or ownerless
legacy exports require operator investigation, not automatic eviction.

The target serializes `CsiPublish` and `CsiUnpublish` under its mutation lock and
stores owner intent and fenced UID tombstones in `/var/lib/greendotrdma/csi` (test-only
override: `greendotctl serve --csi-state-root <directory>`). This directory
must be on durable storage and preserved across helper/target restarts and upgrades.
Do not delete or restore it independently of attachment state. Owner intent is
persisted before an export opens; a fence is persisted before controllers are
severed, and ownership is released only after teardown succeeds. Target reboot
clears configfs but not ownership: reconciliation recreates the same live UID.
A new host/generation is rejected until the previous owner is fenced. Legacy
host-only mutation RPCs cannot bypass recorded generation fences.

Reconciliation reads target ownership before checking Kubernetes attachments and
prunes only that exact generation. Thus stale passes and overlapping controllers
cannot remove a fresh owner or resurrect a completed detach; safety does not rely
on process-local locks or Lease expiry timing. Each volume/API pass is bounded by
30 seconds and failure does not stop following volumes. Tombstones are deliberately
not garbage-collected: storage grows with attachment history, because arbitrary
late RPCs cannot safely be distinguished from reusable generations without them.
Monitor this state directory's capacity; a persistence error fails closed.

Direct test/CLI controller calls must supply an explicit immutable attachment ID
(`csi-e2e --attachment-id <id>`). Reuse it for retries and detach of that attachment,
not for a later attach. Production obtains it from Kubernetes, never from a host ID.
