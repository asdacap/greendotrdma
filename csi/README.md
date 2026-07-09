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
- Volumes are created **closed** (`allow_any_host=0`, empty ACL).
  `ControllerPublishVolume` grants exactly the attaching node's host NQN;
  `ControllerUnpublishVolume` fences: ACL revoke → port unlink (severs live
  controllers; the kernel then DNR-rejects the fenced host's reconnect) →
  relink.

## Provenance

The node service is forked from
[kubernetes-csi/csi-driver-nvmf](https://github.com/kubernetes-csi/csi-driver-nvmf)
(Apache-2.0, see NOTICE) with fixes: NodeStage/NodeUnstage do the fabric
connect/format once per node (upstream conflated stage into publish, letting a
failed second pod disconnect a live mount), rollbacks run on the named return
error, and the connector path is traversal-guarded. The controller is original
(upstream ships stubs).

## Deploy

1. On the box (installed by the deb): create the parent dataset and the SSH
   trust —
   ```sh
   zfs create tank/csi
   install -d -o greendot-csi -g greendot-csi -m 700 /var/lib/greendotrdma/csi/.ssh
   echo 'command="/usr/libexec/greendotrdma/greendotctl pipe",restrict ssh-ed25519 AAAA…' \
     > /var/lib/greendotrdma/csi/.ssh/authorized_keys
   ```
2. In the cluster:
   ```sh
   kubectl -n kube-system create secret generic greendot-csi-ssh --from-file=id_ed25519=…
   ssh-keyscan -H <box> | kubectl -n kube-system create configmap greendot-csi-known-hosts --from-file=known_hosts=/dev/stdin
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
