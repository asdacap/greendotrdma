// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ReconcileExports periodically re-publishes every attached greendot volume, so a
// target reboot — which clears the nvmet exports in configfs while the zvols
// survive — self-heals. The external-attacher never re-publishes an already-
// attached VolumeAttachment, so without this the exports would only return on a
// manual re-attach. Each pass calls the idempotent ensurePublished, so it is safe
// to run continuously. It also prunes exports the controller still holds for
// volumes with no live attachment, self-healing exports leaked by an ungraceful
// node loss (where ControllerUnpublishVolume never ran). Blocks until ctx is
// cancelled.
func (cs *ControllerServer) ReconcileExports(ctx context.Context, kube kubernetes.Interface, interval time.Duration) {
	klog.Infof("export reconcile: re-applying attached greendot exports every %s", interval)
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		cs.reconcileOnce(ctx, kube)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (cs *ControllerServer) reconcileOnce(ctx context.Context, kube kubernetes.Interface) {
	vas, err := kube.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.Errorf("export reconcile: list volumeattachments: %v", err)
		return
	}
	hostNQN := map[string]string{} // node name -> host NQN, one CSINode lookup per node
	live := map[string]bool{}      // PV names with a live (non-deleting) greendot attachment
	applied, failed := 0, 0
	for i := range vas.Items {
		va := &vas.Items[i]
		if va.Spec.Attacher != DriverName || va.DeletionTimestamp != nil {
			continue
		}
		pvName := va.Spec.Source.PersistentVolumeName
		if pvName == nil {
			continue
		}
		// A non-deleting attachment — even one still mid-attach — keeps the
		// export alive, so the prune below never races a starting publish.
		live[*pvName] = true
		if !va.Status.Attached {
			continue
		}
		nqn, ok := hostNQN[va.Spec.NodeName]
		if !ok {
			nqn = cs.nodeHostNQN(ctx, kube, va.Spec.NodeName)
			hostNQN[va.Spec.NodeName] = nqn
		}
		if nqn == "" {
			continue
		}
		pv, err := kube.CoreV1().PersistentVolumes().Get(ctx, *pvName, metav1.GetOptions{})
		if err != nil {
			klog.Warningf("export reconcile: get pv %s: %v", *pvName, err)
			continue
		}
		if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != DriverName {
			continue
		}
		if err := cs.ensurePublished(ctx, pv.Spec.CSI.VolumeHandle, nqn); err != nil {
			klog.Warningf("export reconcile: %s on %s: %v", pv.Spec.CSI.VolumeHandle, va.Spec.NodeName, err)
			failed++
			continue
		}
		applied++
	}
	pruned := cs.pruneExports(ctx, kube, live)
	if applied > 0 || failed > 0 || pruned > 0 {
		klog.Infof("export reconcile: re-applied %d exports, pruned %d (%d failed)", applied, pruned, failed)
	}
}

// pruneExports tears down exports the controller still holds for volumes that
// no longer have a live VolumeAttachment — self-healing exports leaked by an
// ungraceful node loss, where ControllerUnpublishVolume never ran. It consults
// cs.isExported, so the many never-attached lazy volumes are never even probed.
// Returns the number of exports torn down.
func (cs *ControllerServer) pruneExports(ctx context.Context, kube kubernetes.Interface, live map[string]bool) int {
	pvs, err := kube.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		klog.Errorf("export reconcile: list persistentvolumes: %v", err)
		return 0
	}
	pruned := 0
	for i := range pvs.Items {
		pv := &pvs.Items[i]
		if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != DriverName || live[pv.Name] {
			continue
		}
		ref, err := cs.resolveVolumeID(pv.Spec.CSI.VolumeHandle)
		if err != nil {
			continue
		}
		nqn := cs.nqnOf(ref)
		if !cs.isExported(nqn) {
			continue
		}
		if err := cs.deleteExport(ctx, nqn); err != nil {
			klog.Warningf("export reconcile: prune %s: %v", pv.Spec.CSI.VolumeHandle, err)
			continue
		}
		klog.Infof("export reconcile: pruned export for %s (no live attachment)", pv.Spec.CSI.VolumeHandle)
		pruned++
	}
	return pruned
}

// nodeHostNQN maps a Kubernetes node name to the node's greendot host NQN, which
// the node plugin registers as its CSINode driver id (--nodeid = /etc/nvme/hostnqn).
func (cs *ControllerServer) nodeHostNQN(ctx context.Context, kube kubernetes.Interface, node string) string {
	cn, err := kube.StorageV1().CSINodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		klog.Warningf("export reconcile: get csinode %s: %v", node, err)
		return ""
	}
	for _, d := range cn.Spec.Drivers {
		if d.Name == DriverName {
			return d.NodeID
		}
	}
	return ""
}
