// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// ReconcileExports restores attached generations after a target reboot and
// fences removed generations. Target-side tombstones, not API-list freshness
// or controller leadership timing, make overlapping/stale passes safe.
func (cs *ControllerServer) ReconcileExports(ctx context.Context, kube kubernetes.Interface, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		cs.reconcileOnce(ctx, kube)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (cs *ControllerServer) reconcileOnce(ctx context.Context, kube kubernetes.Interface) {
	listContext, cancel := context.WithTimeout(ctx, operationTimeout)
	pvs, err := kube.CoreV1().PersistentVolumes().List(listContext, metav1.ListOptions{})
	cancel()
	if err != nil {
		klog.Errorf("export reconcile: list volumes: %v", err)
		return
	}
	for _, pv := range pvs.Items {
		if ctx.Err() != nil {
			return
		}
		if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != DriverName {
			continue
		}
		volumeContext, cancel := context.WithTimeout(ctx, operationTimeout)
		err := cs.reconcileVolume(volumeContext, kube, pv.Name, pv.Spec.CSI.VolumeHandle)
		cancel()
		if err != nil {
			klog.Warningf("export reconcile: %s: %v", pv.Name, err)
		}
	}
}

func (cs *ControllerServer) reconcileVolume(ctx context.Context, kube kubernetes.Interface, pvName, volume string) error {
	ref, err := cs.resolveVolumeID(volume)
	if err != nil {
		return err
	}
	nqn := cs.nqnOf(ref)
	// Read the expected owner BEFORE the authoritative attachment list. A new
	// publish after this read cannot be pruned: unpublish compares its exact UID.
	owner, err := cs.targetAttachment(ctx, nqn)
	if err != nil {
		return err
	}
	attachments, err := kube.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	ownerLive := false
	for _, attachment := range attachments.Items {
		if attachment.Spec.Attacher == DriverName && attachment.Spec.Source.PersistentVolumeName != nil && *attachment.Spec.Source.PersistentVolumeName == pvName && attachment.DeletionTimestamp == nil && string(attachment.UID) == owner.AttachmentId {
			ownerLive = true
		}
	}
	// Retire a missing/deleting owner before trying a replacement attachment.
	if owner.AttachmentId != "" && !ownerLive {
		if err := cs.unpublishAttachment(ctx, nqn, owner.Hostnqn, owner.AttachmentId); err != nil {
			return err
		}
	}
	for _, attachment := range attachments.Items {
		if attachment.Spec.Attacher != DriverName || attachment.Spec.Source.PersistentVolumeName == nil || *attachment.Spec.Source.PersistentVolumeName != pvName {
			continue
		}
		if attachment.UID == "" {
			return fmt.Errorf("attachment has no UID")
		}
		uid := string(attachment.UID)
		if uid == owner.AttachmentId && !ownerLive {
			continue
		} // fenced above, even if CSINode is gone
		host := cs.nodeHostNQN(ctx, kube, attachment.Spec.NodeName)
		if host == "" {
			return fmt.Errorf("cannot resolve attachment host")
		}
		if attachment.DeletionTimestamp != nil {
			if err := cs.unpublishAttachment(ctx, nqn, host, uid); err != nil {
				return err
			}
		} else if attachment.Status.Attached {
			if err := cs.publishAttachment(ctx, volume, host, uid); err != nil {
				return err
			}
		}
	}

	return nil
}

func (cs *ControllerServer) nodeHostNQN(ctx context.Context, kube kubernetes.Interface, node string) string {
	cn, err := kube.StorageV1().CSINodes().Get(ctx, node, metav1.GetOptions{})
	if err != nil {
		klog.Warningf("export reconcile: get csinode %s: %v", node, err)
		return ""
	}
	for _, driver := range cn.Spec.Drivers {
		if driver.Name == DriverName {
			return driver.NodeID
		}
	}
	return ""
}
