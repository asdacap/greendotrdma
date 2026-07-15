// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
)

func driverPV(name, handle string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: name},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{Driver: DriverName, VolumeHandle: handle},
			},
		},
	}
}

// One reconcile pass re-applies the export for an attached volume (the
// target-reboot self-heal) and, in the same pass, prunes the export the
// controller still holds for a volume with no live attachment (an
// ungraceful-loss leak) — while leaving a never-exported unattached volume
// untouched.
func TestReconcileReappliesAndPrunes(t *testing.T) {
	const (
		hostnqn    = "nqn.2014-08.org.nvmexpress:uuid:aaaa"
		attachedH  = "tank:csi:attached"
		leakedH    = "tank:csi:leaked"
		untouchedH = "tank:csi:untouched"
	)
	f := newFake()
	cs := testController(t, f)
	// The controller already holds an export for the leaked volume (from an
	// earlier publish) but never for the untouched one.
	cs.setExported(CSINQNPrefix+leakedH, true)

	pvName := "pv-attached"
	kube := fake.NewSimpleClientset(
		&storagev1.VolumeAttachment{
			ObjectMeta: metav1.ObjectMeta{Name: "va-attached"},
			Spec: storagev1.VolumeAttachmentSpec{
				Attacher: DriverName,
				NodeName: "node-a",
				Source:   storagev1.VolumeAttachmentSource{PersistentVolumeName: &pvName},
			},
			Status: storagev1.VolumeAttachmentStatus{Attached: true},
		},
		&storagev1.CSINode{
			ObjectMeta: metav1.ObjectMeta{Name: "node-a"},
			Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{
				{Name: DriverName, NodeID: hostnqn},
			}},
		},
		driverPV("pv-attached", attachedH),
		driverPV("pv-leaked", leakedH),
		driverPV("pv-untouched", untouchedH),
	)

	cs.reconcileOnce(context.Background(), kube)

	// Attached volume: export re-applied and the node re-granted.
	if apply, _ := f.reqs["CsiNvmeApply"].(*helperpb.CsiNvmeApply); apply == nil || apply.Nqn != CSINQNPrefix+attachedH {
		t.Fatalf("attached volume export not re-applied: %+v", f.reqs["CsiNvmeApply"])
	}
	if grant, _ := f.reqs["CsiHostGrant"].(*helperpb.CsiHostGrant); grant == nil || grant.Hostnqn != hostnqn {
		t.Fatalf("attached volume not re-granted: %+v", f.reqs["CsiHostGrant"])
	}
	// Exactly the leaked export is pruned — not the attached one (it is live),
	// not the untouched one (the controller never exported it).
	dels := 0
	for _, c := range f.calls {
		if c == "CsiNvmeDelete" {
			dels++
		}
	}
	if dels != 1 {
		t.Fatalf("want exactly one prune, got %d (calls=%v)", dels, f.calls)
	}
	if del, _ := f.reqs["CsiNvmeDelete"].(*helperpb.CsiNvmeDelete); del == nil || del.Nqn != CSINQNPrefix+leakedH {
		t.Fatalf("pruned the wrong export: %+v", f.reqs["CsiNvmeDelete"])
	}
	// Tracking now reflects reality: leaked cleared, attached recorded.
	if cs.isExported(CSINQNPrefix + leakedH) {
		t.Fatalf("leaked export still tracked after prune")
	}
	if !cs.isExported(CSINQNPrefix + attachedH) {
		t.Fatalf("attached export not tracked after re-apply")
	}
}
