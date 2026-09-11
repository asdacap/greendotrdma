// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	corev1 "k8s.io/api/core/v1"
	storagev1 "k8s.io/api/storage/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	ktesting "k8s.io/client-go/testing"
)

func driverPV(name, handle string) *corev1.PersistentVolume {
	return &corev1.PersistentVolume{ObjectMeta: metav1.ObjectMeta{Name: name}, Spec: corev1.PersistentVolumeSpec{PersistentVolumeSource: corev1.PersistentVolumeSource{CSI: &corev1.CSIPersistentVolumeSource{Driver: DriverName, VolumeHandle: handle}}}}
}
func driverVA(name, pv, node string, attached bool) *storagev1.VolumeAttachment {
	return &storagev1.VolumeAttachment{ObjectMeta: metav1.ObjectMeta{Name: name, UID: types.UID(name)}, Spec: storagev1.VolumeAttachmentSpec{Attacher: DriverName, NodeName: node, Source: storagev1.VolumeAttachmentSource{PersistentVolumeName: &pv}}, Status: storagev1.VolumeAttachmentStatus{Attached: attached}}
}

const testHost = "nqn.2014-08.org.nvmexpress:host1"

func driverNode() *storagev1.CSINode {
	return &storagev1.CSINode{ObjectMeta: metav1.ObjectMeta{Name: "node"}, Spec: storagev1.CSINodeSpec{Drivers: []storagev1.CSINodeDriver{{Name: DriverName, NodeID: testHost}}}}
}

// Stateful model of the target protocol; the Rust tests exercise the actual
// durable implementation, while these tests force API/controller interleavings.
type generationHelper struct {
	helperpb.HelperClient
	mu            sync.Mutex
	owners        map[string]*helperpb.CsiAttachmentReply
	fenced        map[string]bool
	beforePublish func()
	beforeRead    func(context.Context, string) error
}

func newGenerationHelper() *generationHelper {
	return &generationHelper{owners: map[string]*helperpb.CsiAttachmentReply{}, fenced: map[string]bool{}}
}
func (h *generationHelper) ZvolInfo(context.Context, *helperpb.ZvolInfo, ...grpc.CallOption) (*helperpb.ZvolInfoReply, error) {
	return &helperpb.ZvolInfoReply{Exists: true}, nil
}
func (h *generationHelper) CsiAttachment(ctx context.Context, in *helperpb.CsiNvmeDelete, _ ...grpc.CallOption) (*helperpb.CsiAttachmentReply, error) {
	if h.beforeRead != nil {
		if err := h.beforeRead(ctx, in.Nqn); err != nil {
			return nil, err
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if owner := h.owners[in.Nqn]; owner != nil {
		return &helperpb.CsiAttachmentReply{Hostnqn: owner.Hostnqn, AttachmentId: owner.AttachmentId}, nil
	}
	return &helperpb.CsiAttachmentReply{}, nil
}
func generationResult(message string) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return newFakeWithFailure(message).task("result", nil)
}
func newFakeWithFailure(message string) *fakeHelper {
	f := newFake()
	f.fail["result"] = message
	return f
}
func (h *generationHelper) CsiPublish(ctx context.Context, in *helperpb.CsiPublish, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	if h.beforePublish != nil {
		h.beforePublish()
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	owner := h.owners[in.Export.Nqn]
	if h.fenced[in.AttachmentId] || owner != nil && (owner.AttachmentId != in.AttachmentId || owner.Hostnqn != in.Hostnqn) {
		return generationResult("attachment conflict: stale or conflicting owner")
	}
	h.owners[in.Export.Nqn] = &helperpb.CsiAttachmentReply{AttachmentId: in.AttachmentId, Hostnqn: in.Hostnqn}
	return generationResult("")
}
func (h *generationHelper) CsiUnpublish(ctx context.Context, in *helperpb.CsiUnpublish, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.fenced[in.AttachmentId] = true
	if owner := h.owners[in.Nqn]; owner != nil && owner.AttachmentId == in.AttachmentId && owner.Hostnqn == in.Hostnqn {
		delete(h.owners, in.Nqn)
	}
	return generationResult("")
}
func controllerWithHelper(t *testing.T, h helperpb.HelperClient) *ControllerServer {
	t.Helper()
	cs, err := NewControllerServer(ControllerConfig{TrAddr: "10.0.0.5", Transport: "tcp"}, h)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func TestGenerationReconcileSchedules(t *testing.T) {
	for _, scenario := range []string{"stale publish after detach", "prune after new publish", "restart prunes persisted owner", "timeout continues"} {
		t.Run(scenario, func(t *testing.T) {
			h := newGenerationHelper()
			cs := controllerWithHelper(t, h)
			const volume = "tank:csi:volume"
			nqn := CSINQNPrefix + volume
			kube := fake.NewSimpleClientset(driverPV("pv", volume), driverNode())
			cs.SetKubernetes(kube)
			h.owners[nqn] = &helperpb.CsiAttachmentReply{Hostnqn: testHost, AttachmentId: "old"}
			switch scenario {
			case "stale publish after detach":
				_, _ = kube.StorageV1().VolumeAttachments().Create(context.Background(), driverVA("old", "pv", "node", true), metav1.CreateOptions{})
				entered, release := make(chan struct{}), make(chan struct{})
				h.beforePublish = func() { close(entered); <-release }
				done := make(chan struct{})
				go func() { cs.reconcileOnce(context.Background(), kube); close(done) }()
				<-entered
				// A second controller completes the fence after the first read its list.
				other := controllerWithHelper(t, h)
				if err := other.unpublishAttachment(context.Background(), nqn, testHost, "old"); err != nil {
					t.Fatal(err)
				}
				close(release)
				<-done
				if h.owners[nqn] != nil {
					t.Fatal("stale pass resurrected detached generation")
				}
			case "prune after new publish":
				kube.PrependReactor("list", "volumeattachments", func(ktesting.Action) (bool, runtime.Object, error) {
					_, _ = h.CsiUnpublish(context.Background(), &helperpb.CsiUnpublish{Nqn: nqn, Hostnqn: testHost, AttachmentId: "old"})
					_, _ = h.CsiPublish(context.Background(), &helperpb.CsiPublish{Export: &helperpb.CsiNvmeApply{Nqn: nqn}, Hostnqn: testHost, AttachmentId: "new"})
					return true, &storagev1.VolumeAttachmentList{}, nil
				})
				cs.reconcileOnce(context.Background(), kube)
				if h.owners[nqn] == nil || h.owners[nqn].AttachmentId != "new" {
					t.Fatal("stale prune removed fresh owner")
				}
			case "restart prunes persisted owner":
				controllerWithHelper(t, h).reconcileOnce(context.Background(), kube)
				if h.owners[nqn] != nil || !h.fenced["old"] {
					t.Fatal("restart lost target ownership")
				}
			case "timeout continues":
				_, _ = kube.CoreV1().PersistentVolumes().Create(context.Background(), driverPV("z-next", "tank:csi:next"), metav1.CreateOptions{})
				visited := false
				h.beforeRead = func(ctx context.Context, nqn string) error {
					if _, ok := ctx.Deadline(); !ok {
						return fmt.Errorf("missing deadline")
					}
					if nqn == CSINQNPrefix+volume {
						return context.DeadlineExceeded
					}
					visited = true
					return nil
				}
				cs.reconcileOnce(context.Background(), kube)
				if !visited {
					t.Fatal("one timeout blocked following volume")
				}
			}
		})
	}
}

func TestAttachmentLookupAndDelayedDetach(t *testing.T) {
	for _, deleting := range []bool{false, true} {
		t.Run(fmt.Sprint(deleting), func(t *testing.T) {
			h := newGenerationHelper()
			cs := controllerWithHelper(t, h)
			va := driverVA("generation", "pv", "node", true)
			if deleting {
				now := metav1.Now()
				va.DeletionTimestamp = &now
			}
			kube := fake.NewSimpleClientset(driverPV("pv", "tank:csi:volume"), driverNode(), va)
			cs.SetKubernetes(kube)
			_, err := cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{VolumeId: "tank:csi:volume", NodeId: testHost, VolumeCapability: rwoCaps()[0]})
			if deleting {
				wantCode(t, err, codes.FailedPrecondition)
			} else {
				wantCode(t, err, codes.OK)
			}
			if !deleting {
				// A delayed detach has no deleting VA: it must not infer the new owner's UID.
				_, err = cs.ControllerUnpublishVolume(context.Background(), &csi.ControllerUnpublishVolumeRequest{VolumeId: "tank:csi:volume", NodeId: testHost})
				wantCode(t, err, codes.OK)
				if h.owners[CSINQNPrefix+"tank:csi:volume"] == nil {
					t.Fatal("delayed detach removed live owner")
				}
			}
		})
	}
}
