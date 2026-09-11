//go:build sanity

// csi-sanity conformance for the controller service, backed by a stateful
// in-process fake helper (no SSH, no daemon). Run via `make sanity`, which
// skips:
//   - 'Node Service' — needs real fabrics/mounts; the NixOS VM e2e covers it;
//   - 'different source volume ID' — snapshot ids here are <vol>@<snap>, so
//     same-name-different-source snapshots are distinct zfs objects and the
//     cluster-unique-name conflict sanity expects cannot be detected without
//     a list rpc (documented design gap);
//   - 'should fail when the node does not exist' — a node IS its host NQN
//     here; any well-formed NQN is a grantable identity, there is no node
//     registry to be absent from.
package sanity_test

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/asdacap/greendotrdma/csi/pkg/driver"
	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/asdacap/greendotrdma/csi/pkg/node"
	"github.com/google/uuid"
	"github.com/kubernetes-csi/csi-test/v5/pkg/sanity"
	"google.golang.org/grpc"
)

type fakeTaskStream struct {
	grpc.ClientStream
	events []*helperpb.TaskEvent
}

func (s *fakeTaskStream) Recv() (*helperpb.TaskEvent, error) {
	if len(s.events) == 0 {
		return nil, io.EOF
	}
	ev := s.events[0]
	s.events = s.events[1:]
	return ev, nil
}

func taskResult(errMsg string) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	fin := &helperpb.Finished{Status: helperpb.SubStatus_SUB_STATUS_SUCCESS}
	if errMsg != "" {
		fin.Status = helperpb.SubStatus_SUB_STATUS_FAILED
		fin.Error = &errMsg
	}
	return &fakeTaskStream{events: []*helperpb.TaskEvent{
		{Event: &helperpb.TaskEvent_Finished{Finished: fin}},
	}}, nil
}

// statefulHelper emulates the daemon's zvol/snapshot/export semantics —
// including the error strings the controller's idempotency mapping keys on.
type statefulHelper struct {
	helperpb.HelperClient
	mu      sync.Mutex
	zvols   map[string]uint64
	snaps   map[string]bool
	exports map[string]bool
}

func newStateful() *statefulHelper {
	return &statefulHelper{
		zvols:   map[string]uint64{},
		snaps:   map[string]bool{},
		exports: map[string]bool{},
	}
}

func (h *statefulHelper) ZvolInfo(ctx context.Context, in *helperpb.ZvolInfo, _ ...grpc.CallOption) (*helperpb.ZvolInfoReply, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	size, ok := h.zvols[in.Dataset]
	return &helperpb.ZvolInfoReply{Exists: ok, SizeBytes: size}, nil
}

func (h *statefulHelper) ZvolCreate(ctx context.Context, in *helperpb.ZvolCreate, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.zvols[in.Dataset] = in.Size
	return taskResult("")
}

func (h *statefulHelper) ZvolDelete(ctx context.Context, in *helperpb.ZvolDelete, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.zvols[in.Dataset]; !ok {
		return taskResult(fmt.Sprintf("cannot open '%s': dataset does not exist", in.Dataset))
	}
	for snap := range h.snaps {
		if strings.HasPrefix(snap, in.Dataset+"@") {
			return taskResult(fmt.Sprintf("cannot destroy '%s': volume has children", in.Dataset))
		}
	}
	delete(h.zvols, in.Dataset)
	return taskResult("")
}

func (h *statefulHelper) ZfsClone(ctx context.Context, in *helperpb.ZfsClone, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.snaps[in.Dataset+"@"+in.Snap] {
		return taskResult(fmt.Sprintf("cannot open '%s@%s': dataset does not exist", in.Dataset, in.Snap))
	}
	size := h.zvols[in.Dataset]
	if in.NewSize != nil {
		size = *in.NewSize
	}
	h.zvols[in.Target] = size
	return taskResult("")
}

func (h *statefulHelper) SnapshotCreate(ctx context.Context, in *helperpb.SnapshotCreate, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.zvols[in.Dataset]; !ok {
		return taskResult(fmt.Sprintf("cannot open '%s': dataset does not exist", in.Dataset))
	}
	key := in.Dataset + "@" + in.Snap
	if h.snaps[key] {
		return taskResult(fmt.Sprintf("cannot create snapshot '%s': dataset already exists", key))
	}
	h.snaps[key] = true
	return taskResult("")
}

func (h *statefulHelper) SnapshotDestroy(ctx context.Context, in *helperpb.SnapshotDestroy, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	key := in.Dataset + "@" + in.Snap
	if !h.snaps[key] {
		return taskResult("could not find any snapshots to destroy")
	}
	delete(h.snaps, key)
	return taskResult("")
}

func (h *statefulHelper) CsiPublish(ctx context.Context, in *helperpb.CsiPublish, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	dataset := strings.TrimPrefix(in.Export.DevicePath, "/dev/zvol/")
	if _, ok := h.zvols[dataset]; !ok {
		return taskResult("backing volume does not exist")
	}
	h.exports[in.Export.Nqn] = true
	return taskResult("")
}

func (h *statefulHelper) CsiUnpublish(ctx context.Context, in *helperpb.CsiUnpublish, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.exports, in.Nqn)
	return taskResult("")
}

func (h *statefulHelper) CsiNvmeApply(ctx context.Context, in *helperpb.CsiNvmeApply, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, ok := h.zvols[strings.TrimPrefix(in.DevicePath, "/dev/zvol/")]; !ok {
		return taskResult("backing volume does not exist")
	}
	h.exports[in.Nqn] = true
	return taskResult("")
}

func (h *statefulHelper) CsiNvmeDelete(ctx context.Context, in *helperpb.CsiNvmeDelete, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	delete(h.exports, in.Nqn)
	return taskResult("")
}

func (h *statefulHelper) CsiHostGrant(ctx context.Context, in *helperpb.CsiHostGrant, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.exports[in.Nqn] {
		return taskResult(fmt.Sprintf("subsystem %s does not exist", in.Nqn))
	}
	return taskResult("")
}

func (h *statefulHelper) CsiHostRevoke(ctx context.Context, in *helperpb.CsiHostRevoke, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return taskResult("")
}

func (h *statefulHelper) CsiVolumeExpand(ctx context.Context, in *helperpb.CsiVolumeExpand, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	// A managed NQN token is the dataset path with ':' separators.
	dataset := strings.ReplaceAll(strings.TrimPrefix(in.Nqn, driver.CSINQNPrefix), ":", "/")
	if _, ok := h.zvols[dataset]; !ok {
		return taskResult("subsystem has no zvol-backed namespace")
	}
	h.zvols[dataset] = in.NewSize
	return taskResult("")
}

// nqnIDs makes sanity's generated node ids valid host NQNs (the controller
// refuses anything else — fencing needs a real identity).
type nqnIDs struct{}

func (nqnIDs) GenerateUniqueValidVolumeID() string { return "tank:csi:sanity-" + uuid.NewString() }
func (nqnIDs) GenerateInvalidVolumeID() string     { return "../invalid" }
func (nqnIDs) GenerateUniqueValidNodeID() string {
	return "nqn.2014-08.org.nvmexpress:uuid:" + uuid.NewString()
}
func (nqnIDs) GenerateInvalidNodeID() string { return "not-an-nqn" }

func TestSanity(t *testing.T) {
	endpoint := "unix://" + filepath.Join(t.TempDir(), "csi.sock")
	cs, err := driver.NewControllerServer(driver.ControllerConfig{
		TrAddr: "10.0.0.5", Transport: "rdma", AttachmentID: "sanity-direct",
	}, newStateful())
	if err != nil {
		t.Fatal(err)
	}
	// The node service is registered for NodeGetInfo/NodeGetCapabilities
	// (several controller specs resolve the node id through it); its
	// hardware-touching specs are under the 'Node Service' skip.
	ns := node.NewNodeServer("nqn.2014-08.org.nvmexpress:uuid:"+uuid.NewString(), "", t.TempDir(), "")
	go func() {
		if err := driver.Serve(endpoint, &driver.IdentityServer{}, cs, ns); err != nil {
			t.Errorf("serve: %v", err)
		}
	}()

	cfg := sanity.NewTestConfig()
	cfg.Address = endpoint
	cfg.IDGen = nqnIDs{}
	// The pool is a StorageClass choice; sanity's CreateVolume calls carry it
	// the same way a real class would.
	cfg.TestVolumeParameters = map[string]string{"datasetParent": "tank/csi"}
	sanity.Test(t, cfg)
}
