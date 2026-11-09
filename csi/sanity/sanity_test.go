//go:build sanity

// csi-sanity conformance for the controller service, backed by a stateful
// in-process fake helper (no SSH, no daemon). Run via `make sanity`, once per
// backend (-backend=zfs, -backend=lvm-thin), which skips:
//   - 'Node Service' — needs real fabrics/mounts; the NixOS VM e2e covers it;
//   - 'different source volume ID' (zfs only) — snapshot ids here are
//     <vol>@<snap>, so same-name-different-source snapshots are distinct zfs
//     objects and the cluster-unique-name conflict sanity expects cannot be
//     detected without a list rpc (documented design gap). A thin-LVM
//     snapshot is a VG-wide LV name, so lvm-thin detects it;
//   - 'should fail when the node does not exist' — a node IS its host NQN
//     here; any well-formed NQN is a grantable identity, there is no node
//     registry to be absent from.
package sanity_test

import (
	"context"
	"flag"
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
	"google.golang.org/protobuf/proto"
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

var backend = flag.String("backend", "zfs", "volume backend under test: zfs or lvm-thin")

// statefulHelper emulates the daemon's zvol/LV/snapshot/export semantics —
// including the error strings the controller's idempotency mapping keys on.
type statefulHelper struct {
	helperpb.HelperClient
	mu      sync.Mutex
	zvols   map[string]uint64
	snaps   map[string]bool
	lvs     map[string]*helperpb.LvInfoReply // "vg/lv"
	exports map[string]bool
}

func newStateful() *statefulHelper {
	return &statefulHelper{
		zvols:   map[string]uint64{},
		snaps:   map[string]bool{},
		lvs:     map[string]*helperpb.LvInfoReply{},
		exports: map[string]bool{},
	}
}

// deviceExists resolves an export's device path against the emulated zvols
// (/dev/zvol/<dataset>) and LVs (/dev/<vg>/<lv>).
func (h *statefulHelper) deviceExists(path string) bool {
	if dataset, ok := strings.CutPrefix(path, "/dev/zvol/"); ok {
		_, exists := h.zvols[dataset]
		return exists
	}
	return h.lvs[strings.TrimPrefix(path, "/dev/")] != nil
}

func lvMissing(vg, lv string) string {
	return fmt.Sprintf("Failed to find logical volume \"%s/%s\"", vg, lv)
}

func lvExists(vg, lv string) string {
	return fmt.Sprintf("Logical Volume \"%s\" already exists in volume group \"%s\"", lv, vg)
}

func (h *statefulHelper) LvInfo(ctx context.Context, in *helperpb.LvInfo, _ ...grpc.CallOption) (*helperpb.LvInfoReply, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if lv := h.lvs[in.Vg+"/"+in.Name]; lv != nil {
		return proto.Clone(lv).(*helperpb.LvInfoReply), nil
	}
	return &helperpb.LvInfoReply{}, nil
}

func (h *statefulHelper) ThinLvCreate(ctx context.Context, in *helperpb.ThinLvCreate, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lvs[in.Vg+"/"+in.Name] != nil {
		return taskResult(lvExists(in.Vg, in.Name))
	}
	h.lvs[in.Vg+"/"+in.Name] = &helperpb.LvInfoReply{Exists: true, SizeBytes: in.VirtualSize, Pool: in.Pool, Active: true}
	return taskResult("")
}

// LvDelete mirrors thin LVM: snapshots survive their origin, which then
// reads as empty.
func (h *statefulHelper) LvDelete(ctx context.Context, in *helperpb.LvDelete, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lvs[in.Vg+"/"+in.Name] == nil {
		return taskResult(lvMissing(in.Vg, in.Name))
	}
	delete(h.lvs, in.Vg+"/"+in.Name)
	for key, lv := range h.lvs {
		if strings.HasPrefix(key, in.Vg+"/") && lv.Origin == in.Name {
			lv.Origin = ""
		}
	}
	return taskResult("")
}

func (h *statefulHelper) LvResize(ctx context.Context, in *helperpb.LvResize, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	lv := h.lvs[in.Vg+"/"+in.Name]
	if lv == nil {
		return taskResult(lvMissing(in.Vg, in.Name))
	}
	lv.SizeBytes = max(lv.SizeBytes, in.NewSize)
	return taskResult("")
}

func (h *statefulHelper) LvThinSnapshot(ctx context.Context, in *helperpb.LvThinSnapshot, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	origin := h.lvs[in.Vg+"/"+in.Origin]
	if origin == nil {
		return taskResult(lvMissing(in.Vg, in.Origin))
	}
	if h.lvs[in.Vg+"/"+in.Name] != nil {
		return taskResult(lvExists(in.Vg, in.Name))
	}
	h.lvs[in.Vg+"/"+in.Name] = &helperpb.LvInfoReply{Exists: true, SizeBytes: origin.SizeBytes, Pool: origin.Pool, Origin: in.Origin}
	return taskResult("")
}

func (h *statefulHelper) LvThinClone(ctx context.Context, in *helperpb.LvThinClone, _ ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	snap := h.lvs[in.Vg+"/"+in.Snap]
	if snap == nil {
		return taskResult(lvMissing(in.Vg, in.Snap))
	}
	if h.lvs[in.Vg+"/"+in.Target] != nil {
		return taskResult(lvExists(in.Vg, in.Target))
	}
	h.lvs[in.Vg+"/"+in.Target] = &helperpb.LvInfoReply{
		Exists: true, SizeBytes: max(snap.SizeBytes, in.GetNewSize()), Pool: snap.Pool, Origin: in.Snap, Active: true,
	}
	return taskResult("")
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
	if !h.deviceExists(in.Export.DevicePath) {
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
	if !h.deviceExists(in.DevicePath) {
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
	// A managed NQN token is lvm1-<vg>:<lv>, or the dataset path with ':'
	// separators.
	token := strings.TrimPrefix(in.Nqn, driver.CSINQNPrefix)
	if rest, ok := strings.CutPrefix(token, "lvm1-"); ok {
		lv := h.lvs[strings.Replace(rest, ":", "/", 1)]
		if lv == nil {
			return taskResult("namespace is not backed by the managed volume")
		}
		lv.SizeBytes = max(lv.SizeBytes, in.NewSize)
		return taskResult("")
	}
	dataset := strings.ReplaceAll(token, ":", "/")
	if _, ok := h.zvols[dataset]; !ok {
		return taskResult("subsystem has no zvol-backed namespace")
	}
	h.zvols[dataset] = in.NewSize
	return taskResult("")
}

// nqnIDs makes sanity's generated node ids valid host NQNs (the controller
// refuses anything else — fencing needs a real identity), and its volume ids
// valid ids of the backend under test.
type nqnIDs struct{ volumePrefix string }

func (ids nqnIDs) GenerateUniqueValidVolumeID() string {
	return ids.volumePrefix + "sanity-" + uuid.NewString()
}
func (nqnIDs) GenerateInvalidVolumeID() string { return "../invalid" }
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
	// The pool is a StorageClass choice; sanity's CreateVolume calls carry it
	// the same way a real class would.
	switch *backend {
	case "zfs":
		cfg.IDGen = nqnIDs{volumePrefix: "tank:csi:"}
		cfg.TestVolumeParameters = map[string]string{"datasetParent": "tank/csi"}
	case "lvm-thin":
		cfg.IDGen = nqnIDs{volumePrefix: "lvm1-vg0:"}
		cfg.TestVolumeParameters = map[string]string{"backend": "lvm-thin", "volumeGroup": "vg0", "thinPool": "pool0"}
	default:
		t.Fatalf("unknown -backend %q", *backend)
	}
	sanity.Test(t, cfg)
}
