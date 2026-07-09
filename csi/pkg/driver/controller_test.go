package driver

import (
	"context"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// fakeTaskStream replays a canned task: subtask + Finished.
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

// fakeHelper answers the handful of rpcs the controller uses, records the
// call order and requests, and fails ops listed in `fail`. The embedded nil
// interface makes any unexpected rpc panic loudly.
type fakeHelper struct {
	helperpb.HelperClient
	calls []string
	reqs  map[string]any
	fail  map[string]string // op -> Finished error
	zvol  *helperpb.ZvolInfoReply
}

func newFake() *fakeHelper {
	return &fakeHelper{
		reqs: map[string]any{},
		fail: map[string]string{},
		zvol: &helperpb.ZvolInfoReply{Exists: false},
	}
}

func (f *fakeHelper) task(op string, req any) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	f.calls = append(f.calls, op)
	f.reqs[op] = req
	st, errMsg := helperpb.SubStatus_SUB_STATUS_SUCCESS, f.fail[op]
	fin := &helperpb.Finished{Status: st}
	if errMsg != "" {
		fin.Status = helperpb.SubStatus_SUB_STATUS_FAILED
		fin.Error = &errMsg
	}
	return &fakeTaskStream{events: []*helperpb.TaskEvent{
		{Event: &helperpb.TaskEvent_Finished{Finished: fin}},
	}}, nil
}

func (f *fakeHelper) ZvolInfo(ctx context.Context, in *helperpb.ZvolInfo, opts ...grpc.CallOption) (*helperpb.ZvolInfoReply, error) {
	f.calls = append(f.calls, "ZvolInfo")
	f.reqs["ZvolInfo"] = in
	return f.zvol, nil
}

func (f *fakeHelper) ZvolCreate(ctx context.Context, in *helperpb.ZvolCreate, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("ZvolCreate", in)
}

func (f *fakeHelper) ZvolDelete(ctx context.Context, in *helperpb.ZvolDelete, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("ZvolDelete", in)
}

func (f *fakeHelper) ZfsClone(ctx context.Context, in *helperpb.ZfsClone, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("ZfsClone", in)
}

func (f *fakeHelper) CsiNvmeApply(ctx context.Context, in *helperpb.CsiNvmeApply, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiNvmeApply", in)
}

func (f *fakeHelper) CsiNvmeDelete(ctx context.Context, in *helperpb.CsiNvmeDelete, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiNvmeDelete", in)
}

func (f *fakeHelper) CsiHostGrant(ctx context.Context, in *helperpb.CsiHostGrant, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiHostGrant", in)
}

func (f *fakeHelper) CsiHostRevoke(ctx context.Context, in *helperpb.CsiHostRevoke, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiHostRevoke", in)
}

func (f *fakeHelper) CsiVolumeExpand(ctx context.Context, in *helperpb.CsiVolumeExpand, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiVolumeExpand", in)
}

func (f *fakeHelper) SnapshotCreate(ctx context.Context, in *helperpb.SnapshotCreate, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("SnapshotCreate", in)
}

func (f *fakeHelper) SnapshotDestroy(ctx context.Context, in *helperpb.SnapshotDestroy, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("SnapshotDestroy", in)
}

func testController(t *testing.T, f *fakeHelper) *ControllerServer {
	t.Helper()
	cs, err := NewControllerServer(ControllerConfig{
		DatasetParent: "tank/csi", TrAddr: "10.0.0.5", Transport: "rdma",
	}, f)
	if err != nil {
		t.Fatal(err)
	}
	return cs
}

func rwoCaps() []*csi.VolumeCapability {
	return []*csi.VolumeCapability{{
		AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
		AccessMode: &csi.VolumeCapability_AccessMode{
			Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
	}}
}

func wantCode(t *testing.T, err error, code codes.Code) {
	t.Helper()
	if code == codes.OK {
		if err != nil {
			t.Fatalf("expected success, got %v", err)
		}
		return
	}
	if st, ok := status.FromError(err); !ok || st.Code() != code {
		t.Fatalf("expected %v, got %v", code, err)
	}
}

// The CreateVolume decision table: fresh create, idempotent retry (zvol
// exists, same size — export still re-applied), size conflict, clone from
// snapshot, a failed export, a custom zvolName, and importing a preexisting
// zvol (adopt, never create). Blank want* fields default to the pvc-1 case.
func TestCreateVolumeDecisions(t *testing.T) {
	imported := encodeImportID("tank/legacy/db")
	cases := []struct {
		name        string
		params      map[string]string
		zvol        *helperpb.ZvolInfoReply
		source      *csi.VolumeContentSource
		failOp      string
		wantCode    codes.Code
		wantCalls   []string
		wantVolID   string // response VolumeId, default "pvc-1"
		wantDataset string // backing dataset, default "tank/csi/pvc-1"
		wantToken   string // nqn suffix, default "pvc-1"
		wantBytes   int64  // response CapacityBytes, default 10<<30
	}{
		{
			name:      "fresh volume: create + apply",
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZvolCreate", "CsiNvmeApply"},
		},
		{
			name:      "retry with matching size skips create but re-applies (heals a partial create)",
			zvol:      &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 10 << 30},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "CsiNvmeApply"},
		},
		{
			name:      "size conflict is AlreadyExists",
			zvol:      &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 5 << 30},
			wantCode:  codes.AlreadyExists,
			wantCalls: []string{"ZvolInfo"},
		},
		{
			name: "from snapshot clones instead of creating",
			zvol: &helperpb.ZvolInfoReply{Exists: false},
			source: &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{
				Snapshot: &csi.VolumeContentSource_SnapshotSource{SnapshotId: "pvc-src@snap1"},
			}},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZfsClone", "CsiNvmeApply"},
		},
		{
			name:      "failed export surfaces as Internal",
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			failOp:    "CsiNvmeApply",
			wantCode:  codes.Internal,
			wantCalls: []string{"ZvolInfo", "ZvolCreate", "CsiNvmeApply"},
		},
		{
			name:        "zvolName overrides the leaf",
			params:      map[string]string{"zvolName": "myvol"},
			zvol:        &helperpb.ZvolInfoReply{Exists: false},
			wantCode:    codes.OK,
			wantCalls:   []string{"ZvolInfo", "ZvolCreate", "CsiNvmeApply"},
			wantVolID:   "myvol",
			wantDataset: "tank/csi/myvol",
			wantToken:   "myvol",
		},
		{
			name:        "importDataset adopts an existing zvol (no create), size adopted",
			params:      map[string]string{"importDataset": "tank/legacy/db"},
			zvol:        &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 20 << 30},
			wantCode:    codes.OK,
			wantCalls:   []string{"ZvolInfo", "CsiNvmeApply"},
			wantVolID:   imported,
			wantDataset: "tank/legacy/db",
			wantToken:   imported,
			wantBytes:   20 << 30,
		},
		{
			name:      "importDataset with a missing target is NotFound",
			params:    map[string]string{"importDataset": "tank/legacy/db"},
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.NotFound,
			wantCalls: []string{"ZvolInfo"},
		},
		{
			name:      "importDataset smaller than the request is OutOfRange",
			params:    map[string]string{"importDataset": "tank/legacy/db"},
			zvol:      &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 5 << 30},
			wantCode:  codes.OutOfRange,
			wantCalls: []string{"ZvolInfo"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.zvol = tc.zvol
			if tc.failOp != "" {
				f.fail[tc.failOp] = "boom"
			}
			cs := testController(t, f)
			resp, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
				Name:                "pvc-1",
				Parameters:          tc.params,
				CapacityRange:       &csi.CapacityRange{RequiredBytes: 10 << 30},
				VolumeCapabilities:  rwoCaps(),
				VolumeContentSource: tc.source,
			})
			wantCode(t, err, tc.wantCode)
			if !slices.Equal(f.calls, tc.wantCalls) {
				t.Fatalf("calls = %v, want %v", f.calls, tc.wantCalls)
			}
			if tc.wantCode != codes.OK {
				return
			}
			wantVolID, wantDataset := orDefault(tc.wantVolID, "pvc-1"), orDefault(tc.wantDataset, "tank/csi/pvc-1")
			wantToken, wantBytes := orDefault(tc.wantToken, "pvc-1"), tc.wantBytes
			if wantBytes == 0 {
				wantBytes = 10 << 30
			}
			if resp.Volume.VolumeId != wantVolID || resp.Volume.CapacityBytes != wantBytes {
				t.Fatalf("bad volume: id=%q cap=%d", resp.Volume.VolumeId, resp.Volume.CapacityBytes)
			}
			apply := f.reqs["CsiNvmeApply"].(*helperpb.CsiNvmeApply)
			if apply.Nqn != CSINQNPrefix+wantToken ||
				apply.DevicePath != "/dev/zvol/"+wantDataset ||
				apply.DeviceUuid != DeviceUUID(apply.Nqn) ||
				apply.Trsvcid != 4421 {
				t.Fatalf("bad apply request: %+v", apply)
			}
			vc := resp.Volume.VolumeContext
			if vc["nqn"] != apply.Nqn || vc["deviceUUID"] != apply.DeviceUuid ||
				vc["targetTrPort"] != "4421" || vc["targetTrType"] != "rdma" {
				t.Fatalf("bad volume context: %v", vc)
			}
			if tc.source != nil {
				clone := f.reqs["ZfsClone"].(*helperpb.ZfsClone)
				if clone.Dataset != "tank/csi/pvc-src" || clone.Snap != "snap1" ||
					clone.Target != "tank/csi/pvc-1" || clone.NewSize == nil {
					t.Fatalf("bad clone request: %+v", clone)
				}
			}
		})
	}
}

func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// resolveVolumeID inverts CreateVolume's ids: bare names map under DatasetParent,
// imp1- ids decode to an adopted path, and corrupt/empty ids error.
func TestResolveVolumeID(t *testing.T) {
	cs := testController(t, newFake())
	imp := encodeImportID("tank/legacy/db")
	cases := []struct {
		id           string
		wantErr      bool
		wantDataset  string
		wantToken    string
		wantImported bool
	}{
		{id: "pvc-abc", wantDataset: "tank/csi/pvc-abc", wantToken: "pvc-abc"},
		{id: imp, wantDataset: "tank/legacy/db", wantToken: imp, wantImported: true},
		{id: "", wantErr: true},
		{id: "../etc", wantErr: true},
		{id: "imp1-!!!", wantErr: true}, // undecodable suffix
	}
	for _, tc := range cases {
		ref, err := cs.resolveVolumeID(tc.id)
		if tc.wantErr {
			if err == nil {
				t.Fatalf("resolveVolumeID(%q) = %+v, want error", tc.id, ref)
			}
			continue
		}
		if err != nil {
			t.Fatalf("resolveVolumeID(%q): %v", tc.id, err)
		}
		if ref.dataset != tc.wantDataset || ref.nqnToken != tc.wantToken || ref.imported != tc.wantImported {
			t.Fatalf("resolveVolumeID(%q) = %+v", tc.id, ref)
		}
	}
}

// The safety invariant: deleting an imported volume tears down the export but
// never runs ZvolDelete against the adopted zvol.
func TestDeleteImportedNeverDestroysZvol(t *testing.T) {
	f := newFake()
	cs := testController(t, f)
	imp := encodeImportID("tank/legacy/db")
	_, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: imp})
	wantCode(t, err, codes.OK)
	if !slices.Equal(f.calls, []string{"CsiNvmeDelete"}) {
		t.Fatalf("imported delete must tear down only the export, got %v", f.calls)
	}
	if del := f.reqs["CsiNvmeDelete"].(*helperpb.CsiNvmeDelete); del.Nqn != CSINQNPrefix+imp {
		t.Fatalf("bad delete nqn %q", del.Nqn)
	}
}

// Publish/unpublish: node_id must be a host NQN and lands verbatim in the
// grant/revoke; a missing export maps to NotFound on publish.
func TestPublishUnpublishFencing(t *testing.T) {
	hostnqn := "nqn.2014-08.org.nvmexpress:uuid:aaaa"
	f := newFake()
	cs := testController(t, f)

	_, err := cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{
		VolumeId: "pvc-1", NodeId: "worker-1", VolumeCapability: rwoCaps()[0],
	})
	wantCode(t, err, codes.InvalidArgument) // not an NQN: fencing impossible

	_, err = cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{
		VolumeId: "pvc-1", NodeId: hostnqn, VolumeCapability: rwoCaps()[0],
	})
	wantCode(t, err, codes.OK)
	grant := f.reqs["CsiHostGrant"].(*helperpb.CsiHostGrant)
	if grant.Nqn != CSINQNPrefix+"pvc-1" || grant.Hostnqn != hostnqn {
		t.Fatalf("bad grant: %+v", grant)
	}

	// An imported id grants against its encoded nqn token, unchanged fencing.
	imp := encodeImportID("tank/legacy/db")
	_, err = cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{
		VolumeId: imp, NodeId: hostnqn, VolumeCapability: rwoCaps()[0],
	})
	wantCode(t, err, codes.OK)
	if grant = f.reqs["CsiHostGrant"].(*helperpb.CsiHostGrant); grant.Nqn != CSINQNPrefix+imp {
		t.Fatalf("imported grant nqn = %q", grant.Nqn)
	}

	f.fail["CsiHostGrant"] = "subsystem nqn.2026-06.io.greendot.csi:pvc-9 does not exist"
	_, err = cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{
		VolumeId: "pvc-9", NodeId: hostnqn, VolumeCapability: rwoCaps()[0],
	})
	wantCode(t, err, codes.NotFound)

	_, err = cs.ControllerUnpublishVolume(context.Background(), &csi.ControllerUnpublishVolumeRequest{
		VolumeId: "pvc-1", NodeId: hostnqn,
	})
	wantCode(t, err, codes.OK)
	revoke := f.reqs["CsiHostRevoke"].(*helperpb.CsiHostRevoke)
	if revoke.Hostnqn != hostnqn {
		t.Fatalf("bad revoke: %+v", revoke)
	}
}

// Delete tolerates already-gone, blocks on snapshot entanglement; expand
// no-ops when the zvol is already big enough.
func TestDeleteAndExpandEdgeCases(t *testing.T) {
	t.Run("delete: missing zvol is success", func(t *testing.T) {
		f := newFake()
		f.fail["ZvolDelete"] = "cannot open 'tank/csi/pvc-1': dataset does not exist"
		cs := testController(t, f)
		_, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: "pvc-1"})
		wantCode(t, err, codes.OK)
		if !slices.Equal(f.calls, []string{"CsiNvmeDelete", "ZvolDelete"}) {
			t.Fatalf("calls = %v", f.calls)
		}
	})
	t.Run("delete: snapshots pin the volume", func(t *testing.T) {
		f := newFake()
		f.fail["ZvolDelete"] = "cannot destroy 'tank/csi/pvc-1': volume has children\nuse '-r' to destroy the following datasets:\ntank/csi/pvc-1@snap1"
		cs := testController(t, f)
		_, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: "pvc-1"})
		wantCode(t, err, codes.FailedPrecondition)
	})
	t.Run("expand: no-op when already big enough", func(t *testing.T) {
		f := newFake()
		f.zvol = &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 20 << 30}
		cs := testController(t, f)
		resp, err := cs.ControllerExpandVolume(context.Background(), &csi.ControllerExpandVolumeRequest{
			VolumeId:      "pvc-1",
			CapacityRange: &csi.CapacityRange{RequiredBytes: 10 << 30},
		})
		wantCode(t, err, codes.OK)
		if slices.Contains(f.calls, "CsiVolumeExpand") {
			t.Fatal("expand rpc must not run when already satisfied")
		}
		if !resp.NodeExpansionRequired {
			t.Fatal("node expansion must still be requested")
		}
	})
	t.Run("expand: grows through CsiVolumeExpand", func(t *testing.T) {
		f := newFake()
		f.zvol = &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 10 << 30}
		cs := testController(t, f)
		_, err := cs.ControllerExpandVolume(context.Background(), &csi.ControllerExpandVolumeRequest{
			VolumeId:      "pvc-1",
			CapacityRange: &csi.CapacityRange{RequiredBytes: 20 << 30},
		})
		wantCode(t, err, codes.OK)
		expand := f.reqs["CsiVolumeExpand"].(*helperpb.CsiVolumeExpand)
		if expand.NewSize != 20<<30 {
			t.Fatalf("bad expand: %+v", expand)
		}
	})
}

// Snapshots: create is retry-tolerant of "already exists"; delete tolerates
// absence and surfaces clone entanglement.
func TestSnapshotLifecycle(t *testing.T) {
	f := newFake()
	cs := testController(t, f)
	resp, err := cs.CreateSnapshot(context.Background(), &csi.CreateSnapshotRequest{
		SourceVolumeId: "pvc-1", Name: "snapshot-abc",
	})
	wantCode(t, err, codes.OK)
	if resp.Snapshot.SnapshotId != "pvc-1@snapshot-abc" {
		t.Fatalf("bad snapshot id %q", resp.Snapshot.SnapshotId)
	}

	f.fail["SnapshotCreate"] = "cannot create snapshot: dataset already exists"
	_, err = cs.CreateSnapshot(context.Background(), &csi.CreateSnapshotRequest{
		SourceVolumeId: "pvc-1", Name: "snapshot-abc",
	})
	wantCode(t, err, codes.OK)

	f.fail["SnapshotDestroy"] = "could not find any snapshots to destroy"
	_, err = cs.DeleteSnapshot(context.Background(), &csi.DeleteSnapshotRequest{
		SnapshotId: "pvc-1@snapshot-abc",
	})
	wantCode(t, err, codes.OK)

	f.fail["SnapshotDestroy"] = "snapshot has dependent clones"
	_, err = cs.DeleteSnapshot(context.Background(), &csi.DeleteSnapshotRequest{
		SnapshotId: "pvc-1@snapshot-abc",
	})
	wantCode(t, err, codes.FailedPrecondition)

	// A malformed id can never have been created here: per CSI, deleting a
	// nonexistent snapshot succeeds — and no rpc may run for it.
	before := len(f.calls)
	_, err = cs.DeleteSnapshot(context.Background(), &csi.DeleteSnapshotRequest{
		SnapshotId: "../../etc@x",
	})
	wantCode(t, err, codes.OK)
	if len(f.calls) != before {
		t.Fatalf("no rpc may run for a malformed snapshot id, got %v", f.calls[before:])
	}
}

// Volume names that would traverse datasets/NQNs are rejected before any rpc.
func TestNameValidationGatesEveryRPC(t *testing.T) {
	f := newFake()
	cs := testController(t, f)
	for _, bad := range []string{"", "../etc", "a/b", "a b", ".hidden", "imp1-!!!"} {
		if _, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
			Name: bad, VolumeCapabilities: rwoCaps(),
		}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("CreateVolume(%q) = %v, want InvalidArgument", bad, err)
		}
		// Delete of a malformed id succeeds without any rpc (it can never
		// have been created here); only a missing id is an argument error.
		wantDel := codes.OK
		if bad == "" {
			wantDel = codes.InvalidArgument
		}
		if _, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{
			VolumeId: bad,
		}); status.Code(err) != wantDel {
			t.Fatalf("DeleteVolume(%q) = %v, want %v", bad, err, wantDel)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("no rpc may run for invalid names, got %v", f.calls)
	}
	// RWX is refused up front: NQN fencing guarantees single-node only.
	caps := rwoCaps()
	caps[0].AccessMode.Mode = csi.VolumeCapability_AccessMode_MULTI_NODE_MULTI_WRITER
	_, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
		Name: "pvc-1", VolumeCapabilities: caps,
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "single-node") {
		t.Fatalf("RWX must be refused, got %v", err)
	}

	// The imp1- namespace is reserved for imported ids; a managed create may
	// not claim it, whether via the CSI name or zvolName.
	for _, req := range []*csi.CreateVolumeRequest{
		{Name: "imp1-abc", VolumeCapabilities: rwoCaps()},
		{Name: "pvc-1", Parameters: map[string]string{"zvolName": "imp1-abc"}, VolumeCapabilities: rwoCaps()},
	} {
		if _, err := cs.CreateVolume(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("reserved imp1- name must be refused, got %v", err)
		}
	}
}
