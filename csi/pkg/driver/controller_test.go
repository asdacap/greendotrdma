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

func (f *fakeHelper) CsiPublish(ctx context.Context, in *helperpb.CsiPublish, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiPublish", in)
}
func (f *fakeHelper) CsiUnpublish(ctx context.Context, in *helperpb.CsiUnpublish, opts ...grpc.CallOption) (grpc.ServerStreamingClient[helperpb.TaskEvent], error) {
	return f.task("CsiUnpublish", in)
}
func (f *fakeHelper) CsiAttachment(ctx context.Context, in *helperpb.CsiNvmeDelete, opts ...grpc.CallOption) (*helperpb.CsiAttachmentReply, error) {
	return &helperpb.CsiAttachmentReply{}, nil
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
	if f.fail["CsiVolumeExpand"] == "" && f.zvol.Exists && f.zvol.SizeBytes < in.NewSize {
		f.zvol.SizeBytes = in.NewSize
	}
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
		TrAddr: "10.0.0.5", Transport: "rdma", AttachmentID: "test-attachment",
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
// snapshot, a failed export, a custom zvolName, per-class pool selection, and
// importing a preexisting zvol (adopt, never create). Unless omitParent is
// set, the runner injects datasetParent=tank/csi; blank want* fields default
// to the pvc-1-on-tank/csi case.
func TestCreateVolumeDecisions(t *testing.T) {
	imported := encodeImportID("tank/legacy/db")
	cases := []struct {
		name       string
		params     map[string]string
		omitParent bool
		zvol       *helperpb.ZvolInfoReply
		source     *csi.VolumeContentSource
		failOp     string
		wantCode   codes.Code
		wantCalls  []string
		wantVolID  string // response VolumeId, default "tank:csi:pvc-1"
		wantToken  string // nqn suffix, default "tank:csi:pvc-1"
		wantBytes  int64  // response CapacityBytes, default 10<<30
	}{
		{
			name:      "fresh volume: create only (export is lazy)",
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZvolCreate"},
		},
		{
			name:      "retry with matching size skips create (export is lazy, no re-apply here)",
			zvol:      &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 10 << 30},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo"},
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
				Snapshot: &csi.VolumeContentSource_SnapshotSource{SnapshotId: "tank:csi:pvc-src@snap1"},
			}},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZfsClone"},
		},
		{
			name:      "failed create surfaces as Internal",
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			failOp:    "ZvolCreate",
			wantCode:  codes.Internal,
			wantCalls: []string{"ZvolInfo", "ZvolCreate"},
		},
		{
			name:      "zvolName overrides the leaf",
			params:    map[string]string{"zvolName": "myvol"},
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZvolCreate"},
			wantVolID: "tank:csi:myvol",
			wantToken: "tank:csi:myvol",
		},
		{
			name: "zvolName ${pvc.*} tokens expand from --extra-create-metadata params",
			params: map[string]string{
				"zvolName":                         "${pvc.namespace}-${pvc.name}",
				"csi.storage.k8s.io/pvc/namespace": "db",
				"csi.storage.k8s.io/pvc/name":      "data",
			},
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZvolCreate"},
			wantVolID: "tank:csi:db-data",
			wantToken: "tank:csi:db-data",
		},
		{
			name:     "zvolName template without provisioner metadata is InvalidArgument",
			params:   map[string]string{"zvolName": "${pvc.namespace}-${pvc.name}"},
			zvol:     &helperpb.ZvolInfoReply{Exists: false},
			wantCode: codes.InvalidArgument,
		},
		{
			name:      "datasetParent routes the volume to the class's pool",
			params:    map[string]string{"datasetParent": "bulk/csi"},
			zvol:      &helperpb.ZvolInfoReply{Exists: false},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo", "ZvolCreate"},
			wantVolID: "bulk:csi:pvc-1",
			wantToken: "bulk:csi:pvc-1",
		},
		{
			name:       "missing datasetParent is InvalidArgument",
			omitParent: true,
			zvol:       &helperpb.ZvolInfoReply{Exists: false},
			wantCode:   codes.InvalidArgument,
		},
		{
			name:      "importDataset adopts an existing zvol (no create), size adopted",
			params:    map[string]string{"importDataset": "tank/legacy/db"},
			zvol:      &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 20 << 30},
			wantCode:  codes.OK,
			wantCalls: []string{"ZvolInfo"},
			wantVolID: imported,
			wantToken: imported,
			wantBytes: 20 << 30,
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
			params := tc.params
			if !tc.omitParent {
				if params == nil {
					params = map[string]string{}
				}
				if _, ok := params["datasetParent"]; !ok {
					params["datasetParent"] = "tank/csi"
				}
			}
			cs := testController(t, f)
			resp, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
				Name:                "pvc-1",
				Parameters:          params,
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
			wantVolID := orDefault(tc.wantVolID, "tank:csi:pvc-1")
			wantToken, wantBytes := orDefault(tc.wantToken, "tank:csi:pvc-1"), tc.wantBytes
			if wantBytes == 0 {
				wantBytes = 10 << 30
			}
			if resp.Volume.VolumeId != wantVolID || resp.Volume.CapacityBytes != wantBytes {
				t.Fatalf("bad volume: id=%q cap=%d", resp.Volume.VolumeId, resp.Volume.CapacityBytes)
			}
			// CreateVolume no longer exports (the export is lazy, created at
			// ControllerPublishVolume); it still returns the node's volume
			// context so the node resolves the device with no read-back rpc.
			wantNqn := CSINQNPrefix + wantToken
			vc := resp.Volume.VolumeContext
			if vc["nqn"] != wantNqn || vc["deviceUUID"] != DeviceUUID(wantNqn) ||
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

// resolveVolumeID inverts CreateVolume's ids: managed ids are dataset paths
// with ':' separators, imp1- ids decode to an adopted path, and corrupt/empty/
// parentless ids error.
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
		{id: "tank:csi:pvc-abc", wantDataset: "tank/csi/pvc-abc", wantToken: "tank:csi:pvc-abc"},
		{id: imp, wantDataset: "tank/legacy/db", wantToken: imp, wantImported: true},
		{id: "", wantErr: true},
		{id: "../etc", wantErr: true},
		{id: "pvc-abc", wantErr: true},   // no pool component
		{id: "tank:", wantErr: true},     // empty component
		{id: "tank:.hid", wantErr: true}, // leading-dot component
		{id: "imp1-!!!", wantErr: true},  // undecodable suffix
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
	host := "nqn.2014-08.org.nvmexpress:uuid:aaaa"
	f := newFake()
	cs := testController(t, f)
	for _, tc := range []struct {
		name, node, volume string
		exists             bool
		failure            string
		code               codes.Code
	}{
		{"invalid host", "worker-1", "tank:csi:pvc-1", true, "", codes.InvalidArgument},
		{"missing volume", host, "tank:csi:missing", false, "", codes.NotFound},
		{"managed", host, "tank:csi:pvc-1", true, "", codes.OK},
		{"imported", host, encodeImportID("tank/legacy/db"), true, "", codes.OK},
		{"other owner", host, "tank:csi:pvc-1", true, "attachment conflict: volume has another owner", codes.FailedPrecondition},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.zvol.Exists = tc.exists
			f.fail["CsiPublish"] = tc.failure
			_, err := cs.ControllerPublishVolume(context.Background(), &csi.ControllerPublishVolumeRequest{VolumeId: tc.volume, NodeId: tc.node, VolumeCapability: rwoCaps()[0]})
			wantCode(t, err, tc.code)
			if tc.code == codes.OK {
				publish := f.reqs["CsiPublish"].(*helperpb.CsiPublish)
				if publish.AttachmentId != "test-attachment" || publish.Hostnqn != host || publish.Export.Nqn != CSINQNPrefix+tc.volume {
					t.Fatalf("bad publish: %v", publish)
				}
			}
		})
	}
	_, err := cs.ControllerUnpublishVolume(context.Background(), &csi.ControllerUnpublishVolumeRequest{VolumeId: "tank:csi:pvc-1", NodeId: host})
	wantCode(t, err, codes.OK)
	unpublish := f.reqs["CsiUnpublish"].(*helperpb.CsiUnpublish)
	if unpublish.AttachmentId != "test-attachment" || unpublish.Hostnqn != host {
		t.Fatalf("bad fence: %v", unpublish)
	}
}

// Delete tolerates already-gone, blocks on snapshot entanglement; expand
// no-ops when the zvol is already big enough.
func TestDeleteAndExpandEdgeCases(t *testing.T) {
	t.Run("delete: missing zvol is success", func(t *testing.T) {
		f := newFake()
		f.fail["ZvolDelete"] = "cannot open 'tank/csi/pvc-1': dataset does not exist"
		cs := testController(t, f)
		_, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: "tank:csi:pvc-1"})
		wantCode(t, err, codes.OK)
		if !slices.Equal(f.calls, []string{"CsiNvmeDelete", "ZvolDelete"}) {
			t.Fatalf("calls = %v", f.calls)
		}
	})
	t.Run("delete: snapshots pin the volume", func(t *testing.T) {
		f := newFake()
		f.fail["ZvolDelete"] = "cannot destroy 'tank/csi/pvc-1': volume has children\nuse '-r' to destroy the following datasets:\ntank/csi/pvc-1@snap1"
		cs := testController(t, f)
		_, err := cs.DeleteVolume(context.Background(), &csi.DeleteVolumeRequest{VolumeId: "tank:csi:pvc-1"})
		wantCode(t, err, codes.FailedPrecondition)
	})
	t.Run("expand: revalidate when already big enough", func(t *testing.T) {
		f := newFake()
		f.zvol = &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 20 << 30}
		cs := testController(t, f)
		resp, err := cs.ControllerExpandVolume(context.Background(), &csi.ControllerExpandVolumeRequest{
			VolumeId:      "tank:csi:pvc-1",
			CapacityRange: &csi.CapacityRange{RequiredBytes: 10 << 30},
		})
		wantCode(t, err, codes.OK)
		if !slices.Contains(f.calls, "CsiVolumeExpand") || resp.CapacityBytes != 20<<30 {
			t.Fatal("expand must revalidate and report actual capacity")
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
			VolumeId:      "tank:csi:pvc-1",
			CapacityRange: &csi.CapacityRange{RequiredBytes: 20 << 30},
		})
		wantCode(t, err, codes.OK)
		expand := f.reqs["CsiVolumeExpand"].(*helperpb.CsiVolumeExpand)
		if expand.NewSize != 20<<30 {
			t.Fatalf("bad expand: %+v", expand)
		}
	})
}

func TestExpansionRetryAfterRevalidationFailure(t *testing.T) {
	f := newFake()
	f.zvol = &helperpb.ZvolInfoReply{Exists: true, SizeBytes: 20 << 30}
	f.fail["CsiVolumeExpand"] = "revalidation interrupted after ZFS grew"
	cs := testController(t, f)
	req := &csi.ControllerExpandVolumeRequest{
		VolumeId:      "tank:csi:pvc-1",
		CapacityRange: &csi.CapacityRange{RequiredBytes: 20 << 30},
	}
	_, err := cs.ControllerExpandVolume(context.Background(), req)
	wantCode(t, err, codes.Internal)
	delete(f.fail, "CsiVolumeExpand")
	resp, err := cs.ControllerExpandVolume(context.Background(), req)
	wantCode(t, err, codes.OK)
	calls := 0
	for _, call := range f.calls {
		if call == "CsiVolumeExpand" {
			calls++
		}
		if call == "CsiPublish" || call == "CsiNvmeApply" {
			t.Fatal("expansion must not create an export")
		}
	}
	if calls != 2 || resp.CapacityBytes != 20<<30 {
		t.Fatalf("retry did not revalidate: calls=%v response=%v", f.calls, resp)
	}
}

// Snapshots: create is retry-tolerant of "already exists"; delete tolerates
// absence and surfaces clone entanglement.
func TestSnapshotLifecycle(t *testing.T) {
	f := newFake()
	cs := testController(t, f)
	resp, err := cs.CreateSnapshot(context.Background(), &csi.CreateSnapshotRequest{
		SourceVolumeId: "tank:csi:pvc-1", Name: "snapshot-abc",
	})
	wantCode(t, err, codes.OK)
	if resp.Snapshot.SnapshotId != "tank:csi:pvc-1@snapshot-abc" {
		t.Fatalf("bad snapshot id %q", resp.Snapshot.SnapshotId)
	}

	f.fail["SnapshotCreate"] = "cannot create snapshot: dataset already exists"
	_, err = cs.CreateSnapshot(context.Background(), &csi.CreateSnapshotRequest{
		SourceVolumeId: "tank:csi:pvc-1", Name: "snapshot-abc",
	})
	wantCode(t, err, codes.OK)

	// Imported volumes are not snapshottable (documented v1 gap).
	_, err = cs.CreateSnapshot(context.Background(), &csi.CreateSnapshotRequest{
		SourceVolumeId: encodeImportID("tank/legacy/db"), Name: "snapshot-abc",
	})
	wantCode(t, err, codes.FailedPrecondition)

	f.fail["SnapshotDestroy"] = "could not find any snapshots to destroy"
	_, err = cs.DeleteSnapshot(context.Background(), &csi.DeleteSnapshotRequest{
		SnapshotId: "tank:csi:pvc-1@snapshot-abc",
	})
	wantCode(t, err, codes.OK)

	f.fail["SnapshotDestroy"] = "snapshot has dependent clones"
	_, err = cs.DeleteSnapshot(context.Background(), &csi.DeleteSnapshotRequest{
		SnapshotId: "tank:csi:pvc-1@snapshot-abc",
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
	parent := map[string]string{"datasetParent": "tank/csi"}
	for _, bad := range []string{"", "../etc", "a/b", "a b", ".hidden", "imp1-!!!"} {
		if _, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{
			Name: bad, Parameters: parent, VolumeCapabilities: rwoCaps(),
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
		Name: "pvc-1", Parameters: parent, VolumeCapabilities: caps,
	})
	if status.Code(err) != codes.InvalidArgument || !strings.Contains(err.Error(), "single-node") {
		t.Fatalf("RWX must be refused, got %v", err)
	}

	// The imp1- namespace is reserved for imported ids; a managed create may
	// not claim it — via the CSI name, zvolName, or a datasetParent whose
	// pool component would make the whole id decode as imported.
	for _, req := range []*csi.CreateVolumeRequest{
		{Name: "imp1-abc", Parameters: parent, VolumeCapabilities: rwoCaps()},
		{Name: "pvc-1", Parameters: map[string]string{"datasetParent": "tank/csi", "zvolName": "imp1-abc"}, VolumeCapabilities: rwoCaps()},
		{Name: "pvc-1", Parameters: map[string]string{"datasetParent": "imp1-pool/csi"}, VolumeCapabilities: rwoCaps()},
	} {
		if _, err := cs.CreateVolume(context.Background(), req); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("reserved imp1- name must be refused, got %v", err)
		}
	}
}

func TestCreateIdentifierBoundariesAndRestoreRetry(t *testing.T) {
	for _, imported := range []bool{false, true} {
		for _, length := range []int{195, 196, 118, 119} {
			dataset := "tank/" + strings.Repeat("a", length-5)
			token := idFromDataset(dataset)
			params := map[string]string{"datasetParent": "tank", "zvolName": strings.TrimPrefix(dataset, "tank/")}
			if imported {
				token = encodeImportID(dataset)
				params = map[string]string{"importDataset": dataset}
			}
			f := newFake()
			f.zvol = &helperpb.ZvolInfoReply{Exists: imported, SizeBytes: 10 << 30}
			cs := testController(t, f)
			_, err := cs.CreateVolume(context.Background(), &csi.CreateVolumeRequest{Name: "pvc-1", Parameters: params, CapacityRange: &csi.CapacityRange{RequiredBytes: 10 << 30}, VolumeCapabilities: rwoCaps()})
			if len(CSINQNPrefix+token) > 223 {
				wantCode(t, err, codes.InvalidArgument)
				if len(f.calls) != 0 {
					t.Fatalf("oversized name touched helper: %v", f.calls)
				}
			} else {
				wantCode(t, err, codes.OK)
			}
		}
	}
	for _, size := range []uint64{5 << 30, 10 << 30} {
		f := newFake()
		f.zvol = &helperpb.ZvolInfoReply{Exists: true, SizeBytes: size}
		_, err := testController(t, f).CreateVolume(context.Background(), &csi.CreateVolumeRequest{Name: "pvc-1", Parameters: map[string]string{"datasetParent": "tank/csi"}, CapacityRange: &csi.CapacityRange{RequiredBytes: 10 << 30}, VolumeCapabilities: rwoCaps(), VolumeContentSource: &csi.VolumeContentSource{Type: &csi.VolumeContentSource_Snapshot{Snapshot: &csi.VolumeContentSource_SnapshotSource{SnapshotId: "tank:csi:source@s1"}}}})
		wantCode(t, err, codes.OK)
		clone, ok := f.reqs["ZfsClone"].(*helperpb.ZfsClone)
		if !ok || clone.GetRestoreRequestId() != "pvc-1" {
			t.Fatalf("retry must verify provenance: %v", f.calls)
		}
	}
}
