// The greendot CSI controller: translates CSI's controller rpcs into
// greendotctl's typed helper rpcs over the SSH pipe. This file is greendot
// original work (upstream csi-driver-nvmf ships only Unimplemented stubs
// here). SPDX-License-Identifier: Apache-2.0
//
// Naming is deterministic so every rpc is retry-idempotent:
//
//	volume_id  = the CSI volume name (external-provisioner's pvc-<uuid>)
//	dataset    = <DatasetParent>/<volume_id>
//	nqn        = CSINQNPrefix + <volume_id>
//	device_uuid= uuid5(ns, nqn)  — pinned target-side, so the node resolves
//	             /dev/disk/by-id/nvme-uuid.<uuid> with no read-back rpc
//
// Fencing: CreateVolume exports closed (allow_any_host=0, empty ACL);
// ControllerPublishVolume grants exactly the attaching node's host NQN, and
// ControllerUnpublishVolume runs the daemon's three-step fence (ACL revoke →
// port sever → relink), which also kills the node's live controllers.
package driver

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ControllerConfig wires the controller to one greendot box.
type ControllerConfig struct {
	// DatasetParent is the ZFS dataset volumes are created under, e.g.
	// tank/csi. It must already exist.
	DatasetParent string
	// TrAddr is the address initiators connect to (the box's RDMA/TCP IP).
	TrAddr string
	// TrSvcID is the CSI port's service id (default 4421 — deliberately not
	// greendot-web's 4420; the CSI port is a separate nvmet port).
	TrSvcID uint32
	// Transport is "rdma" or "tcp".
	Transport string
}

// The uuid5 namespace for device_uuid derivation. Never change this: it would
// re-derive every existing volume's uuid and orphan their by-id paths.
var uuidNamespace = uuid.NewSHA1(uuid.NameSpaceURL, []byte("greendotrdma-csi"))

// Volume names become dataset components, NQN suffixes, and connector file
// names; this is the client-side twin of the daemon's newtype validators.
var volumeNameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

type ControllerServer struct {
	csi.UnimplementedControllerServer
	cfg ControllerConfig
	// The generated client interface, not helper.Client, so tests inject a
	// fake without a daemon.
	helper helperpb.HelperClient
}

func NewControllerServer(cfg ControllerConfig, h helperpb.HelperClient) (*ControllerServer, error) {
	if cfg.DatasetParent == "" || cfg.TrAddr == "" {
		return nil, fmt.Errorf("controller needs --dataset-parent and --traddr")
	}
	if cfg.Transport != "rdma" && cfg.Transport != "tcp" {
		return nil, fmt.Errorf("transport must be rdma or tcp, got %q", cfg.Transport)
	}
	if cfg.TrSvcID == 0 {
		cfg.TrSvcID = 4421
	}
	return &ControllerServer{cfg: cfg, helper: h}, nil
}

func (cs *ControllerServer) dataset(volID string) string {
	return cs.cfg.DatasetParent + "/" + volID
}

func (cs *ControllerServer) nqn(volID string) string {
	return CSINQNPrefix + volID
}

// DeviceUUID is the pinned nvmet namespace uuid for a volume — deterministic,
// so retries re-apply the same identity.
func DeviceUUID(nqn string) string {
	return uuid.NewSHA1(uuidNamespace, []byte(nqn)).String()
}

func (cs *ControllerServer) transport() helperpb.Transport {
	if cs.cfg.Transport == "tcp" {
		return helperpb.Transport_TRANSPORT_TCP
	}
	return helperpb.Transport_TRANSPORT_RDMA
}

// checkVolumeName gates every rpc that derives names from a volume id.
func checkVolumeName(name string) error {
	if !volumeNameRe.MatchString(name) {
		return status.Errorf(codes.InvalidArgument, "invalid volume name %q", name)
	}
	return nil
}

// checkCapabilities admits only single-node access modes — RWO/RWOP is what
// per-node NQN fencing can actually guarantee.
func checkCapabilities(caps []*csi.VolumeCapability) error {
	if len(caps) == 0 {
		return status.Error(codes.InvalidArgument, "volume capabilities are required")
	}
	for _, c := range caps {
		switch c.GetAccessMode().GetMode() {
		case csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_READER_ONLY,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_SINGLE_WRITER,
			csi.VolumeCapability_AccessMode_SINGLE_NODE_MULTI_WRITER:
		default:
			return status.Errorf(codes.InvalidArgument,
				"unsupported access mode %s (single-node only)", c.GetAccessMode().GetMode())
		}
	}
	return nil
}

func (cs *ControllerServer) CreateVolume(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	name := req.GetName()
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	if err := checkCapabilities(req.GetVolumeCapabilities()); err != nil {
		return nil, err
	}
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if capacity == 0 {
		capacity = 1 << 30
	}
	dataset := cs.dataset(name)
	nqn := cs.nqn(name)

	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: dataset})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	switch {
	case info.Exists && info.SizeBytes != uint64(capacity):
		// The name exists with a different size: a genuinely different
		// request, per CSI's idempotency contract.
		return nil, status.Errorf(codes.AlreadyExists,
			"volume %s exists with size %d (requested %d)", name, info.SizeBytes, capacity)
	case info.Exists:
		// Retry after a partial create: the zvol is there; fall through to
		// re-apply the export (heals a failed CsiNvmeApply).
	case req.GetVolumeContentSource().GetSnapshot() != nil:
		srcDataset, snap, err := cs.parseSnapshotID(req.GetVolumeContentSource().GetSnapshot().GetSnapshotId())
		if err != nil {
			// A malformed source id cannot name an existing snapshot.
			return nil, status.Errorf(codes.NotFound, "source snapshot: %v", err)
		}
		size := uint64(capacity)
		stream, err := cs.helper.ZfsClone(ctx, &helperpb.ZfsClone{
			Dataset: srcDataset, Snap: snap, Target: dataset, NewSize: &size,
		})
		res, err := helper.RunTask("ZfsClone", stream, err)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if res.Failed() && res.Mentions("does not exist") {
			return nil, status.Errorf(codes.NotFound, "source snapshot: %s", res.Error)
		}
		if err := res.Err("cloning " + dataset); err != nil {
			return nil, err
		}
	default:
		create := &helperpb.ZvolCreate{Dataset: dataset, Size: uint64(capacity)}
		if v := req.GetParameters()["volblocksize"]; v != "" {
			var vbs uint32
			if _, err := fmt.Sscanf(v, "%d", &vbs); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "bad volblocksize %q", v)
			}
			create.Volblocksize = &vbs
		}
		create.Sparse = req.GetParameters()["sparse"] == "true"
		stream, err := cs.helper.ZvolCreate(ctx, create)
		res, err := helper.RunTask("ZvolCreate", stream, err)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if err := res.Err("creating " + dataset); err != nil {
			return nil, err
		}
	}

	stream, err := cs.helper.CsiNvmeApply(ctx, &helperpb.CsiNvmeApply{
		Nqn:        nqn,
		DevicePath: "/dev/zvol/" + dataset,
		DeviceUuid: DeviceUUID(nqn),
		Traddr:     cs.cfg.TrAddr,
		Trsvcid:    cs.cfg.TrSvcID,
		Transport:  cs.transport(),
	})
	res, err := helper.RunTask("CsiNvmeApply", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("exporting " + nqn); err != nil {
		return nil, err
	}

	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      name,
		CapacityBytes: capacity,
		ContentSource: req.GetVolumeContentSource(),
		// The stock csi-driver-nvmf volume_context keys, so the node half
		// stays wire-compatible with upstream.
		VolumeContext: map[string]string{
			"targetTrAddr": cs.cfg.TrAddr,
			"targetTrPort": fmt.Sprintf("%d", cs.cfg.TrSvcID),
			"targetTrType": cs.cfg.Transport,
			"nqn":          nqn,
			"deviceUUID":   DeviceUUID(nqn),
		},
	}}, nil
}

func (cs *ControllerServer) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	name := req.GetVolumeId()
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id is required")
	}
	if checkVolumeName(name) != nil {
		// A malformed id can never have been created here — per CSI,
		// deleting a volume that does not exist succeeds.
		return &csi.DeleteVolumeResponse{}, nil
	}
	// Export first (frees the zvol), then the zvol. Both absent-tolerant.
	stream, err := cs.helper.CsiNvmeDelete(ctx, &helperpb.CsiNvmeDelete{Nqn: cs.nqn(name)})
	res, err := helper.RunTask("CsiNvmeDelete", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("deleting export"); err != nil {
		return nil, err
	}
	zstream, err := cs.helper.ZvolDelete(ctx, &helperpb.ZvolDelete{Dataset: cs.dataset(name)})
	res, err = helper.RunTask("ZvolDelete", zstream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() {
		switch {
		case res.Mentions("does not exist"):
			// Retry after a completed delete: success.
		case res.Mentions("has children"),
			res.Mentions("snapshot"):
			// Snapshots (or clones of them) pin the zvol; surface the zfs
			// error verbatim (no zfs promote in v1 — a deliberate gap).
			return nil, status.Errorf(codes.FailedPrecondition, "deleting %s: %s", cs.dataset(name), res.Error)
		default:
			return nil, res.Err("deleting " + cs.dataset(name))
		}
	}
	return &csi.DeleteVolumeResponse{}, nil
}

// ControllerPublishVolume grants the attaching node's host NQN. node_id IS
// the hostnqn (the DaemonSet passes --nodeid="$(cat /etc/nvme/hostnqn)"), so
// no side-channel mapping exists to go stale.
func (cs *ControllerServer) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	name, node := req.GetVolumeId(), req.GetNodeId()
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	}
	if err := checkCapabilities([]*csi.VolumeCapability{req.GetVolumeCapability()}); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(node, "nqn.") {
		return nil, status.Errorf(codes.InvalidArgument,
			"node id %q is not a host NQN — the node plugin must run with --nodeid from /etc/nvme/hostnqn", node)
	}
	stream, err := cs.helper.CsiHostGrant(ctx, &helperpb.CsiHostGrant{
		Nqn: cs.nqn(name), Hostnqn: node,
	})
	res, err := helper.RunTask("CsiHostGrant", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() && res.Mentions("does not exist") {
		return nil, status.Errorf(codes.NotFound, "volume %s has no export: %s", name, res.Error)
	}
	if err := res.Err("granting " + node); err != nil {
		return nil, err
	}
	return &csi.ControllerPublishVolumeResponse{}, nil
}

// ControllerUnpublishVolume is the fence. It runs against the *storage*, so
// it works exactly when it matters: the node is unreachable and Kubernetes is
// detaching the volume out from under it.
func (cs *ControllerServer) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	name, node := req.GetVolumeId(), req.GetNodeId()
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	if !strings.HasPrefix(node, "nqn.") {
		return nil, status.Errorf(codes.InvalidArgument, "node id %q is not a host NQN", node)
	}
	stream, err := cs.helper.CsiHostRevoke(ctx, &helperpb.CsiHostRevoke{
		Nqn: cs.nqn(name), Hostnqn: node,
	})
	res, err := helper.RunTask("CsiHostRevoke", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("fencing " + node); err != nil {
		return nil, err
	}
	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

func (cs *ControllerServer) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	name := req.GetVolumeId()
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if capacity <= 0 {
		return nil, status.Error(codes.InvalidArgument, "expansion needs a required capacity")
	}
	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: cs.dataset(name)})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "volume %s not found", name)
	}
	if info.SizeBytes < uint64(capacity) {
		stream, err := cs.helper.CsiVolumeExpand(ctx, &helperpb.CsiVolumeExpand{
			Nqn: cs.nqn(name), NewSize: uint64(capacity),
		})
		res, err := helper.RunTask("CsiVolumeExpand", stream, err)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if err := res.Err("expanding " + name); err != nil {
			return nil, err
		}
	}
	return &csi.ControllerExpandVolumeResponse{
		CapacityBytes: capacity,
		// The filesystem still has to grow on the node.
		NodeExpansionRequired: true,
	}, nil
}

// Snapshot ids are "<volume_id>@<snap>", directly the zfs name.
func (cs *ControllerServer) parseSnapshotID(id string) (dataset, snap string, err error) {
	vol, snap, ok := strings.Cut(id, "@")
	if !ok || checkVolumeName(vol) != nil || checkVolumeName(snap) != nil {
		return "", "", status.Errorf(codes.InvalidArgument, "invalid snapshot id %q", id)
	}
	return cs.dataset(vol), snap, nil
}

func (cs *ControllerServer) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	vol, name := req.GetSourceVolumeId(), req.GetName()
	if err := checkVolumeName(vol); err != nil {
		return nil, err
	}
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	stream, err := cs.helper.SnapshotCreate(ctx, &helperpb.SnapshotCreate{
		Dataset: cs.dataset(vol), Snap: name,
	})
	res, err := helper.RunTask("SnapshotCreate", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	// A retried create finds the snapshot already there — success. (The
	// stringly seam documented in the plan; zfs has no create-if-absent.)
	if res.Failed() {
		switch {
		case res.Mentions("already exists"):
		case res.Mentions("does not exist"):
			return nil, status.Errorf(codes.NotFound, "source volume %s: %s", vol, res.Error)
		default:
			return nil, res.Err("snapshotting " + vol)
		}
	}
	return &csi.CreateSnapshotResponse{Snapshot: &csi.Snapshot{
		SnapshotId:     vol + "@" + name,
		SourceVolumeId: vol,
		CreationTime:   timestamppb.Now(),
		ReadyToUse:     true,
	}}, nil
}

func (cs *ControllerServer) DeleteSnapshot(ctx context.Context, req *csi.DeleteSnapshotRequest) (*csi.DeleteSnapshotResponse, error) {
	if req.GetSnapshotId() == "" {
		return nil, status.Error(codes.InvalidArgument, "snapshot id is required")
	}
	dataset, snap, err := cs.parseSnapshotID(req.GetSnapshotId())
	if err != nil {
		// A malformed id can never have been created here — per CSI,
		// deleting a snapshot that does not exist succeeds.
		return &csi.DeleteSnapshotResponse{}, nil
	}
	stream, err := cs.helper.SnapshotDestroy(ctx, &helperpb.SnapshotDestroy{
		Dataset: dataset, Snap: snap,
	})
	res, err := helper.RunTask("SnapshotDestroy", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() {
		switch {
		case res.Mentions("does not exist"),
			res.Mentions("could not find"):
			// Already gone: success.
		case res.Mentions("clone"):
			return nil, status.Errorf(codes.FailedPrecondition, "deleting snapshot: %s", res.Error)
		default:
			return nil, res.Err("deleting snapshot")
		}
	}
	return &csi.DeleteSnapshotResponse{}, nil
}

func (cs *ControllerServer) ValidateVolumeCapabilities(ctx context.Context, req *csi.ValidateVolumeCapabilitiesRequest) (*csi.ValidateVolumeCapabilitiesResponse, error) {
	name := req.GetVolumeId()
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: cs.dataset(name)})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "volume %s not found", name)
	}
	if len(req.GetVolumeCapabilities()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "volume capabilities are required")
	}
	if err := checkCapabilities(req.GetVolumeCapabilities()); err != nil {
		// Present but unsupported: an unconfirmed (not error) response.
		return &csi.ValidateVolumeCapabilitiesResponse{Message: err.Error()}, nil
	}
	return &csi.ValidateVolumeCapabilitiesResponse{
		Confirmed: &csi.ValidateVolumeCapabilitiesResponse_Confirmed{
			VolumeCapabilities: req.GetVolumeCapabilities(),
		},
	}, nil
}

func (cs *ControllerServer) ControllerGetCapabilities(ctx context.Context, req *csi.ControllerGetCapabilitiesRequest) (*csi.ControllerGetCapabilitiesResponse, error) {
	var caps []*csi.ControllerServiceCapability
	for _, c := range []csi.ControllerServiceCapability_RPC_Type{
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_VOLUME,
		csi.ControllerServiceCapability_RPC_PUBLISH_UNPUBLISH_VOLUME,
		csi.ControllerServiceCapability_RPC_EXPAND_VOLUME,
		csi.ControllerServiceCapability_RPC_CREATE_DELETE_SNAPSHOT,
	} {
		caps = append(caps, &csi.ControllerServiceCapability{
			Type: &csi.ControllerServiceCapability_Rpc{
				Rpc: &csi.ControllerServiceCapability_RPC{Type: c},
			},
		})
	}
	return &csi.ControllerGetCapabilitiesResponse{Capabilities: caps}, nil
}
