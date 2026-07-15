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
// Fencing: the export is created lazily, closed (allow_any_host=0, empty ACL),
// by ControllerPublishVolume, which then grants exactly the attaching node's
// host NQN; ControllerUnpublishVolume runs the daemon's three-step fence (ACL
// revoke → port sever → relink) — which also kills the node's live controllers
// — and then tears the export down, since the volume is no longer in use.
package driver

import (
	"context"
	"encoding/base32"
	"fmt"
	"regexp"
	"strings"
	"sync"

	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ControllerConfig wires the controller to one greendot box. Where volumes
// live is not part of it: every StorageClass names its own pool via the
// datasetParent parameter, so one controller serves any number of pools.
type ControllerConfig struct {
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

// zvolName template variables. The external-provisioner does not expand
// arbitrary StorageClass parameters, so ${...} tokens are resolved here from
// the PVC/PV metadata it passes when run with --extra-create-metadata.
var zvolNameVars = map[string]string{
	"${pvc.namespace}": "csi.storage.k8s.io/pvc/namespace",
	"${pvc.name}":      "csi.storage.k8s.io/pvc/name",
	"${pv.name}":       "csi.storage.k8s.io/pv/name",
}

func expandZvolName(tmpl string, params map[string]string) (string, error) {
	name := tmpl
	for token, key := range zvolNameVars {
		if !strings.Contains(name, token) {
			continue
		}
		v := params[key]
		if v == "" {
			return "", status.Errorf(codes.InvalidArgument,
				"zvolName %q references %s but %s was not passed — run csi-provisioner with --extra-create-metadata", tmpl, token, key)
		}
		name = strings.ReplaceAll(name, token, v)
	}
	return name, nil
}

type ControllerServer struct {
	csi.UnimplementedControllerServer
	cfg ControllerConfig
	// The generated client interface, not helper.Client, so tests inject a
	// fake without a daemon.
	helper helperpb.HelperClient

	// exported is the set of NQNs the controller currently holds an nvmet
	// export for. The reconcile GC prunes only these, so the many never-
	// attached lazy volumes cost it nothing. Guarded by exportedMu — the gRPC
	// handlers and the reconcile goroutine touch it concurrently.
	exportedMu sync.Mutex
	exported   map[string]bool
}

func NewControllerServer(cfg ControllerConfig, h helperpb.HelperClient) (*ControllerServer, error) {
	if cfg.TrAddr == "" {
		return nil, fmt.Errorf("controller needs --traddr")
	}
	if cfg.Transport != "rdma" && cfg.Transport != "tcp" {
		return nil, fmt.Errorf("transport must be rdma or tcp, got %q", cfg.Transport)
	}
	if cfg.TrSvcID == 0 {
		cfg.TrSvcID = 4421
	}
	return &ControllerServer{cfg: cfg, helper: h, exported: map[string]bool{}}, nil
}

// A managed volume id IS its dataset path with '/' replaced by ':' — readable,
// bijective (':' cannot appear inside a path component), and valid both as an
// NQN suffix and as a connector file name. The id must carry the full path
// because the pool comes from the StorageClass, and CSI hands DeleteVolume
// (and expand/publish/snapshot) only the id — never the class.
func idFromDataset(dataset string) string {
	return strings.ReplaceAll(dataset, "/", ":")
}

func datasetFromID(volID string) (string, error) {
	// A zvol always lives below a pool, so a valid id has ≥2 components.
	if !strings.Contains(volID, ":") {
		return "", status.Errorf(codes.InvalidArgument, "invalid volume id %q", volID)
	}
	dataset := strings.ReplaceAll(volID, ":", "/")
	if err := validDatasetPath(dataset); err != nil {
		return "", err
	}
	return dataset, nil
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

// importCodec encodes the full dataset path carried by an imported volume id.
// base32hex keeps the token to [a-z0-9] once lowercased — a valid NQN suffix —
// and round-trips the path bijectively.
var importCodec = base32.HexEncoding.WithPadding(base32.NoPadding)

func encodeImportID(dataset string) string {
	return importedPrefix + strings.ToLower(importCodec.EncodeToString([]byte(dataset)))
}

// volumeRef is a resolved volume id: the backing dataset, the token appended to
// CSINQNPrefix, and whether it adopts a preexisting zvol (which DeleteVolume
// must never destroy).
type volumeRef struct {
	dataset  string
	nqnToken string
	imported bool
}

func (cs *ControllerServer) nqnOf(ref *volumeRef) string {
	return CSINQNPrefix + ref.nqnToken
}

// resolveVolumeID inverts the ids CreateVolume hands out: a managed id is its
// dataset path with ':' separators (created under the StorageClass's
// datasetParent); an imp1-<base32hex> id decodes to an adopted zvol at an
// arbitrary path. The prefix is matched before the managed grammar, so a
// corrupt imported id can never be misread as managed.
func (cs *ControllerServer) resolveVolumeID(volID string) (*volumeRef, error) {
	if volID == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id is required")
	}
	if rest, ok := strings.CutPrefix(volID, importedPrefix); ok {
		raw, err := importCodec.DecodeString(strings.ToUpper(rest))
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid imported volume id %q", volID)
		}
		dataset := string(raw)
		if err := validDatasetPath(dataset); err != nil {
			return nil, err
		}
		return &volumeRef{dataset: dataset, nqnToken: volID, imported: true}, nil
	}
	dataset, err := datasetFromID(volID)
	if err != nil {
		return nil, err
	}
	return &volumeRef{dataset: dataset, nqnToken: volID, imported: false}, nil
}

// validDatasetPath is the multi-component twin of volumeNameRe: every
// slash-separated component is a valid volume name (which already forbids empty
// components and leading-dot . / .. traversal).
func validDatasetPath(path string) error {
	if path == "" {
		return status.Error(codes.InvalidArgument, "dataset path is required")
	}
	for _, comp := range strings.Split(path, "/") {
		if !volumeNameRe.MatchString(comp) {
			return status.Errorf(codes.InvalidArgument, "invalid dataset path %q", path)
		}
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
	if err := checkCapabilities(req.GetVolumeCapabilities()); err != nil {
		return nil, err
	}
	if imp := req.GetParameters()["importDataset"]; imp != "" {
		return cs.createImportedVolume(ctx, req, imp)
	}

	// zvolName lets a StorageClass pick the leaf (typically templated per PVC,
	// e.g. "${pvc.namespace}-${pvc.name}"); otherwise it is the provisioner's
	// pvc-<uuid>. The imp1- namespace is reserved for imported ids.
	name := req.GetName()
	if v := req.GetParameters()["zvolName"]; v != "" {
		expanded, err := expandZvolName(v, req.GetParameters())
		if err != nil {
			return nil, err
		}
		name = expanded
	}
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	if strings.HasPrefix(name, importedPrefix) {
		return nil, status.Errorf(codes.InvalidArgument, "volume name may not start with %q", importedPrefix)
	}
	// The pool is the StorageClass's choice, not the driver's.
	parent := req.GetParameters()["datasetParent"]
	if parent == "" {
		return nil, status.Error(codes.InvalidArgument,
			"StorageClass parameter datasetParent is required (the ZFS dataset volumes live under, e.g. tank/csi)")
	}
	if err := validDatasetPath(parent); err != nil {
		return nil, err
	}
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if capacity == 0 {
		capacity = 1 << 30
	}
	dataset := parent + "/" + name
	volID := idFromDataset(dataset)
	if strings.HasPrefix(volID, importedPrefix) {
		// A pool component named imp1-* would make the id decode as imported.
		return nil, status.Errorf(codes.InvalidArgument, "datasetParent may not start with %q", importedPrefix)
	}
	nqn := cs.nqn(volID)

	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: dataset})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	switch {
	case info.Exists && info.SizeBytes != uint64(capacity):
		// The name exists with a different size: a genuinely different
		// request, per CSI's idempotency contract.
		return nil, status.Errorf(codes.AlreadyExists,
			"volume %s exists with size %d (requested %d)", dataset, info.SizeBytes, capacity)
	case info.Exists:
		// Retry after a partial create: the zvol is there, nothing else to do.
		// The export is created lazily at ControllerPublishVolume, not here.
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

	// The export is created lazily on ControllerPublishVolume (per attach).
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      volID,
		CapacityBytes: capacity,
		ContentSource: req.GetVolumeContentSource(),
		VolumeContext: cs.volumeContext(nqn),
	}}, nil
}

// createImportedVolume adopts a preexisting zvol at an arbitrary dataset path:
// it never creates or clones a zvol (the export is created lazily at publish),
// and returns an imp1- volume id so DeleteVolume spares the zvol.
func (cs *ControllerServer) createImportedVolume(ctx context.Context, req *csi.CreateVolumeRequest, imp string) (*csi.CreateVolumeResponse, error) {
	if err := validDatasetPath(imp); err != nil {
		return nil, err
	}
	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: imp})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "import target %s does not exist", imp)
	}
	if want := req.GetCapacityRange().GetRequiredBytes(); want > int64(info.SizeBytes) {
		return nil, status.Errorf(codes.OutOfRange,
			"import target %s is %d bytes, requested %d", imp, info.SizeBytes, want)
	}
	ref := &volumeRef{dataset: imp, nqnToken: encodeImportID(imp), imported: true}
	nqn := cs.nqnOf(ref)
	// The export is created lazily on ControllerPublishVolume (per attach).
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      ref.nqnToken,
		CapacityBytes: int64(info.SizeBytes), // adopt the actual size
		VolumeContext: cs.volumeContext(nqn),
	}}, nil
}

// applyExport (re-)creates the nvmet subsystem for dataset, closed to all
// hosts; ControllerPublishVolume opens it to the attaching node.
func (cs *ControllerServer) applyExport(ctx context.Context, nqn, dataset string) error {
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
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("exporting " + nqn); err != nil {
		return err
	}
	cs.setExported(nqn, true)
	return nil
}

// deleteExport tears the volume's nvmet export down (unbinds the CSI port,
// deletes the subsystem, reaps the empty port). Absent-tolerant, so it is the
// shared body of the last-detach un-export (ControllerUnpublishVolume),
// DeleteVolume, and the reconcile GC of volumes with no live attachment.
func (cs *ControllerServer) deleteExport(ctx context.Context, nqn string) error {
	stream, err := cs.helper.CsiNvmeDelete(ctx, &helperpb.CsiNvmeDelete{Nqn: nqn})
	res, err := helper.RunTask("CsiNvmeDelete", stream, err)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("deleting export " + nqn); err != nil {
		return err
	}
	cs.setExported(nqn, false)
	return nil
}

// setExported records (up) or clears the controller's belief that nqn has a
// live export, so the reconcile GC prunes only exports it created.
func (cs *ControllerServer) setExported(nqn string, up bool) {
	cs.exportedMu.Lock()
	defer cs.exportedMu.Unlock()
	if up {
		cs.exported[nqn] = true
	} else {
		delete(cs.exported, nqn)
	}
}

func (cs *ControllerServer) isExported(nqn string) bool {
	cs.exportedMu.Lock()
	defer cs.exportedMu.Unlock()
	return cs.exported[nqn]
}

// volumeContext is the stock csi-driver-nvmf volume_context, so the node half
// stays wire-compatible with upstream and needs no import-specific handling.
func (cs *ControllerServer) volumeContext(nqn string) map[string]string {
	return map[string]string{
		"targetTrAddr": cs.cfg.TrAddr,
		"targetTrPort": fmt.Sprintf("%d", cs.cfg.TrSvcID),
		"targetTrType": cs.cfg.Transport,
		"nqn":          nqn,
		"deviceUUID":   DeviceUUID(nqn),
	}
}

func (cs *ControllerServer) DeleteVolume(ctx context.Context, req *csi.DeleteVolumeRequest) (*csi.DeleteVolumeResponse, error) {
	if req.GetVolumeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id is required")
	}
	ref, err := cs.resolveVolumeID(req.GetVolumeId())
	if err != nil {
		// A malformed id can never have been created here — per CSI,
		// deleting a volume that does not exist succeeds. A corrupt imp1- id
		// fails here too, so ZvolDelete is unreachable for it.
		return &csi.DeleteVolumeResponse{}, nil
	}
	// Export first (frees the zvol), then the zvol. Both absent-tolerant.
	if err := cs.deleteExport(ctx, cs.nqnOf(ref)); err != nil {
		return nil, err
	}
	if ref.imported {
		// An adopted zvol predates the driver: tear down only the export.
		return &csi.DeleteVolumeResponse{}, nil
	}
	zstream, err := cs.helper.ZvolDelete(ctx, &helperpb.ZvolDelete{Dataset: ref.dataset})
	res, err := helper.RunTask("ZvolDelete", zstream, err)
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
			return nil, status.Errorf(codes.FailedPrecondition, "deleting %s: %s", ref.dataset, res.Error)
		default:
			return nil, res.Err("deleting " + ref.dataset)
		}
	}
	return &csi.DeleteVolumeResponse{}, nil
}

// ControllerPublishVolume grants the attaching node's host NQN. node_id IS
// the hostnqn (the DaemonSet passes --nodeid="$(cat /etc/nvme/hostnqn)"), so
// no side-channel mapping exists to go stale.
func (cs *ControllerServer) ControllerPublishVolume(ctx context.Context, req *csi.ControllerPublishVolumeRequest) (*csi.ControllerPublishVolumeResponse, error) {
	if req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "volume capability is required")
	}
	if err := checkCapabilities([]*csi.VolumeCapability{req.GetVolumeCapability()}); err != nil {
		return nil, err
	}
	if err := cs.ensurePublished(ctx, req.GetVolumeId(), req.GetNodeId()); err != nil {
		return nil, err
	}
	return &csi.ControllerPublishVolumeResponse{}, nil
}

// ensurePublished (re)creates the volume's export and grants the node access. It
// is idempotent, so it is the shared body of ControllerPublishVolume (called per
// attach) and the export reconcile (ReconcileExports), which calls it to self-heal
// exports a target reboot wiped: the nvmet export lives in the target's kernel
// configfs, which a reboot clears while the zvol (ZFS) survives, and the
// external-attacher never re-publishes an already-attached VolumeAttachment — so
// without the reconcile a rebooted target's volumes would stay unexportable until
// a manual re-attach.
func (cs *ControllerServer) ensurePublished(ctx context.Context, volID, node string) error {
	ref, err := cs.resolveVolumeID(volID)
	if err != nil {
		return err
	}
	if !strings.HasPrefix(node, "nqn.") {
		return status.Errorf(codes.InvalidArgument,
			"node id %q is not a host NQN — the node plugin must run with --nodeid from /etc/nvme/hostnqn", node)
	}
	// Re-apply the export first: idempotent (same code path as CreateVolume),
	// it rebuilds the subsystem + RDMA port that a target reboot wiped.
	if err := cs.applyExport(ctx, cs.nqnOf(ref), ref.dataset); err != nil {
		return err
	}
	stream, err := cs.helper.CsiHostGrant(ctx, &helperpb.CsiHostGrant{
		Nqn: cs.nqnOf(ref), Hostnqn: node,
	})
	res, err := helper.RunTask("CsiHostGrant", stream, err)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() && res.Mentions("does not exist") {
		return status.Errorf(codes.NotFound, "volume %s has no export: %s", volID, res.Error)
	}
	return res.Err("granting " + node)
}

// ControllerUnpublishVolume is the fence. It runs against the *storage*, so
// it works exactly when it matters: the node is unreachable and Kubernetes is
// detaching the volume out from under it.
func (cs *ControllerServer) ControllerUnpublishVolume(ctx context.Context, req *csi.ControllerUnpublishVolumeRequest) (*csi.ControllerUnpublishVolumeResponse, error) {
	node := req.GetNodeId()
	ref, err := cs.resolveVolumeID(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	if !strings.HasPrefix(node, "nqn.") {
		return nil, status.Errorf(codes.InvalidArgument, "node id %q is not a host NQN", node)
	}
	stream, err := cs.helper.CsiHostRevoke(ctx, &helperpb.CsiHostRevoke{
		Nqn: cs.nqnOf(ref), Hostnqn: node,
	})
	res, err := helper.RunTask("CsiHostRevoke", stream, err)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("fencing " + node); err != nil {
		return nil, err
	}
	// Single-node access modes only (checkCapabilities), so the revoked node was
	// the volume's only host — it is now unused, so tear the export down (lazy
	// un-export). Absent-tolerant. If MULTI_NODE modes are ever allowed this must
	// become a last-host check.
	if err := cs.deleteExport(ctx, cs.nqnOf(ref)); err != nil {
		return nil, err
	}
	return &csi.ControllerUnpublishVolumeResponse{}, nil
}

func (cs *ControllerServer) ControllerExpandVolume(ctx context.Context, req *csi.ControllerExpandVolumeRequest) (*csi.ControllerExpandVolumeResponse, error) {
	ref, err := cs.resolveVolumeID(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	if ref.imported {
		return nil, status.Errorf(codes.FailedPrecondition, "imported volumes are not expandable")
	}
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if capacity <= 0 {
		return nil, status.Error(codes.InvalidArgument, "expansion needs a required capacity")
	}
	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: ref.dataset})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "volume %s not found", req.GetVolumeId())
	}
	if info.SizeBytes < uint64(capacity) {
		stream, err := cs.helper.CsiVolumeExpand(ctx, &helperpb.CsiVolumeExpand{
			Nqn: cs.nqnOf(ref), NewSize: uint64(capacity),
		})
		res, err := helper.RunTask("CsiVolumeExpand", stream, err)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if err := res.Err("expanding " + req.GetVolumeId()); err != nil {
			return nil, err
		}
	}
	return &csi.ControllerExpandVolumeResponse{
		CapacityBytes: capacity,
		// The filesystem still has to grow on the node.
		NodeExpansionRequired: true,
	}, nil
}

// Snapshot ids are "<volume_id>@<snap>" — with the id's ':' separators turned
// back into '/', directly the zfs name.
func (cs *ControllerServer) parseSnapshotID(id string) (dataset, snap string, err error) {
	vol, snap, ok := strings.Cut(id, "@")
	if !ok || checkVolumeName(snap) != nil {
		return "", "", status.Errorf(codes.InvalidArgument, "invalid snapshot id %q", id)
	}
	dataset, err = datasetFromID(vol)
	if err != nil {
		return "", "", status.Errorf(codes.InvalidArgument, "invalid snapshot id %q", id)
	}
	return dataset, snap, nil
}

func (cs *ControllerServer) CreateSnapshot(ctx context.Context, req *csi.CreateSnapshotRequest) (*csi.CreateSnapshotResponse, error) {
	vol, name := req.GetSourceVolumeId(), req.GetName()
	ref, err := cs.resolveVolumeID(vol)
	if err != nil {
		return nil, err
	}
	if ref.imported {
		return nil, status.Error(codes.FailedPrecondition, "imported volumes are not snapshottable")
	}
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	stream, err := cs.helper.SnapshotCreate(ctx, &helperpb.SnapshotCreate{
		Dataset: ref.dataset, Snap: name,
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
	ref, err := cs.resolveVolumeID(req.GetVolumeId())
	if err != nil {
		return nil, err
	}
	info, err := cs.helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: ref.dataset})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying zvol: %v", err)
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "volume %s not found", req.GetVolumeId())
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
