// The thin-LVM half of the controller: a StorageClass with backend: lvm-thin
// provisions thin LVs in its volumeGroup/thinPool. SPDX-License-Identifier:
// Apache-2.0
//
//	volume_id = lvm1-<vg>:<lv>   (lvmi1-<vg>:<lv> for an adopted LV)
//	device    = /dev/<vg>/<lv>
//	snapshot  = <volume_id>@<snap>, the inactive thin snapshot LV <snap> in <vg>
//
// Idempotency comes from LvInfo: a thin LV carries its pool and snapshot
// origin, which is all a retry needs to tell its own earlier attempt from a
// different volume under the same name.
package driver

import (
	"context"
	"strings"

	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// lvRef parses the "<vg>:<lv>" that follows an LVM id prefix.
func lvRef(volID, rest string, imported bool) (*volumeRef, error) {
	vg, lv, ok := strings.Cut(rest, ":")
	if !ok || checkVolumeName(vg) != nil || checkVolumeName(lv) != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid volume id %q", volID)
	}
	return &volumeRef{vg: vg, lv: lv, nqnToken: volID, imported: imported}, nil
}

func (cs *ControllerServer) lvInfo(ctx context.Context, vg, lv string) (*helperpb.LvInfoReply, error) {
	info, err := cs.helper.LvInfo(ctx, &helperpb.LvInfo{Vg: vg, Name: lv})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "querying LV %s/%s: %v", vg, lv, err)
	}
	return info, nil
}

// createThinLv is CreateVolume for backend: lvm-thin. The LV name is the
// provisioner's pvc-<uuid>, or the class's lvName template.
func (cs *ControllerServer) createThinLv(ctx context.Context, req *csi.CreateVolumeRequest) (*csi.CreateVolumeResponse, error) {
	params := req.GetParameters()
	if imp := params["importLv"]; imp != "" {
		return cs.createImportedLv(ctx, req, imp)
	}
	vg, pool := params["volumeGroup"], params["thinPool"]
	if vg == "" || pool == "" {
		return nil, status.Error(codes.InvalidArgument,
			"StorageClass parameters volumeGroup and thinPool are required for backend lvm-thin (e.g. vg0 and pool0)")
	}
	if err := checkVolumeName(vg); err != nil {
		return nil, err
	}
	if err := checkVolumeName(pool); err != nil {
		return nil, err
	}
	name := req.GetName()
	if v := params["lvName"]; v != "" {
		expanded, err := expandZvolName(v, params)
		if err != nil {
			return nil, err
		}
		name = expanded
	}
	if err := checkVolumeName(name); err != nil {
		return nil, err
	}
	ref := &volumeRef{vg: vg, lv: name, nqnToken: lvmPrefix + vg + ":" + name}
	nqn := cs.nqnOf(ref)
	if err := checkNQNLength(nqn); err != nil {
		return nil, err
	}
	capacity := req.GetCapacityRange().GetRequiredBytes()
	if capacity == 0 {
		capacity = 1 << 30
	}
	var err error
	if src := req.GetVolumeContentSource().GetSnapshot(); src != nil {
		capacity, err = cs.restoreThinLv(ctx, ref, pool, src.GetSnapshotId(), capacity)
	} else {
		capacity, err = cs.ensureThinLv(ctx, ref, pool, capacity)
	}
	if err != nil {
		return nil, err
	}
	// The export is created lazily on ControllerPublishVolume (per attach).
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      ref.nqnToken,
		CapacityBytes: capacity,
		ContentSource: req.GetVolumeContentSource(),
		VolumeContext: cs.volumeContext(nqn),
	}}, nil
}

// ensureThinLv creates the thin LV, or accepts it on a retry: same pool, not
// a snapshot, and at least as big (LVM rounds sizes up to whole extents).
func (cs *ControllerServer) ensureThinLv(ctx context.Context, ref *volumeRef, pool string, capacity int64) (int64, error) {
	info, err := cs.lvInfo(ctx, ref.vg, ref.lv)
	if err != nil {
		return 0, err
	}
	if info.Exists {
		if info.Pool != pool || info.Origin != "" || info.SizeBytes < uint64(capacity) {
			return 0, status.Errorf(codes.AlreadyExists,
				"LV %s/%s exists (pool %q, origin %q, %d bytes) and does not match this request",
				ref.vg, ref.lv, info.Pool, info.Origin, info.SizeBytes)
		}
		return int64(info.SizeBytes), nil
	}
	stream, err := cs.helper.ThinLvCreate(ctx, &helperpb.ThinLvCreate{
		Vg: ref.vg, Pool: pool, Name: ref.lv, VirtualSize: uint64(capacity),
	})
	res, err := helper.RunTask("ThinLvCreate", stream, err)
	if err != nil {
		return 0, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("creating " + ref.vg + "/" + ref.lv); err != nil {
		return 0, err
	}
	return capacity, nil
}

// restoreThinLv makes ref a writable thin snapshot of an lvm-thin snapshot in
// the class's own pool. A retry finds the target already restored from that
// snapshot and only finishes the grow; anything else under the name is a
// different volume.
func (cs *ControllerServer) restoreThinLv(ctx context.Context, ref *volumeRef, pool, snapID string, capacity int64) (int64, error) {
	src, snap, err := cs.parseSnapshotID(snapID)
	if err != nil {
		// A malformed source id cannot name an existing snapshot.
		return 0, status.Errorf(codes.NotFound, "source snapshot: %v", err)
	}
	if src.lv == "" || src.vg != ref.vg {
		return 0, status.Errorf(codes.InvalidArgument,
			"snapshot %s is not an lvm-thin snapshot in volume group %s", snapID, ref.vg)
	}
	target, err := cs.lvInfo(ctx, ref.vg, ref.lv)
	if err != nil {
		return 0, err
	}
	if target.Exists {
		if target.Origin != snap {
			return 0, status.Errorf(codes.AlreadyExists,
				"LV %s/%s exists and is not a restore of %s", ref.vg, ref.lv, snapID)
		}
		if target.SizeBytes >= uint64(capacity) {
			return int64(target.SizeBytes), nil
		}
		stream, err := cs.helper.LvResize(ctx, &helperpb.LvResize{Vg: ref.vg, Name: ref.lv, NewSize: uint64(capacity)})
		res, err := helper.RunTask("LvResize", stream, err)
		if err != nil {
			return 0, status.Errorf(codes.Unavailable, "%v", err)
		}
		return capacity, res.Err("growing " + ref.vg + "/" + ref.lv)
	}
	source, err := cs.lvInfo(ctx, ref.vg, snap)
	if err != nil {
		return 0, err
	}
	if !source.Exists {
		return 0, status.Errorf(codes.NotFound, "source snapshot %s does not exist", snapID)
	}
	if source.Pool != pool {
		return 0, status.Errorf(codes.InvalidArgument,
			"snapshot %s is in thin pool %q, not the class's %q", snapID, source.Pool, pool)
	}
	clone := &helperpb.LvThinClone{Vg: ref.vg, Snap: snap, Target: ref.lv}
	if uint64(capacity) > source.SizeBytes {
		size := uint64(capacity)
		clone.NewSize = &size
	} else {
		capacity = int64(source.SizeBytes)
	}
	stream, err := cs.helper.LvThinClone(ctx, clone)
	res, err := helper.RunTask("LvThinClone", stream, err)
	if err != nil {
		return 0, status.Errorf(codes.Unavailable, "%v", err)
	}
	if err := res.Err("restoring " + ref.vg + "/" + ref.lv); err != nil {
		return 0, err
	}
	return capacity, nil
}

// createImportedLv adopts a preexisting LV (thin or not): it is only ever
// exported, and its lvmi1- id makes DeleteVolume spare it.
func (cs *ControllerServer) createImportedLv(ctx context.Context, req *csi.CreateVolumeRequest, imp string) (*csi.CreateVolumeResponse, error) {
	vg, lv, ok := strings.Cut(imp, "/")
	if !ok || checkVolumeName(vg) != nil || checkVolumeName(lv) != nil {
		return nil, status.Errorf(codes.InvalidArgument, "importLv %q must be <vg>/<lv>", imp)
	}
	ref := &volumeRef{vg: vg, lv: lv, nqnToken: lvmImportedPrefix + vg + ":" + lv, imported: true}
	nqn := cs.nqnOf(ref)
	if err := checkNQNLength(nqn); err != nil {
		return nil, err
	}
	info, err := cs.lvInfo(ctx, vg, lv)
	if err != nil {
		return nil, err
	}
	if !info.Exists {
		return nil, status.Errorf(codes.NotFound, "import target %s does not exist", imp)
	}
	if want := req.GetCapacityRange().GetRequiredBytes(); want > int64(info.SizeBytes) {
		return nil, status.Errorf(codes.OutOfRange,
			"import target %s is %d bytes, requested %d", imp, info.SizeBytes, want)
	}
	// The export is created lazily on ControllerPublishVolume (per attach).
	return &csi.CreateVolumeResponse{Volume: &csi.Volume{
		VolumeId:      ref.nqnToken,
		CapacityBytes: int64(info.SizeBytes), // adopt the actual size
		VolumeContext: cs.volumeContext(nqn),
	}}, nil
}

// deleteThinLv removes a managed LV once its export is gone. Thin snapshots
// do not pin their origin, so a volume with snapshots is deletable.
func (cs *ControllerServer) deleteThinLv(ctx context.Context, ref *volumeRef) (*csi.DeleteVolumeResponse, error) {
	if err := cs.removeLv(ctx, ref.vg, ref.lv); err != nil {
		return nil, err
	}
	return &csi.DeleteVolumeResponse{}, nil
}

// removeLv is lvremove that treats an already-absent LV (a retry after a
// completed delete) as success.
func (cs *ControllerServer) removeLv(ctx context.Context, vg, lv string) error {
	stream, err := cs.helper.LvDelete(ctx, &helperpb.LvDelete{Vg: vg, Name: lv})
	res, err := helper.RunTask("LvDelete", stream, err)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() && res.Mentions("Failed to find") {
		return nil
	}
	return res.Err("deleting " + vg + "/" + lv)
}

// lvSnapshotName is the LV a CSI snapshot name becomes. LVM reserves names
// starting "snapshot" or "pvmove" — and csi-snapshotter generates
// snapshot-<uuid> — so those get a "gd-" prefix. The LV name rides in the
// snapshot id, so delete and restore never re-derive it.
func lvSnapshotName(name string) string {
	if strings.HasPrefix(name, "snapshot") || strings.HasPrefix(name, "pvmove") {
		return "gd-" + name
	}
	return name
}

// createThinSnapshot snapshots ref as the LV `name`. LV names are VG-wide, so
// an existing LV of that name is this snapshot only if ref is its origin.
func (cs *ControllerServer) createThinSnapshot(ctx context.Context, vol string, ref *volumeRef, name string) error {
	info, err := cs.lvInfo(ctx, ref.vg, name)
	if err != nil {
		return err
	}
	if info.Exists {
		if info.Origin != ref.lv {
			return status.Errorf(codes.AlreadyExists,
				"snapshot %s already exists with a different source (%q)", name, info.Origin)
		}
		return nil
	}
	stream, err := cs.helper.LvThinSnapshot(ctx, &helperpb.LvThinSnapshot{Vg: ref.vg, Origin: ref.lv, Name: name})
	res, err := helper.RunTask("LvThinSnapshot", stream, err)
	if err != nil {
		return status.Errorf(codes.Unavailable, "%v", err)
	}
	if res.Failed() && res.Mentions("Failed to find") {
		return status.Errorf(codes.NotFound, "source volume %s: %s", vol, res.Error)
	}
	return res.Err("snapshotting " + vol)
}

// deleteThinSnapshot removes the snapshot LV. A thin snapshot outlives its
// origin (whose name then reads empty), but an LV with another origin, or an
// active one, is not a snapshot this driver made — never delete a volume
// through a mismatched snapshot id.
func (cs *ControllerServer) deleteThinSnapshot(ctx context.Context, ref *volumeRef, snap string) error {
	info, err := cs.lvInfo(ctx, ref.vg, snap)
	if err != nil {
		return err
	}
	if !info.Exists {
		return nil
	}
	if info.Active || (info.Origin != "" && info.Origin != ref.lv) {
		return status.Errorf(codes.FailedPrecondition,
			"LV %s/%s is not an inactive snapshot of %s", ref.vg, snap, ref.lv)
	}
	return cs.removeLv(ctx, ref.vg, snap)
}
