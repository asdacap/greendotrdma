/*
Copyright 2021 The Kubernetes Authors.
Forked from kubernetes-csi/csi-driver-nvmf (pkg/nvmf/nodeserver.go, nvmf.go).
greendot modifications — the reasons this is a fork and not a dependency:

 1. Stage/Publish split. Upstream connects the fabric in NodePublishVolume
    (per pod) with NodeStageVolume a no-op; two pods sharing one RWO PVC on a
    node then race, and the failed pod's unpublish disconnects the controller
    under the running pod's live mount. Here the connect + format happen once
    per node in NodeStageVolume, and publish is only a bind mount.
 2. Rollback defers rewritten against the named return error (upstream
    captured `err` at defer time, so its rollbacks never ran).
 3. Connector-path traversal guard (fabrics.go).
 4. The node's identity IS its host NQN (--nodeid from /etc/nvme/hostnqn), so
    ControllerPublishVolume can grant it into allowed_hosts verbatim.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package node

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sync"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
	mount "k8s.io/mount-utils"
	utilexec "k8s.io/utils/exec"
)

type NodeServer struct {
	csi.UnimplementedNodeServer
	// NodeID is this node's host NQN (the DaemonSet reads /etc/nvme/hostnqn).
	NodeID string
	// HostID is this node's host id (the DaemonSet reads /etc/nvme/hostid); it
	// pairs with NodeID in the fabric connect so the kernel accepts the NQN.
	HostID string
	// VolumeMapDir persists one connector JSON per staged volume, so unstage
	// (which only receives the volume id) can disconnect the right subsystem.
	VolumeMapDir string
	// SoftRoceNetdev, when set, is the netdev an rxe (Soft-RoCE) link is created
	// on if an rdma stage finds no RDMA device (nodes without a hardware NIC).
	SoftRoceNetdev string
	mounter        *mount.SafeFormatAndMount
	publishMu      sync.Mutex
}

func NewNodeServer(nodeID, hostID, volumeMapDir, softRoceNetdev string) *NodeServer {
	return &NodeServer{
		NodeID:         nodeID,
		HostID:         hostID,
		VolumeMapDir:   volumeMapDir,
		SoftRoceNetdev: softRoceNetdev,
		mounter:        &mount.SafeFormatAndMount{Interface: mount.New(""), Exec: utilexec.New()},
	}
}

func (ns *NodeServer) NodeGetCapabilities(ctx context.Context, req *csi.NodeGetCapabilitiesRequest) (*csi.NodeGetCapabilitiesResponse, error) {
	var caps []*csi.NodeServiceCapability
	for _, c := range []csi.NodeServiceCapability_RPC_Type{
		csi.NodeServiceCapability_RPC_STAGE_UNSTAGE_VOLUME,
		csi.NodeServiceCapability_RPC_EXPAND_VOLUME,
	} {
		caps = append(caps, &csi.NodeServiceCapability{
			Type: &csi.NodeServiceCapability_Rpc{
				Rpc: &csi.NodeServiceCapability_RPC{Type: c},
			},
		})
	}
	return &csi.NodeGetCapabilitiesResponse{Capabilities: caps}, nil
}

func (ns *NodeServer) NodeGetInfo(ctx context.Context, req *csi.NodeGetInfoRequest) (*csi.NodeGetInfoResponse, error) {
	return &csi.NodeGetInfoResponse{NodeId: ns.NodeID}, nil
}

// connectorFromContext builds the connector from the PV's volume_context —
// the stock csi-driver-nvmf keys, filled by the controller's CreateVolume.
func (ns *NodeServer) connectorFromContext(volID string, volCtx map[string]string) (*Connector, error) {
	c := &Connector{
		VolumeID:   volID,
		TargetNqn:  volCtx["nqn"],
		TargetAddr: volCtx["targetTrAddr"],
		TargetPort: volCtx["targetTrPort"],
		Transport:  volCtx["targetTrType"],
		DeviceUUID: volCtx["deviceUUID"],
		HostNqn:    ns.NodeID,
		HostID:     ns.HostID,
	}
	if c.TargetNqn == "" || c.TargetAddr == "" || c.TargetPort == "" ||
		c.Transport == "" || c.DeviceUUID == "" {
		return nil, status.Errorf(codes.InvalidArgument,
			"volume context is missing nvmf fields (nqn/targetTrAddr/targetTrPort/targetTrType/deviceUUID): %v", volCtx)
	}
	return c, nil
}

// NodeStageVolume connects the fabric and (for Mount volumes) formats and
// mounts to the staging path — once per volume per node. Rollbacks run on the
// *named* return error: a failure leaves neither a connection nor a connector
// file behind.
func (ns *NodeServer) NodeStageVolume(ctx context.Context, req *csi.NodeStageVolumeRequest) (resp *csi.NodeStageVolumeResponse, retErr error) {
	volID, staging := req.GetVolumeId(), req.GetStagingTargetPath()
	if volID == "" || staging == "" || req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "volume id, staging path, and capability are required")
	}
	connector, err := ns.connectorFromContext(volID, req.GetVolumeContext())
	if err != nil {
		return nil, err
	}

	if err := connector.prepareTransport(ns.SoftRoceNetdev); err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "preparing %s transport: %v", connector.Transport, err)
	}

	devicePath, err := connector.Connect()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "connecting %s: %v", connector.TargetNqn, err)
	}
	defer func() {
		if retErr != nil {
			if err := connector.Disconnect(); err != nil {
				klog.Errorf("stage rollback: disconnect %s: %v", connector.TargetNqn, err)
			}
		}
	}()

	if err := persistConnector(ns.VolumeMapDir, connector); err != nil {
		return nil, status.Errorf(codes.Internal, "persisting connector: %v", err)
	}
	defer func() {
		if retErr != nil {
			_ = removeConnector(ns.VolumeMapDir, volID)
		}
	}()

	if m := req.GetVolumeCapability().GetMount(); m != nil {
		notMnt, err := ns.mounter.IsLikelyNotMountPoint(staging)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, status.Errorf(codes.Internal, "checking %s: %v", staging, err)
			}
			if err := os.MkdirAll(staging, 0o750); err != nil {
				return nil, status.Errorf(codes.Internal, "creating %s: %v", staging, err)
			}
			notMnt = true
		}
		if notMnt {
			fsType := m.GetFsType()
			if fsType == "" {
				fsType = "ext4"
			}
			if err := ns.mounter.FormatAndMount(devicePath, staging, fsType, m.GetMountFlags()); err != nil {
				return nil, status.Errorf(codes.Internal,
					"formatting/mounting %s at %s: %v", devicePath, staging, err)
			}
		}
	}
	// Block volumes need no staging mount: publish bind-mounts the device.
	return &csi.NodeStageVolumeResponse{}, nil
}

// NodePublishVolume is per pod and purely local: a bind mount from the staged
// filesystem (or the raw device) into the pod's target path.
func (ns *NodeServer) NodePublishVolume(ctx context.Context, req *csi.NodePublishVolumeRequest) (*csi.NodePublishVolumeResponse, error) {
	volID, staging, target := req.GetVolumeId(), req.GetStagingTargetPath(), req.GetTargetPath()
	if volID == "" || staging == "" || target == "" || req.GetVolumeCapability() == nil {
		return nil, status.Error(codes.InvalidArgument, "volume id, staging path, target path, and capability are required")
	}
	ns.publishMu.Lock()
	defer ns.publishMu.Unlock()
	options := []string{"bind"}
	if req.GetReadonly() {
		options = append(options, "ro")
	}

	if req.GetVolumeCapability().GetBlock() != nil {
		connector, err := loadConnector(ns.VolumeMapDir, volID)
		if err != nil {
			return nil, status.Errorf(codes.FailedPrecondition, "volume %s is not staged: %v", volID, err)
		}
		mountPoints, err := ns.mounter.List()
		if err != nil {
			return nil, status.Errorf(codes.Internal, "listing mounts: %v", err)
		}
		for _, mountPoint := range mountPoints {
			if filepath.Clean(mountPoint.Path) != filepath.Clean(target) {
				continue
			}
			if !sameBlockMount(connector.DevicePath(), target, mountPoint.Device) || slices.Contains(mountPoint.Opts, "ro") != req.GetReadonly() {
				return nil, status.Errorf(codes.FailedPrecondition, "target %s is mounted with a different device or readonly mode", target)
			}
			return &csi.NodePublishVolumeResponse{}, nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o750); err != nil {
			return nil, status.Errorf(codes.Internal, "creating %s: %v", filepath.Dir(target), err)
		}
		// The bind target of a block device is a file.
		if f, err := os.OpenFile(target, os.O_CREATE, 0o640); err == nil {
			f.Close()
		} else if !os.IsExist(err) {
			return nil, status.Errorf(codes.Internal, "creating %s: %v", target, err)
		}
		if err := ns.mounter.Mount(connector.DevicePath(), target, "", options); err != nil {
			return nil, status.Errorf(codes.Internal, "bind-mounting device: %v", err)
		}
		return &csi.NodePublishVolumeResponse{}, nil
	}

	notMnt, err := ns.mounter.IsLikelyNotMountPoint(target)
	if err != nil {
		if !os.IsNotExist(err) {
			return nil, status.Errorf(codes.Internal, "checking %s: %v", target, err)
		}
		if err := os.MkdirAll(target, 0o750); err != nil {
			return nil, status.Errorf(codes.Internal, "creating %s: %v", target, err)
		}
		notMnt = true
	}
	if !notMnt {
		return &csi.NodePublishVolumeResponse{}, nil // idempotent re-publish
	}
	if err := ns.mounter.Mount(staging, target, "", options); err != nil {
		return nil, status.Errorf(codes.Internal, "bind-mounting %s to %s: %v", staging, target, err)
	}
	return &csi.NodePublishVolumeResponse{}, nil
}

// A device bind mount may list devtmpfs rather than the device as its source.
// In that case the mounted target and the by-id device still identify one inode.
func sameBlockMount(devicePath, target, source string) bool {
	if devicePath == source {
		return true
	}
	deviceInfo, err := os.Stat(devicePath)
	if err != nil {
		return false
	}
	targetInfo, err := os.Stat(target)
	return err == nil && os.SameFile(deviceInfo, targetInfo)
}

func (ns *NodeServer) NodeUnpublishVolume(ctx context.Context, req *csi.NodeUnpublishVolumeRequest) (*csi.NodeUnpublishVolumeResponse, error) {
	target := req.GetTargetPath()
	if req.GetVolumeId() == "" || target == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id and target path are required")
	}
	ns.publishMu.Lock()
	defer ns.publishMu.Unlock()
	if err := mount.CleanupMountPoint(target, ns.mounter, true); err != nil {
		return nil, status.Errorf(codes.Internal, "unmounting %s: %v", target, err)
	}
	return &csi.NodeUnpublishVolumeResponse{}, nil
}

// NodeUnstageVolume unmounts the staging path and disconnects the fabric —
// the per-node teardown, after kubelet has unpublished every pod.
func (ns *NodeServer) NodeUnstageVolume(ctx context.Context, req *csi.NodeUnstageVolumeRequest) (*csi.NodeUnstageVolumeResponse, error) {
	volID, staging := req.GetVolumeId(), req.GetStagingTargetPath()
	if volID == "" || staging == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id and staging path are required")
	}
	if err := mount.CleanupMountPoint(staging, ns.mounter, true); err != nil {
		return nil, status.Errorf(codes.Internal, "unmounting %s: %v", staging, err)
	}
	connector, err := loadConnector(ns.VolumeMapDir, volID)
	if err != nil {
		if os.IsNotExist(err) {
			// Never staged here (or already unstaged): idempotent success.
			return &csi.NodeUnstageVolumeResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "loading connector: %v", err)
	}
	if err := connector.Disconnect(); err != nil {
		return nil, status.Errorf(codes.Internal, "disconnecting %s: %v", connector.TargetNqn, err)
	}
	if err := removeConnector(ns.VolumeMapDir, volID); err != nil {
		return nil, status.Errorf(codes.Internal, "removing connector: %v", err)
	}
	return &csi.NodeUnstageVolumeResponse{}, nil
}

// NodeExpandVolume rescans the controller so the kernel sees the grown
// namespace, then grows the filesystem.
func (ns *NodeServer) NodeExpandVolume(ctx context.Context, req *csi.NodeExpandVolumeRequest) (*csi.NodeExpandVolumeResponse, error) {
	volID, volPath := req.GetVolumeId(), req.GetVolumePath()
	if volID == "" || volPath == "" {
		return nil, status.Error(codes.InvalidArgument, "volume id and volume path are required")
	}
	connector, err := loadConnector(ns.VolumeMapDir, volID)
	if err != nil {
		return nil, status.Errorf(codes.FailedPrecondition, "volume %s is not staged: %v", volID, err)
	}
	devicePath := connector.DevicePath()
	if err := rescanController(devicePath); err != nil {
		return nil, status.Errorf(codes.Internal, "rescanning: %v", err)
	}
	if req.GetVolumeCapability().GetBlock() != nil {
		return &csi.NodeExpandVolumeResponse{}, nil
	}
	resizer := mount.NewResizeFs(ns.mounter.Exec)
	if _, err := resizer.Resize(devicePath, volPath); err != nil {
		return nil, status.Errorf(codes.Internal, "growing filesystem on %s: %v", devicePath, err)
	}
	return &csi.NodeExpandVolumeResponse{}, nil
}

// rescanController follows sysfs membership instead of inferring controller
// numbers from a namespace name (multipath subsystem and controller IDs differ).
func rescanController(devicePath string) error {
	return rescanNamespace(devicePath, "/sys/class/block")
}

var nvmeControllerName = regexp.MustCompile(`^nvme[0-9]+$`)

func rescanNamespace(devicePath, blockClass string) error {
	resolved, err := filepath.EvalSymlinks(devicePath)
	if err != nil {
		return fmt.Errorf("resolving %s: %w", devicePath, err)
	}
	device := filepath.Join(blockClass, filepath.Base(resolved), "device")
	// Without native multipath, device points directly at the controller.
	scan := filepath.Join(device, "rescan_controller")
	if _, err := os.Stat(scan); err == nil {
		return writeRescan(scan)
	} else if !os.IsNotExist(err) {
		return err
	}
	// A multipath namespace points at its subsystem, whose nvmeN links
	// identify every member controller. Rescan all paths, not an assumed c0.
	entries, err := os.ReadDir(device)
	if err != nil {
		return fmt.Errorf("reading namespace subsystem %s: %w", device, err)
	}
	rescanned := false
	for _, entry := range entries {
		if !nvmeControllerName.MatchString(entry.Name()) {
			continue
		}
		if err := writeRescan(filepath.Join(device, entry.Name(), "rescan_controller")); err != nil {
			return err
		}
		rescanned = true
	}
	if !rescanned {
		return fmt.Errorf("no NVMe controllers for namespace %s", resolved)
	}
	return nil
}

func writeRescan(path string) error {
	// Never create a missing sysfs attribute: absence is a layout/error signal.
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.WriteString("1")
	return err
}
