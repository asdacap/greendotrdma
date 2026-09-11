// csi-e2e: a scripted client for the NixOS VM e2e test. It builds the real
// SSH tunnel + controller and invokes one controller action per run, so the
// test script can interleave initiator connects between CSI steps. The CSI
// gRPC serving layer itself is covered by csi-sanity; this exercises the part
// only a live box can: ssh → greendotctl pipe → daemon → configfs → fence.
// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"fmt"
	"strings"

	"github.com/asdacap/greendotrdma/csi/pkg/driver"
	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/node"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/klog/v2"
)

func main() {
	var (
		attachmentID = flag.String("attachment-id", "", "immutable direct test attachment generation (publish/unpublish)")
		action       = flag.String("action", "", "create|publish|unpublish|delete|expand|node-stage|node-publish|node-unpublish|node-unstage|node-expand")
		volume       = flag.String("volume", "", "volume id")
		size         = flag.Int64("size", 64<<20, "capacity bytes (create/expand)")
		hostnqn      = flag.String("hostnqn", "", "node host NQN (publish/unpublish/node-stage)")

		// node-stage: exercise the real node plugin (transport prep + fabric
		// connect) instead of a raw nvme connect, so the test proves the driver
		// configures RDMA itself.
		nqn        = flag.String("nqn", "", "target subsystem nqn (node-stage)")
		hostid     = flag.String("hostid", "", "node host id, cat /etc/nvme/hostid (node-stage)")
		deviceUUID = flag.String("device-uuid", "", "pinned namespace uuid (node-stage)")
		softRoce   = flag.String("soft-roce-netdev", "", "Soft-RoCE netdev for the node plugin (node-stage)")
		staging    = flag.String("staging-path", "/tmp/csi-e2e-staging", "node staging target path (node-stage)")
		targetPath = flag.String("target-path", "/tmp/csi-e2e-target", "node publish target")
		filesystem = flag.Bool("filesystem", false, "stage and publish an ext4 filesystem instead of raw block")
		volmap     = flag.String("volume-map-dir", "/tmp/csi-e2e-volumes", "node connector map dir (node-stage)")

		sshAddr   = flag.String("ssh-addr", "", "storage box sshd, host:port")
		sshUser   = flag.String("ssh-user", "greendot-csi", "SSH login user")
		sshKey    = flag.String("ssh-key", "", "SSH private key path")
		sshKnown  = flag.String("ssh-known-hosts", "", "pinned known_hosts path")
		sshCmd    = flag.String("ssh-command", "", "remote pipe command")
		dataset   = flag.String("dataset-parent", "tank/csi", "parent dataset")
		traddr    = flag.String("traddr", "", "target data address")
		trsvcid   = flag.Uint("trsvcid", 4421, "CSI port service id")
		transport = flag.String("transport", "rdma", "rdma or tcp")
	)
	flag.Parse()

	// Node actions use the real node plugin entirely on the initiator.
	if strings.HasPrefix(*action, "node-") {
		ns := node.NewNodeServer(*hostnqn, *hostid, *volmap, *softRoce)
		capability := &csi.VolumeCapability{
			AccessType: &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}},
			AccessMode: &csi.VolumeCapability_AccessMode{Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER},
		}
		if *filesystem {
			capability.AccessType = &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{FsType: "ext4"}}
		}
		ctx := context.Background()
		var err error
		switch *action {
		case "node-stage":
			_, err = ns.NodeStageVolume(ctx, &csi.NodeStageVolumeRequest{
				VolumeId: *volume, StagingTargetPath: *staging,
				VolumeContext: map[string]string{
					"nqn": *nqn, "targetTrAddr": *traddr,
					"targetTrPort": fmt.Sprintf("%d", *trsvcid),
					"targetTrType": *transport, "deviceUUID": *deviceUUID,
				},
				VolumeCapability: capability,
			})
		case "node-publish":
			_, err = ns.NodePublishVolume(ctx, &csi.NodePublishVolumeRequest{
				VolumeId: *volume, StagingTargetPath: *staging, TargetPath: *targetPath, VolumeCapability: capability,
			})
		case "node-unpublish":
			_, err = ns.NodeUnpublishVolume(ctx, &csi.NodeUnpublishVolumeRequest{VolumeId: *volume, TargetPath: *targetPath})
		case "node-unstage":
			_, err = ns.NodeUnstageVolume(ctx, &csi.NodeUnstageVolumeRequest{VolumeId: *volume, StagingTargetPath: *staging})
		case "node-expand":
			_, err = ns.NodeExpandVolume(ctx, &csi.NodeExpandVolumeRequest{
				VolumeId: *volume, VolumePath: *staging, VolumeCapability: capability,
				CapacityRange: &csi.CapacityRange{RequiredBytes: *size},
			})
		default:
			klog.Fatalf("unknown node action %q", *action)
		}
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Println("ok")
		return
	}

	tunnel, err := helper.NewTunnel(helper.SSHConfig{
		Addr: *sshAddr, User: *sshUser, KeyPath: *sshKey,
		KnownHostsPath: *sshKnown, Command: *sshCmd,
	})
	if err != nil {
		klog.Fatal(err)
	}
	client, err := helper.Connect(tunnel)
	if err != nil {
		klog.Fatal(err)
	}
	cs, err := driver.NewControllerServer(driver.ControllerConfig{
		TrAddr:       *traddr,
		AttachmentID: *attachmentID,
		TrSvcID:      uint32(*trsvcid), Transport: *transport,
	}, client.Helper)
	if err != nil {
		klog.Fatal(err)
	}

	// The test script addresses volumes by bare leaf name; managed ids are
	// dataset paths with ':' separators, so qualify with -dataset-parent
	// (which in a real deployment is the StorageClass's datasetParent).
	volID := *volume
	if *volume != "" && !strings.Contains(*volume, ":") {
		volID = strings.ReplaceAll(*dataset, "/", ":") + ":" + *volume
	}

	caps := []*csi.VolumeCapability{{
		AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}},
		AccessMode: &csi.VolumeCapability_AccessMode{
			Mode: csi.VolumeCapability_AccessMode_SINGLE_NODE_WRITER,
		},
	}}
	ctx := context.Background()
	switch *action {
	case "create":
		resp, err := cs.CreateVolume(ctx, &csi.CreateVolumeRequest{
			Name:               *volume,
			Parameters:         map[string]string{"datasetParent": *dataset},
			CapacityRange:      &csi.CapacityRange{RequiredBytes: *size},
			VolumeCapabilities: caps,
		})
		if err != nil {
			klog.Fatal(err)
		}
		fmt.Printf("volumeId=%s\n", resp.Volume.VolumeId)
		for _, k := range []string{"nqn", "deviceUUID", "targetTrAddr", "targetTrPort"} {
			fmt.Printf("%s=%s\n", k, resp.Volume.VolumeContext[k])
		}
	case "publish":
		if _, err := cs.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
			VolumeId: volID, NodeId: *hostnqn, VolumeCapability: caps[0],
		}); err != nil {
			klog.Fatal(err)
		}
	case "unpublish":
		if _, err := cs.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{
			VolumeId: volID, NodeId: *hostnqn,
		}); err != nil {
			klog.Fatal(err)
		}
	case "expand":
		if _, err := cs.ControllerExpandVolume(ctx, &csi.ControllerExpandVolumeRequest{
			VolumeId:      volID,
			CapacityRange: &csi.CapacityRange{RequiredBytes: *size},
		}); err != nil {
			klog.Fatal(err)
		}
	case "delete":
		if _, err := cs.DeleteVolume(ctx, &csi.DeleteVolumeRequest{VolumeId: volID}); err != nil {
			klog.Fatal(err)
		}
	default:
		klog.Fatalf("unknown action %q", *action)
	}
	fmt.Println("ok")
}
