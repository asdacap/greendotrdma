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

	"github.com/asdacap/greendotrdma/csi/pkg/driver"
	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/container-storage-interface/spec/lib/go/csi"
	"k8s.io/klog/v2"
)

func main() {
	var (
		action  = flag.String("action", "", "create|publish|unpublish|delete|expand")
		volume  = flag.String("volume", "", "volume id")
		size    = flag.Int64("size", 64<<20, "capacity bytes (create/expand)")
		hostnqn = flag.String("hostnqn", "", "node host NQN (publish/unpublish)")

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
		DatasetParent: *dataset, TrAddr: *traddr,
		TrSvcID: uint32(*trsvcid), Transport: *transport,
	}, client.Helper)
	if err != nil {
		klog.Fatal(err)
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
			CapacityRange:      &csi.CapacityRange{RequiredBytes: *size},
			VolumeCapabilities: caps,
		})
		if err != nil {
			klog.Fatal(err)
		}
		for _, k := range []string{"nqn", "deviceUUID", "targetTrAddr", "targetTrPort"} {
			fmt.Printf("%s=%s\n", k, resp.Volume.VolumeContext[k])
		}
	case "publish":
		if _, err := cs.ControllerPublishVolume(ctx, &csi.ControllerPublishVolumeRequest{
			VolumeId: *volume, NodeId: *hostnqn, VolumeCapability: caps[0],
		}); err != nil {
			klog.Fatal(err)
		}
	case "unpublish":
		if _, err := cs.ControllerUnpublishVolume(ctx, &csi.ControllerUnpublishVolumeRequest{
			VolumeId: *volume, NodeId: *hostnqn,
		}); err != nil {
			klog.Fatal(err)
		}
	case "expand":
		if _, err := cs.ControllerExpandVolume(ctx, &csi.ControllerExpandVolumeRequest{
			VolumeId:      *volume,
			CapacityRange: &csi.CapacityRange{RequiredBytes: *size},
		}); err != nil {
			klog.Fatal(err)
		}
	case "delete":
		if _, err := cs.DeleteVolume(ctx, &csi.DeleteVolumeRequest{VolumeId: *volume}); err != nil {
			klog.Fatal(err)
		}
	default:
		klog.Fatalf("unknown action %q", *action)
	}
	fmt.Println("ok")
}
