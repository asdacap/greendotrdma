// greendot-csi: the greendotrdma CSI driver binary. --mode=controller serves
// the provisioning half (talking to greendotctl over SSH); --mode=node serves
// the per-worker half (fabric connect + mounts, forked from
// kubernetes-csi/csi-driver-nvmf). SPDX-License-Identifier: Apache-2.0
package main

import (
	"flag"
	"os"

	"github.com/asdacap/greendotrdma/csi/pkg/driver"
	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/node"
	"k8s.io/klog/v2"
)

func main() {
	var (
		endpoint = flag.String("endpoint", "unix:///csi/csi.sock", "CSI endpoint")
		mode     = flag.String("mode", "", "controller or node")

		// node
		nodeID = flag.String("nodeid", "", "this node's host NQN (cat /etc/nvme/hostnqn)")
		volDir = flag.String("volume-map-dir", "/var/lib/kubelet/plugins/"+driver.DriverName+"/volumes",
			"where staged volumes' connector files persist")

		// controller
		sshAddr    = flag.String("ssh-addr", "", "storage box sshd, host:port")
		sshUser    = flag.String("ssh-user", "greendot-csi", "SSH login user")
		sshKey     = flag.String("ssh-key", "", "SSH private key path")
		sshKnown   = flag.String("ssh-known-hosts", "", "pinned known_hosts path (required; never auto-accepted)")
		sshCommand = flag.String("ssh-command", "", "remote pipe command (default: the packaged greendotctl pipe)")
		dataset    = flag.String("dataset-parent", "", "ZFS dataset volumes live under, e.g. tank/csi")
		traddr     = flag.String("traddr", "", "target address initiators connect to")
		trsvcid    = flag.Uint("trsvcid", 4421, "CSI nvmet port service id")
		transport  = flag.String("transport", "rdma", "rdma or tcp")
	)
	klog.InitFlags(nil)
	flag.Parse()

	switch *mode {
	case "node":
		if *nodeID == "" {
			klog.Fatal("--mode=node requires --nodeid (the host NQN)")
		}
		ns := node.NewNodeServer(*nodeID, *volDir)
		if err := driver.Serve(*endpoint, &driver.IdentityServer{}, nil, ns); err != nil {
			klog.Fatal(err)
		}
	case "controller":
		tunnel, err := helper.NewTunnel(helper.SSHConfig{
			Addr:           *sshAddr,
			User:           *sshUser,
			KeyPath:        *sshKey,
			KnownHostsPath: *sshKnown,
			Command:        *sshCommand,
		})
		if err != nil {
			klog.Fatal(err)
		}
		client, err := helper.Connect(tunnel)
		if err != nil {
			klog.Fatal(err)
		}
		cs, err := driver.NewControllerServer(driver.ControllerConfig{
			DatasetParent: *dataset,
			TrAddr:        *traddr,
			TrSvcID:       uint32(*trsvcid),
			Transport:     *transport,
		}, client.Helper)
		if err != nil {
			klog.Fatal(err)
		}
		if err := driver.Serve(*endpoint, &driver.IdentityServer{}, cs, nil); err != nil {
			klog.Fatal(err)
		}
	default:
		klog.Error("--mode must be controller or node")
		os.Exit(2)
	}
}
