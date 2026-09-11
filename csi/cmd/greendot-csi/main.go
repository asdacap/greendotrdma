// greendot-csi: the greendotrdma CSI driver binary. --mode=controller serves
// the provisioning half (talking to greendotctl over SSH); --mode=node serves
// the per-worker half (fabric connect + mounts, forked from
// kubernetes-csi/csi-driver-nvmf). SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"flag"
	"os"
	"time"

	"github.com/asdacap/greendotrdma/csi/pkg/driver"
	"github.com/asdacap/greendotrdma/csi/pkg/helper"
	"github.com/asdacap/greendotrdma/csi/pkg/node"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/klog/v2"
)

// inClusterKube builds a Kubernetes client from the pod's service account, used
// by the controller's export reconcile to enumerate attached volumes.
func inClusterKube() (kubernetes.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		return nil, err
	}
	return kubernetes.NewForConfig(cfg)
}

func main() {
	var (
		endpoint = flag.String("endpoint", "unix:///csi/csi.sock", "CSI endpoint")
		mode     = flag.String("mode", "", "controller or node")

		// node
		nodeID = flag.String("nodeid", "", "this node's host NQN (cat /etc/nvme/hostnqn)")
		hostID = flag.String("hostid", "", "this node's host id (cat /etc/nvme/hostid); pairs with --nodeid")
		volDir = flag.String("volume-map-dir", "/var/lib/kubelet/plugins/"+driver.DriverName+"/volumes",
			"where staged volumes' connector files persist")
		softRoce = flag.String("soft-roce-netdev", "",
			"if set and no RDMA device exists, create a Soft-RoCE (rxe) link on this netdev before rdma connects")

		// controller
		sshAddr    = flag.String("ssh-addr", "", "storage box sshd, host:port")
		sshUser    = flag.String("ssh-user", "greendot-csi", "SSH login user")
		sshKey     = flag.String("ssh-key", "", "SSH private key path")
		sshKnown   = flag.String("ssh-known-hosts", "", "pinned known_hosts path (required; never auto-accepted)")
		sshCommand = flag.String("ssh-command", "", "remote pipe command (default: the packaged greendotctl pipe)")
		traddr     = flag.String("traddr", "", "target address initiators connect to")
		trsvcid    = flag.Uint("trsvcid", 4421, "CSI nvmet port service id")
		transport  = flag.String("transport", "rdma", "rdma or tcp")
		reconcile  = flag.Duration("export-reconcile-interval", time.Minute,
			"how often the controller re-applies attached volumes' exports to self-heal a target reboot; 0 disables")
	)
	klog.InitFlags(nil)
	flag.Parse()

	switch *mode {
	case "node":
		if *nodeID == "" {
			klog.Fatal("--mode=node requires --nodeid (the host NQN)")
		}
		ns := node.NewNodeServer(*nodeID, *hostID, *volDir, *softRoce)
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
			TrAddr:    *traddr,
			TrSvcID:   uint32(*trsvcid),
			Transport: *transport,
		}, client.Helper)
		if err != nil {
			klog.Fatal(err)
		}
		// Attachment UIDs are the target's durable fencing generations. An
		// unavailable Kubernetes identity source must never fall back to host-only grants.
		kube, err := inClusterKube()
		if err != nil {
			klog.Fatalf("controller requires Kubernetes attachment lookup: %v", err)
		}
		cs.SetKubernetes(kube)
		if *reconcile > 0 {
			go cs.ReconcileExports(context.Background(), kube, *reconcile)
		}
		if err := driver.Serve(*endpoint, &driver.IdentityServer{}, cs, nil); err != nil {
			klog.Fatal(err)
		}
	default:
		klog.Error("--mode must be controller or node")
		os.Exit(2)
	}
}
