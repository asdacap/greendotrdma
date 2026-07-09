// Fabric transport preparation: load the NVMe-oF transport's kernel modules and,
// for RDMA, make sure an RDMA device exists (optionally standing up Soft-RoCE)
// before Connect writes /dev/nvme-fabrics. The Go mirror of the box side's
// crates/greendotctl/src/modules.rs (ensure/rxe_add). SPDX: Apache-2.0
package node

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"k8s.io/klog/v2"
)

const sysInfiniband = "/sys/class/infiniband"

// fabricModules maps an NVMe-oF transport to the modules that must be loaded
// before /dev/nvme-fabrics accepts a connect for it. New transport = one entry.
var fabricModules = map[string][]string{
	"rdma": {"nvme-rdma"},
	"tcp":  {"nvme-tcp"},
}

// run executes a command and folds its output into the error. Indirected so
// tests can capture the invocations without a kernel to talk to.
var run = func(name string, args ...string) error {
	klog.Infof("transport prep: %s %s", name, strings.Join(args, " "))
	if out, err := exec.Command(name, args...).CombinedOutput(); err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// rdmaDevicePresent reports whether the kernel exposes at least one RDMA device
// (hardware NIC or an already-provisioned Soft-RoCE link).
var rdmaDevicePresent = func() bool {
	entries, err := os.ReadDir(sysInfiniband)
	return err == nil && len(entries) > 0
}

// modprobe loads the named modules in one idempotent call.
func modprobe(names ...string) error {
	return run("modprobe", append([]string{"-a"}, names...)...)
}

// prepareTransport makes the host ready to connect this volume's fabric: the
// transport's kernel modules are loaded and, for RDMA, an RDMA device is
// present. Every step is idempotent, so it is safe to call before each Connect.
func (c *Connector) prepareTransport(softRoceNetdev string) error {
	mods, ok := fabricModules[c.Transport]
	if !ok {
		return fmt.Errorf("transport %q not supported (tcp/rdma)", c.Transport)
	}
	if err := modprobe(mods...); err != nil {
		return err
	}
	if c.Transport == "rdma" {
		return ensureRdmaDevice(softRoceNetdev)
	}
	return nil
}

// ensureRdmaDevice guarantees an RDMA device exists. With hardware RDMA (or an
// externally-provisioned rxe) /sys/class/infiniband is already populated. Else,
// if a Soft-RoCE netdev was configured, load rdma_rxe and add an rxe link over
// it (mirrors greendotctl modules.rs rxe_add); with no netdev we return a
// diagnostic error naming the missing device.
func ensureRdmaDevice(netdev string) error {
	if rdmaDevicePresent() {
		return nil
	}
	if netdev == "" {
		return fmt.Errorf("transport=rdma but no RDMA device under %s and --soft-roce-netdev unset: "+
			"enable an RDMA NIC or set --soft-roce-netdev", sysInfiniband)
	}
	if err := modprobe("rdma_rxe"); err != nil {
		return err
	}
	// rdma link add fails if the link already exists (a re-run); tolerate that
	// as long as a device is now present.
	if err := run("rdma", "link", "add", "rxe-"+netdev, "type", "rxe", "netdev", netdev); err != nil && !rdmaDevicePresent() {
		return err
	}
	return nil
}
