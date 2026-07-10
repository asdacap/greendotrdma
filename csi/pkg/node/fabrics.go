/*
Copyright 2021 The Kubernetes Authors.
Forked from kubernetes-csi/csi-driver-nvmf (pkg/nvmf/fabrics.go). greendot
modifications: the /run/nvmf hostnqn-keyed refcount map is gone (stage/unstage
is the per-node lifecycle now, so no per-pod refcounting is needed); the
device is resolved by the controller-pinned namespace uuid; the connector file
path is traversal-guarded (upstream's own `todo: maybe be attack` comment).

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
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"k8s.io/klog/v2"
)

const sysNvme = "/sys/class/nvme"

// Connector is everything needed to connect (and later disconnect) one
// volume's subsystem. Persisted as JSON per staged volume so NodeUnstageVolume
// — which receives only the volume id — can find its way back.
type Connector struct {
	VolumeID   string
	TargetNqn  string
	TargetAddr string
	TargetPort string
	Transport  string
	HostNqn    string
	HostID     string
	DeviceUUID string
}

// DevicePath is the udev by-id path for the pinned namespace uuid — stable
// across enumeration order, no read-back from the target needed.
func (c *Connector) DevicePath() string {
	return "/dev/disk/by-id/nvme-uuid." + c.DeviceUUID
}

// Connect writes the fabrics connect string to /dev/nvme-fabrics and waits
// for the device to appear. On wait failure the connection is rolled back.
func (c *Connector) Connect() (string, error) {
	if c.Transport != "tcp" && c.Transport != "rdma" {
		return "", fmt.Errorf("transport %q not supported (tcp/rdma)", c.Transport)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "nqn=%s,transport=%s,traddr=%s,trsvcid=%s",
		c.TargetNqn, c.Transport, c.TargetAddr, c.TargetPort)
	if c.HostNqn != "" {
		fmt.Fprintf(&b, ",hostnqn=%s", c.HostNqn)
	}
	// Pair the host NQN with its host id: without one the kernel falls back to
	// its default hostid, which is already bound to a different (default) NQN —
	// the connect is then rejected with "same hostid but different hostnqn".
	if c.HostID != "" {
		fmt.Fprintf(&b, ",hostid=%s", c.HostID)
	}

	f, err := os.OpenFile("/dev/nvme-fabrics", os.O_RDWR, 0o666)
	if err != nil {
		return "", fmt.Errorf("opening /dev/nvme-fabrics (is nvme-%s loaded?): %w", c.Transport, err)
	}
	defer f.Close()
	if _, err := f.WriteString(b.String()); err != nil {
		// EALREADY: this node already holds a controller to the subsystem
		// (a retried stage). The device path check below decides success.
		if !strings.Contains(err.Error(), "already") {
			return "", fmt.Errorf("connect %s: %w", c.TargetNqn, err)
		}
		klog.Infof("connect %s: already connected, reusing", c.TargetNqn)
	}

	devicePath := c.DevicePath()
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(devicePath); err == nil {
			return devicePath, nil
		}
		time.Sleep(time.Second)
	}
	if err := c.Disconnect(); err != nil {
		klog.Errorf("rollback disconnect of %s failed: %v", c.TargetNqn, err)
	}
	return "", fmt.Errorf("device %s did not appear after connecting %s", devicePath, c.TargetNqn)
}

// Disconnect deletes this node's controllers for the subsystem: every
// /sys/class/nvme/<ctrl> whose subsysnqn matches (and, when the kernel
// exposes it and we have one, whose hostnqn matches too).
func (c *Connector) Disconnect() error {
	entries, err := os.ReadDir(sysNvme)
	if err != nil {
		return fmt.Errorf("reading %s: %w", sysNvme, err)
	}
	deleted := 0
	for _, e := range entries {
		ctrl := filepath.Join(sysNvme, e.Name())
		if readTrim(filepath.Join(ctrl, "subsysnqn")) != c.TargetNqn {
			continue
		}
		if c.HostNqn != "" {
			if h := readTrim(filepath.Join(ctrl, "hostnqn")); h != "" && h != c.HostNqn {
				continue
			}
		}
		if err := os.WriteFile(filepath.Join(ctrl, "delete_controller"), []byte("1"), 0o200); err != nil {
			return fmt.Errorf("deleting controller %s: %w", e.Name(), err)
		}
		deleted++
	}
	klog.Infof("disconnect %s: deleted %d controller(s)", c.TargetNqn, deleted)
	return nil
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// Volume ids become file names under the connector dir; anything else is a
// path traversal attempt (upstream fabrics.go:355's unfixed todo). ':' is the
// managed ids' dataset-path separator — never a traversal character.
var volumeIDRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._:-]*$`)

func connectorPath(dir, volumeID string) (string, error) {
	if !volumeIDRe.MatchString(volumeID) {
		return "", fmt.Errorf("invalid volume id %q", volumeID)
	}
	return filepath.Join(dir, volumeID+".json"), nil
}

func persistConnector(dir string, c *Connector) error {
	path, err := connectorPath(dir, c.VolumeID)
	if err != nil {
		return err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func loadConnector(dir, volumeID string) (*Connector, error) {
	path, err := connectorPath(dir, volumeID)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Connector{}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, err
	}
	return c, nil
}

func removeConnector(dir, volumeID string) error {
	path, err := connectorPath(dir, volumeID)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
