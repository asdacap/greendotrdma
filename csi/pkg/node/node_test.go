package node

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	mount "k8s.io/mount-utils"
)

func TestPublishRetries(t *testing.T) {
	for _, tc := range []struct {
		name                                    string
		block, readonly, conflict, modeConflict bool
	}{
		{name: "block", block: true},
		{name: "readonly block", block: true, readonly: true},
		{name: "different device", block: true, conflict: true},
		{name: "different mode", block: true, modeConflict: true},
		{name: "filesystem"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			directory := t.TempDir()
			target := filepath.Join(directory, "target")
			connector := &Connector{VolumeID: "tank:volume", DeviceUUID: "test-device"}
			if err := persistConnector(directory, connector); err != nil {
				t.Fatal(err)
			}
			mounter := mount.NewFakeMounter(nil)
			ns := NewNodeServer("", "", directory, "")
			ns.mounter = &mount.SafeFormatAndMount{Interface: mounter}
			capability := &csi.VolumeCapability{AccessType: &csi.VolumeCapability_Mount{Mount: &csi.VolumeCapability_MountVolume{}}}
			if tc.block {
				capability.AccessType = &csi.VolumeCapability_Block{Block: &csi.VolumeCapability_BlockVolume{}}
			}
			if tc.conflict || tc.modeConflict {
				if err := os.WriteFile(target, nil, 0600); err != nil {
					t.Fatal(err)
				}
				source := connector.DevicePath()
				options := []string{"bind", "ro"}
				if tc.conflict {
					source = "/dev/wrong-device"
					options = []string{"bind"}
				}
				mounter.MountPoints = []mount.MountPoint{{Device: source, Path: target, Opts: options}}
			}
			request := &csi.NodePublishVolumeRequest{VolumeId: connector.VolumeID, StagingTargetPath: filepath.Join(directory, "staging"), TargetPath: target, VolumeCapability: capability, Readonly: tc.readonly}
			var workers sync.WaitGroup
			for i := 0; i < 12; i++ {
				workers.Add(1)
				go func() {
					defer workers.Done()
					_, err := ns.NodePublishVolume(context.Background(), request)
					want := codes.OK
					if tc.conflict || tc.modeConflict {
						want = codes.FailedPrecondition
					}
					if status.Code(err) != want {
						t.Errorf("publish: got %v, want %s", err, want)
					}
				}()
			}
			workers.Wait()
			mounts, err := mounter.List()
			if err != nil || len(mounts) != 1 {
				t.Fatalf("mounts: %v, %v", mounts, err)
			}
			if tc.conflict || tc.modeConflict {
				if len(mounter.GetLog()) != 0 {
					t.Fatal("conflicting mount was mutated")
				}
				return
			}
			if len(mounter.GetLog()) != 1 {
				t.Fatalf("expected one mount operation: %v", mounter.GetLog())
			}
			if _, err := ns.NodeUnpublishVolume(context.Background(), &csi.NodeUnpublishVolumeRequest{VolumeId: connector.VolumeID, TargetPath: target}); err != nil {
				t.Fatal(err)
			}
			mounts, err = mounter.List()
			if err != nil || len(mounts) != 0 {
				t.Fatalf("mounts after unpublish: %v, %v", mounts, err)
			}
			if _, err := os.Stat(target); !os.IsNotExist(err) {
				t.Fatalf("target not removed: %v", err)
			}
		})
	}
}

func TestBlockMountIdentity(t *testing.T) {
	directory := t.TempDir()
	device := filepath.Join(directory, "device")
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(device, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(device, target); err != nil {
		t.Fatal(err)
	}
	if !sameBlockMount(device, target, "devtmpfs") {
		t.Fatal("same inode was not recognized")
	}
	if sameBlockMount(device, filepath.Join(directory, "missing"), "devtmpfs") {
		t.Fatal("missing target matched")
	}
}

func TestRescanNamespaceLayouts(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		controllers              []string
		direct, missingAttribute bool
	}{
		{name: "non-multipath", direct: true},
		{name: "multipath different controller index", controllers: []string{"nvme7"}},
		{name: "multiple paths", controllers: []string{"nvme2", "nvme9"}},
		{name: "no controllers"},
		{name: "missing attribute", controllers: []string{"nvme7"}, missingAttribute: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			blockClass := filepath.Join(root, "block")
			device := filepath.Join(blockClass, "nvme1n1", "device")
			if err := os.MkdirAll(device, 0750); err != nil {
				t.Fatal(err)
			}
			deviceNode := filepath.Join(root, "nvme1n1")
			if err := os.WriteFile(deviceNode, nil, 0600); err != nil {
				t.Fatal(err)
			}
			byID := filepath.Join(root, "by-id")
			if err := os.Symlink(deviceNode, byID); err != nil {
				t.Fatal(err)
			}
			var attributes []string
			if tc.direct {
				attributes = append(attributes, filepath.Join(device, "rescan_controller"))
			}
			for _, controller := range tc.controllers {
				controllerDir := filepath.Join(root, controller)
				if err := os.MkdirAll(controllerDir, 0750); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(controllerDir, filepath.Join(device, controller)); err != nil {
					t.Fatal(err)
				}
				attributes = append(attributes, filepath.Join(controllerDir, "rescan_controller"))
			}
			// Namespace entries in the subsystem must not be treated as controllers.
			if err := os.MkdirAll(filepath.Join(device, "nvme1n1"), 0750); err != nil {
				t.Fatal(err)
			}
			if !tc.missingAttribute {
				for _, attribute := range attributes {
					if err := os.WriteFile(attribute, []byte("0"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := rescanNamespace(byID, blockClass)
			wantError := tc.missingAttribute || !tc.direct && len(tc.controllers) == 0
			if (err != nil) != wantError {
				t.Fatalf("rescan error = %v, want error %v", err, wantError)
			}
			for _, attribute := range attributes {
				data, err := os.ReadFile(attribute)
				if tc.missingAttribute {
					if !os.IsNotExist(err) {
						t.Fatalf("missing attribute was created: %s", attribute)
					}
				} else if err != nil || string(data) != "1" {
					t.Fatalf("attribute %s = %q, %v", attribute, data, err)
				}
			}
		})
	}
}
