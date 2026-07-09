package node

import (
	"slices"
	"strings"
	"testing"
)

// prepareTransport drives modprobe and (for rdma) the rxe setup. The table
// covers every branch: tcp, rdma with a device already present, rdma standing
// up Soft-RoCE, rdma with no device and no netdev, and an unknown transport.
func TestPrepareTransport(t *testing.T) {
	for _, tc := range []struct {
		name      string
		transport string
		netdev    string
		hasDevice bool
		wantCmds  []string
		wantErr   bool
	}{
		{
			name:      "tcp loads only nvme-tcp",
			transport: "tcp",
			wantCmds:  []string{"modprobe -a nvme-tcp"},
		},
		{
			name:      "rdma with device present skips rxe",
			transport: "rdma",
			hasDevice: true,
			wantCmds:  []string{"modprobe -a nvme-rdma"},
		},
		{
			name:      "rdma without device stands up soft-roce",
			transport: "rdma",
			netdev:    "eth0",
			wantCmds: []string{
				"modprobe -a nvme-rdma",
				"modprobe -a rdma_rxe",
				"rdma link add rxe-eth0 type rxe netdev eth0",
			},
		},
		{
			name:      "rdma without device or netdev errors",
			transport: "rdma",
			wantCmds:  []string{"modprobe -a nvme-rdma"},
			wantErr:   true,
		},
		{
			name:      "unknown transport errors before any command",
			transport: "fc",
			wantErr:   true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var got []string
			restoreRun, restoreDev := run, rdmaDevicePresent
			t.Cleanup(func() { run, rdmaDevicePresent = restoreRun, restoreDev })
			run = func(name string, args ...string) error {
				got = append(got, strings.Join(append([]string{name}, args...), " "))
				return nil
			}
			rdmaDevicePresent = func() bool { return tc.hasDevice }

			c := &Connector{Transport: tc.transport}
			err := c.prepareTransport(tc.netdev)
			if (err != nil) != tc.wantErr {
				t.Fatalf("prepareTransport err = %v, wantErr = %v", err, tc.wantErr)
			}
			if !slices.Equal(got, tc.wantCmds) {
				t.Fatalf("commands = %v, want %v", got, tc.wantCmds)
			}
		})
	}
}
