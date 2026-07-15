/*
Copyright 2021 The Kubernetes Authors.
Forked from kubernetes-csi/csi-driver-nvmf (pkg/nvmf/server.go, nvmfplugin);
greendot modifications: trimmed logging interceptor, endpoint parsing inlined.

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

// Package driver assembles the greendot CSI driver: the identity service, the
// greendotctl-backed controller service, and the node service forked from
// csi-driver-nvmf. One binary, --mode selects which half serves.
package driver

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/container-storage-interface/spec/lib/go/csi"
	"google.golang.org/grpc"
	"k8s.io/klog/v2"
)

const (
	DriverName    = "csi.greendot.io"
	DriverVersion = "0.3.0"

	// CSINQNPrefix mirrors greendot-proto's CSI_NQN_PREFIX: the ownership
	// boundary. The daemon re-validates it; this constant only derives names.
	CSINQNPrefix = "nqn.2026-06.io.greendot.csi:"

	// importedPrefix marks a volume id that adopts a preexisting zvol at an
	// arbitrary dataset path rather than one the driver created. The full path
	// is base32hex-encoded after the prefix, so the imported flag and the path
	// both ride the volume id (the only per-volume state Kubernetes replays).
	// DeleteVolume tears down the export but never destroys such a zvol.
	importedPrefix = "imp1-"
)

// Serve runs the given CSI services on `endpoint` (unix:///… or tcp://…)
// until the server stops. Nil services are simply not registered.
func Serve(endpoint string, ids csi.IdentityServer, cs csi.ControllerServer, ns csi.NodeServer) error {
	proto, addr, err := parseEndpoint(endpoint)
	if err != nil {
		return err
	}
	if proto == "unix" {
		if err := os.Remove(addr); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("removing stale socket %s: %w", addr, err)
		}
	}
	listener, err := net.Listen(proto, addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", endpoint, err)
	}
	server := grpc.NewServer(grpc.UnaryInterceptor(logGRPC))
	if ids != nil {
		csi.RegisterIdentityServer(server, ids)
	}
	if cs != nil {
		csi.RegisterControllerServer(server, cs)
	}
	if ns != nil {
		csi.RegisterNodeServer(server, ns)
	}
	klog.Infof("listening on %v", listener.Addr())
	return server.Serve(listener)
}

func parseEndpoint(ep string) (string, string, error) {
	if proto, addr, ok := strings.Cut(ep, "://"); ok && addr != "" {
		switch strings.ToLower(proto) {
		case "unix":
			return "unix", "/" + strings.TrimLeft(addr, "/"), nil
		case "tcp":
			return "tcp", addr, nil
		}
	}
	return "", "", fmt.Errorf("invalid endpoint: %v", ep)
}

func logGRPC(ctx context.Context, req interface{}, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	klog.V(4).Infof("gRPC call: %s", info.FullMethod)
	resp, err := handler(ctx, req)
	if err != nil {
		klog.Errorf("gRPC %s error: %v", info.FullMethod, err)
	}
	return resp, err
}
