package helper

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

func TestTunnelRecovery(t *testing.T) {
	for _, failure := range []string{"handshake", "session", "exec", "cancel", "drop", "host-key"} {
		t.Run(failure, func(t *testing.T) {
			_, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			signer, err := ssh.NewSignerFromKey(key)
			if err != nil {
				t.Fatal(err)
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			keyBlock, err := ssh.MarshalPrivateKey(key, "test")
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			keyPath, hostsPath := filepath.Join(dir, "key"), filepath.Join(dir, "known_hosts")
			if err := os.WriteFile(keyPath, pem.EncodeToMemory(keyBlock), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(hostsPath, []byte(knownhosts.Line([]string{listener.Addr().String()}, signer.PublicKey())+"\n"), 0600); err != nil {
				t.Fatal(err)
			}
			tunnel, err := NewTunnel(SSHConfig{Addr: listener.Addr().String(), User: "test", KeyPath: keyPath, KnownHostsPath: hostsPath})
			if err != nil {
				t.Fatal(err)
			}
			tunnel.conf.Timeout = 200 * time.Millisecond
			config := &ssh.ServerConfig{PublicKeyCallback: func(_ ssh.ConnMetadata, pub ssh.PublicKey) (*ssh.Permissions, error) { return nil, nil }}
			config.AddHostKey(signer)
			var workers sync.WaitGroup
			closed := make(chan struct{}, 2)
			accepted := make(chan struct{}, 2)
			serverErrors := make(chan error, 2)
			workers.Add(1)
			go func() {
				defer workers.Done()
				for attempt := 0; attempt < 2; attempt++ {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Add(1)
					go func(attempt int) {
						defer workers.Done()
						defer conn.Close()
						defer func() { closed <- struct{}{} }()
						accepted <- struct{}{}
						if attempt == 0 && (failure == "handshake" || failure == "cancel") {
							io.Copy(io.Discard, conn)
							return
						}
						serverConfig := config
						if attempt == 0 && failure == "host-key" {
							_, otherKey, _ := ed25519.GenerateKey(rand.Reader)
							otherSigner, _ := ssh.NewSignerFromKey(otherKey)
							serverConfig = &ssh.ServerConfig{PublicKeyCallback: config.PublicKeyCallback}
							serverConfig.AddHostKey(otherSigner)
						}
						server, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
						if err != nil {
							if failure != "host-key" {
								serverErrors <- err
							}
							return
						}
						defer server.Close()
						go ssh.DiscardRequests(requests)
						for channel := range channels {
							if attempt == 0 && failure == "session" {
								continue
							}
							stream, reqs, err := channel.Accept()
							if err != nil {
								return
							}
							for request := range reqs {
								if attempt == 0 && failure == "exec" {
									continue
								}
								request.Reply(true, nil)
								if attempt == 0 && failure == "drop" {
									return
								}
								io.Copy(stream, stream)
								return
							}
						}
					}(attempt)
				}
			}()
			defer func() {
				listener.Close()
				workers.Wait()
				close(serverErrors)
				for err := range serverErrors {
					t.Error(err)
				}
			}()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if failure == "cancel" {
				go func() { <-accepted; cancel() }()
			}
			start := time.Now()
			conn, err := tunnel.DialContext(ctx, "")
			if failure == "drop" {
				if err == nil {
					conn.SetReadDeadline(time.Now().Add(time.Second))
					_, err = conn.Read(make([]byte, 1))
					conn.Close()
				}
			} else if conn != nil {
				conn.Close()
				t.Fatal("failed setup unexpectedly connected")
			}
			if err == nil {
				t.Fatal("expected connection failure")
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("setup did not respect timeout/cancellation")
			}
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("failed transport was not closed")
			}
			// Every redial owns a fresh transport, even after a failed handshake or
			// a successfully established session that the peer subsequently dropped.
			tunnel.conf.Timeout = 2 * time.Second
			conn, err = tunnel.DialContext(context.Background(), "")
			if err != nil {
				t.Fatal(err)
			}
			conn.SetDeadline(time.Now().Add(time.Second))
			if _, err := conn.Write([]byte("ok")); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			reply := make([]byte, 2)
			if _, err := io.ReadFull(conn, reply); err != nil {
				conn.Close()
				t.Fatal(err)
			}
			if string(reply) != "ok" {
				t.Errorf("unexpected reply %q", reply)
			}
			conn.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
			if _, err := conn.Read(reply); err == nil {
				t.Error("read deadline did not interrupt the idle session")
			}
			conn.Close()
			select {
			case <-closed:
			case <-time.After(2 * time.Second):
				t.Fatal("successful transport was not closed")
			}
		})
	}
}
