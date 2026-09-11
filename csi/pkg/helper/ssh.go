// Package helper is the CSI controller's client for the greendotctl daemon:
// gRPC/h2 tunnelled through SSH to `greendotctl pipe` (the forced command of
// the greendot-csi user), plus the TaskEvent stream driver that turns the
// daemon's recorded tasks into synchronous results.
//
// The SSH host key is ALWAYS verified against a pinned known_hosts file —
// this controller holds a credential to the storage box, and presenting it
// to an unverified host is how democratic-csi got it wrong.
package helper

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

// DefaultPipeCommand is what the tunnel asks sshd to exec. With the intended
// deployment (authorized_keys `command="…greendotctl pipe",restrict`) the
// string is ignored by sshd and the forced command runs regardless; without a
// forced command (e.g. a test environment) it runs the pipe directly.
const DefaultPipeCommand = "/usr/libexec/greendotrdma/greendotctl pipe"

// SSHConfig locates and authenticates the tunnel to the storage box.
type SSHConfig struct {
	// Addr is host:port of the box's sshd.
	Addr string
	// User is the SSH login (the packaged greendot-csi user).
	User string
	// KeyPath is the private key file.
	KeyPath string
	// KnownHostsPath pins the box's host key. Required — there is no
	// insecure fallback.
	KnownHostsPath string
	// Command overrides DefaultPipeCommand.
	Command string
}

// Tunnel dials SSH sessions whose stdio carries gRPC to the daemon socket.
// Each gRPC connection owns its SSH transport. Redials always build a fresh
// connection; closing a failed channel cannot leave a stale cached SSH client.
type Tunnel struct {
	addr    string
	command string
	conf    *ssh.ClientConfig
}

// NewTunnel validates the config and prepares the SSH client config. It does
// not connect; the first DialContext does.
func NewTunnel(cfg SSHConfig) (*Tunnel, error) {
	if cfg.KnownHostsPath == "" {
		return nil, fmt.Errorf("ssh: known_hosts path is required (host keys are always verified)")
	}
	hostKeys, err := knownhosts.New(cfg.KnownHostsPath)
	if err != nil {
		return nil, fmt.Errorf("ssh: loading known_hosts %s: %w", cfg.KnownHostsPath, err)
	}
	keyBytes, err := os.ReadFile(cfg.KeyPath)
	if err != nil {
		return nil, fmt.Errorf("ssh: reading key %s: %w", cfg.KeyPath, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh: parsing key %s: %w", cfg.KeyPath, err)
	}
	command := cfg.Command
	if command == "" {
		command = DefaultPipeCommand
	}
	return &Tunnel{
		addr:    cfg.Addr,
		command: command,
		conf: &ssh.ClientConfig{
			User:            cfg.User,
			Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
			HostKeyCallback: hostKeys,
			Timeout:         15 * time.Second,
		},
	}, nil
}

// DialContext opens one SSH session running the pipe command and returns its
// stdio as a net.Conn — the shape grpc.WithContextDialer wants.
func (t *Tunnel) DialContext(ctx context.Context, _ string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, t.conf.Timeout)
	defer cancel()
	transport, err := (&net.Dialer{}).DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dialing %s: %w", t.addr, err)
	}
	// Closing the TCP transport interrupts handshake, channel-open and exec
	// waits, including peers that accept TCP but never answer SSH requests.
	cancelled := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		transport.Close()
		close(cancelled)
	})
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := transport.SetDeadline(deadline); err != nil {
		transport.Close()
		return nil, err
	}
	connected := false
	defer func() {
		if !connected {
			transport.Close()
		}
	}()
	connection, channels, requests, err := ssh.NewClientConn(transport, t.addr, t.conf)
	if err != nil {
		return nil, fmt.Errorf("ssh: handshake: %w", err)
	}
	client := ssh.NewClient(connection, channels, requests)
	sess, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("ssh: opening session: %w", err)
	}
	stdin, err := sess.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: stdin pipe: %w", err)
	}
	stdout, err := sess.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("ssh: stdout pipe: %w", err)
	}
	if err := sess.Start(t.command); err != nil {
		return nil, fmt.Errorf("ssh: starting %q: %w", t.command, err)
	}
	if !stop() {
		<-cancelled
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := transport.SetDeadline(time.Time{}); err != nil {
		return nil, err
	}
	connected = true
	return &sessionConn{Conn: transport, in: stdin, out: stdout}, nil
}

// sessionConn adapts session stdio while retaining real TCP deadlines and
// ownership. Close shuts down the transport directly: sending SSH EOF/close
// first can itself block indefinitely on an unresponsive peer.
type sessionConn struct {
	net.Conn
	in  interface{ Write([]byte) (int, error) }
	out interface{ Read([]byte) (int, error) }
}

func (c *sessionConn) Read(b []byte) (int, error)  { return c.out.Read(b) }
func (c *sessionConn) Write(b []byte) (int, error) { return c.in.Write(b) }

type pipeAddr struct{}

func (pipeAddr) Network() string { return "ssh" }
func (pipeAddr) String() string  { return "greendotctl-pipe" }

func (c *sessionConn) LocalAddr() net.Addr  { return pipeAddr{} }
func (c *sessionConn) RemoteAddr() net.Addr { return pipeAddr{} }
