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
	"sync"
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
// One ssh.Client is kept per live gRPC connection: gRPC redials through
// DialContext when the channel drops, which builds a fresh SSH connection.
type Tunnel struct {
	addr    string
	command string
	conf    *ssh.ClientConfig

	mu     sync.Mutex
	client *ssh.Client
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
	client, err := t.sshClient()
	if err != nil {
		return nil, err
	}
	sess, err := client.NewSession()
	if err != nil {
		// The cached client may be a dead TCP connection; drop it so the
		// next dial rebuilds, and fail this attempt (gRPC retries).
		t.reset(client)
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
	return &sessionConn{sess: sess, in: stdin, out: stdout}, nil
}

func (t *Tunnel) sshClient() (*ssh.Client, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client != nil {
		return t.client, nil
	}
	client, err := ssh.Dial("tcp", t.addr, t.conf)
	if err != nil {
		return nil, fmt.Errorf("ssh: dialing %s: %w", t.addr, err)
	}
	t.client = client
	return client, nil
}

func (t *Tunnel) reset(stale *ssh.Client) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.client == stale {
		t.client.Close()
		t.client = nil
	}
}

// sessionConn adapts an SSH session's stdio to net.Conn. Deadlines are no-ops:
// gRPC drives cancellation through contexts and its own keepalives.
type sessionConn struct {
	sess *ssh.Session
	in   interface {
		Write([]byte) (int, error)
		Close() error
	}
	out interface{ Read([]byte) (int, error) }
}

func (c *sessionConn) Read(b []byte) (int, error)  { return c.out.Read(b) }
func (c *sessionConn) Write(b []byte) (int, error) { return c.in.Write(b) }

func (c *sessionConn) Close() error {
	c.in.Close() // EOF to the pipe -> daemon sees a clean shutdown
	return c.sess.Close()
}

type pipeAddr struct{}

func (pipeAddr) Network() string { return "ssh" }
func (pipeAddr) String() string  { return "greendotctl-pipe" }

func (c *sessionConn) LocalAddr() net.Addr                { return pipeAddr{} }
func (c *sessionConn) RemoteAddr() net.Addr               { return pipeAddr{} }
func (c *sessionConn) SetDeadline(t time.Time) error      { return nil }
func (c *sessionConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *sessionConn) SetWriteDeadline(t time.Time) error { return nil }
