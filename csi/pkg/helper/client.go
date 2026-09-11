package helper

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/status"
	"k8s.io/klog/v2"
)

// Mirrors the daemon's MAX_MESSAGE ceiling.
const maxMessage = 256 * 1024

// Client is the gRPC client to greendotctl. TLS is deliberately absent at the
// gRPC layer: SSH is the authenticated, encrypted channel.
type Client struct {
	Helper helperpb.HelperClient
	conn   *grpc.ClientConn
}

// Connect builds a lazy client over the tunnel; the first rpc dials.
func Connect(t *Tunnel) (*Client, error) {
	conn, err := grpc.NewClient("passthrough:///greendotctl",
		grpc.WithContextDialer(t.DialContext),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time: 30 * time.Second, Timeout: 10 * time.Second, PermitWithoutStream: true,
		}),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxMessage),
			grpc.MaxCallSendMsgSize(maxMessage),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("grpc client: %w", err)
	}
	return &Client{Helper: helperpb.NewHelperClient(conn), conn: conn}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// TaskResult is one finished daemon task: terminal status, its first error,
// and the recorded log (the controller's pod log is the CSI-side audit trail
// for ops that bypass greendot-web's Tasks page).
type TaskResult struct {
	Status helperpb.SubStatus
	Error  string
	Log    []string
}

// Failed reports whether the task terminated Failed (Skipped counts as ok —
// it is the daemon's visible no-op for already-satisfied steps).
func (r TaskResult) Failed() bool {
	return r.Status == helperpb.SubStatus_SUB_STATUS_FAILED
}

// Mentions reports whether the failure mentions `s` — in the terminal error
// OR anywhere in the recorded output. A failed CLI's terminal error is the
// generic "zfs exited with status 1"; the actionable text ("dataset does not
// exist") is on the task's stderr, so idempotency matching must scan both.
func (r TaskResult) Mentions(s string) bool {
	if strings.Contains(r.Error, s) {
		return true
	}
	for _, line := range r.Log {
		if strings.Contains(line, s) {
			return true
		}
	}
	return false
}

// Err folds the result into a gRPC status: nil on success/skip, otherwise
// InvalidArgument for requests the daemon rejected at its validation choke
// point and Internal for operational failures.
func (r TaskResult) Err(op string) error {
	if !r.Failed() {
		return nil
	}
	if strings.Contains(r.Error, "invalid request") {
		return status.Errorf(codes.InvalidArgument, "%s: %s", op, r.Error)
	}
	return status.Errorf(codes.Internal, "%s: %s", op, r.Error)
}

// EventStream is the receive half of any task rpc's reply stream.
type EventStream interface {
	Recv() (*helperpb.TaskEvent, error)
}

// Drain consumes a task rpc's stream to completion. The transport erroring,
// or a stream that ends without the terminal Finished frame, is an error
// distinct from a *failed task* (which is a valid TaskResult).
func Drain(stream EventStream) (TaskResult, error) {
	var res TaskResult
	finished := false
	for {
		ev, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return res, err
		}
		switch e := ev.Event.(type) {
		case *helperpb.TaskEvent_SubtaskStarted:
			line := "== " + e.SubtaskStarted.Name
			if e.SubtaskStarted.Command != nil {
				line += ": $ " + *e.SubtaskStarted.Command + " " +
					strings.Join(e.SubtaskStarted.Args, " ")
			}
			res.Log = append(res.Log, line)
		case *helperpb.TaskEvent_Stdout:
			res.Log = append(res.Log, strings.TrimRight(e.Stdout.Data, "\n"))
		case *helperpb.TaskEvent_Stderr:
			res.Log = append(res.Log, strings.TrimRight(e.Stderr.Data, "\n"))
		case *helperpb.TaskEvent_SubtaskFinished:
			if e.SubtaskFinished.Error != nil {
				res.Log = append(res.Log, "error: "+*e.SubtaskFinished.Error)
			}
		case *helperpb.TaskEvent_Finished:
			finished = true
			res.Status = e.Finished.Status
			if e.Finished.Error != nil {
				res.Error = *e.Finished.Error
			}
		}
	}
	if !finished {
		return res, fmt.Errorf("task stream ended without a terminal Finished frame")
	}
	return res, nil
}

// RunTask starts one task rpc, drains it, and logs the recorded task to the
// pod log under `op` — the CSI-side audit trail. The returned TaskResult may
// be a failed task; transport errors surface as the error.
func RunTask(op string, stream EventStream, startErr error) (TaskResult, error) {
	if startErr != nil {
		return TaskResult{}, fmt.Errorf("%s: starting task rpc: %w", op, startErr)
	}
	res, err := Drain(stream)
	if err != nil {
		return res, fmt.Errorf("%s: task stream: %w", op, err)
	}
	for _, line := range res.Log {
		klog.Infof("[%s] %s", op, line)
	}
	klog.Infof("[%s] finished: %s %s", op, res.Status, res.Error)
	return res, nil
}

// ZvolInfo is the one typed read the controller needs (CreateVolume
// idempotency, expand no-op detection).
func (c *Client) ZvolInfo(ctx context.Context, dataset string) (*helperpb.ZvolInfoReply, error) {
	return c.Helper.ZvolInfo(ctx, &helperpb.ZvolInfo{Dataset: dataset})
}
