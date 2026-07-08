package helper

import (
	"io"
	"strings"
	"testing"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeStream struct {
	events []*helperpb.TaskEvent
}

func (f *fakeStream) Recv() (*helperpb.TaskEvent, error) {
	if len(f.events) == 0 {
		return nil, io.EOF
	}
	ev := f.events[0]
	f.events = f.events[1:]
	return ev, nil
}

func started(name string) *helperpb.TaskEvent {
	return &helperpb.TaskEvent{Event: &helperpb.TaskEvent_SubtaskStarted{
		SubtaskStarted: &helperpb.SubtaskStarted{Name: name},
	}}
}

func finished(st helperpb.SubStatus, errMsg string) *helperpb.TaskEvent {
	f := &helperpb.Finished{Status: st}
	if errMsg != "" {
		f.Error = &errMsg
	}
	return &helperpb.TaskEvent{Event: &helperpb.TaskEvent_Finished{Finished: f}}
}

// One table drives the whole Drain + Err contract: status folding, error
// propagation, code mapping, and the no-Finished transport error.
func TestDrainAndErrMapping(t *testing.T) {
	cases := []struct {
		name      string
		events    []*helperpb.TaskEvent
		wantErr   bool // Drain itself errors (transport-level)
		wantCode  codes.Code
		wantInErr string
	}{
		{
			name:     "success is nil",
			events:   []*helperpb.TaskEvent{started("a"), finished(helperpb.SubStatus_SUB_STATUS_SUCCESS, "")},
			wantCode: codes.OK,
		},
		{
			name:     "skipped is nil (idempotent retry)",
			events:   []*helperpb.TaskEvent{started("a"), finished(helperpb.SubStatus_SUB_STATUS_SKIPPED, "")},
			wantCode: codes.OK,
		},
		{
			name: "daemon-side validation rejection maps to InvalidArgument",
			events: []*helperpb.TaskEvent{
				started("Validate request"),
				finished(helperpb.SubStatus_SUB_STATUS_FAILED, "invalid request: invalid CSI NQN"),
			},
			wantCode:  codes.InvalidArgument,
			wantInErr: "invalid CSI NQN",
		},
		{
			name: "operational failure maps to Internal",
			events: []*helperpb.TaskEvent{
				started("Resize zvol tank/x"),
				finished(helperpb.SubStatus_SUB_STATUS_FAILED, "dataset does not exist"),
			},
			wantCode:  codes.Internal,
			wantInErr: "does not exist",
		},
		{
			name:    "stream without Finished is a transport error, not a task result",
			events:  []*helperpb.TaskEvent{started("a")},
			wantErr: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := Drain(&fakeStream{events: tc.events})
			if tc.wantErr {
				if err == nil {
					t.Fatalf("Drain should have errored, got %+v", res)
				}
				return
			}
			if err != nil {
				t.Fatalf("Drain: %v", err)
			}
			opErr := res.Err("op")
			if tc.wantCode == codes.OK {
				if opErr != nil {
					t.Fatalf("expected nil, got %v", opErr)
				}
				return
			}
			st, ok := status.FromError(opErr)
			if !ok || st.Code() != tc.wantCode {
				t.Fatalf("expected code %v, got %v", tc.wantCode, opErr)
			}
			if !strings.Contains(st.Message(), tc.wantInErr) {
				t.Fatalf("expected %q in %q", tc.wantInErr, st.Message())
			}
		})
	}
}
