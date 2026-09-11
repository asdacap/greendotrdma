// SPDX-License-Identifier: Apache-2.0
package driver

import (
	"context"
	"time"

	"github.com/asdacap/greendotrdma/csi/pkg/helperpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

const operationTimeout = 30 * time.Second

// SetKubernetes enables authoritative VolumeAttachment UID lookup. Production
// requires it; direct test/CLI users must explicitly supply AttachmentID instead.
func (cs *ControllerServer) SetKubernetes(kube kubernetes.Interface) { cs.kube = kube }

func (cs *ControllerServer) attachmentID(ctx context.Context, volume, host string, publishing bool) (string, error) {
	if cs.cfg.AttachmentID != "" {
		return cs.cfg.AttachmentID, nil
	}
	if cs.kube == nil {
		return "", status.Error(codes.FailedPrecondition, "Kubernetes attachment lookup or explicit direct attachment ID is required")
	}
	ctx, cancel := context.WithTimeout(ctx, operationTimeout)
	defer cancel()
	attachments, err := cs.kube.StorageV1().VolumeAttachments().List(ctx, metav1.ListOptions{})
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "listing attachments: %v", err)
	}
	var found string
	for _, attachment := range attachments.Items {
		if attachment.Spec.Attacher != DriverName || attachment.Spec.Source.PersistentVolumeName == nil {
			continue
		}
		if publishing == (attachment.DeletionTimestamp != nil) {
			continue
		}
		pv, err := cs.kube.CoreV1().PersistentVolumes().Get(ctx, *attachment.Spec.Source.PersistentVolumeName, metav1.GetOptions{})
		if err != nil {
			return "", status.Errorf(codes.Unavailable, "reading attachment volume: %v", err)
		}
		if pv.Spec.CSI == nil || pv.Spec.CSI.Driver != DriverName || pv.Spec.CSI.VolumeHandle != volume {
			continue
		}
		nodeHost := cs.nodeHostNQN(ctx, cs.kube, attachment.Spec.NodeName)
		if nodeHost == "" {
			return "", status.Error(codes.Unavailable, "cannot resolve attachment host")
		}
		if nodeHost != host {
			continue
		}
		if attachment.UID == "" || found != "" {
			return "", status.Error(codes.FailedPrecondition, "missing or ambiguous attachment generation")
		}
		found = string(attachment.UID)
	}
	if found == "" && publishing {
		return "", status.Error(codes.FailedPrecondition, "no live attachment for volume and host")
	}
	// An already-removed attachment is an idempotent detach. Never infer a UID
	// from the current target owner: a delayed detach could then fence a new one.
	return found, nil
}

func (cs *ControllerServer) targetAttachment(ctx context.Context, nqn string) (*helperpb.CsiAttachmentReply, error) {
	owner, err := cs.helper.CsiAttachment(ctx, &helperpb.CsiNvmeDelete{Nqn: nqn})
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "reading target attachment: %v", err)
	}
	if owner.Error != "" {
		return nil, status.Errorf(codes.Internal, "reading target attachment: %s", owner.Error)
	}
	return owner, nil
}
