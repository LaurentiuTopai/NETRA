package detector

import (
	"context"
	"fmt"
	"time"

	"edr-agent/pkg/events"
	"edr-agent/pkg/response"
	"edr-agent/pkg/store"
)

const (
	MaxWritesAllowed = 20
	TimeWindow       = 1 * time.Second
)

type RansomewareDetector struct {
	store *store.ProcessStore
	ctx   context.Context
}

func NewRansomewareDetector(ps *store.ProcessStore, ctx context.Context) *RansomewareDetector {
	return &RansomewareDetector{
		store: ps,
		ctx:   ctx,
	}
}

func (d *RansomewareDetector) OnFileWrite(pid uint32, comm string, filename string) {
	if store.IsCommWhiteListed(comm) || store.IsPathWhiteListed(filename) {
		return
	}
	writeCount, _ := d.store.UpdateFileWrite(pid, comm, filename, TimeWindow)

	if writeCount > MaxWritesAllowed {
		msg := fmt.Sprintf("Suspect rapid file writes: %d files written in %v", writeCount, TimeWindow)
		fmt.Printf("[RANSOMWARE] PID:%d (%s) %s\n", pid, comm, msg)
		events.SendAlert(d.ctx, "[RANSOMWARE][STOPPED]", pid, comm, msg)
		response.QuarantineProcess(pid, comm)
	}
}
