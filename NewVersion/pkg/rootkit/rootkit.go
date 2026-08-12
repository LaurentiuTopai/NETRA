package rootkit

import (
	"context"
	"fmt"

	"edr-agent/pkg/events"
	"edr-agent/pkg/store"
)

const (
	EventMemfdCreate = 1
	EventFinitModule = 2
	EventPtrace      = 3
	EventBPF         = 4
)

type Event struct {
	Type   uint32
	Pid    uint32
	Ppid   uint32
	Uid    uint32
	Comm   string
	Arg1   int64
	Arg2   int64
	StrArg string
}

type Rootkit struct {
	store *store.ProcessStore
	ctx   context.Context
}

func NewRootkit(ps *store.ProcessStore, ctx context.Context) *Rootkit {
	return &Rootkit{
		store: ps,
		ctx:   ctx,
	}
}

func (r *Rootkit) TrackEvent(e Event) {
	switch e.Type {
	case EventMemfdCreate:
		msg := fmt.Sprintf("Memfile:%s | Flags:0x%x", e.StrArg, e.Arg2)
		fmt.Printf("[ALERT - FileLess Malware] PID:%d | PPID:%d | UID:%d | Exec:%s | %s\n",
			e.Pid, e.Ppid, e.Uid, e.Comm, msg)
		events.SendAlert(r.ctx, "[ROOTKIT][FILELESS]", e.Pid, e.Comm, msg)

	case EventFinitModule:
		msg := fmt.Sprintf("FD:%d | Flags:0x%x", e.Arg1, e.Arg2)
		fmt.Printf("[ALERT - LKM Module LOAD] PID:%d | PPID:%d | UID:%d | Exec:%s | %s\n",
			e.Pid, e.Ppid, e.Uid, e.Comm, msg)
		events.SendAlert(r.ctx, "[ROOTKIT][LKM_LOAD]", e.Pid, e.Comm, msg)

	case EventPtrace:
		msg := fmt.Sprintf("Target PID:%d | Request:%d", e.Arg2, e.Arg1)
		fmt.Printf("[ALERT - PROCESS INJECTION] PID:%d | PPID:%d | Exec:%s -> %s\n",
			e.Pid, e.Ppid, e.Comm, msg)
		events.SendAlert(r.ctx, "[ROOTKIT][PTRACE_INJECT]", e.Pid, e.Comm, msg)

	case EventBPF:
		msg := fmt.Sprintf("BPF_cmd_code:%d", e.Arg1)
		fmt.Printf("[ALERT - EBPF PROGRAM LOAD] PID:%d | PPID:%d | Exec:%s | %s\n",
			e.Pid, e.Ppid, e.Comm, msg)
		events.SendAlert(r.ctx, "[ROOTKIT][EBPF_LOAD]", e.Pid, e.Comm, msg)
	}
}
