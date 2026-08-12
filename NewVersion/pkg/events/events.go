package events

import (
	"context"
	"time"

	"github.com/wailsapp/wails/v2/pkg/runtime"
)

type EDRAlert struct {
	Type      string `json:"type"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Message   string `json:"message"`
	Timestamp string `json:"timestamp"`
}

type NetworkPacket struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Pid       uint32 `json:"pid"`
	Comm      string `json:"comm"`
	Protocol  string `json:"protocol"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	DstPort   uint16 `json:"dst_port"`
	Len       uint32 `json:"len"`
	Payload   string `json:"payload"`
	HexDump   string `json:"hex_dump"`
}

func SendAlert(ctx context.Context, alertType string, pid uint32, comm string, message string) {
	if ctx == nil {
		return
	}

	alert := EDRAlert{
		Type:      alertType,
		Pid:       pid,
		Comm:      comm,
		Message:   message,
		Timestamp: time.Now().Format("15:04:05"),
	}
	runtime.EventsEmit(ctx, "edr:alert", alert)
}

func SendNetworkPacket(ctx context.Context, packet NetworkPacket) {
	if ctx == nil {
		return
	}
	runtime.EventsEmit(ctx, "ndr:packet", packet)
}
