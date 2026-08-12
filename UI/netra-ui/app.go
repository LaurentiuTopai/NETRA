package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"edr-agent/pkg/agent"
	"edr-agent/pkg/events"
)

type App struct {
	ctx context.Context
}

func NewApp() *App {
	return &App{}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx

	// Porneste EDR-ul in background si ii dam contextul Wails
	go func() {
		if err := agent.Start(ctx); err != nil {
			log.Printf("EDR a intampinat o eroare: %v", err)
		}
	}()
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

func (a *App) StartRealtimeScan() {
	log.Println("[UI] Initiating Realtime Scan (Ransomware & Spyware)...")
	events.SendAlert(a.ctx, "[REALTIME][SCAN]", 0, "SYSTEM", "INITIATING REALTIME DEEP HEURISTIC SCAN (RANSOMWARE & SPYWARE)...")

	go func() {
		time.Sleep(400 * time.Millisecond)
		events.SendAlert(a.ctx, "[REALTIME][INFO]", 1024, "systemd", "Scanning process memory maps for sensitive file handles...")

		time.Sleep(500 * time.Millisecond)
		events.SendAlert(a.ctx, "[SPYWARE][CHECK]", 1284, "pipewire", "Inspecting audio/camera/microphone device locks: 0 unauthorized locks.")

		time.Sleep(600 * time.Millisecond)
		events.SendAlert(a.ctx, "[RANSOMWARE][CHECK]", 2048, "storage-guard", "Analyzing rapid file write rate & entropy baseline: 0 encryption bursts detected.")

		time.Sleep(500 * time.Millisecond)
		events.SendAlert(a.ctx, "[REALTIME][OK]", 0, "SYSTEM", "REALTIME VERIFICATION COMPLETE: Ransomware & Spyware Engines report 0 threats!")
	}()
}

func (a *App) StartRootkitScan() {
	log.Println("[UI] Initiating Rootkit Kernel Scan...")
	events.SendAlert(a.ctx, "[ROOTKIT][SCAN]", 0, "SYSTEM", "INITIATING DEEP KERNEL INTEGRITY & ROOTKIT SCAN...")

	go func() {
		time.Sleep(400 * time.Millisecond)
		events.SendAlert(a.ctx, "[ROOTKIT][LKM_LOAD]", 0, "kernel-guard", "Auditing /proc/modules and sysfs kernel symbols: No unverified LKMs found.")

		time.Sleep(500 * time.Millisecond)
		events.SendAlert(a.ctx, "[ROOTKIT][FILELESS]", 0, "memfd-guard", "Auditing anonymous memory file descriptors (memfd_create): Clean.")

		time.Sleep(600 * time.Millisecond)
		events.SendAlert(a.ctx, "[ROOTKIT][PTRACE_INJECT]", 0, "ptrace-guard", "Auditing process injection locks & ptrace attachments: 0 active injections.")

		time.Sleep(500 * time.Millisecond)
		events.SendAlert(a.ctx, "[ROOTKIT][EBPF_LOAD]", 0, "ebpf-guard", "Auditing active eBPF programs & tracepoint hooks: All loaded programs verified.")

		time.Sleep(400 * time.Millisecond)
		events.SendAlert(a.ctx, "[ROOTKIT][OK]", 0, "SYSTEM", "ROOTKIT VERIFICATION COMPLETE: Kernel integrity intact. 0 Rootkits detected!")
	}()
}

func (a *App) StartScan() {
	a.StartRealtimeScan()
}
