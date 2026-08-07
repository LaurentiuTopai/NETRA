package main

import (
	"context"
	"fmt"
	"log"

	"edr-agent/pkg/agent"
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

// Am sters simularea (StartScan) pentru ca acum folosim motorul EDR real
func (a *App) StartScan() {
	// Poti porni/opri eventuale flag-uri de scanare aici in viitor
	fmt.Println("Scanare UI apasata. Motorul eBPF ruleaza deja in background.")
}
