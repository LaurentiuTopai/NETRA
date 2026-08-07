package main

import (
	"context"
	"log"

	"edr-agent/pkg/agent"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := agent.Start(ctx); err != nil {
		log.Fatalf("Agent failed: %v", err)
	}
}
