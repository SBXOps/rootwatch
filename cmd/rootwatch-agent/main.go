package main

import (
	"log"
	"os"

	"github.com/rootwatch/rootwatch/internal/config"
	agent "github.com/rootwatch/rootwatch/internal/agent"
)

func main() {
	configPath := os.Getenv("ROOTWATCH_CONFIG")
	if configPath == "" {
		configPath = "/etc/rootwatch/config.yaml"
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", configPath, err)
	}

	if cfg.AgentToken == "" {
		log.Fatalf("No agent token configured")
	}

	agent.Start(cfg)
}
