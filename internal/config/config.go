package config

import (
    "fmt"
    "os"

    "gopkg.in/yaml.v3"
)

type Config struct {
    APIURL       string `yaml:"api_url"`
    AgentToken   string `yaml:"agent_token"`
    ScanInterval string `yaml:"scan_interval"`
    LogLevel     string `yaml:"log_level"`
}

func Load(path string) (*Config, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("failed to read config file: %w", err)
    }

    var cfg Config
    if err := yaml.Unmarshal(data, &cfg); err != nil {
        return nil, fmt.Errorf("failed to parse yaml config: %w", err)
    }

    // Set defaults if missing
    if cfg.ScanInterval == "" {
        cfg.ScanInterval = "24h"
    }
    if cfg.LogLevel == "" {
        cfg.LogLevel = "info"
    }

    return &cfg, nil
}
