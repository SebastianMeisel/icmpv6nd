package main

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Interfaces []string `yaml:"interfaces"`
	Interface  string   `yaml:"interface"`

	Capture struct {
		Filter string `yaml:"filter"`
	} `yaml:"capture"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.Interfaces) == 0 && cfg.Interface != "" {
		cfg.Interfaces = []string{cfg.Interface}
	}

	if len(cfg.Interfaces) == 0 {
		return nil, fmt.Errorf("config: at least one interface is required")
	}

	return &cfg, nil
}
