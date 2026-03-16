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

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

func normalizeConfig(cfg *Config) {
	if len(cfg.Interfaces) == 0 && cfg.Interface != "" {
		cfg.Interfaces = []string{cfg.Interface}
	}
}

func validateConfig(cfg *Config) error {
	if len(cfg.Interfaces) == 0 {
		return fmt.Errorf("config: define at least one interface in interfaces")
	}
	return nil
}
